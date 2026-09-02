//! Offline file/repo helpers. No network. Paths must stay under the workspace.

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Context, Result};
use argon2::Argon2;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256, Sha512};

/// Flag npm / PyPI versions published more recently than this.
pub const REGISTRY_FRESH_DAYS: i64 = 7;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAGIC: &[u8; 4] = b"ACH1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

pub fn resolve_under(root: &Path, rel: &str) -> Result<PathBuf> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let joined = if Path::new(rel).is_absolute() {
        PathBuf::from(rel)
    } else {
        root.join(rel)
    };
    let canon = joined.canonicalize().unwrap_or(joined);
    if !canon.starts_with(&root) {
        bail!("path is outside the workspace");
    }
    Ok(canon)
}

pub fn hash_file(path: &Path) -> Result<serde_json::Value> {
    let bytes = read_capped(path)?;
    Ok(serde_json::json!({
        "path": path.to_string_lossy(),
        "bytes": bytes.len(),
        "sha256": hex(&sha256(&bytes)),
        "sha512": hex(&sha512(&bytes)),
    }))
}

pub fn hash_verify(path: &Path, expected: &str) -> Result<serde_json::Value> {
    let hashed = hash_file(path)?;
    let want = expected.trim().to_ascii_lowercase();
    let sha256 = hashed.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
    let sha512 = hashed.get("sha512").and_then(|v| v.as_str()).unwrap_or("");
    let matches = want == sha256 || want == sha512;
    Ok(serde_json::json!({
        "path": hashed.get("path"),
        "sha256": sha256,
        "sha512": sha512,
        "matches": matches,
    }))
}

pub fn redact_text(text: &str) -> String {
    let mut out = text.to_string();
    for (pat, repl) in [
        (r"AKIA[0-9A-Z]{16}", "AKIA****************"),
        (r"(?i)bearer\s+[A-Za-z0-9._\-]+", "Bearer [redacted]"),
        (r"gh[pousr]_[A-Za-z0-9_]{20,}", "gh*_ [redacted]"),
        (r"github_pat_[A-Za-z0-9_]{20,}", "github_pat_[redacted]"),
        (r"xox[baprs]-[A-Za-z0-9-]{10,}", "xox*-[redacted]"),
        (r"sk-[A-Za-z0-9]{20,}", "sk-[redacted]"),
        (r"AIza[0-9A-Za-z\-_]{20,}", "AIza[redacted]"),
        (
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            "[redacted private key]",
        ),
    ] {
        if let Ok(re) = regex::Regex::new(pat) {
            out = re.replace_all(&out, repl).into_owned();
        }
    }
    out
}

pub fn entropy(text: &str) -> serde_json::Value {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return serde_json::json!({ "shannon": 0.0, "chars": 0 });
    }
    let mut counts = [0u64; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    serde_json::json!({ "shannon": h, "chars": bytes.len() })
}

pub fn decode_hex(text: &str) -> Result<serde_json::Value> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        bail!("hex length must be even");
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    let chars: Vec<char> = clean.chars().collect();
    for pair in chars.chunks(2) {
        let s: String = pair.iter().collect();
        bytes.push(u8::from_str_radix(&s, 16).context("invalid hex")?);
    }
    Ok(serde_json::json!({
        "bytes": bytes.len(),
        "utf8": String::from_utf8(bytes.clone()).ok(),
        "base64": STANDARD.encode(&bytes),
    }))
}

pub fn encode_base64(text: &str) -> serde_json::Value {
    serde_json::json!({ "base64": STANDARD.encode(text.as_bytes()) })
}

pub fn decode_base64(text: &str) -> Result<serde_json::Value> {
    let bytes = STANDARD
        .decode(text.trim())
        .or_else(|_| URL_SAFE_NO_PAD.decode(text.trim()))
        .context("invalid base64")?;
    Ok(serde_json::json!({
        "bytes": bytes.len(),
        "utf8": String::from_utf8(bytes.clone()).ok(),
        "hex": hex(&bytes),
    }))
}

/// Decode JWT header + payload. Does not verify the signature.
pub fn decode_jwt(token: &str) -> Result<serde_json::Value> {
    let mut parts = token.trim().split('.');
    let header = parts.next().context("jwt needs header")?;
    let payload = parts.next().context("jwt needs payload")?;
    let sig = parts.next();
    Ok(serde_json::json!({
        "header": decode_b64url_json(header)?,
        "payload": decode_b64url_json(payload)?,
        "signaturePresent": sig.is_some(),
        "verified": false,
        "note": "Decoded only. Signature is not checked.",
    }))
}

pub fn encrypt_file(path: &Path, passphrase: &str) -> Result<serde_json::Value> {
    if passphrase.len() < 8 {
        bail!("passphrase must be at least 8 characters");
    }
    let plain = read_capped(path)?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|e| anyhow::anyhow!("{e}"))?;
    getrandom::fill(&mut nonce_bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
    let key_bytes = derive_key(passphrase, &salt)?;
    let key = Key::<Aes256Gcm>::from(key_bytes);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plain.as_ref())
        .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?;
    let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    let dest = PathBuf::from(format!("{}.ach1", path.display()));
    std::fs::write(&dest, &out)?;
    Ok(serde_json::json!({
        "wrote": dest.to_string_lossy(),
        "bytes": out.len(),
        "sha256": hex(&sha256(&out)),
        "note": "AES-256-GCM, Argon2id key. Keep the passphrase; it is not stored.",
    }))
}

pub fn decrypt_file(path: &Path, passphrase: &str) -> Result<serde_json::Value> {
    let blob = read_capped(path)?;
    if blob.len() < MAGIC.len() + SALT_LEN + NONCE_LEN + 16 {
        bail!("file is too small to be an Achilles ciphertext");
    }
    if &blob[..4] != MAGIC {
        bail!("not an ACH1 ciphertext");
    }
    let salt = &blob[4..4 + SALT_LEN];
    let nonce_bytes = &blob[4 + SALT_LEN..4 + SALT_LEN + NONCE_LEN];
    let ciphertext = &blob[4 + SALT_LEN + NONCE_LEN..];
    let key_bytes = derive_key(passphrase, salt)?;
    let key = Key::<Aes256Gcm>::from(key_bytes);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::try_from(nonce_bytes).map_err(|_| anyhow::anyhow!("bad nonce"))?;
    let plain = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decrypt failed (wrong passphrase or truncated file)"))?;
    let dest = path.with_extension("decrypted");
    std::fs::write(&dest, &plain)?;
    Ok(serde_json::json!({
        "wrote": dest.to_string_lossy(),
        "bytes": plain.len(),
        "sha256": hex(&sha256(&plain)),
        "note": "Plaintext written to disk. Do not paste it into chat.",
    }))
}

pub fn shred_file(path: &Path, confirm: bool) -> Result<serde_json::Value> {
    if !confirm {
        bail!("set confirm=true to overwrite and delete. On SSDs this is not a forensic wipe.");
    }
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        bail!("shred only works on files");
    }
    if meta.len() > MAX_BYTES {
        bail!("file larger than {MAX_BYTES} bytes");
    }
    let len = meta.len() as usize;
    for _ in 0..3 {
        let mut buf = vec![0u8; len.max(1)];
        getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        std::fs::write(path, &buf)?;
    }
    std::fs::remove_file(path)?;
    Ok(serde_json::json!({
        "deleted": path.to_string_lossy(),
        "passes": 3,
        "note": "Working-tree overwrite only. Git history is unchanged. SSDs may retain remnants.",
    }))
}

/// Commands only. Never rewrites history.
pub fn git_purge_plan(root: &Path, rel: &str) -> Result<serde_json::Value> {
    let path = resolve_under(root, rel)?;
    let shown = path
        .strip_prefix(root)
        .unwrap_or(&path)
        .to_string_lossy()
        .replace('\\', "/");
    Ok(serde_json::json!({
        "executed": false,
        "path": shown,
        "warning": "Achilles will not rewrite git history. These commands are destructive and usually need a coordinated force-push.",
        "rotateFirst": true,
        "commands": [
            format!("git filter-repo --invert-paths --path {shown}"),
            format!("# alternative: git rm --cached {shown} && commit, then a history tool if the blob is already pushed"),
        ],
    }))
}

#[derive(Debug, Clone)]
pub struct UtilsArgs<'a> {
    pub action: &'a str,
    pub root: &'a Path,
    pub path: Option<&'a str>,
    pub text: Option<&'a str>,
    pub passphrase: Option<&'a str>,
    pub expected: Option<&'a str>,
    pub confirm: bool,
}

/// Shared by `appsec_utils` and the desktop Tools page.
pub fn run(args: UtilsArgs<'_>) -> Result<serde_json::Value> {
    let file = |rel: &str| resolve_under(args.root, rel);
    match args.action {
        "hash" => {
            let path = file(args.path.context("path is required for hash")?)?;
            hash_file(&path)
        }
        "hash_verify" => {
            let path = file(args.path.context("path is required")?)?;
            hash_verify(&path, args.expected.context("expected sha256 hex is required")?)
        }
        "redact" => {
            let text = args.text.context("text is required for redact")?;
            Ok(serde_json::json!({ "redacted": redact_text(text) }))
        }
        "entropy" => Ok(entropy(args.text.context("text is required for entropy")?)),
        "hex" => {
            let text = args.text.context("text is required for hex")?;
            let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.len() >= 2
                && compact.len() % 2 == 0
                && compact.chars().all(|c| c.is_ascii_hexdigit())
            {
                decode_hex(text)
            } else {
                Ok(serde_json::json!({ "hex": hex(text.as_bytes()) }))
            }
        }
        "base64" => {
            let text = args.text.context("text is required for base64")?;
            decode_base64(text).or_else(|_| Ok(encode_base64(text)))
        }
        "jwt" => decode_jwt(args.text.context("text is required for jwt")?),
        "encrypt" => encrypt_file(
            &file(args.path.context("path is required for encrypt")?)?,
            args.passphrase.context("passphrase is required for encrypt")?,
        ),
        "decrypt" => decrypt_file(
            &file(args.path.context("path is required for decrypt")?)?,
            args.passphrase.context("passphrase is required for decrypt")?,
        ),
        "shred" => shred_file(
            &file(args.path.context("path is required for shred")?)?,
            args.confirm,
        ),
        "git_purge_plan" => git_purge_plan(
            args.root,
            args.path.context("path is required for git_purge_plan")?,
        ),
        other => bail!(
            "unknown action {other}; use hash, hash_verify, redact, entropy, hex, base64, jwt, encrypt, decrypt, shred, or git_purge_plan"
        ),
    }
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(key)
}

fn read_capped(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_BYTES {
        bail!("file larger than {MAX_BYTES} bytes");
    }
    Ok(std::fs::read(path)?)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn sha512(bytes: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// True when `published` is strictly less than [`REGISTRY_FRESH_DAYS`] before `now`.
pub fn registry_publish_is_fresh(published: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now.signed_duration_since(published) < Duration::days(REGISTRY_FRESH_DAYS)
}

pub fn parse_registry_time(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S")
                .ok()
                .map(|naive| naive.and_utc())
        })
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|naive| naive.and_utc())
        })
}

fn decode_b64url_json(part: &str) -> Result<serde_json::Value> {
    let mut s = part.replace('-', "+").replace('_', "/");
    while s.len() % 4 != 0 {
        s.push('=');
    }
    let bytes = STANDARD.decode(&s).context("jwt b64")?;
    serde_json::from_slice(&bytes).context("jwt json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_refuse_escape() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, "hi").unwrap();
        let hashed = hash_file(&file).unwrap();
        assert_eq!(hashed["bytes"], 2);
        assert!(resolve_under(dir.path(), "../x").is_err());
        assert_eq!(
            hash_verify(&file, hashed["sha256"].as_str().unwrap()).unwrap()["matches"],
            true
        );
    }

    #[test]
    fn entropy_is_higher_for_randomish() {
        let low = entropy("aaaaaaaa")
            .get("shannon")
            .unwrap()
            .as_f64()
            .unwrap();
        let high = entropy("aB3$kQ9!")
            .get("shannon")
            .unwrap()
            .as_f64()
            .unwrap();
        assert!(high > low);
    }

    #[test]
    fn encrypt_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secret.txt");
        std::fs::write(&file, "classified").unwrap();
        let enc = encrypt_file(&file, "passphrase-long").unwrap();
        let wrote = PathBuf::from(enc["wrote"].as_str().unwrap());
        let dec = decrypt_file(&wrote, "passphrase-long").unwrap();
        let out = PathBuf::from(dec["wrote"].as_str().unwrap());
        assert_eq!(std::fs::read_to_string(out).unwrap(), "classified");
    }

    #[test]
    fn jwt_header_payload() {
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.sig";
        let v = decode_jwt(token).unwrap();
        assert_eq!(v["payload"]["sub"], "123");
        assert_eq!(v["verified"], false);
    }

    #[test]
    fn purge_is_a_plan() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("leak.env");
        std::fs::write(&file, "x").unwrap();
        let plan = git_purge_plan(dir.path(), "leak.env").unwrap();
        assert_eq!(plan["executed"], false);
    }

    #[test]
    fn run_redacts_without_a_scan() {
        let dir = tempfile::tempdir().unwrap();
        let out = run(UtilsArgs {
            action: "redact",
            root: dir.path(),
            path: None,
            text: Some("Bearer abcdefghijklmnop"),
            passphrase: None,
            expected: None,
            confirm: false,
        })
        .unwrap();
        assert!(out["redacted"].as_str().unwrap().contains("[redacted]"));
        let key = run(UtilsArgs {
            action: "redact",
            root: dir.path(),
            path: None,
            text: Some("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"),
            passphrase: None,
            expected: None,
            confirm: false,
        })
        .unwrap();
        assert!(key["redacted"]
            .as_str()
            .unwrap()
            .contains("redacted private key"));
    }

    #[test]
    fn flags_only_under_seven_days() {
        let now = DateTime::parse_from_rfc3339("2026-09-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let six = now - Duration::days(6);
        let seven = now - Duration::days(7);
        let eight = now - Duration::days(8);
        assert!(registry_publish_is_fresh(six, now));
        assert!(!registry_publish_is_fresh(seven, now));
        assert!(!registry_publish_is_fresh(eight, now));
        assert!(parse_registry_time("2026-08-30T00:00:00.000Z").is_some());
    }
}
