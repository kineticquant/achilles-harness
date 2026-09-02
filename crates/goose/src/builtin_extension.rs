use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;

pub type SpawnServerFn = fn(tokio::io::DuplexStream, tokio::io::DuplexStream);

static BUILTIN_REGISTRY: Lazy<RwLock<HashMap<&'static str, SpawnServerFn>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Register a builtin extension into the global registry
pub fn register_builtin_extension(name: &'static str, spawn_fn: SpawnServerFn) {
    BUILTIN_REGISTRY.write().unwrap().insert(name, spawn_fn);
}

/// Register multiple builtin extensions from a HashMap
pub fn register_builtin_extensions(extensions: HashMap<&'static str, SpawnServerFn>) {
    let mut registry = BUILTIN_REGISTRY.write().unwrap();
    registry.extend(extensions);
}

/// Get a copy of all registered builtin extensions
pub fn get_builtin_extension(name: &str) -> Option<SpawnServerFn> {
    BUILTIN_REGISTRY.read().unwrap().get(name).cloned()
}

pub fn get_builtin_extension_names() -> Vec<&'static str> {
    BUILTIN_REGISTRY.read().unwrap().keys().copied().collect()
}

/// Goose-era builtins we keep in the registry so leftover configs can still
/// spawn them, but we do not offer them in Achilles settings or discovery.
pub fn is_hidden_builtin(name: &str) -> bool {
    let key: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    matches!(
        key.as_str(),
        "tutorial" | "autovisualiser" | "computercontroller"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hides_goose_era_builtins_under_display_or_id_names() {
        assert!(is_hidden_builtin("tutorial"));
        assert!(is_hidden_builtin("Auto Visualiser"));
        assert!(is_hidden_builtin("computercontroller"));
        assert!(is_hidden_builtin("Computer Controller"));
        assert!(!is_hidden_builtin("memory"));
        assert!(!is_hidden_builtin("developer"));
    }
}
