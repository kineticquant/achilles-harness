---
name: auth-review
description: Review authentication and authorization in this workspace — login, sessions, JWT, permission checks. Prefer existing Achilles findings. No exploit steps.
---

Use this skill when the user asks about auth, sessions, JWT, IDOR, “can anyone hit this route?”, or RBAC.

## Method

1. `appsec_query` for auth-shaped findings (SAST, surfaces). Lead with those finding ids.
2. Find how this app actually authenticates: session cookie, JWT, API key, SSO middleware, framework `login_required` / `Depends` / Spring Security, etc. Read the real middleware, not a guess.
3. Trace **one** request path from an entry (route/handler) to a sensitive action (read/write user data, admin, deploy). Ask: is the same check present as on neighboring routes?
4. Look for: checks only in the UI, IDs taken from the client without ownership checks, JWT `alg`/`none`, cookies without the flags the rest of the app uses, default/test credentials in config.

## Do not

- Call missing client-side checks a vulnerability (the server must enforce)
- Invent an identity provider that fingerprint did not see
- Print secrets or session tokens
- Write exploit scripts

## Output

A short review: how auth works here, blockers with file:line (and finding ids if any), then nits. If you cannot find an auth layer, say so — that is itself the finding to investigate, not a claim that “there is no auth on the internet.”
