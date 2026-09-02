# Achilles engine fixtures

Synthetic trees for exercising fingerprint + secrets + surface engines. Nothing here is a real credential or a production app.

In the desktop app: **Findings → Choose workspace** → pick one of the folders below → **Scan my repo**.

CI/headless (binary is still `goose`):

```bash
goose appsec scan --path examples/achilles-fixtures/aws-terraform
goose appsec scan --path examples/achilles-fixtures/kubernetes
goose appsec scan --path examples/achilles-fixtures/github-actions
goose appsec scan --path examples/achilles-fixtures/cloudflare-worker
goose appsec scan --path examples/achilles-fixtures/compose-paas
goose appsec scan --path examples/achilles-fixtures/ansible
goose appsec scan --path examples/achilles-fixtures/secrets
goose appsec scan --path examples/achilles-fixtures/sast
goose appsec scan --path examples/achilles-fixtures/literals --literals
goose appsec scan --path examples/achilles-fixtures/deps-unpinned
goose appsec scan --path examples/achilles-fixtures/deps-hygiene
```

Kitchen-sink (mixed): `examples/achilles-scan-fixture`.
