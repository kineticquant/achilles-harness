# Achilles scan fixture

Synthetic tree for exercising Achilles engines. Values are **fake / documentation examples** (including the AWS `EXAMPLE` access-key pattern). Do not treat anything here as a real credential or a real production app.

**Product path:** desktop Findings → Choose workspace → this folder → Scan my repo.

CI/headless (binary is still `goose`):

```bash
goose appsec scan --path examples/achilles-scan-fixture
goose appsec query --path examples/achilles-scan-fixture
```

Dedicated stacks (AWS, k8s, GitHub Actions, Cloudflare, Compose/PaaS, secrets) are under `examples/achilles-fixtures/`.
