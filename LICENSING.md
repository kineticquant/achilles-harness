# Licensing

This repository is a **proprietary fork** of [goose](https://github.com/aaif-goose/goose) used as the base for **Achilles** (the harness) and **Arrav** (the model).

> Not legal advice. Confirm the final structure with counsel before shipping or selling.

## Short version

| Material | License |
|----------|---------|
| Upstream goose code and assets (and modifications that remain goose-derived) | [Apache License 2.0](LICENSE-APACHE) |
| Original Achilles / Arrav code, branding, model weights/configs, product docs | [LICENSE-ACHILLES](LICENSE-ACHILLES) (restrictive / commercial) |
| Combined product distribution | Your commercial terms **plus** Apache attribution obligations for goose portions |

## What Apache 2.0 still requires

You **must** keep for goose-derived material:

1. A copy of the Apache 2.0 license (`LICENSE-APACHE`)
2. Copyright / attribution notices (`NOTICE`)
3. Clear indication of modifications when you redistribute source
4. No implication that AAIF / goose endorses Achilles

Apache 2.0 **does** allow commercial use of goose itself. You **cannot** revoke third parties’ rights to use **upstream goose** from aaif-goose/goose. What you can restrict is **your** fork’s original work, product packaging, trademarks, and how *you* distribute the combined Achilles product.

## Practical layering

1. Keep goose history and Apache notices intact.
2. Put new Achilles / Arrav work under `LICENSE-ACHILLES` (or a later EULA).
3. Prefer isolating proprietary pieces (model integration, Arrav provider, branding, business logic) so license boundaries stay clear.
4. When customers get binaries or source, ship:
   - `LICENSE-APACHE`
   - `NOTICE`
   - Your commercial license / EULA
5. Do **not** strip Apache headers from goose files. Add Achilles headers only on **new** files you author.

## Upstream sync

Pulling from `upstream` (aaif-goose/goose) brings more Apache-licensed code. New Achilles-only files stay under `LICENSE-ACHILLES`. Resolve conflicts carefully so you do not accidentally relicense or delete required notices.

## Trademarks

Do not use “Goose” or AAIF marks in a way that implies official endorsement. This product is branded **Achilles** (harness) and **Arrav** (model).
