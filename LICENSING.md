# Licensing

This repository is a **fork** of [goose](https://github.com/aaif-goose/goose) used to build **Achilles** (the harness) and **Arrav** (the model).

The published source in this tree — goose-derived files **and** original Achilles / Arrav source — is licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) and [LICENSE-APACHE](LICENSE-APACHE).

> Not legal advice.

## Short version

| Material | License |
|----------|---------|
| Upstream goose code and modifications of it | [Apache License 2.0](LICENSE-APACHE) |
| Original Achilles / Arrav source in this repo | [Apache License 2.0](LICENSE-APACHE) |
| Attribution for the goose project | [NOTICE](NOTICE) |

You may use, modify, and redistribute this repository under Apache 2.0. Keep the Apache license text and `NOTICE` when you distribute source or binaries.

## What Apache 2.0 requires (do not skip)

For goose-derived material (and, now, the rest of this tree):

1. Keep a copy of the Apache 2.0 license (`LICENSE-APACHE`)
2. Keep copyright / attribution notices (`NOTICE` and file headers on goose-derived files)
3. Indicate modifications when you redistribute
4. Do not imply that AAIF / goose endorses Achilles

Apache 2.0 **does** allow commercial use. You **cannot** revoke third parties’ rights to use **upstream goose** from aaif-goose/goose.

Do **not** relicense goose files as MIT. They are Apache 2.0; Achilles original work in this repo is also Apache 2.0. The combined product is not MIT.

## Practical rules for this fork

1. Keep goose history and Apache notices intact. Do **not** strip Apache headers from goose-derived files.
2. New Achilles / Arrav source files are Apache 2.0 as well. A short module note is enough; do not add a second product license.
3. Prefer isolating Arrav-specific integration so upstream goose merges stay easier — that is a mergeability choice, not a license split.
4. When you ship binaries or source, include `LICENSE-APACHE` and `NOTICE`.
5. Unpublished Arrav **weights** (if any) stay out of public remotes until you choose to publish them under Apache 2.0 or a separate model license.

## Upstream sync

Pulling from `upstream` (aaif-goose/goose) brings more Apache-licensed code. Keep `NOTICE` and goose file headers. Do not introduce a second, conflicting license for new Achilles files.

## Trademarks

Do not use “Goose” or AAIF marks in a way that implies official endorsement. This product is branded **Achilles** (harness) and **Arrav** (model).
