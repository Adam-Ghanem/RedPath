# Presentation-link validation

**Validated:** 2026-08-12 (GMT+1)
**Scope:** `README.md`, `CONTRIBUTING.md`, `docs/demo-deployment.md`, `docs/github-metadata.md`, `docs/record-demo.md`, `assets/demo/README.md`, and both issue templates.

## Results

| Check | Result |
| --- | --- |
| Repository-local Markdown links | **15 / 15 valid** |
| Public external URLs | **12 / 12 returned HTTP 200** |
| Localhost endpoints | Intentionally documented but not fetched; they require the reader to start the local demo profile first. |

## Public URLs checked

| Category | Verified destinations |
| --- | --- |
| Live project | `https://redpath-sec.vercel.app`, `https://github.com/Adam-Ghanem/RedPath` |
| Badges | The five README `img.shields.io` badge URLs |
| External utility | `https://gif.ski/` |
| ATT&CK references | `T1021.002`, `T1558.003`, `T1558.004`, and `T1649` official MITRE pages |

The marked demo-video placeholder is intentionally not counted as a published asset link: it appears only as a literal destination in a fenced recording instruction and remains visibly marked as pending a real browser recording.
