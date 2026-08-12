# Contributing to RedPath

RedPath welcomes contributions that improve **safe, explainable, and reproducible** Active Directory lab assessment. The project is intentionally built for authorized, synthetic, or isolated lab environments. Contributions must preserve that boundary.

## Development workflow

Fork the repository, create a focused branch, and keep each change small enough to review. The frontend is a zero-configuration Vite application; it should remain immediately explorable even when the Python API is unavailable.

```bash
git clone https://github.com/<your-account>/RedPath.git
cd RedPath/frontend
pnpm install
pnpm test
pnpm run build
```

The backend can be validated independently with Python 3.11 or later.

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=. pytest
```

## Synthetic-data and safety standard

Demo fixtures must remain synthetic. Do not submit customer data, credentials, private hostnames, production IP ranges, authentication material, captured directory exports, or command paths that would enable credential theft or exploitation. New scenario content must be evidence-led, dry-run by default, bounded to an authorized lab, and explicit about its defensive purpose.

| Contribution area | Expected standard |
| --- | --- |
| Product UI | Preserve the zero-configuration demo mode and explain state transitions through visible evidence. |
| Synthetic data | Use invented identities, hosts, domains, network ranges, and alert records only. |
| Attack-path logic | Keep weighted edges, assumptions, and chokepoints explainable and covered by tests. |
| ATT&CK mappings | Include the technique ID, a brief rationale, and a link to the relevant official entry. |
| Pull requests | Describe the security value, validation performed, and any visual or documentation updates. |

## Pull requests

Before opening a pull request, run the frontend checks shown above and update the README, screenshots, or scenario documentation when a user-visible behavior changes. Use a concise title in the form `feat:`, `fix:`, `docs:`, `test:`, or `chore:`. Reviewers will prioritize clarity, safety, determinism, and evidence-backed product behavior over feature volume.

## Reporting issues responsibly

If you identify a vulnerability in RedPath rather than a lab finding that the product models, do not publish sensitive details in a public issue. Use the repository’s private security reporting channel if available, or contact the maintainer directly with a minimal, reproducible description.
