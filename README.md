<p align="center">
  <a href="https://github.com/Adam-Ghanem/RedPath">
    <img src="assets/redpath-logo.png" alt="RedPath red-fang logo" width="144" />
  </a>
</p>

<h1 align="center">RedPath</h1>

<p align="center"><strong>See the path. Prove the gap.</strong></p>

<p align="center">
  <a href="https://redpath-sec.vercel.app"><strong>Try the live demo →</strong></a>
</p>

<p align="center">
  <a href="https://redpath-sec.vercel.app"><img src="https://img.shields.io/badge/demo-live%20on%20Vercel-22c55e.svg" alt="Live demo on Vercel" /></a>
  <a href="frontend/DEPLOYMENT.md"><img src="https://img.shields.io/badge/build-production%20verified-2563eb.svg" alt="Production build verified" /></a>
  <a href="frontend/DEPLOYMENT.md"><img src="https://img.shields.io/badge/tests-3%20passing%20locally-22c55e.svg" alt="Three frontend tests passing locally" /></a>
  <a href="backend/requirements.txt"><img src="https://img.shields.io/badge/python-3.11%2B-3776ab.svg" alt="Python 3.11 or later" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-f59e0b.svg" alt="MIT License" /></a>
</p>

Most pentest tools list vulnerabilities. **RedPath answers the question a SOC team actually needs answered:** *if this attack path exists, do we have evidence that we would detect it?*

RedPath turns a synthetic Active Directory trust map into a visual case file: weighted exposure paths, ATT&CK-aligned detection coverage, evidence-backed findings, and practical remediation in one explainable console. It is safe to explore immediately—no directory, credentials, agent, API key, or clone required.

## TL;DR

- **Explore a complete attack-path case file in your browser:** [open the seeded live demo](https://redpath-sec.vercel.app).
- **Connect exposure to detection:** inspect weighted paths, chokepoints, ATT&CK coverage, evidence, and remediation together.
- **Built for safe evaluation:** every asset, path, finding, and scenario is fully synthetic and dry-run by design.

## See it in action

![RedPath live dashboard with attack path graph](screenshots/redpath-hero.webp)

> **Product walkthrough:** A concise tour of the attack-path graph, detection-coverage view, and report workflow is planned for this section. Maintainers can follow the free recording guide in [`docs/record-demo.md`](docs/record-demo.md) to add `assets/demo/redpath-walkthrough.gif` (under 10 MB) from the live demo.

| In less than one minute | What the viewer sees |
| --- | --- |
| **Attack path graph** | A weighted, visual chain from a user-side asset to a privileged objective, with observed versus inferred relationships. |
| **Detection coverage** | ATT&CK-aligned coverage by tactic, purple-team gaps, and the evidence supporting each verdict. |
| **Case report workflow** | Evidence cards, remediation ownership, and a print-ready case-file layout that can be saved as a PDF from the browser. |

## Why this is different

| Generic vulnerability scanner | RedPath |
| --- | --- |
| Lists isolated weaknesses. | Connects weak signals into an explainable, weighted exposure path. |
| Reports a finding without showing defensive context. | Maps each path and finding to detection coverage and a clear gap verdict. |
| Usually requires an environment connection before it is useful. | Starts instantly with a safe, synthetic domain that is already explorable. |
| Treats remediation as a generic recommendation. | Keeps evidence, ATT&CK context, remediation owner, and review state in the same case file. |

## What you can inspect

| Surface | What it demonstrates |
| --- | --- |
| **Attack-path explorer** | Weighted synthetic Active Directory relationships, shortest paths, chokepoints, and observed versus inferred edges. |
| **Detection coverage** | Expected behaviors mapped to ATT&CK techniques, purple-team evidence, coverage by tactic, and gap verdicts. |
| **Findings dossier** | Asset-level severity, CVSS, technique mapping, supporting evidence, and a concrete remediation action. |
| **Safe scenario library** | Four individually detailed playbooks with expected techniques, dry-run recon plans, and evidence-backed risk summaries. |
| **Case-file report** | A structured, print-ready briefing surface that can be saved as a PDF from a browser without an external reporting service. |

## Quickstart

The live demo is the fastest route. To run the same seeded console locally, use three commands:

```bash
git clone https://github.com/Adam-Ghanem/RedPath.git && cd RedPath/frontend
pnpm install
pnpm dev
```

Open [http://localhost:5173](http://localhost:5173). The frontend renders the synthetic lab immediately and does not connect to a directory or execute commands.

## Demo mode and safety

The default dataset models six fictional assets, five evidence-backed findings, three weighted paths, ATT&CK tactic coverage, and four safe scenario playbooks. It is intentionally a **synthetic, dry-run learning and evaluation environment**.

| Synthetic scenario | Expected techniques | Coverage verdict |
| --- | --- | --- |
| Service identity exposure | `T1558.003`, `T1021.002` | Coverage gap |
| Pre-authentication drift | `T1558.004`, `T1098` | Partially covered |
| Certificate template escape | `T1649`, `T1098` | Coverage gap |
| File services blast radius | `T1021.002`, `T1098` | Validated |

> RedPath must only be used against systems you own or are explicitly authorized to assess. Demo mode contains fabricated hosts, identities, evidence, and paths; it does not store credentials, execute reconnaissance, or connect to an Active Directory environment.

## Architecture

![RedPath architecture: synthetic AD lab data flows through exposure reasoning into weighted attack paths, ATT&CK coverage, evidence-backed findings, and the decision console.](assets/redpath-architecture.png)

The browser-first console uses pre-seeded TypeScript data to stay immediately explorable. The repository also includes a FastAPI backend for authorized lab workflows, audit-oriented services, and Docker Compose guidance; the live demo remains useful without those services.

## Screenshots

| Forensic dashboard | Interactive path console |
| --- | --- |
| ![RedPath landing overview](screenshots/redpath-hero.webp) | ![RedPath interactive topology console](screenshots/redpath-console.webp) |

See [the screenshot guide](docs/screenshots.md) for verified views and data-handling notes.

## Optional full stack

The optional stack is for maintainers inspecting API contracts—not for using the demo.

```bash
docker compose --profile demo up --build
```

The console is available at [http://localhost:5173](http://localhost:5173); API documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs). Read the [safe demo deployment guide](docs/demo-deployment.md) before deploying the profile to Render or Fly.io.

## Contributing

Contributions are welcome when they preserve RedPath’s safe, explainable, and reproducible design. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request.

## Roadmap

- [ ] Add a concise, real browser walkthrough GIF for the live dashboard, coverage view, and PDF save flow.
- [ ] Add evidence-detail deep links from each graph node.
- [ ] Publish additional synthetic scenarios for identity, certificate, and lateral-movement coverage gaps.

## References

[1]: https://attack.mitre.org/techniques/T1558/003/ "MITRE ATT&CK: Kerberoasting"
[2]: https://attack.mitre.org/techniques/T1558/004/ "MITRE ATT&CK: AS-REP Roasting"
[3]: https://attack.mitre.org/techniques/T1649/ "MITRE ATT&CK: Steal or Forge Authentication Certificates"
[4]: https://attack.mitre.org/techniques/T1021/002/ "MITRE ATT&CK: SMB/Windows Admin Shares"

## AI Features

RedPath’s AI features are an **optional enhancement layer** over deterministic defensive analysis. The graph and risk engines remain authoritative: AI does not enumerate networks, execute commands, replace path scoring, or make autonomous remediation changes.

| Feature | Behavior | Fallback |
| --- | --- | --- |
| **AI risk assessment** | Adds a concise, evidence-grounded explanation and up to two recommended review actions to a modeled path. The deterministic risk tier and score remain authoritative. | Returns the deterministic path explanation, raw centrality score, modeled tier, and hardening actions when AI is disabled or unavailable. |
| **SOC copilot** | Explains a tenant-scoped finding or recently analyzed attack path in no more than three concise paragraphs, using stored finding data and the local MITRE registry. | Returns a context-only summary without external model claims. |

RedPath supports three explicit provider modes: `AI_PROVIDER=none` for deterministic rule-based explanations with no model call, `AI_PROVIDER=local` for an operator-controlled Ollama/vLLM-compatible endpoint, and `AI_PROVIDER=anthropic` for approved external processing through the Anthropic Messages API. Provider selection is server-side; clients cannot submit arbitrary provider URLs or keys.

Anthropic mode is tiered rather than globally pinned to one expensive model. Risk scoring uses the fast `claude-haiku-4-5` tier for latency-sensitive requests; copilot explanations use the deep `claude-sonnet-4-6` tier with a separate stricter rate limit, larger output budget, and longer timeout. The live catalog captured on 2026-08-14 did not list `claude-sonnet-5`, so RedPath uses the verified `claude-sonnet-4-6` identifier instead of an unverified default. A 20-case comparison measured tier agreement improving from 95% on Haiku to 100% on Sonnet 4-6, with a 3.40× estimated evaluation cost; technique validity and the bounded grounding check were 100% for both. See [`docs/AI_MODEL_COMPARISON.md`](docs/AI_MODEL_COMPARISON.md) for the artifact-backed comparison.

All model modes receive only a **redacted and bounded projection**. Credentials, tokens, authorization values, raw payload fields, and IP addresses are excluded. Every call—including local and null-provider calls—creates a separate append-only AI audit event containing the tenant, endpoint, provider, context hash, included field categories, response summary, latency, and success/failure state. The admin-only `GET /api/v1/ai/audit-log` route exposes tenant-scoped records without raw prompts. Analysts can record `confirmed` or `incorrect` feedback through `POST /api/v1/ai/feedback`.

AI output is advisory. High-stakes results set `requires_human_review=true`, and the frontend displays **AI-generated — verify before acting** beside explanation surfaces. The deterministic graph and risk engines remain authoritative, and feedback never changes scores or remediation state automatically. See [`docs/AI_COMPLIANCE.md`](docs/AI_COMPLIANCE.md) for data flow, self-hosted setup, audit review, and retention policy.

AI is disabled by default. Review the provider and audit settings in [`.env.example`](.env.example); CI uses mocked providers and never makes live model calls.
