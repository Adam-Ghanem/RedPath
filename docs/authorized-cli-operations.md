# Authorized RedPath CLI Operations

The `red` CLI is a **reconnaissance and candidate-vulnerability-correlation tool** for company networks that have explicit written approval. It is not an exploitation tool.

## Prerequisites

Run the CLI from `backend/` after installing the documented Python dependencies. The operator must have an approved scope file, a change or authorization identifier, and an approved time window.

```bash
cd backend
chmod +x red
```

## Scope File

Copy `scope.example.json` to a private local location and replace every example value with an approved value. Never commit a company scope file, authorization identifier, or report to source control.

```json
{
  "scope_id": "CHG-2026-0001",
  "allowed_cidrs": ["192.0.2.0/24"],
  "allowed_web_origins": ["https://portal.company.example"],
  "max_targets": 1,
  "max_web_paths": 6
}
```

## Dry Run First

Every operator must plan and review the command before execution. Dry run is the default and sends no network traffic.

```bash
python3 red scan 192.0.2.10 \
  --scope-file /secure/path/company-scope.json \
  --authorization-id CHG-2026-0001 \
  --operator security.analyst \
  --report-file /secure/path/dry-run-report.json
```

Review the report, including the scoped target, planned command, rate-limited profile, and any warnings. The append-only audit file defaults to `.redpath-audit.jsonl` and is written with owner-only permissions.

## Authorized Execution

Only after the scope owner has approved the dry-run report, repeat the command with `--execute`.

```bash
python3 red scan 192.0.2.10 \
  --scope-file /secure/path/company-scope.json \
  --authorization-id CHG-2026-0001 \
  --operator security.analyst \
  --execute \
  --report-file /secure/path/executed-report.json
```

The service profile uses bounded TCP-connect inventory and local candidate correlation. Candidate results require analyst validation and are not confirmed vulnerabilities.

## Optional Approved Web Inventory

The optional web base URL must exactly match an origin in `allowed_web_origins`. It requests only a small fixed path set, does not follow redirects, does not submit forms, does not authenticate, and does not bypass controls.

```bash
python3 red scan 192.0.2.10 \
  --scope-file /secure/path/company-scope.json \
  --authorization-id CHG-2026-0001 \
  --operator security.analyst \
  --web-base-url https://portal.company.example \
  --execute
```

## Stop Conditions

Stop immediately if the target is outside scope, the authorization window closes, the owner withdraws approval, unexpected load occurs, an unfamiliar IP appears, or a report indicates a potentially critical candidate. Preserve the audit and report artifacts, notify the designated contact, and do not retry with broader settings.

> Do not run `sudo red` by default. The approved inventory profile does not need root privileges, and privileged execution must not expand the CLI's capabilities.
