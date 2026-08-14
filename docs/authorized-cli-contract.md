# Authorized RedPath CLI Contract

The RedPath command-line interface is intended for **authorized company networks only**. It performs scope-bound discovery, service inventory, vulnerability correlation, and bounded web content enumeration. It is not an exploitation framework.

## Command Model

```text
red scan <target> --scope-file <approved-scope-file> --confirm <authorization-id>
```

The initial implementation does not require `sudo`. Its discovery profile uses a TCP-connect scan and avoids raw-packet behavior. Running the command as root does not unlock additional scan modes.

## Mandatory Controls

| Control | Requirement |
| --- | --- |
| Scope | The target must be an IP address in a configured CIDR allowlist. Hostnames, public IPs, URLs outside an approved web scope, and CIDR expansion are rejected. |
| Confirmation | An explicit authorization identifier must be supplied for every non-dry-run scan. |
| Audit | The target, scope identifier, authorization identifier, profile, timestamps, command plan, result summary, and operator must be written to an append-only audit record. |
| Rate limits | Safe defaults apply: bounded ports, TCP connect only, low timing profile, timeouts, and a maximum target count. |
| Web enumeration | Only explicitly allowed HTTP(S) base URLs are eligible. The initial profile uses a small approved wordlist, single-host traversal, low concurrency, response-size limits, and no authentication bypass. |
| Vulnerability output | RedPath correlates discovered service versions with local advisory metadata and labels results as candidates requiring validation. It does not exploit, brute-force, or verify credentials. |

## Prohibited Behavior

The CLI must not execute exploit payloads, credential spraying, password attacks, stealth/evasion techniques, UDP/raw-packet scans, unauthorised subdomain expansion, third-party redirection traversal, destructive requests, shell injection, or scans outside the approved scope.

## Delivery Model

The CLI emits a structured JSON report containing discovered assets, services, candidate vulnerability correlations, web content observations, warnings, audit identifiers, and recommended remediation. The report may be imported into RedPath as evidence and used to create a case after analyst review.

> Before an operator runs a scan, the company must approve the scope, owner, time window, target ranges, web base URLs, rate limits, and emergency contact. A local lab fixture is required for CI and pre-production validation.
