# Backup and restore drill design

This is a release-readiness design for authorized RedPath environments. It does not perform a backup, restore, upload, deletion, or remote-state mutation. Operators must adapt the steps to the approved storage platform and obtain the required change authorization before running a real drill.

## Scope and recovery targets

| Item | Design target | Evidence required |
| --- | --- | --- |
| Recovery point objective (RPO) | 15 minutes for production-managed persistence; operator-defined cadence for the demo SQLite profile | Backup manifest with UTC creation time and source release |
| Recovery time objective (RTO) | Four hours from authorization to isolated readiness | Drill timeline with operator and approval records |
| Data sources | Managed database snapshot or export, append-only audit JSONL, evidence metadata, migration version, and deployment configuration without secrets | Inventory manifest and SHA-256 digests |
| Exclusions | Credentials, access tokens, raw PCAP bytes, raw SIEM documents, temporary files, caches, and unapproved customer data | Exclusion report and secret scan |
| Restore destination | Isolated account, project, namespace, or local temporary environment with no production network route | Destination isolation evidence |

A point-in-time backup is immutable evidence for the drill. Never rename, rewrite, or silently replace a backup package after its manifest is recorded. Store backup packages with encryption at rest, access control, retention, and a separate integrity manifest.

## Drill sequence

First, obtain an approved change record naming the operator, reviewer, source environment, target isolated environment, RPO/RTO targets, and rollback authority. Confirm the source tenant boundaries, migration revision, release identifier, audit-log location, and backup package digests without printing sensitive values.

Next, restore the package into the isolated destination. Apply only the reviewed forward migrations required by the recorded release. Do not point the restored application at production databases, Wazuh indexes, directory services, or production object stores. Keep outbound access disabled unless an explicitly approved read-only dependency check is required.

Start the application in dry-run mode and verify liveness and readiness. Confirm that tenant-filtered reads cannot cross tenants, server-derived actor identity remains authoritative, RBAC denies unauthorized roles, audit-chain verification succeeds, evidence digests remain unchanged, and no raw telemetry or packet bytes appear in logs or restored metadata. Use synthetic fixtures where functional behavior must be exercised.

Compare counts, migration versions, hashes, and selected synthetic records against the backup manifest. Verify that incomplete or corrupt packages fail closed with an actionable error and do not partially replace the isolated destination. Record the observed restore time, newest recovered timestamp, checks performed, deviations, and reviewer decision.

At the end of the drill, discard the isolated environment through the approved infrastructure process. Do not delete or alter the source environment as part of a drill. Retain only the minimum drill evidence needed for audit, including the manifest, checksums, timeline, results, and approval record.

## Success criteria

A drill passes only when the destination is isolated, the exact backup package is verified, the application reaches readiness without unsafe overrides, tenant isolation and RBAC checks pass, audit integrity passes, dry-run behavior remains enabled, no prohibited payloads or secrets are restored, and the observed RPO/RTO are within the approved targets. Any failed check blocks production cutover and requires a documented corrective action.

## Rollback and migration note

This release-assurance change does not alter application persistence schemas or add migrations. Its rollback is a source-control rollback to the prior release-verification documentation and scripts. If a future release includes a schema migration, the release record must include a reviewed forward migration, a tested compatible rollback or isolated restore procedure, and the migration verification result before promotion.

## Verification command

The local synthetic contract can be checked without touching any external system:

```bash
PYTHONPATH=backend python ci/verify_backup.py --self-test
```

For an approved manifest, provide a read-only manifest and an isolated verification root:

```bash
PYTHONPATH=backend python ci/verify_backup.py --manifest /approved/manifest.json --root /isolated/restore-root
```

The verifier checks relative paths, SHA-256 digests, tenant-scope confirmation, audit-integrity confirmation, and redaction metadata. It never performs the restore, deletes a source, changes a database, or contacts a remote service. A failed digest or invariant blocks cutover and leaves the source unchanged.
