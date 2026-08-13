# RedPath Detection Packages

This directory contains versioned, defensive detection package inputs. `pack.json` is the manifest of rule IDs, exact revisions, fixture assignments, owner, and measurable baselines. Synthetic normalized fixtures live under `fixtures/`; rule implementation and the safe declarative catalog remain in the backend service layer.

Package checks are read-only and CI-safe:

```bash
python3 scripts/validate_detection_pack.py
```

A valid package must use supported MITRE technique IDs, safe declarative condition paths and operators, explicit rule versions, non-empty fixture assignments, and passing true-positive, false-positive, and coverage baselines. Production promotion additionally requires explicit approval evidence. Fixtures must contain only bounded normalized telemetry and optional bounded attack-path evidence; never add raw payloads, credentials, commands, exploit logic, or external-state instructions.
