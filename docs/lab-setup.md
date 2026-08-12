# RedPath lab setup

This guide describes a **disposable, host-only lab** for RedPath. Use a hypervisor network that has no route to the corporate network or the public Internet. Take snapshots before each exercise, use synthetic or dedicated lab identities, and keep RedPath's CIDR allow-list aligned with the host-only segment.

## Recommended topology

| VM | Suggested role | Example address | Notes |
| --- | --- | --- | --- |
| `DC-01` | Windows Server domain controller and DNS | `192.168.56.10` | `LAB.LOCAL`; create only synthetic users and groups |
| `WS-01` | Windows workstation or member server | `192.168.56.20` | Install Wazuh agent and generate normal lab telemetry |
| `SEC-01` | Ubuntu security tooling VM | `192.168.56.30` | Run RedPath API and, optionally, Wazuh manager/indexer |

A two-VM variant can place RedPath and Wazuh on the host or on `WS-01`, but three VMs make the data flow clearer during a portfolio demo. The lab network should be host-only or an isolated virtual switch. Disable shared clipboard, shared folders, bridged networking, and unnecessary USB passthrough for the Windows guests.

## Active Directory baseline

Install Windows Server on `DC-01`, create a new forest named `LAB.LOCAL`, and configure the lab DNS service. Join `WS-01` to the domain using a synthetic workstation account. Create a small set of synthetic identities: a standard user, a service identity used only for lab services, a security analyst account, and a disabled test account. Do not reuse personal or production passwords.

For RedPath's MVP, export configuration facts into JSON rather than asking RedPath to bind to AD. For example, create a fixture containing a service principal name, an account with pre-authentication disabled for controlled testing, and certificate-template metadata. The detector analyzes the fixture and returns findings; it does not request Kerberos tickets, crack hashes, enroll certificates, or modify directory objects.

```json
[
  {"asset_id": "DC-01", "service_principal_name": "MSSQLSvc/db01.lab.local:1433"},
  {"asset_id": "USER-07", "preauth_disabled": true},
  {"asset_id": "CA-01", "enrollee_supplies_subject": true, "client_auth_eku": true}
]
```

RedPath maps the first two conditions to MITRE ATT&CK `T1558.003` and `T1558.004`. The certificate condition is represented by `T1649`. The official MITRE pages describe Kerberoasting and AS-REP Roasting as Windows credential-access sub-techniques, and the AS-REP page includes detection guidance around Event ID 4768 with pre-authentication type 0 [1] [2].

## Wazuh integration

Install the Wazuh manager and indexer only inside the isolated lab. Install a Wazuh agent on `WS-01` and configure it to collect Windows event channels relevant to authentication and certificate activity. Start with read-only evidence retrieval: RedPath should query the indexer and compare alerts; it should not push rules or execute active-response commands.

The Wazuh documentation states that the manager processes events into alerts, stores them in `alerts.log` and `alerts.json`, and forwards them to the indexer. Its indexer API examples query alerts from `wazuh-alerts*` with `_search` [3]. Create a dedicated read-only indexer account for RedPath and provide its credentials only through the environment at runtime. Never commit them to `.env`, Docker Compose, fixtures, or screenshots.

A minimal alert query pattern is:

```bash
curl --fail --silent --show-error \
  --user "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" \
  --cacert "$WAZUH_CA_CERT" \
  -H 'Content-Type: application/json' \
  -X POST "$WAZUH_INDEXER_URL/wazuh-alerts*/_search" \
  -d '{
    "size": 100,
    "query": {
      "bool": {
        "must": [
          {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}},
          {"query_string": {"query": "T1558.003 OR T1558.004 OR T1649"}}
        ]
      }
    },
    "sort": [{"timestamp": {"order": "desc"}}]
  }'
```

Use the response as an imported evidence set for `/api/v1/purple/analyze`. The report marks a technique as covered if a matching technique ID or evidence hint appears in the alert's rule or data fields. This is deliberately conservative: a match is evidence of a signal, not proof that the detection is high quality.

## Detection engineering exercises

Start with synthetic Windows events and confirm the alert pipeline before using any lab identity-risk fixture. Review Event ID 4768 and 4769 coverage for Kerberos, test whether rule descriptions preserve the mapped technique ID, and record the observed alert ID in the report. For certificate activity, validate that the lab CA and template inventory are visible to the monitoring pipeline, then write a rule regression test from the observed event shape.

If a detection is absent, RedPath should produce a gap with a tuning recommendation. Apply rule changes manually, rerun the same fixture, and compare the before/after coverage. Do not let RedPath change Wazuh rules automatically in the portfolio version.

## Running RedPath

From the repository root, copy `.env.example` to `.env`, keep `DRY_RUN=true`, and set only the host-only CIDRs. Start the API with `docker compose up --build`, then open `http://localhost:5173`. The API documentation is available at `http://localhost:8000/docs`.

For a local Python run, create a virtual environment, install `backend/requirements.txt`, set `PYTHONPATH=backend`, and launch `uvicorn app.main:app --reload --app-dir backend`. The first demo path is the dry-run recon call, followed by the observation fixture and graph-analysis endpoints.

## Stop conditions

Stop immediately if a target is not inside the configured allow-list, if a command would require arbitrary shell text, if a tool tries to authenticate to a non-lab service, or if a Wazuh account has write privileges. Restore a snapshot after each exercise and rotate any lab secrets that were exposed in a test log.

## References

[1]: https://attack.mitre.org/techniques/T1558/003/ "MITRE ATT&CK: Kerberoasting"
[2]: https://attack.mitre.org/techniques/T1558/004/ "MITRE ATT&CK: AS-REP Roasting"
[3]: https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html "Wazuh Indexer API use cases"
[4]: https://documentation.wazuh.com/current/user-manual/manager/alert-management.html "Wazuh alert management"
