# Identity, tenancy, RBAC, and API protection

## Scope

This capability protects the FastAPI operational API with authenticated, opaque bearer sessions; assigns every authenticated request to one tenant; applies route-level role permissions; derives actor fields from the authenticated principal; and adds an idempotent schema migration for identity and tenant ownership records.

The public surface is deliberately small. The health endpoint remains public for service checks. Bootstrap and token issuance are public but rate-limited, and bootstrap is disabled unless `AUTH_BOOTSTRAP_TOKEN` is configured. All operational and identity-management endpoints require a bearer token.

## Identity lifecycle

The first deployment is initialized with `POST /api/v1/auth/bootstrap`. The request must include the deployment-only bootstrap secret, a tenant slug and name, and an initial administrator password of at least 12 characters. Bootstrap is single-use: if any user already exists, later bootstrap attempts return `409`. The initial principal receives `platform_admin` and `tenant_admin` memberships in the bootstrap tenant.

Subsequent sessions are created with `POST /api/v1/auth/token`. The API returns a 15-minute opaque bearer token. Only a SHA-256 digest of the token is persisted in `auth_sessions`; the raw token is returned once and is not written to RedPath tables or the audit log. Session lookup verifies token digest, expiry, revocation state, user and tenant activity, and the user session version. The current slice intentionally does not implement refresh tokens; callers must perform a new login after expiry.

> **Security contract:** Caller-provided `owner`, `reviewer`, `actor`, and `approver` fields are no longer accepted as authoritative identity values. Campaign ownership, evidence review attribution, remediation lifecycle notes, and risk-acceptance approval are derived from the authenticated principal.

## Role and permission model

Roles are tenant memberships. A principal may hold more than one role, and permissions are the union of all active memberships in the selected tenant. `platform_admin` bypasses permission checks but still operates within the tenant selected by the session. Tenant identifiers are never accepted from operational request bodies.

| Role | Read | Analyze | Manage cases | Manage identity | View audit |
| --- | ---: | ---: | ---: | ---: | ---: |
| `platform_admin` | Yes | Yes | Yes | Yes | Yes |
| `tenant_admin` | Yes | Yes | Yes | Yes | Yes |
| `analyst` | Yes | Yes | Yes | No | No |
| `remediation_manager` | Yes | No | Yes | No | No |
| `viewer` | Yes | No | No | No | No |

Platform administrators can provision an additional tenant with `POST /api/v1/auth/tenants`, including its initial tenant-local administrator. Tenant administrators can provision users only inside their own tenant with `POST /api/v1/auth/users`. Duplicate tenant slugs and tenant-local usernames return `409`.

## Tenant isolation

Identity records use `tenants`, `users`, `memberships`, and `auth_sessions`. Existing assessment, campaign, evidence, remediation, risk-acceptance, and assessment-run tables now carry `tenant_id`. The migration is additive and non-destructive: existing rows are assigned to the reserved `legacy` tenant, and operational queries filter by the authenticated tenant. Records from the reserved tenant are not visible to newly bootstrapped tenants unless an explicit future administrative migration assigns them.

Nested lookups are also tenant constrained. For example, linking a run to a campaign, reading an evidence manifest, exporting a campaign, or updating a remediation requires both the resource identifier and the current tenant to match. A resource in another tenant is intentionally returned as not found rather than revealing its existence.

## API protection behavior

The protected router resolves a bearer session before route execution, applies an in-memory per-client and per-token rate limit, stores the principal in request context, and removes that context after the request completes. Missing or invalid credentials return `401` with a bearer challenge. Valid credentials without the required role or permission return `403`. Rate exhaustion returns `429`. Public bootstrap and token issuance use the same bounded client limiter.

Audit events use the authenticated username as the actor for protected operations. Authentication events record only tenant slug, username, and non-sensitive lifecycle metadata. Passwords, bearer tokens, raw telemetry, and credential material are not recorded.

## Configuration

Set `AUTH_BOOTSTRAP_TOKEN` to a random secret of at least 16 characters before the first deployment. Leave the setting empty to disable bootstrap. `RATE_LIMIT_REQUESTS_PER_MINUTE` controls the default bounded in-memory limiter and should be tuned per deployment topology. In a multi-process deployment, the current limiter is process-local; a shared rate-limit store is a follow-up integration point.

| Setting | Default | Purpose |
| --- | --- | --- |
| `AUTH_BOOTSTRAP_TOKEN` | empty | Enables one-time initial bootstrap when non-empty |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | `120` | Per-client and per-token request budget |

## Integration contract for contributors

New sensitive endpoints must be registered on the protected router and must declare the narrowest permission or role dependency. Services that read or write tenant-owned records must obtain `current_tenant_id()` from request context and include it in every lookup. Actor fields must use `current_actor()` rather than request-body values. Long-running jobs should capture the principal's immutable `user_id`, `tenant_id`, and roles at enqueue time and re-authorize resource access when the worker executes.

The current slice does not add a refresh-token flow, MFA enrollment, external identity-provider federation, distributed rate limiting, or a full Alembic history. These are explicit follow-up items rather than implicit security assumptions.

## Validation

The focused backend validation commands are:

```text
ruff check backend/app backend/tests --output-format concise
pytest -q
bandit -r backend/app -x backend/tests
```

The API tests cover public-versus-protected routing, one-time bootstrap, Argon2id-backed login, role denial for viewers, server-derived actor attribution, platform-admin tenant provisioning, tenant-isolated campaign reads and nested lookups, out-of-scope recon rejection after authentication, and representative campaign/evidence/remediation/governance workflows.

## References

[1]: https://owasp.org/www-project-api-security/ "OWASP API Security Project"

[2]: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html "OWASP Authentication Cheat Sheet"

## Enterprise identity integration

The application exposes a replaceable `AuthenticationProvider` boundary. The default lab provider resolves opaque sessions from the RedPath database. Deployments that use an external identity provider inject an OIDC verifier through the application factory; the verifier is responsible for validating issuer, audience, signature, expiry, key rotation, and revocation or session policy before returning the server-owned `Principal` contract. RedPath does not intercept passwords, store OIDC client secrets, or accept unverified claims.

The principal carries an `auth_method`, optional MFA assurance state, step-up expiry, and explicit permission scopes. Existing bearer and role behavior remains unchanged when the default opaque provider is used. A configurable `MfaStepUpPolicy` hook can require externally verified step-up assurance for selected permissions. The default configuration requires no step-up, while deployments may opt in for identity administration and audit access.

## Service-account lifecycle

Tenant administrators may create a service account with a bounded set of least-privilege scopes. The API returns a newly generated bearer token once; only its SHA-256 digest is stored. Service-account tokens are tenant-scoped, expire within the configured maximum lifetime, and are never written to audit events. Rotation revokes all prior active tokens, increments the service-account token version, and returns one replacement token. Revocation disables the account, increments its token version, and revokes all active tokens. Service-account principals cannot use human-only role assumptions and are limited to their declared permission scopes.

## Migration and rollback

Migration version 5 creates the additive `service_accounts` and `service_account_tokens` tables. Migration version 6 adds nullable `mfa_verified_until` to `auth_sessions`. Both migrations are idempotent and non-destructive; existing sessions and tenant records remain valid. Rollback is application-level first: deploy the previous application version while retaining the additive tables and nullable column, then revoke or archive service-account credentials through the new lifecycle endpoints. Dropping the new tables is intentionally not automatic and requires a separately reviewed maintenance migration after all service-account tokens are disabled and retention requirements are satisfied.

## Privacy and safe failure

Tenant IDs, roles, service-account scopes, and session state are evaluated server-side. Cross-tenant resource access remains concealed as not found. Authentication, authorization, step-up, and rate-limit failures return stable generic error envelopes with request IDs and do not disclose raw claims, bearer tokens, passwords, OTPs, provider responses, resource identifiers, or stack traces. Audit events record the authenticated actor, route template, operation, and bounded non-sensitive metadata while preserving the append-only digest chain.
