# Safe demo deployment

RedPath’s public demo is deliberately browser-first: the visual case file reads from committed synthetic frontend data, so it remains useful without a directory connection, account, agent, or API key. The optional API in the Compose profile is constrained to dry-run mode and uses RFC 5737 documentation CIDRs rather than private-network defaults.

## Run the profile locally

```bash
docker compose --profile demo up --build
```

The static console is available at [http://localhost:5173](http://localhost:5173), while the auxiliary API health endpoint is available at [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health). Stop the stack with `docker compose --profile demo down`.

| Demo property | Guarantee |
| --- | --- |
| Seeded console content | The published interface packages the same synthetic path, findings, coverage, and scenario data used by the live browser demo. |
| Recon behavior | `DRY_RUN` is a literal Compose value of `"true"`; a host environment variable cannot override it. |
| Allowed range | The profile uses documentation-only ranges `192.0.2.0/24` and `198.51.100.0/24`. |
| Persistence | The profile uses an isolated `redpath-demo-data` volume. Remove it with `docker compose --profile demo down -v` when the demo is finished. |

## Deploy the static seeded demo

For a public portfolio or trial deployment, deploy **only** the static `frontend/Dockerfile.demo` image. This is the recommended free-tier shape because the visual console is self-contained and does not expose the auxiliary API.

| Platform | Container configuration |
| --- | --- |
| Render | Create a new Web Service from this repository, select **Docker**, set the Dockerfile path to `frontend/Dockerfile.demo`, and set the service port to `80`. |
| Fly.io | Run `fly launch --dockerfile frontend/Dockerfile.demo` from the repository root, then set the generated service `internal_port` to `80` before deployment. |

The production Vercel project is already Git-connected to `main` with `frontend/` as its root directory. Each successful push to `main` automatically creates the live-demo deployment at [redpath-sec.vercel.app](https://redpath-sec.vercel.app); no duplicate deployment workflow is required for that connected project.

## Optional GitHub Actions deployment template

The repository includes [`docs/github-actions/deploy-vercel.yml`](github-actions/deploy-vercel.yml) as a template for teams that deliberately prefer GitHub Actions-managed Vercel deploys. It is stored outside `.github/workflows/` because a maintainer must authorize workflow-file changes and add the required Vercel secrets. Do not activate it alongside the existing Git-connected Vercel deployment unless the latter is disconnected; running both can produce redundant deployments.

To activate the template, copy it to `.github/workflows/deploy-vercel.yml` with an authorized maintainer account and add `VERCEL_TOKEN`, `VERCEL_ORG_ID`, and `VERCEL_PROJECT_ID` as repository secrets.
