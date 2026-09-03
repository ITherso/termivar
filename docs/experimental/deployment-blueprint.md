# Deployment blueprint (non-deployable design sketch)

> **Status: non-deployable architecture sketch.** The unreleased Termivar
> `0.10.0-alpha.1` source line has **no
> supported deployment surface**. This document preserves the *intent* of a
> future orchestrated deployment. It is prose and tables only — deliberately not
> executable Helm, Terraform, or Kubernetes source — so it cannot be mistaken for
> a working manifest by a person or a scanner.

## Why the previous manifests were removed

The repository previously tracked Helm, Terraform, and Kubernetes material that
*looked* deployable but did not match the product. Keeping it invited operators
to run infrastructure that cannot work, and it produced misleading "green looks
possible" signals. Rather than move the files to another folder — where security
scanners would still parse them and where they would still read as real — the
executable manifests were **removed**. They remain fully recoverable from Git
history.

Concretely, the removed material claimed capabilities the current code does not
provide:

| Removed surface | What it claimed | Product reality today |
| --- | --- | --- |
| `docker-compose.yml` | A default proxy on port 8080 plus PostgreSQL, Redis, Prometheus, Grafana with `admin` credentials, and security-disabled Elasticsearch. | The default image runs `termivar --help`, opens no listener, and needs none of those services. The root Compose file was removed rather than preserved as a misleading deployment example. |
| `k8s/deployment.yaml` | A historical `venom-proxy` Deployment whose liveness/readiness probes hit `GET /health` on the API port (3000), with an HPA, PVC, RBAC, and injected database/Redis secrets. | `termivar api` **does not bind a network listener** (`termivar_api::start_api` returns an unsupported-adapter error without binding or printing a startup claim). The container's default command is inert CLI help, not an API server on 3000. The probes could never pass. |
| `k8s/services.yaml` | PostgreSQL and Redis `StatefulSet`s, an Ingress, and a `NetworkPolicy` the workload depends on. | The scanner/proxy code does not integrate a PostgreSQL or Redis runtime dependency. These were aspirational. |
| `helm/Chart.yaml`, `helm/values.yaml` | A versioned (`1.0.0`) chart with 3 replicas, autoscaling, ingress+TLS, and PostgreSQL/Redis subchart dependencies. | The chart had **no `templates/` directory and no vendored `charts/`**, so it could not render. Its subchart dependencies were never resolvable in-repo. |
| `terraform/main.tf`, `variables.tf`, `prod.tfvars` | An AWS stack composing local `./modules/vpc`, `./modules/eks`, `./modules/rds`, and `./modules/elasticache`. | **None of those module directories exist**, so `terraform init` fails immediately. The configuration was never applyable. |

## What must exist before executable manifests may return

A future deployment surface may be re-introduced only once each of the following
contracts is real, documented, and independently reviewed. Until then the
repository's machine-readable deployment status stays **unsupported**, and the
`xtask architecture` gate forbids executable manifests under `helm/`,
`terraform/`, `k8s/`, and `kubernetes/`.

- **Supported API / container entrypoint.** A real HTTP listener (not a startup
  hook) with a documented address contract, and a container default command that
  starts exactly that workload.
- **Health / readiness contract.** Real `/health` and `/ready` endpoints with
  defined semantics, matched by probe configuration.
- **Persistence contract.** Whether a database is required at all; if so, its
  schema ownership, migration story, and backup/restore expectations.
- **Redis requirement decision.** Whether Redis is actually needed, or was
  aspirational; documented either way.
- **Secret management.** How credentials are provisioned and rotated — never
  in-repo placeholder values.
- **Network topology.** Ingress, egress, and service boundaries tied to real
  ports the product listens on.
- **Image / version policy.** Which image tag or digest is published, by which
  pipeline, and how it is pinned.
- **State backend.** For any IaC: a real remote state backend and locking.
- **Upgrade / rollback contract.** How a release is advanced and reverted safely.
- **Threat model.** Documented trust boundaries for a network-exposed
  deployment.
- **Independent deployment security review.** A review distinct from the code
  author before any manifest is marked supported.

## Recovering the previous drafts

The removed files remain in Git history. To inspect a prior draft without
re-introducing it into the working tree, read it directly from the commit that
deleted it (its parent still contains the files), for example via
`git show <deletion-commit>^:helm/values.yaml`. Re-adding executable manifests is
gated: see the deployment policy in `xtask`.
