# Terraform Infrastructure

## Overview

Infrastructure is split into two Terraform workspaces with a shared `config.yaml`:

```
config.yaml            Shared configuration (project ID, region, resource specs)
init/                  Bootstrap resources (run once)
iac/                   Application infrastructure (run on every deploy)
```

Both `init/local.tf` and `iac/local.tf` load the same `config.yaml` via `yamldecode(file("${path.root}/../config.yaml"))`.

## init/ (Bootstrap, One Time Setup)

Creates foundational resources that must exist before the main infrastructure:

| File                  | Resources Created                              |
|-----------------------|------------------------------------------------|
| `local.tf`            | Shared locals from config.yaml                 |
| `provider.tf`         | Google provider configuration                  |
| `state-backend.tf`    | GCS bucket for Terraform state (versioned)     |
| `services.tf`         | GCP API enablement (Cloud Run, Secret Manager, etc.) |
| `devops.tf`           | DevOps service account for CI/CD               |

**Outputs used by iac/:**
- `backend_config`: GCS backend block for iac/provider.tf
- `docker_registry_location`: Used to configure Docker auth

## iac/ (Application Infrastructure)

Manages the running application:

| File              | Resources Created                              |
|-------------------|------------------------------------------------|
| `local.tf`            | Shared locals from config.yaml                 |
| `service-accounts.tf` | Cloud Build and Cloud Run workload service accounts |
| `kms.tf`              | KMS keyring, crypto key, IAM for state encryption |
| `docker.tf`           | Docker image build (local) and push to Artifact Registry |
| `secrets.tf`          | Secret Manager secret for OAuth credentials    |
| `workload-mcp.tf`    | Artifact Registry repo, Cloud Run service, domain mapping, DNS, IAM |

### docker.tf Details
Uses the `kreuzwerker/docker` Terraform provider to:
1. Build the Docker image locally from the project Dockerfile
2. Push to Artifact Registry (`<region>-docker.pkg.dev/<project>/<repo>/<name>:latest`)
3. Triggers rebuild on changes to source files (hashes of Go files, Dockerfile, go.mod)

### workload-mcp.tf Details
- **Artifact Registry**: Docker repository for container images
- **Cloud Run v2 Service**: Runs the MCP server container with environment variables (HOST, SECRET_NAME, BASE_URL, ENVIRONMENT, PROJECT_ID, FIRESTORE_DATABASE, KMS_KEY_NAME)
- **Firestore Database**: Native mode database for persisting OAuth2 tokens and clients as individual documents
- **Domain Mapping**: Maps `lastpass.mcp.scm-platform.org` to the Cloud Run service
- **DNS Record**: CNAME pointing to `ghs.googlehosted.com.` for managed SSL
- **IAM**: Service account gets Secret Manager accessor role; optional public access via `allUsers` invoker role

### secrets.tf Details
Creates a Secret Manager secret shell. The actual secret version (OAuth credentials JSON) must be added manually:
```bash
gcloud secrets versions add scm-pwd-lastpass-oauth-creds \
  --data-file=$HOME/.credentials/scm-pwd-lastpass.json \
  --project=scmlastpass-mcp-prd
```

## Configuration (config.yaml)

Key fields:

| Field                           | Value                              |
|---------------------------------|------------------------------------|
| `prefix`                        | `scmlastpass`                      |
| `env`                           | `prd`                              |
| `gcp.project_id`                | `scmlastpass-mcp-prd`              |
| `gcp.location`                  | `europe-west1`                     |
| `gcp.resources.cloud_run.cpu`   | `1`                                |
| `gcp.resources.cloud_run.memory`| `256Mi`                            |
| `gcp.resources.cloud_run.min_instances` | `0`                        |
| `gcp.resources.cloud_run.max_instances` | `3`                        |
| `parameters.base_url`           | `https://lastpass.mcp.scm-platform.org` |
| `parameters.domain`             | `lastpass.mcp.scm-platform.org`    |
| `parameters.dns_zone`           | `scm-platform-org`                 |

## Deployment Workflow

### First Time Setup
```bash
make init-plan          # Review bootstrap resources
make init-deploy        # Create state bucket, service accounts, enable APIs
                        # (auto runs update-backend and configure-docker-auth)
make plan               # Review application infrastructure
make deploy             # Build Docker, push, deploy Cloud Run
```

### Subsequent Deployments
```bash
make plan               # Review changes
make deploy             # Apply (rebuilds Docker if sources changed)
```

### Teardown
```bash
make undeploy           # Destroy application infrastructure
make init-destroy       # Destroy bootstrap resources (requires confirmation)
```

## Custom Domain and SSL

The domain `lastpass.mcp.scm-platform.org` is configured via:
1. `google_cloud_run_domain_mapping` maps the domain to the Cloud Run service
2. `google_dns_record_set` creates a CNAME record pointing to `ghs.googlehosted.com.`
3. Google manages SSL certificate provisioning and renewal automatically
