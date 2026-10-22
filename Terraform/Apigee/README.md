# Secure Apigee on Google Cloud with Terraform

This Terraform configuration provisions a security-focused, single-region Apigee cloud runtime on Google Cloud. It creates an Apigee organization, runtime instance, environment, and environment attachment while enabling the required Google Cloud APIs.

The configuration assumes that the VPC network—and any customer-managed encryption keys (CMEK)—already exist. It does not deploy API proxies, public ingress, load balancers, DNS, or client-side Private Service Connect endpoints.

## Architecture

Terraform manages the following resources:

- Required Google Cloud project APIs
- One Apigee organization using the cloud runtime
- One regional Apigee runtime instance
- One Apigee proxy environment
- One attachment between the environment and runtime instance

The runtime is connected to an explicitly authorized VPC and uses a dedicated private `/22` address range.

## Security features

### Explicit network authorization

The Apigee organization is bound to the VPC supplied through `network_id`. This prevents the deployment from relying on an implicit network selection and makes the intended trust boundary visible in code.

The runtime also requires a dedicated, non-overlapping RFC1918 `/22` through `instance_ip_range`. The range must not overlap VPC subnets, peered networks, VPN routes, or on-premises networks.

### Private Service Connect allowlist

The organization project is always placed in `consumer_accept_list`. `psc_consumer_project_ids` adds only explicitly trusted Google Cloud projects or project numbers. Keep this list limited to projects that require private access to the Apigee service attachment.

An empty additional list still permits the organization project; it does not mean deny all. This configuration does not create a consumer-side PSC endpoint. Any required endpoint, forwarding rule, DNS, and related network policy must be managed separately.

### Customer-managed encryption keys

The configuration can use Cloud KMS keys for:

- Runtime database encryption
- Runtime instance disk encryption
- Control-plane data encryption
- API consumer data encryption

CMEK provides control over key rotation, access, revocation, and audit logging. The keys are referenced by this configuration but are not created by it. Key locations must be compatible with the relevant Apigee resource, and the applicable Apigee service agents must receive `roles/cloudkms.cryptoKeyEncrypterDecrypter` on each key.

Disabling, destroying, or removing Apigee access to a key can make the instance unavailable and may eventually cause resource deletion. Review Google's Apigee CMEK requirements before deployment.

### Keyless Terraform authentication

The Google provider supports service-account impersonation through `impersonate_service_account`. This avoids storing downloaded service-account JSON keys in the repository or on operator workstations.

The initiating identity must have `roles/iam.serviceAccountTokenCreator` on the deployment service account. That service account should receive only the permissions required to provision the declared resources.

If impersonation is not configured, the provider uses Google Application Default Credentials.

### Access logging

Runtime access logging is always enabled. `access_log_filter` accepts a CEL filter; its default empty value requests all supported access events. These logs support monitoring, incident response, and audit investigations.

Review filters, log retention, sink permissions, sensitive-data handling, and expected Cloud Logging charges before production deployment.

### Controlled deletion behavior

`deletion_retention` controls Apigee organization retention after deletion. This can provide a recovery window following an accidental destructive operation.

Required project APIs use `disable_on_destroy = false`, so destroying this stack does not unexpectedly disable foundational APIs that other project workloads might use.

### Environment isolation and least privilege

The configuration creates a distinct Apigee environment and attaches only that environment to the managed runtime instance. Separate environments can isolate lifecycle stages such as development, testing, and production, with corresponding IAM and deployment controls.

The environment defaults explicitly to `BASE` and `CONFIGURABLE`. These settings provide the lowest-cost, least-capable option for standard proxies instead of relying on API defaults. Change them only when programmable proxies or higher-tier capabilities are required.

`deployment_type` defaults to `PROXY`. Set it to `ARCHIVE` only when using an archive-based delivery pipeline; archive deployment limits direct mutations and can provide a more immutable deployment model.

### Trusted client-IP resolution

`client_ip_header_index` can resolve the original client from `X-Forwarded-For` for analytics and security controls. It is disabled by default because the safe index depends on the exact trusted load-balancer and reverse-proxy path. Document that path before enabling this setting; an incorrect index may trust an attacker-controlled value.

### Controlled runtime egress

`forward_proxy_uri` can route environment traffic through an approved HTTP or HTTPS forward proxy for destination policy, inspection, and centralized logging. It is disabled by default because this configuration does not create the required highly available proxy.

### Data residency

`api_consumer_data_location` can pin API consumer data to a supported single region. It is optional because availability and KMS-location compatibility depend on the selected Apigee residency configuration. Confirm current Google requirements before setting it.

### Input validation and resource identification

Terraform validates project and resource names, region, billing type, environment capabilities, PSC consumers, KMS resource names, service-account identity, forward-proxy format, access-log filter, deletion retention, and a network-aligned RFC1918 `/22` runtime range. Provider default labels identify supported resources as managed by Terraform and associated with Apigee.

Validation reduces configuration mistakes but does not confirm CIDR availability or overlap, KMS location compatibility, IAM permissions, billing entitlement, trusted proxy topology, or organization-policy compliance.

## Prerequisites

Before running Terraform, ensure that you have:

1. Terraform 1.5 or later.
2. A Google Cloud project with billing enabled.
3. Apigee Pay-as-you-go or subscription entitlement.
4. An existing VPC suitable for Apigee.
5. An available, correctly aligned, non-overlapping RFC1918 `/22` range.
6. Sufficient IAM permissions, preferably through service-account impersonation.
7. Compatible Cloud KMS keys and IAM grants if CMEK is required.

The configuration enables these APIs:

- `apigee.googleapis.com`
- `compute.googleapis.com`
- `servicenetworking.googleapis.com`

## Configuration

Create a local `terraform.tfvars` file with environment-specific values. Do not commit secrets or credentials.

```hcl terraform.tfvars
project_id        = "example-project-id"
region            = "us-central1"
network_id        = "projects/example-project-id/global/networks/example-vpc"
instance_ip_range = "10.20.0.0/22"

billing_type            = "PAYG"
apigee_instance_name    = "apigee-instance"
apigee_environment_name = "dev"
apigee_environment_type = "BASE"
api_proxy_type           = "CONFIGURABLE"
deployment_type          = "PROXY"

# Add only explicitly trusted PSC consumer projects. The organization project
# is included automatically by this configuration.
psc_consumer_project_ids = [
  "trusted-consumer-project",
]

impersonate_service_account = "terraform-apigee@example-project-id.iam.gserviceaccount.com"

runtime_database_kms_key_name = "projects/example-project-id/locations/us-central1/keyRings/apigee/cryptoKeys/runtime-database"
instance_disk_kms_key_name    = "projects/example-project-id/locations/us-central1/keyRings/apigee/cryptoKeys/runtime-disk"
control_plane_kms_key_name    = "projects/example-project-id/locations/us/keyRings/apigee/cryptoKeys/control-plane"
consumer_data_kms_key_name    = "projects/example-project-id/locations/us/keyRings/apigee/cryptoKeys/consumer-data"
api_consumer_data_location    = "us-central1"

# Optional controls; enable only after provisioning the dependencies and
# documenting the trusted ingress path.
forward_proxy_uri      = "https://egress-proxy.internal.example:8443"
client_ip_header_index = -2
```

Verify all key locations against current Apigee CMEK requirements. Remove optional CMEK values only when Google permits Google-managed encryption for the selected billing model and deployment type.

## Deploy

Authenticate with Application Default Credentials:

```shell terminal
 gcloud auth application-default login
```

Then initialize, format, validate, and review the plan:

```shell terminal
terraform init
terraform fmt -check
terraform validate
terraform plan
```

Apply only after reviewing the plan, CIDR allocation, KMS permissions, billing model, and deletion implications:

```shell terminal
terraform apply
```

Apigee provisioning and deletion can take significantly longer than a short test window. Pay-as-you-go charges accrue while billable environments remain active, not merely while Terraform is running.

## Destroy

Review the destroy plan before removing the deployment:

```shell terminal
terraform plan -destroy
terraform destroy
```

Afterward, verify in Google Cloud that the environment and other billable resources have actually been removed. Retention settings may preserve organization data after deletion.

## Policy as code with OPA and Regula

The central `../OPA Policies/Apigee/` service directory contains the plan-based Rego controls associated with this Terraform configuration:

- `../OPA Policies/Apigee/apigee_security.rego` — security policy evaluated against Terraform plan JSON
- `../OPA Policies/Apigee/apigee_security_test.rego` — positive and negative unit tests for every control

The policy checks the rendered plan rather than raw HCL, so Terraform expressions, defaults, and variables are evaluated before enforcement. It also inspects `resource_changes`, including resources addressed within child modules.

Run the unit tests with OPA 0.68 or later:

```shell terminal
opa fmt --fail "../OPA Policies/Apigee"
opa test "../OPA Policies/Apigee" -v
```

Create a plan JSON document and evaluate it:

```shell terminal
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
opa eval \
  --fail-defined \
  --format pretty \
  --data "../OPA Policies/Apigee/apigee_security.rego" \
  --input tfplan.json \
  'data.apigee.security.deny[_]'
```

`undefined` means that the policy produced no denial. Any returned object identifies the failed `APIGEE-*` control, resource address where applicable, and reason. The `--fail-defined` option gives CI a nonzero exit code when at least one denial exists.

The same Terraform can be scanned separately with Regula for its built-in rules. These custom policies use standard OPA Terraform plan JSON input and are deliberately independent of Regula's internal rule-library APIs, which can vary by Regula version. Run both checks in CI when Regula findings and these Apigee-specific controls are required.

Do not commit `tfplan` or `tfplan.json`; Terraform plans may contain sensitive values.

### Custom policy controls

| Control | Requirement |
|---|---|
| `APIGEE-001` | Exactly one organization, instance, environment, and attachment must exist |
| `APIGEE-002` | Required APIs must be present and retained during destroy |
| `APIGEE-003` | The organization must use the cloud runtime |
| `APIGEE-004` | An authorized VPC must be explicit |
| `APIGEE-005` | Configured CMEK values must be full CryptoKey resource names |
| `APIGEE-006` | Runtime networking must use RFC1918 `/22` space |
| `APIGEE-007` | The PSC consumer allowlist must not be empty |
| `APIGEE-008` | Runtime access logging must be enabled |
| `APIGEE-009` | The environment tier must be explicit and supported |
| `APIGEE-010` | The API proxy type must be explicit and supported |
| `APIGEE-011` | The deployment type must be explicit and supported |
| `APIGEE-012` | A configured forward proxy must use HTTPS and an explicit port |
| `APIGEE-013` | Client-IP resolution must use a trusted nonzero `X-Forwarded-For` index |

## Files

- `providers.tf` — Terraform version, Google provider, impersonation, and default labels
- `variables.tf` — configurable inputs and validation rules
- `main.tf` — APIs and Apigee resources
- `../OPA Policies/Apigee/apigee_security.rego` — centralized OPA security controls for Terraform plan JSON
- `../OPA Policies/Apigee/apigee_security_test.rego` — centralized OPA unit tests
- `.terraform.lock.hcl` — selected provider versions and checksums

## Production considerations

This configuration is a secure foundation, not a complete production edge architecture. A production deployment may additionally require:

- A remote, encrypted, versioned Terraform state backend with restricted IAM
- Dedicated deployment identities and least-privilege IAM
- VPC and private service networking resources
- Consumer-side Private Service Connect endpoints and private DNS
- HTTPS load balancing, managed certificates, and Cloud Armor
- API authentication, authorization, quotas, rate limiting, and threat protection
- Log sinks, alerting, dashboards, audit controls, and retention policies
- Multiple regions and tested disaster-recovery procedures
- Separate projects or environments for development, testing, and production
- CI/CD policy checks and approval gates
- `prevent_destroy` lifecycle guards for long-lived production organizations and instances; these are intentionally not enabled so test deployments can be destroyed and billing stopped

Always run `terraform plan` and complete a security, networking, and cost review before applying changes.

## Security controls in place

- [x] Only required Google Cloud APIs are enabled by this stack
- [x] Required APIs remain enabled during destroy to avoid collateral disruption
- [x] Apigee is explicitly bound to an authorized VPC
- [x] Runtime networking requires a network-aligned private RFC1918 `/22`
- [x] Private Service Connect consumers are explicitly allowlisted
- [x] The organization project is always retained in the PSC allowlist
- [x] Runtime access logging is always enabled
- [x] Access-log filters are limited to supported `statusCode` expressions
- [x] Optional CMEK coverage exists for runtime database, disks, control-plane data, and API consumer data
- [x] Cloud KMS resource names are format-validated
- [x] Optional API consumer data residency can be selected explicitly
- [x] Service-account impersonation is supported to avoid static credential files
- [x] Service-account identity input is format-validated
- [x] Environment tier defaults explicitly to least-privilege `BASE`
- [x] Proxy capability defaults explicitly to least-privilege `CONFIGURABLE`
- [x] Archive deployment is available for immutable pipeline-driven releases
- [x] Trusted client-IP resolution is available and disabled until the proxy chain is documented
- [x] Controlled egress through a forward proxy is available
- [x] Environment-to-runtime attachment is explicit
- [x] Deletion retention behavior is configurable
- [x] Project, resource, PSC consumer, environment, CIDR, and security-option inputs are validated
- [x] Terraform-managed resources receive consistent provider labels where supported
- [x] Apigee-specific plan controls are enforced through OPA/Rego
- [x] Positive and negative policy tests cover all custom controls
- [ ] KMS keys and their IAM bindings must be provisioned separately
- [ ] PSC endpoints, DNS, firewall rules, and private service networking must be provisioned separately
- [ ] Load balancing, TLS, Cloud Armor, and API-layer policies must be provisioned separately
- [ ] Remote Terraform state, monitoring, alerting, and organization-level guardrails must be configured separately
