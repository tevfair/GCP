# Google Cloud API Hub

This Terraform configuration provisions an Apigee API Hub instance in an existing Google Cloud project using explicit Google-managed encryption.

## Resources

- Enables and retains `apihub.googleapis.com`
- Registers the existing project as the API Hub host project
- Creates the API Hub Google-managed service identity
- Grants `roles/apihub.admin` and `roles/apihub.runtimeProjectServiceAgent`
- Provisions one regional API Hub instance
- Optionally enables Vertex AI-powered semantic search

## Prerequisites

- Terraform 1.5 or later
- Existing Google Cloud project with billing enabled
- Application Default Credentials or service-account impersonation
- Sufficient API Hub, Service Usage, and project IAM administration permissions
- No incompatible resource-location organization policy

## Configure and deploy

From this directory:

```shell terminal
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform fmt -check
terraform validate
terraform plan
terraform apply
```

Update `terraform.tfvars` before planning. The file is excluded from Git because environment values may be sensitive.

## Semantic search

Semantic search is disabled by default. To enable it, set:

```hcl terraform.tfvars
enable_semantic_search = true
vertex_location        = "us"
```

Confirm supported API Hub and Vertex AI locations and data-residency requirements before deployment.

## OPA policy checks

API Hub controls and tests are centralized in `../OPA Policies/API Hub/`. The repository GitHub Action runs these checks automatically and publishes control-by-control evidence.

Run them locally from the repository root:

```shell terminal
opa fmt --fail "Terraform/OPA Policies"
opa check --strict "Terraform/OPA Policies"
opa test "Terraform/OPA Policies" --verbose
```

## Important considerations

- Only one API Hub instance can be provisioned per host project.
- API Hub provisioning may create or use an associated Apigee organization entitlement.
- After deprovisioning, Google may require a seven-day wait before reprovisioning in the same project.
- Destroying this stack does not disable the API Hub API, reducing the risk of disrupting other consumers.
- Review the Terraform plan, IAM grants, data residency, costs, and deletion implications before applying.
