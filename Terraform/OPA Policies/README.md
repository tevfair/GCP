# Open Policy Agent policies

This directory centralizes OPA/Rego policies for the Terraform services in this repository. Each service has its own subdirectory so policies and tests remain associated with the infrastructure they evaluate.

## Services

- `Apigee/` — plan-based security controls and unit tests for `../Apigee/`

## Run all policy tests

From the repository root:

```shell terminal
opa fmt --fail "Terraform/OPA Policies"
opa test "Terraform/OPA Policies" -v
```

## Add policies for another service

Create a service-specific directory under this folder, for example `API Hub/`, and keep both its policy and `_test.rego` files there.
