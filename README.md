# GCP Infrastructure and OPA Policies

[![OPA policy tests](https://github.com/tevfair/GCP/actions/workflows/opa-policy-tests.yml/badge.svg?branch=main)](https://github.com/tevfair/GCP/actions/workflows/opa-policy-tests.yml)

Terraform configurations and Open Policy Agent controls for Google Cloud services.

## Pipeline workflow

[![GCP OPA policy testing pipeline](docs/images/opa-policy-pipeline.svg)](https://github.com/tevfair/GCP/actions/workflows/opa-policy-tests.yml)

The pipeline automatically validates and tests every service policy, builds commit-pinned control evidence, publishes a GitHub job summary, and retains the complete results as a downloadable artifact. Select the diagram to open the workflow runs.

## Policy coverage

The automated workflow validates Rego formatting, performs strict policy checks, runs all unit tests, and publishes control-by-control evidence for:

- GCP API Hub
- Apigee

Select the workflow badge above to view current and historical test results.
