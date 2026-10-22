# SECURITY: Enable only the APIs required by this Apigee deployment to reduce
# unnecessary service exposure in the project.
locals {
  required_services = toset([
    "apigee.googleapis.com",
    "compute.googleapis.com",
    "servicenetworking.googleapis.com",
  ])
}

# SECURITY: Keep foundational APIs enabled during resource teardown so deleting
# this stack does not unexpectedly disrupt other protected project workloads.
resource "google_project_service" "required" {
  for_each = local.required_services

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_apigee_organization" "this" {
  project_id       = var.project_id
  analytics_region = var.region
  billing_type     = var.billing_type

  # SECURITY: Bind the organization to the explicitly approved VPC instead of
  # relying on an unrestricted or implicit network.
  authorized_network = var.network_id
  runtime_type       = "CLOUD"

  # SECURITY: Optional CMEK settings give the organization control over key
  # rotation, revocation, and auditability for each Apigee data category.
  runtime_database_encryption_key_name  = var.runtime_database_kms_key_name
  control_plane_encryption_key_name     = var.control_plane_kms_key_name
  api_consumer_data_encryption_key_name = var.consumer_data_kms_key_name

  # SECURITY: Pin API consumer data to an approved residency region when one is
  # required. The location and CMEK location must be compatible.
  api_consumer_data_location = var.api_consumer_data_location

  # SECURITY: Preserve organization data for the configured recovery window
  # after deletion, reducing the impact of accidental destructive operations.
  retention = var.deletion_retention

  depends_on = [google_project_service.required]
}

resource "google_apigee_instance" "this" {
  name     = var.apigee_instance_name
  location = var.region
  org_id   = google_apigee_organization.this.id

  # SECURITY: Use a dedicated, non-overlapping private /22 range for runtime
  # isolation and predictable firewall controls.
  ip_range = var.instance_ip_range

  # SECURITY: Encrypt instance disks with an optional customer-managed key.
  disk_encryption_key_name = var.instance_disk_kms_key_name

  # SECURITY: Restrict Private Service Connect access to this organization’s
  # project plus explicitly trusted consumer projects.
  consumer_accept_list = distinct(concat([var.project_id], var.psc_consumer_project_ids))

  # SECURITY: Send runtime access events to Cloud Logging for detection,
  # investigation, and audit. Keep the filter empty to capture all requests.
  access_logging_config {
    enabled = true
    filter  = var.access_log_filter
  }
}

# SECURITY: Maintain a distinct environment boundary so API proxies and their
# configuration can be separated by lifecycle stage and IAM policy.
resource "google_apigee_environment" "this" {
  name        = var.apigee_environment_name
  org_id      = google_apigee_organization.this.id
  description = "Managed by Terraform"

  # SECURITY: Explicitly constrain environment capabilities instead of relying
  # on provider or API defaults. BASE and CONFIGURABLE are least privilege for
  # standard proxies; increase either only when additional features are needed.
  type           = var.apigee_environment_type
  api_proxy_type = var.api_proxy_type

  # SECURITY: ARCHIVE can enforce a more immutable, pipeline-driven deployment
  # model. PROXY remains available for conventional revision deployments.
  deployment_type = var.deployment_type

  # SECURITY: Route runtime egress through an approved inspection point when a
  # controlled forward proxy is supplied.
  forward_proxy_uri = var.forward_proxy_uri

  # SECURITY: Resolve the originating client only from the configured position
  # in X-Forwarded-For. Enable this only after documenting the trusted proxy path.
  dynamic "client_ip_resolution_config" {
    for_each = var.client_ip_header_index == null ? [] : [var.client_ip_header_index]

    content {
      header_index_algorithm {
        ip_header_name  = "X-Forwarded-For"
        ip_header_index = client_ip_resolution_config.value
      }
    }
  }
}

# SECURITY: Attach only the explicitly managed environment to this runtime,
# preventing unintended environments from executing on the instance.
resource "google_apigee_instance_attachment" "this" {
  instance_id = google_apigee_instance.this.id
  environment = google_apigee_environment.this.name
}
