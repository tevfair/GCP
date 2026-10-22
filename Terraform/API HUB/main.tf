resource "google_project_service" "apihub" {
  project            = var.project_id
  service            = "apihub.googleapis.com"
  disable_on_destroy = false
}

resource "google_apihub_host_project_registration" "this" {
  project                      = var.project_id
  location                     = var.location
  host_project_registration_id = var.project_id
  gcp_project                  = "projects/${var.project_id}"

  depends_on = [google_project_service.apihub]
}

resource "google_project_service_identity" "apihub" {
  provider = google-beta
  project  = var.project_id
  service  = "apihub.googleapis.com"

  depends_on = [google_project_service.apihub]
}

resource "google_project_iam_member" "apihub_service_identity" {
  for_each = toset([
    "roles/apihub.admin",
    "roles/apihub.runtimeProjectServiceAgent",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_project_service_identity.apihub.email}"
}

resource "google_apihub_api_hub_instance" "this" {
  project             = var.project_id
  location            = var.location
  api_hub_instance_id = var.api_hub_instance_id
  description         = var.description

  config {
    encryption_type = "GMEK"
    disable_search  = !var.enable_semantic_search
    vertex_location = var.enable_semantic_search ? var.vertex_location : null
  }

  lifecycle {
    precondition {
      condition     = !var.enable_semantic_search || var.vertex_location != null
      error_message = "vertex_location must be set when semantic search is enabled."
    }
  }

  depends_on = [
    google_apihub_host_project_registration.this,
    google_project_iam_member.apihub_service_identity,
  ]
}
