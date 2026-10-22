provider "google" {
  project                     = var.project_id
  region                      = var.location
  impersonate_service_account = var.impersonate_service_account

  default_labels = {
    managed_by = "terraform"
    service    = "api-hub"
  }
}

provider "google-beta" {
  project                     = var.project_id
  region                      = var.location
  impersonate_service_account = var.impersonate_service_account

  default_labels = {
    managed_by = "terraform"
    service    = "api-hub"
  }
}
