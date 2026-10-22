output "api_hub_instance_name" {
  description = "Fully qualified API Hub instance resource name."
  value       = google_apihub_api_hub_instance.this.name
}

output "api_hub_service_identity" {
  description = "Email address of the Google-managed API Hub service identity."
  value       = google_project_service_identity.apihub.email
}

output "host_project_registration_name" {
  description = "Fully qualified API Hub host project registration name."
  value       = google_apihub_host_project_registration.this.name
}
