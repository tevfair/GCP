variable "project_id" {
  description = "Existing Google Cloud project in which API Hub will be provisioned."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid Google Cloud project ID."
  }
}

variable "location" {
  description = "Supported Google Cloud region for the host registration and API Hub instance."
  type        = string
  default     = "us-central1"

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.location))
    error_message = "location must be a regional Google Cloud location such as us-central1."
  }
}

variable "api_hub_instance_id" {
  description = "Identifier for the API Hub instance."
  type        = string
  default     = "api-hub"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,62}$", var.api_hub_instance_id))
    error_message = "api_hub_instance_id must start with a lowercase letter and contain only lowercase letters, numbers, and hyphens."
  }
}

variable "description" {
  description = "Description assigned to the API Hub instance."
  type        = string
  default     = "Organization API catalog managed by Terraform"

  validation {
    condition     = length(trimspace(var.description)) > 0
    error_message = "description must not be empty."
  }
}

variable "enable_semantic_search" {
  description = "Enable Vertex AI-powered semantic search for the API catalog."
  type        = bool
  default     = false
}

variable "vertex_location" {
  description = "Vertex AI multi-region used by semantic search, such as us or eu."
  type        = string
  default     = null

  validation {
    condition     = var.vertex_location == null || contains(["us", "eu"], var.vertex_location)
    error_message = "vertex_location must be null, us, or eu."
  }
}

variable "impersonate_service_account" {
  description = "Optional deployment service account to impersonate instead of using static credentials."
  type        = string
  default     = null

  validation {
    condition = (
      var.impersonate_service_account == null ||
      can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.impersonate_service_account))
    )
    error_message = "impersonate_service_account must be a valid Google service-account email address."
  }
}
