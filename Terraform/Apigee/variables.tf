variable "project_id" {
  description = "The GCP project ID in which to deploy Apigee."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID."
  }
}

variable "region" {
  description = "The GCP region for the Apigee runtime instance and analytics data."
  type        = string
  default     = "us-central1"

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "region must be a valid regional location such as us-central1."
  }
}

variable "apigee_instance_name" {
  description = "The name of the Apigee runtime instance."
  type        = string
  default     = "apigee-instance"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,61}[a-z0-9]$", var.apigee_instance_name))
    error_message = "apigee_instance_name must use lowercase letters, numbers, and hyphens, start with a letter, and end with a letter or number."
  }
}

variable "apigee_environment_name" {
  description = "The name of the Apigee environment."
  type        = string
  default     = "dev"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,30}[a-z0-9]$", var.apigee_environment_name))
    error_message = "apigee_environment_name must use lowercase letters, numbers, and hyphens, start with a letter, and end with a letter or number."
  }
}

variable "billing_type" {
  description = "Apigee billing type enabled for the project."
  type        = string
  default     = "PAYG"

  validation {
    condition     = contains(["PAYG", "SUBSCRIPTION"], var.billing_type)
    error_message = "billing_type must be PAYG or SUBSCRIPTION."
  }
}

variable "network_id" {
  description = "The self-link of an existing VPC network authorized to connect to Apigee. Required for VPC peering deployments."
  type        = string
}

variable "instance_ip_range" {
  description = "A dedicated, non-overlapping RFC1918 /22 range reserved for the Apigee instance."
  type        = string

  validation {
    condition = (
      can(cidrhost(var.instance_ip_range, 0)) &&
      can(regex("/22$", var.instance_ip_range)) &&
      can(regex("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)", cidrhost(var.instance_ip_range, 0))) &&
      can(regex("^${replace(cidrhost(var.instance_ip_range, 0), ".", "\\.")}/22$", var.instance_ip_range))
    )
    error_message = "instance_ip_range must be a network-aligned RFC1918 /22 CIDR range."
  }
}

variable "psc_consumer_project_ids" {
  description = "Additional project IDs or numbers explicitly permitted to connect through Private Service Connect. The Apigee project is always included by this configuration."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for project in var.psc_consumer_project_ids :
      can(regex("^([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,20})$", project))
    ])
    error_message = "Each PSC consumer must be a valid GCP project ID or numeric project number."
  }
}

variable "access_log_filter" {
  description = "CEL filter for Apigee access logs. Only statusCode expressions are supported; empty logs all requests."
  type        = string
  default     = ""

  validation {
    condition     = var.access_log_filter == "" || can(regex("^statusCode( |[<>=!&|0-9])+$", var.access_log_filter))
    error_message = "access_log_filter must be empty or a CEL expression that uses only statusCode."
  }
}

variable "apigee_environment_type" {
  description = "Apigee environment capability and billing tier. BASE applies least privilege and lowest cost."
  type        = string
  default     = "BASE"

  validation {
    condition     = contains(["BASE", "INTERMEDIATE", "COMPREHENSIVE"], var.apigee_environment_type)
    error_message = "apigee_environment_type must be BASE, INTERMEDIATE, or COMPREHENSIVE."
  }
}

variable "api_proxy_type" {
  description = "API proxy capability. CONFIGURABLE is the least-privilege standard proxy type."
  type        = string
  default     = "CONFIGURABLE"

  validation {
    condition     = contains(["CONFIGURABLE", "PROGRAMMABLE"], var.api_proxy_type)
    error_message = "api_proxy_type must be CONFIGURABLE or PROGRAMMABLE."
  }
}

variable "deployment_type" {
  description = "Environment deployment model. ARCHIVE provides stronger immutability but requires an archive-based delivery workflow."
  type        = string
  default     = "PROXY"

  validation {
    condition     = contains(["PROXY", "ARCHIVE"], var.deployment_type)
    error_message = "deployment_type must be PROXY or ARCHIVE."
  }
}

variable "forward_proxy_uri" {
  description = "Optional HTTP(S) forward proxy used to inspect and control Apigee runtime egress."
  type        = string
  default     = null

  validation {
    condition     = var.forward_proxy_uri == null || can(regex("^https?://[^/:[:space:]]+:[0-9]{1,5}$", var.forward_proxy_uri))
    error_message = "forward_proxy_uri must be null or an HTTP(S) URI with an explicit host and port."
  }
}

variable "client_ip_header_index" {
  description = "Optional trusted X-Forwarded-For index used to resolve client IPs. Valid values are -3 through 3; null disables custom resolution."
  type        = number
  default     = null

  validation {
    condition     = var.client_ip_header_index == null ? true : contains([-3, -2, -1, 0, 1, 2, 3], var.client_ip_header_index)
    error_message = "client_ip_header_index must be null or an integer from -3 through 3."
  }
}

variable "runtime_database_kms_key_name" {
  description = "Full Cloud KMS CryptoKey name for Apigee runtime database encryption. Required for a CMEK deployment."
  type        = string
  default     = null

  validation {
    condition     = var.runtime_database_kms_key_name == null || can(regex("^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$", var.runtime_database_kms_key_name))
    error_message = "runtime_database_kms_key_name must be null or a full Cloud KMS CryptoKey resource name."
  }
}

variable "instance_disk_kms_key_name" {
  description = "Full regional Cloud KMS CryptoKey name for Apigee instance disk encryption. Required for paid subscriptions."
  type        = string
  default     = null

  validation {
    condition     = var.instance_disk_kms_key_name == null || can(regex("^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$", var.instance_disk_kms_key_name))
    error_message = "instance_disk_kms_key_name must be null or a full Cloud KMS CryptoKey resource name."
  }
}

variable "control_plane_kms_key_name" {
  description = "Optional full Cloud KMS CryptoKey name for control-plane encryption when using a supported data residency region."
  type        = string
  default     = null

  validation {
    condition     = var.control_plane_kms_key_name == null || can(regex("^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$", var.control_plane_kms_key_name))
    error_message = "control_plane_kms_key_name must be null or a full Cloud KMS CryptoKey resource name."
  }
}

variable "consumer_data_kms_key_name" {
  description = "Optional full Cloud KMS CryptoKey name for API consumer data encryption."
  type        = string
  default     = null

  validation {
    condition     = var.consumer_data_kms_key_name == null || can(regex("^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$", var.consumer_data_kms_key_name))
    error_message = "consumer_data_kms_key_name must be null or a full Cloud KMS CryptoKey resource name."
  }
}

variable "api_consumer_data_location" {
  description = "Optional approved single region for API consumer data residency. Confirm current Apigee region support before setting it."
  type        = string
  default     = null

  validation {
    condition     = var.api_consumer_data_location == null || can(regex("^[a-z]+-[a-z]+[0-9]+$", var.api_consumer_data_location))
    error_message = "api_consumer_data_location must be null or a regional location such as us-central1."
  }
}

variable "deletion_retention" {
  description = "Organization retention behavior after deletion."
  type        = string
  default     = "DELETION_RETENTION_UNSPECIFIED"

  validation {
    condition     = contains(["DELETION_RETENTION_UNSPECIFIED", "MINIMUM"], var.deletion_retention)
    error_message = "deletion_retention must be DELETION_RETENTION_UNSPECIFIED or MINIMUM."
  }
}

variable "impersonate_service_account" {
  description = "Optional deployment service account to impersonate, avoiding downloaded service-account keys."
  type        = string
  default     = null

  validation {
    condition     = var.impersonate_service_account == null || can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.impersonate_service_account))
    error_message = "impersonate_service_account must be null or a valid Google service-account email address."
  }
}
