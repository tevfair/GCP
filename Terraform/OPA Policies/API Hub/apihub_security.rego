package apihub.security

import future.keywords.in

# Evaluates Terraform plan JSON produced by `terraform show -json`.
managed_resources[resource] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
}

resources_by_type(resource_type) = resources {
	resources := [resource |
		resource := managed_resources[_]
		resource.type == resource_type
	]
}

value(resource, key) = result {
	result := object.get(resource.change.after, key, null)
}

kms_key_pattern := "^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$"

# A complete API Hub deployment requires one host registration and one instance.
deny[result] {
	count(resources_by_type("google_apihub_host_project_registration")) != 1
	result := {"control": "APIHUB-001", "message": "The plan must contain exactly one API Hub host project registration."}
}

deny[result] {
	count(resources_by_type("google_apihub_api_hub_instance")) != 1
	result := {"control": "APIHUB-001", "message": "The plan must contain exactly one API Hub instance."}
}

# The API Hub API must be enabled and retained during destroy.
deny[result] {
	services := [resource |
		resource := resources_by_type("google_project_service")[_]
		value(resource, "service") == "apihub.googleapis.com"
		value(resource, "disable_on_destroy") == false
	]
	count(services) != 1
	result := {"control": "APIHUB-002", "message": "apihub.googleapis.com must be enabled and retained during destroy."}
}

# The host registration must explicitly identify a project resource.
deny[result] {
	resource := resources_by_type("google_apihub_host_project_registration")[_]
	gcp_project := value(resource, "gcp_project")
	not regex.match("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]$", gcp_project)
	result := {"control": "APIHUB-003", "address": resource.address, "message": "The host registration must use a full projects/PROJECT_ID resource name."}
}

# Host registration and API Hub instance must use the same explicit project.
deny[result] {
	host := resources_by_type("google_apihub_host_project_registration")[_]
	host_project := value(host, "project")
	not is_nonempty_string(host_project)
	result := {"control": "APIHUB-004", "address": host.address, "message": "The host registration project must be explicit."}
}

deny[result] {
	host := resources_by_type("google_apihub_host_project_registration")[_]
	instance := resources_by_type("google_apihub_api_hub_instance")[_]
	value(host, "project") != value(instance, "project")
	result := {"control": "APIHUB-004", "address": instance.address, "message": "The host registration and API Hub instance must use the same project."}
}

# Host registration and API Hub instance must use the same explicit location.
deny[result] {
	host := resources_by_type("google_apihub_host_project_registration")[_]
	host_location := value(host, "location")
	not is_nonempty_string(host_location)
	result := {"control": "APIHUB-005", "address": host.address, "message": "The host registration location must be explicit."}
}

deny[result] {
	host := resources_by_type("google_apihub_host_project_registration")[_]
	instance := resources_by_type("google_apihub_api_hub_instance")[_]
	value(host, "location") != value(instance, "location")
	result := {"control": "APIHUB-005", "address": instance.address, "message": "The host registration and API Hub instance must use the same location."}
}

# API Hub requires a managed service identity.
deny[result] {
	identities := [resource |
		resource := resources_by_type("google_project_service_identity")[_]
		value(resource, "service") == "apihub.googleapis.com"
	]
	count(identities) != 1
	result := {"control": "APIHUB-006", "message": "The plan must create exactly one API Hub service identity."}
}

# The service identity requires the API Hub admin and runtime agent roles.
deny[result] {
	required := {"roles/apihub.admin", "roles/apihub.runtimeProjectServiceAgent"}
	configured := {role |
		resource := resources_by_type("google_project_iam_member")[_]
		role := value(resource, "role")
	}
	missing := required - configured
	count(missing) > 0
	result := {"control": "APIHUB-007", "message": sprintf("Required API Hub service identity roles are missing: %v", [missing])}
}

# Encryption must be explicit and any CMEK must be a full CryptoKey name.
deny[result] {
	resource := resources_by_type("google_apihub_api_hub_instance")[_]
	configs := value(resource, "config")
	not valid_encryption(configs)
	result := {"control": "APIHUB-008", "address": resource.address, "message": "Encryption must use explicit GMEK or a valid CMEK CryptoKey resource name."}
}

# Semantic search requires an explicit Vertex AI location.
deny[result] {
	resource := resources_by_type("google_apihub_api_hub_instance")[_]
	configs := value(resource, "config")
	count(configs) == 1
	configs[0].disable_search == false
	not is_nonempty_string(object.get(configs[0], "vertex_location", null))
	result := {"control": "APIHUB-009", "address": resource.address, "message": "Enabled semantic search requires an explicit Vertex AI location."}
}

# Instance IDs must be explicit and use a stable resource-safe format.
deny[result] {
	resource := resources_by_type("google_apihub_api_hub_instance")[_]
	instance_id := value(resource, "api_hub_instance_id")
	not regex.match("^[a-z][a-z0-9-]{2,62}$", instance_id)
	result := {"control": "APIHUB-010", "address": resource.address, "message": "The API Hub instance ID must use lowercase letters, numbers, and hyphens."}
}

valid_encryption(configs) {
	is_array(configs)
	count(configs) == 1
	object.get(configs[0], "encryption_type", "GMEK") == "GMEK"
}

valid_encryption(configs) {
	is_array(configs)
	count(configs) == 1
	configs[0].encryption_type == "CMEK"
	regex.match(kms_key_pattern, object.get(configs[0], "cmek_key_name", ""))
}

is_nonempty_string(item) {
	is_string(item)
	trim_space(item) != ""
}
