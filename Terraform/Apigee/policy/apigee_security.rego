package apigee.security

import future.keywords.in

# This policy evaluates Terraform plan JSON produced by `terraform show -json`.
# It intentionally inspects resource_changes so resources in child modules are
# evaluated as well as resources in the root module.

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

private_22_pattern := "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)[0-9]+\\.[0-9]+\\.[0-9]+/22$"

# Every plan must contain exactly one organization, instance, environment, and
# attachment. This prevents an empty or partial plan from passing silently.
deny[result] {
	resource_type := "google_apigee_organization"
	count(resources_by_type(resource_type)) != 1
	result := {"control": "APIGEE-001", "message": "The plan must contain exactly one Apigee organization."}
}

deny[result] {
	resource_type := "google_apigee_instance"
	count(resources_by_type(resource_type)) != 1
	result := {"control": "APIGEE-001", "message": "The plan must contain exactly one Apigee instance."}
}

deny[result] {
	resource_type := "google_apigee_environment"
	count(resources_by_type(resource_type)) != 1
	result := {"control": "APIGEE-001", "message": "The plan must contain exactly one Apigee environment."}
}

deny[result] {
	resource_type := "google_apigee_instance_attachment"
	count(resources_by_type(resource_type)) != 1
	result := {"control": "APIGEE-001", "message": "The plan must contain exactly one Apigee environment attachment."}
}

# Required APIs must remain enabled when Terraform destroys the stack.
deny[result] {
	required := {"apigee.googleapis.com", "compute.googleapis.com", "servicenetworking.googleapis.com"}
	configured := {service |
		resource := resources_by_type("google_project_service")[_]
		service := value(resource, "service")
		value(resource, "disable_on_destroy") == false
	}
	missing := required - configured
	count(missing) > 0
	result := {"control": "APIGEE-002", "message": sprintf("Required APIs are absent or configured to be disabled on destroy: %v", [missing])}
}

# The organization must use the cloud runtime and an explicit authorized VPC.
deny[result] {
	resource := resources_by_type("google_apigee_organization")[_]
	value(resource, "runtime_type") != "CLOUD"
	result := {"control": "APIGEE-003", "address": resource.address, "message": "Apigee runtime_type must be CLOUD."}
}

deny[result] {
	resource := resources_by_type("google_apigee_organization")[_]
	network := value(resource, "authorized_network")
	not is_nonempty_string(network)
	result := {"control": "APIGEE-004", "address": resource.address, "message": "Apigee must use an explicit authorized VPC network."}
}

# Any configured customer-managed key must be a full CryptoKey resource name.
deny[result] {
	resource := resources_by_type("google_apigee_organization")[_]
	key_name := [
		"runtime_database_encryption_key_name",
		"control_plane_encryption_key_name",
		"api_consumer_data_encryption_key_name",
	][_]
	key := value(resource, key_name)
	key != null
	not regex.match(kms_key_pattern, key)
	result := {"control": "APIGEE-005", "address": resource.address, "message": sprintf("%s must be a full Cloud KMS CryptoKey resource name.", [key_name])}
}

deny[result] {
	resource := resources_by_type("google_apigee_instance")[_]
	key := value(resource, "disk_encryption_key_name")
	key != null
	not regex.match(kms_key_pattern, key)
	result := {"control": "APIGEE-005", "address": resource.address, "message": "disk_encryption_key_name must be a full Cloud KMS CryptoKey resource name."}
}

# Runtime instances must use private /22 space and explicitly restrict PSC.
deny[result] {
	resource := resources_by_type("google_apigee_instance")[_]
	cidr := value(resource, "ip_range")
	not regex.match(private_22_pattern, cidr)
	result := {"control": "APIGEE-006", "address": resource.address, "message": "The Apigee instance must use an RFC1918 /22 range."}
}

deny[result] {
	resource := resources_by_type("google_apigee_instance")[_]
	consumers := value(resource, "consumer_accept_list")
	not is_nonempty_array(consumers)
	result := {"control": "APIGEE-007", "address": resource.address, "message": "The PSC consumer accept list must not be empty."}
}

# Access logging must be explicitly enabled.
deny[result] {
	resource := resources_by_type("google_apigee_instance")[_]
	configs := value(resource, "access_logging_config")
	not logging_enabled(configs)
	result := {"control": "APIGEE-008", "address": resource.address, "message": "Apigee runtime access logging must be enabled."}
}

# Environment capabilities are constrained to explicit supported values.
deny[result] {
	resource := resources_by_type("google_apigee_environment")[_]
	not value(resource, "type") in {"BASE", "INTERMEDIATE", "COMPREHENSIVE"}
	result := {"control": "APIGEE-009", "address": resource.address, "message": "The Apigee environment type must be explicit."}
}

deny[result] {
	resource := resources_by_type("google_apigee_environment")[_]
	not value(resource, "api_proxy_type") in {"CONFIGURABLE", "PROGRAMMABLE"}
	result := {"control": "APIGEE-010", "address": resource.address, "message": "The API proxy type must be explicit and supported."}
}

deny[result] {
	resource := resources_by_type("google_apigee_environment")[_]
	not value(resource, "deployment_type") in {"PROXY", "ARCHIVE"}
	result := {"control": "APIGEE-011", "address": resource.address, "message": "The deployment type must be explicit and supported."}
}

# If a forward proxy is configured, require TLS and an explicit port.
deny[result] {
	resource := resources_by_type("google_apigee_environment")[_]
	proxy := value(resource, "forward_proxy_uri")
	proxy != null
	not regex.match("^https://[^/:[:space:]]+:[0-9]{1,5}$", proxy)
	result := {"control": "APIGEE-012", "address": resource.address, "message": "The forward proxy must use HTTPS with an explicit port."}
}

# Custom client-IP resolution may trust only X-Forwarded-For and a supported
# non-zero index. Requiring a non-zero index avoids blindly trusting the first
# client-supplied value in common proxy topologies.
deny[result] {
	resource := resources_by_type("google_apigee_environment")[_]
	configs := value(resource, "client_ip_resolution_config")
	count(configs) > 0
	algorithm := configs[0].header_index_algorithm[0]
	algorithm.ip_header_name != "X-Forwarded-For"
	result := {"control": "APIGEE-013", "address": resource.address, "message": "Client IP resolution may use only X-Forwarded-For."}
}

deny[result] {
	resource := resources_by_type("google_apigee_environment")[_]
	configs := value(resource, "client_ip_resolution_config")
	count(configs) > 0
	index := configs[0].header_index_algorithm[0].ip_header_index
	not index in {-3, -2, -1, 1, 2, 3}
	result := {"control": "APIGEE-013", "address": resource.address, "message": "Client IP resolution must use a documented non-zero trusted proxy index."}
}

is_nonempty_string(value) {
	is_string(value)
	trim_space(value) != ""
}

is_nonempty_array(value) {
	is_array(value)
	count(value) > 0
}

logging_enabled(configs) {
	is_array(configs)
	count(configs) == 1
	configs[0].enabled == true
}
