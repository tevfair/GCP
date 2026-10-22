package apigee.security

import future.keywords.in

valid_plan := {"resource_changes": [
	project_service("google_project_service.required[\"apigee.googleapis.com\"]", "apigee.googleapis.com"),
	project_service("google_project_service.required[\"compute.googleapis.com\"]", "compute.googleapis.com"),
	project_service("google_project_service.required[\"servicenetworking.googleapis.com\"]", "servicenetworking.googleapis.com"),
	managed_resource("google_apigee_organization.this", "google_apigee_organization", {
		"authorized_network": "projects/example-project/global/networks/apigee-vpc",
		"runtime_type": "CLOUD",
		"runtime_database_encryption_key_name": "projects/example-project/locations/us/keyRings/apigee/cryptoKeys/runtime-db",
		"control_plane_encryption_key_name": null,
		"api_consumer_data_encryption_key_name": null,
	}),
	managed_resource("google_apigee_instance.this", "google_apigee_instance", {
		"ip_range": "10.20.0.0/22",
		"disk_encryption_key_name": "projects/example-project/locations/us-central1/keyRings/apigee/cryptoKeys/runtime-disk",
		"consumer_accept_list": ["example-project"],
		"access_logging_config": [{"enabled": true, "filter": ""}],
	}),
	managed_resource("google_apigee_environment.this", "google_apigee_environment", {
		"type": "BASE",
		"api_proxy_type": "CONFIGURABLE",
		"deployment_type": "PROXY",
		"forward_proxy_uri": null,
		"client_ip_resolution_config": [],
	}),
	managed_resource("google_apigee_instance_attachment.this", "google_apigee_instance_attachment", {
		"environment": "dev",
		"instance_id": "organizations/example-project/instances/apigee-instance",
	}),
]}

managed_resource(address, resource_type, after) := {
	"address": address,
	"mode": "managed",
	"type": resource_type,
	"change": {"after": after},
}

project_service(address, service) := managed_resource(address, "google_project_service", {
	"service": service,
	"disable_on_destroy": false,
})

control_present(violations, control) {
	some violation in violations
	violation.control == control
	print(sprintf("EXPECTED_DENIAL control=%s evidence=%s", [control, json.marshal(violation)]))
}

test_secure_plan_has_no_denials {
	violations := deny with input as valid_plan
	count(violations) == 0
	print("VALID_PLAN service=Apigee denials=0")
}

test_empty_plan_is_rejected {
	violations := deny with input as {"resource_changes": []}
	control_present(violations, "APIGEE-001")
}

test_required_api_must_remain_enabled {
	plan := object.union(valid_plan, {"resource_changes": array.concat(
		array.slice(valid_plan.resource_changes, 0, 2),
		array.slice(valid_plan.resource_changes, 3, count(valid_plan.resource_changes)),
	)})
	violations := deny with input as plan
	control_present(violations, "APIGEE-002")
}

test_runtime_must_be_cloud {
	resource := managed_resource("google_apigee_organization.this", "google_apigee_organization", {
		"authorized_network": "projects/example-project/global/networks/apigee-vpc",
		"runtime_type": "HYBRID",
	})
	plan := replace_resource(valid_plan, 3, resource)
	violations := deny with input as plan
	control_present(violations, "APIGEE-003")
}

test_authorized_network_is_required {
	resource := managed_resource("google_apigee_organization.this", "google_apigee_organization", {
		"authorized_network": "",
		"runtime_type": "CLOUD",
	})
	plan := replace_resource(valid_plan, 3, resource)
	violations := deny with input as plan
	control_present(violations, "APIGEE-004")
}

test_invalid_kms_key_is_rejected {
	resource := managed_resource("google_apigee_organization.this", "google_apigee_organization", {
		"authorized_network": "projects/example-project/global/networks/apigee-vpc",
		"runtime_type": "CLOUD",
		"runtime_database_encryption_key_name": "not-a-kms-key",
	})
	plan := replace_resource(valid_plan, 3, resource)
	violations := deny with input as plan
	control_present(violations, "APIGEE-005")
}

test_public_instance_range_is_rejected {
	resource := managed_resource("google_apigee_instance.this", "google_apigee_instance", {
		"ip_range": "8.8.8.0/22",
		"consumer_accept_list": ["example-project"],
		"access_logging_config": [{"enabled": true, "filter": ""}],
	})
	plan := replace_resource(valid_plan, 4, resource)
	violations := deny with input as plan
	control_present(violations, "APIGEE-006")
}

test_empty_psc_allowlist_is_rejected {
	resource := managed_resource("google_apigee_instance.this", "google_apigee_instance", {
		"ip_range": "10.20.0.0/22",
		"consumer_accept_list": [],
		"access_logging_config": [{"enabled": true, "filter": ""}],
	})
	plan := replace_resource(valid_plan, 4, resource)
	violations := deny with input as plan
	control_present(violations, "APIGEE-007")
}

test_disabled_access_logging_is_rejected {
	resource := managed_resource("google_apigee_instance.this", "google_apigee_instance", {
		"ip_range": "10.20.0.0/22",
		"consumer_accept_list": ["example-project"],
		"access_logging_config": [{"enabled": false, "filter": ""}],
	})
	plan := replace_resource(valid_plan, 4, resource)
	violations := deny with input as plan
	control_present(violations, "APIGEE-008")
}

test_environment_type_must_be_explicit {
	resource := managed_resource("google_apigee_environment.this", "google_apigee_environment", {
		"type": "ENVIRONMENT_TYPE_UNSPECIFIED",
		"api_proxy_type": "CONFIGURABLE",
		"deployment_type": "PROXY",
		"forward_proxy_uri": null,
		"client_ip_resolution_config": [],
	})
	plan := replace_resource(valid_plan, 5, resource)
	violations := deny with input as plan
	control_present(violations, "APIGEE-009")
}

test_proxy_type_must_be_explicit {
	resource := managed_resource("google_apigee_environment.this", "google_apigee_environment", {
		"type": "BASE",
		"api_proxy_type": "API_PROXY_TYPE_UNSPECIFIED",
		"deployment_type": "PROXY",
		"forward_proxy_uri": null,
		"client_ip_resolution_config": [],
	})
	plan := replace_resource(valid_plan, 5, resource)
	violations := deny with input as plan
	control_present(violations, "APIGEE-010")
}

test_deployment_type_must_be_explicit {
	resource := managed_resource("google_apigee_environment.this", "google_apigee_environment", {
		"type": "BASE",
		"api_proxy_type": "CONFIGURABLE",
		"deployment_type": "DEPLOYMENT_TYPE_UNSPECIFIED",
		"forward_proxy_uri": null,
		"client_ip_resolution_config": [],
	})
	plan := replace_resource(valid_plan, 5, resource)
	violations := deny with input as plan
	control_present(violations, "APIGEE-011")
}

test_insecure_forward_proxy_is_rejected {
	resource := managed_resource("google_apigee_environment.this", "google_apigee_environment", {
		"type": "BASE",
		"api_proxy_type": "CONFIGURABLE",
		"deployment_type": "PROXY",
		"forward_proxy_uri": "http://proxy.internal:8080",
		"client_ip_resolution_config": [],
	})
	plan := replace_resource(valid_plan, 5, resource)
	violations := deny with input as plan
	control_present(violations, "APIGEE-012")
}

test_untrusted_client_ip_index_is_rejected {
	resource := managed_resource("google_apigee_environment.this", "google_apigee_environment", {
		"type": "BASE",
		"api_proxy_type": "CONFIGURABLE",
		"deployment_type": "PROXY",
		"forward_proxy_uri": null,
		"client_ip_resolution_config": [{"header_index_algorithm": [{
			"ip_header_name": "X-Forwarded-For",
			"ip_header_index": 0,
		}]}],
	})
	plan := replace_resource(valid_plan, 5, resource)
	violations := deny with input as plan
	control_present(violations, "APIGEE-013")
}

replace_resource(plan, index, replacement) := object.union(plan, {"resource_changes": array.concat(
	array.concat(
		array.slice(plan.resource_changes, 0, index),
		[replacement],
	),
	array.slice(plan.resource_changes, index + 1, count(plan.resource_changes)),
)})
