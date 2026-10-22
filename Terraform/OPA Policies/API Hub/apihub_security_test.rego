package apihub.security

import future.keywords.in

valid_plan := {"resource_changes": [
	managed_resource("google_project_service.apihub", "google_project_service", {
		"project": "example-project",
		"service": "apihub.googleapis.com",
		"disable_on_destroy": false,
	}),
	managed_resource("google_apihub_host_project_registration.this", "google_apihub_host_project_registration", {
		"project": "example-project",
		"location": "us-central1",
		"gcp_project": "projects/example-project",
	}),
	managed_resource("google_project_service_identity.apihub", "google_project_service_identity", {
		"project": "example-project",
		"service": "apihub.googleapis.com",
	}),
	managed_resource("google_project_iam_member.admin", "google_project_iam_member", {
		"project": "example-project",
		"role": "roles/apihub.admin",
	}),
	managed_resource("google_project_iam_member.runtime", "google_project_iam_member", {
		"project": "example-project",
		"role": "roles/apihub.runtimeProjectServiceAgent",
	}),
	managed_resource("google_apihub_api_hub_instance.this", "google_apihub_api_hub_instance", {
		"project": "example-project",
		"location": "us-central1",
		"api_hub_instance_id": "api-hub",
		"config": [{
			"encryption_type": "GMEK",
			"cmek_key_name": null,
			"disable_search": true,
			"vertex_location": null,
		}],
	}),
]}

managed_resource(address, resource_type, after) := {
	"address": address,
	"mode": "managed",
	"type": resource_type,
	"change": {"after": after},
}

control_present(violations, control) {
	some violation in violations
	violation.control == control
}

replace_resource(plan, index, replacement) := object.union(plan, {"resource_changes": array.concat(
	array.concat(array.slice(plan.resource_changes, 0, index), [replacement]),
	array.slice(plan.resource_changes, index + 1, count(plan.resource_changes)),
)})

test_secure_plan_has_no_denials {
	violations := deny with input as valid_plan
	count(violations) == 0
}

test_complete_deployment_is_required {
	violations := deny with input as {"resource_changes": []}
	control_present(violations, "APIHUB-001")
}

test_api_must_remain_enabled {
	service := managed_resource("google_project_service.apihub", "google_project_service", {
		"project": "example-project",
		"service": "apihub.googleapis.com",
		"disable_on_destroy": true,
	})
	violations := deny with input as replace_resource(valid_plan, 0, service)
	control_present(violations, "APIHUB-002")
}

test_host_project_resource_name_is_required {
	host := managed_resource("google_apihub_host_project_registration.this", "google_apihub_host_project_registration", {
		"project": "example-project",
		"location": "us-central1",
		"gcp_project": "example-project",
	})
	violations := deny with input as replace_resource(valid_plan, 1, host)
	control_present(violations, "APIHUB-003")
}

test_projects_must_match {
	instance := managed_resource("google_apihub_api_hub_instance.this", "google_apihub_api_hub_instance", {
		"project": "different-project",
		"location": "us-central1",
		"api_hub_instance_id": "api-hub",
		"config": [{"encryption_type": "GMEK", "disable_search": true}],
	})
	violations := deny with input as replace_resource(valid_plan, 5, instance)
	control_present(violations, "APIHUB-004")
}

test_locations_must_match {
	instance := managed_resource("google_apihub_api_hub_instance.this", "google_apihub_api_hub_instance", {
		"project": "example-project",
		"location": "europe-west1",
		"api_hub_instance_id": "api-hub",
		"config": [{"encryption_type": "GMEK", "disable_search": true}],
	})
	violations := deny with input as replace_resource(valid_plan, 5, instance)
	control_present(violations, "APIHUB-005")
}

test_service_identity_is_required {
	plan := object.union(valid_plan, {"resource_changes": array.concat(
		array.slice(valid_plan.resource_changes, 0, 2),
		array.slice(valid_plan.resource_changes, 3, count(valid_plan.resource_changes)),
	)})
	violations := deny with input as plan
	control_present(violations, "APIHUB-006")
}

test_required_roles_are_enforced {
	plan := object.union(valid_plan, {"resource_changes": array.concat(
		array.slice(valid_plan.resource_changes, 0, 4),
		array.slice(valid_plan.resource_changes, 5, count(valid_plan.resource_changes)),
	)})
	violations := deny with input as plan
	control_present(violations, "APIHUB-007")
}

test_invalid_cmek_is_rejected {
	instance := managed_resource("google_apihub_api_hub_instance.this", "google_apihub_api_hub_instance", {
		"project": "example-project",
		"location": "us-central1",
		"api_hub_instance_id": "api-hub",
		"config": [{
			"encryption_type": "CMEK",
			"cmek_key_name": "invalid-key",
			"disable_search": true,
		}],
	})
	violations := deny with input as replace_resource(valid_plan, 5, instance)
	control_present(violations, "APIHUB-008")
}

test_semantic_search_requires_vertex_location {
	instance := managed_resource("google_apihub_api_hub_instance.this", "google_apihub_api_hub_instance", {
		"project": "example-project",
		"location": "us-central1",
		"api_hub_instance_id": "api-hub",
		"config": [{
			"encryption_type": "GMEK",
			"disable_search": false,
			"vertex_location": null,
		}],
	})
	violations := deny with input as replace_resource(valid_plan, 5, instance)
	control_present(violations, "APIHUB-009")
}

test_instance_id_format_is_enforced {
	instance := managed_resource("google_apihub_api_hub_instance.this", "google_apihub_api_hub_instance", {
		"project": "example-project",
		"location": "us-central1",
		"api_hub_instance_id": "INVALID_ID",
		"config": [{"encryption_type": "GMEK", "disable_search": true}],
	})
	violations := deny with input as replace_resource(valid_plan, 5, instance)
	control_present(violations, "APIHUB-010")
}
