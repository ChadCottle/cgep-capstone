# METADATA
# title: SOC 2 CC6.1 — S3 uploads bucket must use SSE-KMS with a Customer Managed Key
# custom:
#   framework: soc2
#   controls:
#     - "CC6.1"
#   severity: high
#   remediation: "Configure aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = 'aws:kms' and a customer-managed kms_master_key_id."
package compliance.soc2.s3_kms

import rego.v1

# Check that an S3 server-side encryption configuration exists in the plan using aws:kms and a CMK
has_valid_kms_encryption if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	rc.mode == "managed"
	not "delete" in rc.change.actions

	some rule in rc.change.after.rule
	some default_enc in rule.apply_server_side_encryption_by_default
	default_enc.sse_algorithm == "aws:kms"
	has_cmk_reference(rc, default_enc)
}

# Case 1: KMS key ARN is already known in the plan
has_cmk_reference(_, default_enc) if {
	default_enc.kms_master_key_id != null
	default_enc.kms_master_key_id != ""
}

# Case 2: KMS key is being created in the same plan, so its ARN is computed after apply
has_cmk_reference(rc, _) if {
	some rule in rc.change.after_unknown.rule
	some default_enc in rule.apply_server_side_encryption_by_default
	default_enc.kms_master_key_id == true
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.name == "uploads"
	not "delete" in rc.change.actions
	not has_valid_kms_encryption

	msg := sprintf(
		"[SOC 2 CC6.1] GAP-01 violation: S3 bucket '%s' must be encrypted with SSE-KMS using a customer-managed KMS key (kms_master_key_id).",
		[rc.address],
	)
}

