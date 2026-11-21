package compliance.soc2.s3_kms_test

import rego.v1
import data.compliance.soc2.s3_kms

test_allow_s3_with_known_cmk if {
	mock_plan := {"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"name": "uploads",
			"mode": "managed",
			"change": {"actions": ["no-op"]},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads_kms",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads_kms",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {"rule": [{"apply_server_side_encryption_by_default": [{
					"sse_algorithm": "aws:kms",
					"kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
				}]}]},
			},
		},
	]}

	count(s3_kms.deny) == 0 with input as mock_plan
}

test_allow_s3_with_computed_cmk if {
	mock_plan := {"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"name": "uploads",
			"mode": "managed",
			"change": {"actions": ["create"]},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads_kms",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads_kms",
			"mode": "managed",
			"change": {
				"actions": ["create"],
				"after": {"rule": [{"apply_server_side_encryption_by_default": [{
					"sse_algorithm": "aws:kms",
					"kms_master_key_id": null,
				}]}]},
				"after_unknown": {"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": true}]}]},
			},
		},
	]}

	count(s3_kms.deny) == 0 with input as mock_plan
}

test_deny_s3_without_kms if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"name": "uploads",
		"mode": "managed",
		"change": {"actions": ["create"]},
	}]}

	count(s3_kms.deny) == 1 with input as mock_plan
}

