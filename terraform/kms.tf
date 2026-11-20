resource "aws_kms_key" "workload_cmk" {
  description             = "Acme Health CMK for Patient Intake PHI storage"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Project   = "cgep-capstone"
    Framework = "soc2"
  }
}

resource "aws_kms_alias" "workload_cmk" {
  name          = "alias/${local.name_prefix}-workload-cmk"
  target_key_id = aws_kms_key.workload_cmk.key_id
}

