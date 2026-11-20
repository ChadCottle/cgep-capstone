# SOC 2 Type II Control-to-Gap Mapping

This document maps the eight intentional compliance gaps in the `cgep-app-starter` Patient Intake API to the **SOC 2 Trust Services Criteria (TSC)**, serving as the control traceability matrix for Acme Health's GRC Engineering Capstone.

## Primary Framework Rationale

**SOC 2 Type II (Trust Services Criteria)** is selected as the primary compliance framework to satisfy enterprise healthcare customer due diligence requirements and demonstrate that technical controls operate continuously over time—directly aligning with an automated CI/CD evidence pipeline that produces signed, immutable artifacts on every merge to `main`.

SOC2 Type II has the additional benefit as being a sales enabler and "commercial trust signal.” As we are a young and eager-to-grow company, this seems like the right framework as it aligns with the company's expressed plan to generate revenue, acquire new customers and ensures that security is not an afterthought or ad hoc process. The goal is to bring rigor to engineering, security, and compliance while providing an opportunity to positively impact ACME's sales/revenue generating capabilities.  


## Control-to-Gap Matrix

| Gap ID | Starter Vulnerability | Target Terraform Resource | SOC 2 Control | Criteria Description |
| :--- | :--- | :--- | :--- | :--- |
| **GAP-01** | S3 uploads bucket uses default SSE-S3 instead of customer-managed KMS (CMK) encryption. | `aws_s3_bucket.uploads` | **CC6.1** | Logical access controls — restrict access to information assets and cryptographic key custody. |
| **GAP-02** | DynamoDB submissions table uses the AWS-owned default encryption key instead of a customer CMK. | `aws_dynamodb_table.intake` | **CC6.1** | Logical access controls — restrict access to information assets and cryptographic key custody. |
| **GAP-03** | S3 uploads bucket lacks a bucket policy denying non-TLS (`aws:SecureTransport`) requests. | `aws_s3_bucket.uploads` | **CC6.7** | Transmission security — protect data in transit against unauthorized interception. |
| **GAP-04** | S3 uploads bucket has no versioning enabled, leaving patient file overwrites unrecoverable. | `aws_s3_bucket.uploads` | **A1.2** | System availability — environmental protections, data backup, and recovery capabilities. |
| **GAP-05** | Lambda intake function runs in the default Lambda environment instead of the starter-provisioned VPC. | `aws_lambda_function.intake` | **CC6.6** | Boundary protection — protect against unauthorized access to internal system components. |
| **GAP-06** | Lambda intake function lacks reserved concurrency, a Dead Letter Queue (DLQ), and X-Ray tracing. | `aws_lambda_function.intake` | **CC7.2** | System monitoring — detection of anomalies, failures, and security events. |
| **GAP-07** | Lambda IAM execution policy grants wildcard `dynamodb:*` and `s3:*` permissions on workload resources. | `aws_iam_role_policy.lambda_inline` | **CC6.3** | Authorization — enforce least privilege and restrict access to authorized actions. |
| **GAP-08** | API Gateway stage lacks access logging, request throttling, and Web Application Firewall (WAF) protection. | `aws_apigatewayv2_stage.default` | **CC7.2** | System monitoring — detection of anomalies, abuse, and security events. |

## Implementation Notes

* **Rego Policy Requirement:** At least five of the gaps above must be enforced via Rego policies in `policies/`, citing the corresponding SOC 2 criterion (e.g., `CC6.1`, `CC6.3`, `CC6.7`, `A1.2`, `CC6.6`, `CC7.2`) in both the `# METADATA` block and `deny` messages.
* **OSCAL Catalog Strategy:** Because the AICPA does not publish an official NIST OSCAL catalog for SOC 2 Trust Services Criteria, Layer 4 (`oscal/components/`) will either reference a community-maintained SOC 2 TSC OSCAL catalog URI or map these TSC criteria to **NIST SP 800-53 Rev. 5** controls while documenting the SOC 2 IDs in the component `props`.
