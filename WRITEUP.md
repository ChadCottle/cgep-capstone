# Acme Health: GRC Engineering Capstone Write-up

## Primary framework
**SOC 2 Type II** (Trust Services Criteria) is selected as the primary compliance framework to satisfy enterprise healthcare customer due diligence requirements and demonstrate that technical controls operate continuously over time—directly aligning with an automated CI/CD evidence pipeline that produces signed, immutable artifacts on every merge to main.

**SOC2 Type II** has the additional benefit of being a sales enabler and "commercial trust signal.” As we are a young and eager-to-grow company, this seems like the right framework as it aligns with the company's expressed plan to generate revenue, acquire new customers and ensures that security is not an afterthought or ad hoc process. The goal is to bring rigor to engineering, security, and compliance while providing an opportunity to positively impact ACME's sales/revenue generating capabilities.

## Control coverage
[For each gap from GAPS.md: which control it maps to, and whether you closed
it in Terraform, enforced it in policy, or both. A table works well here.]

## Design decisions
[Walk each decision from the brief: region, Object Lock mode, apply-on-merge
vs manual gate, single vs separate account, Terraform-vs-policy split.
For each, state what you chose and the trade-off you accepted.]

## How the pipeline produces evidence
[Trace one run end to end: PR opened → gate → apply → sign → vault.
Name the run ID an assessor can verify.]

## Trade-offs and what I'd do with another sprint
[Be specific and honest. This section earns more than a padded "everything works."]

## What I didn't get to
[Name it plainly. This costs nothing and signals judgment.]
