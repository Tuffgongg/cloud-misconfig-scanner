# Cloud Misconfiguration Scanner with Policy Mapping

## Overview
A cloud security tool that scans an AWS account for common misconfigurations, maps each finding to relevant NIST CSF and CIS AWS Benchmark controls, and generates plain-English remediation reports using an LLM. Built to practice the technical and risk-translation skills used in cloud security and security consulting roles.

## Architecture

## Setup
1. Create a Python virtual environment: `python -m venv venv`
2. Activate it and install dependencies: `pip install boto3`
3. Configure AWS credentials for a least-privilege IAM user (see `/policies` for the exact custom policy used — deliberately scoped to read-only actions, not the AWS-managed ReadOnlyAccess policy)
4. Run `python detectors.py`

## Usage

## Findings Detected
- **Public S3 buckets** — checks Block Public Access configuration and bucket policy for public access grants
- **Open security groups** — checks inbound rules for unrestricted access (0.0.0.0/0) on sensitive ports (SSH, RDP, and common database ports), rather than flagging all open ports indiscriminately
- **IAM wildcard policies** — checks customer-managed policies and role inline policies for statements granting `Action:*` and/or `Resource:*`, including partial wildcards (e.g. `iam:*`) and risky `NotAction` usage. Maps to CIS AWS Foundations Benchmark 1.22 and NIST CSF PR.AC-4.
- **Unencrypted EBS volumes** — checks every volume in the current region for missing encryption at rest, distinguishing volumes actively attached to an instance from unattached ones. Maps to CIS AWS Foundations Benchmark 2.2.1 and NIST CSF PR.DS-1.

## Design Decisions
- **Custom least-privilege IAM policy instead of AWS-managed ReadOnlyAccess** — scoped to only the specific read/describe/list actions each detector needs, minimizing blast radius if credentials were ever compromised. This policy is expanded incrementally as new detectors are added (e.g. `iam:ListEntitiesForPolicy`, `iam:ListRoles`, `iam:ListRolePolicies`, and `iam:GetRolePolicy` were added specifically to support the IAM wildcard detector) rather than granted broadly up front.
- **Explicit error-code handling rather than blanket exception catching** — the S3 detector distinguishes a genuinely missing Block Public Access configuration from other failures (e.g., an IAM permissions gap), so a scan failure is reported as "unverified" rather than silently mislabeled as a security finding.
- **Severity implied through finding language, not a separate field** — e.g. the EBS detector explicitly notes whether an unencrypted volume is attached to a live instance vs. unattached, since an in-use unencrypted volume is a more urgent finding than an orphaned one, even though both are flagged.

## Testing
Findings are validated against a deliberately misconfigured sandbox environment, not assumed to work from code review alone:
- An IAM policy granting `Action:*`/`Resource:*`, attached to a test role
- An unencrypted, unattached EBS volume

Both were confirmed live in AWS and independently verified to be caught by their respective detector before being considered complete.