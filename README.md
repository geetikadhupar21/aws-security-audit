\# AWS Security Audit Tool



A Python (boto3) script that scans an AWS account for common security misconfigurations and writes a JSON report.



\## Checks

\- IAM users without MFA

\- IAM access keys older than 90 days

\- S3 buckets that are public via ACL

\- Security groups with SSH (22) or RDP (3389) open to 0.0.0.0/0, across all regions



\## Setup

1\. Create an IAM user with the AWS managed `SecurityAudit` policy (read-only).

2\. `pip install boto3 awscli`

3\. `aws configure` with that user's access key.

4\. `python audit.py`



\## Result

First run on my practice account found 5 issues (4 security groups with SSH open to the world, 1 IAM user without MFA). After tightening the security groups, 1 issue remained.



\## Limitations

\- S3 check looks at bucket ACLs only, not bucket policies.

\- Read-only: it reports issues, it does not fix them.

