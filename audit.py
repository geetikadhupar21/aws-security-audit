import boto3, json, datetime as dt

now = dt.datetime.now(dt.timezone.utc)
findings = []

def flag(check, resource, detail):
    findings.append({"check": check, "resource": resource, "detail": detail})
    print(f"[!] {check}: {resource} - {detail}")

iam = boto3.client("iam")
s3 = boto3.client("s3")

print("Scanning IAM users...")
for page in iam.get_paginator("list_users").paginate():
    for u in page["Users"]:
        name = u["UserName"]
        if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
            flag("MFA missing", name, "no MFA device")
        for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
            age = (now - k["CreateDate"]).days
            if age > 90:
                flag("Old access key", name, f"key ...{k['AccessKeyId'][-4:]} is {age} days old")

print("Scanning S3 buckets...")
for b in s3.list_buckets()["Buckets"]:
    grants = s3.get_bucket_acl(Bucket=b["Name"])["Grants"]
    if any("AllUsers" in str(g["Grantee"]) for g in grants):
        flag("Public S3 bucket", b["Name"], "ACL allows AllUsers")

print("Scanning security groups in all regions...")
regions = boto3.client("ec2", region_name="ap-south-1").describe_regions()["Regions"]
for r in regions:
    ec2 = boto3.client("ec2", region_name=r["RegionName"])
    for g in ec2.describe_security_groups()["SecurityGroups"]:
        for p in g["IpPermissions"]:
            open_world = any(x["CidrIp"] == "0.0.0.0/0" for x in p["IpRanges"])
            if open_world and p.get("FromPort") in (22, 3389, None):
                flag("Open security group", f"{g['GroupId']} ({r['RegionName']})",
                     f"port {p.get('FromPort', 'all')} open to 0.0.0.0/0")

with open("report.json", "w") as f:
    json.dump(findings, f, indent=2, default=str)

print(f"\nDone. {len(findings)} issue(s) found. Report saved to report.json")