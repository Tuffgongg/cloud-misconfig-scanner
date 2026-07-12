import boto3

def detect_public_s3_buckets():
    """
    Checks every S3 bucket in the account for public accessibility.
    Returns a list of findings (dicts) for any bucket that is publicly readable.
    """
    s3 = boto3.client('s3')
    findings = []

    # Step 1: get every bucket in the account
    response = s3.list_buckets()
    buckets = response['Buckets']

    for bucket in buckets:
        bucket_name = bucket['Name']
        is_public = False
        reason = []

        # Step 2: check the Block Public Access settings for this specific bucket
        try:
            public_access_block = s3.get_public_access_block(Bucket=bucket_name)
            config = public_access_block['PublicAccessBlockConfiguration']
            # If any of these are False, public access isn't fully blocked
            if not all(config.values()):
                is_public = True
                reason.append("Block Public Access exists but is not fully enabled (one or more settings are off)")
        except s3.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchPublicAccessBlockConfiguration':
                # This specific error means no config was ever set at all
                is_public = True
                reason.append("No Block Public Access configuration exists for this bucket")
            else:
                # Some other unexpected error occurred — don't silently treat as a finding
                reason.append(f"Could not check Block Public Access settings: {error_code}")

        # Step 3: check the bucket policy for a public "Principal": "*" statement
        try:
            policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
            if policy_status['PolicyStatus']['IsPublic']:
                is_public = True
                reason.append("Bucket policy allows public access")
        except s3.exceptions.ClientError:
            # No bucket policy exists at all — not itself a finding
            pass

        if is_public:
            findings.append({
                "resource_type": "S3 Bucket",
                "resource_name": bucket_name,
                "issue": "Publicly accessible bucket",
                "details": reason
            })

    return findings

def detect_open_security_groups():
    """
    Checks every security group in the account for inbound rules that allow
    unrestricted access (0.0.0.0/0) on sensitive ports.
    Returns a list of findings for any security group with this exposure.
    """
    ec2 = boto3.client('ec2')
    findings = []

    # Ports considered sensitive enough to flag if open to the world
    SENSITIVE_PORTS = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB"
    }

    # Step 1: get every security group in the account
    response = ec2.describe_security_groups()
    security_groups = response['SecurityGroups']

    for sg in security_groups:
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', 'N/A')
        open_rules = []

        # Step 2: check each inbound rule
        for permission in sg['IpPermissions']:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')

            # Step 3: check if this rule allows traffic from anywhere (0.0.0.0/0)
            for ip_range in permission.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    # Step 4: check if the open port range includes a sensitive port
                    if from_port is not None and to_port is not None:
                        for port, service_name in SENSITIVE_PORTS.items():
                            if from_port <= port <= to_port:
                                open_rules.append({
                                    "port": port,
                                    "service": service_name,
                                    "source": "0.0.0.0/0 (anywhere)"
                                })

        if open_rules:
            findings.append({
                "resource_type": "Security Group",
                "resource_name": sg_name,
                "resource_id": sg_id,
                "issue": "Inbound rule allows unrestricted access on sensitive port(s)",
                "details": open_rules
            })

    return findings

if __name__ == "__main__":
    import json

    all_findings = []
    all_findings.extend(detect_public_s3_buckets())
    all_findings.extend(detect_open_security_groups())

    print(json.dumps(all_findings, indent=2))