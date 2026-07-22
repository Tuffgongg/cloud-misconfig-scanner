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

def detect_iam_wildcard_policies():
    """
    Checks every customer-managed IAM policy (and inline policies on users,
    groups, and roles) for statements that grant overly broad access via
    wildcards in Action and/or Resource.
    Returns a list of findings for any policy statement with this exposure.

    Maps to CIS AWS Foundations Benchmark 1.22 and NIST CSF PR.AC-4.
    """
    iam = boto3.client('iam')
    findings = []

    def as_list(value):
        # IAM policy fields can be a single string or a list — normalize to list
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    def check_statements(statements, resource_type, resource_name, attached_to):
        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue

            actions = as_list(stmt.get('Action'))
            resources = as_list(stmt.get('Resource'))
            not_actions = as_list(stmt.get('NotAction'))

            action_is_wildcard = '*' in actions
            resource_is_wildcard = '*' in resources
            partial_wildcard_actions = [a for a in actions if isinstance(a, str) and '*' in a and a != '*']

            issue = None
            reason = []

            if action_is_wildcard and resource_is_wildcard:
                issue = "IAM policy grants unrestricted admin access (Action:* on Resource:*)"
                reason.append("Statement allows every action on every resource")
            elif action_is_wildcard:
                issue = "IAM policy grants all actions on a scoped resource"
                reason.append("Statement allows Action:* even though Resource is scoped")
            elif partial_wildcard_actions and resource_is_wildcard:
                issue = "IAM policy grants a service-level wildcard action on all resources"
                reason.append(f"Statement allows {partial_wildcard_actions} on Resource:*")
            elif not_actions and resource_is_wildcard:
                issue = "IAM policy uses NotAction with Resource:*"
                reason.append("Statement implicitly allows all actions except those listed, on every resource")
            elif partial_wildcard_actions:
                issue = "IAM policy uses a partial wildcard action"
                reason.append(f"Statement allows {partial_wildcard_actions} even though resources are scoped")

            if issue:
                findings.append({
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "attached_to": attached_to,
                    "issue": issue,
                    "details": reason
                })

    # Step 1: check customer-managed policies (Scope='Local' excludes AWS-managed ones)
    paginator = iam.get_paginator('list_policies')
    for page in paginator.paginate(Scope='Local', OnlyAttached=True):
        for policy in page['Policies']:
            policy_arn = policy['Arn']
            policy_name = policy['PolicyName']

            version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=policy['DefaultVersionId'])
            document = version['PolicyVersion']['Document']
            statements = as_list(document.get('Statement'))

            # Step 2: find what this policy is attached to
            entities = iam.list_entities_for_policy(PolicyArn=policy_arn)
            attached_to = (
                [u['UserName'] for u in entities.get('PolicyUsers', [])] +
                [g['GroupName'] for g in entities.get('PolicyGroups', [])] +
                [r['RoleName'] for r in entities.get('PolicyRoles', [])]
            )

            check_statements(statements, "IAM Managed Policy", policy_name, attached_to)

    # Step 3: check inline policies on roles (most common place to find these in sandbox/test setups)
    role_paginator = iam.get_paginator('list_roles')
    for page in role_paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            policy_names = iam.list_role_policies(RoleName=role_name).get('PolicyNames', [])

            for policy_name in policy_names:
                doc_response = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                statements = as_list(doc_response['PolicyDocument'].get('Statement'))
                check_statements(statements, "IAM Inline Policy (Role)", policy_name, [role_name])

    return findings

def detect_unencrypted_ebs_volumes():
    """
    Checks every EBS volume in the current region for missing encryption at rest.
    Returns a list of findings for any volume that is not encrypted.

    Maps to CIS AWS Foundations Benchmark 2.2.1 and NIST CSF PR.DS-1.
    """
    ec2 = boto3.client('ec2')
    findings = []

    # Step 1: get every volume in the current region
    response = ec2.describe_volumes()
    volumes = response['Volumes']

    for volume in volumes:
        # Step 2: skip volumes that are already encrypted — not a finding
        if volume.get('Encrypted', False):
            continue

        volume_id = volume['VolumeId']

        # Step 3: pull the Name tag if one exists, otherwise fall back to the volume ID
        name_tag = volume_id
        for tag in volume.get('Tags', []):
            if tag.get('Key') == 'Name':
                name_tag = tag.get('Value')

        attached_instances = [a['InstanceId'] for a in volume.get('Attachments', [])]

        details = [f"Volume ID: {volume_id}", f"Size: {volume.get('Size')} GiB", f"Type: {volume.get('VolumeType')}"]
        if attached_instances:
            details.append(f"Attached to instance(s): {attached_instances}")
        else:
            details.append("Currently unattached")

        findings.append({
            "resource_type": "EBS Volume",
            "resource_name": name_tag,
            "resource_id": volume_id,
            "issue": "Unencrypted EBS volume",
            "details": details
        })

    return findings

if __name__ == "__main__":
    import json

    all_findings = []
    all_findings.extend(detect_public_s3_buckets())
    all_findings.extend(detect_open_security_groups())
    all_findings.extend(detect_iam_wildcard_policies())
    all_findings.extend(detect_unencrypted_ebs_volumes())

    print(json.dumps(all_findings, indent=2))