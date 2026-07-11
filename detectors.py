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


if __name__ == "__main__":
    results = detect_public_s3_buckets()
    print(f"Found {len(results)} public S3 bucket(s):\n")
    for finding in results:
        print(finding)