import boto3
import argparse
import time
import sys
from botocore.exceptions import ClientError

def simulate(profile, region, alt_region, burst, sleep_time, test_bucket, test_key):
    print(f"[*] Starting simulation at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC")
    
    session = boto3.Session(profile_name=profile, region_name=region)
    sts = session.client('sts')
    iam = session.client('iam')
    s3 = session.client('s3')
    ec2 = session.client('ec2')

    try:
        identity = sts.get_caller_identity()
        print(f"[*] Identity: {identity['Arn']}")
    except Exception as e:
        print(f"[!] Failed to get identity: {e}")
        return

    actions = [
        ("iam:ListUsers", iam.list_users, {}),
        ("iam:ListRoles", iam.list_roles, {}),
        ("s3:ListAllMyBuckets", s3.list_buckets, {}),
        ("ec2:DescribeInstances", ec2.describe_instances, {}),
        ("ec2:DescribeVpcs", ec2.describe_vpcs, {}),
        ("ec2:DescribeSecurityGroups", ec2.describe_security_groups, {}),
    ]

    print(f"[*] Performing reconnaissance (Region: {region})...")
    for name, func, kwargs in actions:
        try:
            func(**kwargs)
            print(f"    [+] {name}: Success")
        except ClientError as e:
            print(f"    [-] {name}: Failed ({e.response['Error']['Code']})")
        time.sleep(sleep_time)

    # Denied Actions
    print("[*] Attempting unauthorized actions (expecting AccessDenied)...")
    
    # 1. GetObject on canary (Explicit Deny)
    if test_bucket:
        try:
            s3.get_object(Bucket=test_bucket, Key=test_key)
            print(f"    [!] s3:GetObject: UNEXPECTED SUCCESS (Should be denied)")
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print(f"    [+] s3:GetObject: AccessDenied (Expected)")
            else:
                print(f"    [-] s3:GetObject: Failed with {e.response['Error']['Code']}")
    
    # 2. CreateUser (Explicit Deny)
    try:
        iam.create_user(UserName='evil-backdoor-user')
        print(f"    [!] iam:CreateUser: UNEXPECTED SUCCESS (Should be denied)")
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            print(f"    [+] iam:CreateUser: AccessDenied (Expected)")
        else:
            print(f"    [-] iam:CreateUser: Failed with {e.response['Error']['Code']}")

    # Alt Region
    if alt_region:
        print(f"[*] pivoting to alternative region: {alt_region}")
        ec2_alt = session.client('ec2', region_name=alt_region)
        try:
            ec2_alt.describe_instances()
            print(f"    [+] ec2:DescribeInstances ({alt_region}): Success")
        except ClientError as e:
             print(f"    [-] ec2:DescribeInstances ({alt_region}): Failed ({e.response['Error']['Code']})")

    print(f"[*] Simulation complete at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simulate suspicious activity for Cloud IR Lab')
    parser.add_argument('--profile', required=True, help='AWS CLI profile for suspect user')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--alt-region', help='Alternative region to test')
    parser.add_argument('--burst', type=int, default=15, help='Number of actions (approx)')
    parser.add_argument('--sleep', type=float, default=0.2, help='Sleep between actions')
    parser.add_argument('--test-bucket', help='Test data bucket name')
    parser.add_argument('--test-key', default='canary.txt', help='Test object key')

    args = parser.parse_args()
    simulate(args.profile, args.region, args.alt_region, args.burst, args.sleep, args.test_bucket, args.test_key)
