"""Detect lateral movement indicators in CloudTrail events.

Queries CloudTrail LookupEvents for API calls commonly associated with
lateral movement across AWS accounts and compute instances.

MITRE ATT&CK Techniques:
    T1550.001 - Use Alternate Authentication Material: Application Access Token
    T1021.007 - Remote Services: Cloud Services (SSM)
    T1098.004 - Account Manipulation: SSH Authorized Keys
    T1078.004 - Valid Accounts: Cloud Accounts
"""

import boto3
import argparse
import json
import datetime
import os
from botocore.exceptions import ClientError

DETECTION_RULES = [
    {
        'event_names': ['AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity'],
        'rule_id': 'LATERAL-001',
        'description': 'Cross-account AssumeRole detected',
        'severity': 'HIGH',
        'mitre': 'T1550.001 - Use Alternate Authentication Material: Application Access Token',
    },
    {
        'event_names': ['SendCommand'],
        'rule_id': 'LATERAL-002',
        'description': 'SSM SendCommand for remote execution detected',
        'severity': 'HIGH',
        'mitre': 'T1021.007 - Remote Services: Cloud Services',
    },
    {
        'event_names': ['SendSSHPublicKey'],
        'rule_id': 'LATERAL-003',
        'description': 'EC2 Instance Connect SSH key push detected',
        'severity': 'MEDIUM',
        'mitre': 'T1098.004 - Account Manipulation: SSH Authorized Keys',
    },
]

# Build lookup
_EVENT_RULE_MAP = {}
for rule in DETECTION_RULES:
    for name in rule['event_names']:
        _EVENT_RULE_MAP[name] = rule


def default_serializer(obj):
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    return str(obj)


def _is_cross_account(detail):
    """Check if an AssumeRole event crosses account boundaries."""
    caller_account = detail.get('userIdentity', {}).get('accountId')
    req_params = detail.get('requestParameters', {})
    role_arn = req_params.get('roleArn', '')

    if not caller_account or not role_arn:
        return False

    # Extract account ID from role ARN: arn:aws:iam::ACCOUNT_ID:role/...
    arn_parts = role_arn.split(':')
    if len(arn_parts) >= 5:
        target_account = arn_parts[4]
        return target_account != caller_account

    return False


def detect(profile, region, start_time, end_time, out_file):
    session = boto3.Session(profile_name=profile, region_name=region)
    ct = session.client('cloudtrail')

    print(f"[*] Scanning CloudTrail for lateral movement indicators from {start_time} to {end_time}...")

    try:
        s_dt = datetime.datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        e_dt = datetime.datetime.fromisoformat(end_time.replace('Z', '+00:00'))
    except ValueError:
        print("Error: Times must be ISO8601 format (e.g. 2023-10-27T10:00:00Z)")
        return

    findings = []
    total_events = 0

    paginator = ct.get_paginator('lookup_events')

    try:
        page_iterator = paginator.paginate(
            StartTime=s_dt,
            EndTime=e_dt,
        )

        for page in page_iterator:
            for event in page['Events']:
                total_events += 1
                event_name = event.get('EventName')

                if event_name not in _EVENT_RULE_MAP:
                    continue

                detail = {}
                if 'CloudTrailEvent' in event:
                    detail = json.loads(event['CloudTrailEvent'])

                rule = _EVENT_RULE_MAP[event_name]

                # For AssumeRole, only flag cross-account calls
                if event_name in ('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity'):
                    if not _is_cross_account(detail):
                        continue

                finding = {
                    'eventTime': event.get('EventTime').isoformat(),
                    'eventName': event_name,
                    'eventSource': event.get('EventSource'),
                    'awsRegion': detail.get('awsRegion', region),
                    'sourceIPAddress': detail.get('sourceIPAddress'),
                    'userAgent': detail.get('userAgent'),
                    'errorCode': detail.get('errorCode'),
                    'errorMessage': detail.get('errorMessage'),
                    'userIdentityArn': detail.get('userIdentity', {}).get('arn'),
                    'recipientAccountId': detail.get('recipientAccountId'),
                    'requestParameters': detail.get('requestParameters'),
                    'detection': {
                        'ruleId': rule['rule_id'],
                        'description': rule['description'],
                        'severity': rule['severity'],
                        'mitre': rule['mitre'],
                    },
                }
                findings.append(finding)

    except ClientError as e:
        print(f"[!] AWS API error: {e}")
        return

    # Write output
    out_dir = os.path.dirname(out_file)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir)

    with open(out_file, 'w') as f:
        json.dump(findings, f, indent=2, default=default_serializer)

    print(f"[*] Scanned {total_events} total events.")
    print(f"[*] Found {len(findings)} lateral movement indicators.")

    # Summary
    rule_counts = {}
    for finding in findings:
        rid = finding['detection']['ruleId']
        rule_counts[rid] = rule_counts.get(rid, 0) + 1

    if rule_counts:
        print("[*] Breakdown:")
        for rid, count in sorted(rule_counts.items()):
            desc = next(r['description'] for r in DETECTION_RULES if r['rule_id'] == rid)
            print(f"    {rid}: {count} - {desc}")

    print(f"[*] Results saved to {out_file}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Detect lateral movement indicators in CloudTrail')
    parser.add_argument('--profile', required=True, help='AWS profile name')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--start', required=True, help='ISO8601 Start Time')
    parser.add_argument('--end', required=True, help='ISO8601 End Time')
    parser.add_argument('--out', default='detect_lateral_findings.json',
                        help='Output JSON file path')

    args = parser.parse_args()
    detect(args.profile, args.region, args.start, args.end, args.out)
