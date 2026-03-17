"""Detect privilege escalation indicators in CloudTrail events.

Queries CloudTrail LookupEvents for API calls commonly associated with
privilege escalation in AWS, flags matches with severity and MITRE ATT&CK
technique references.

MITRE ATT&CK Techniques:
    T1078.004 - Valid Accounts: Cloud Accounts
    T1098     - Account Manipulation
    T1098.001 - Account Manipulation: Additional Cloud Credentials
    T1484.002 - Domain Policy Modification: Domain Trust Modification
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
        'rule_id': 'PRIVESC-001',
        'description': 'STS AssumeRole call detected',
        'severity': 'MEDIUM',
        'mitre': 'T1078.004 - Valid Accounts: Cloud Accounts',
    },
    {
        'event_names': ['CreatePolicyVersion', 'SetDefaultPolicyVersion'],
        'rule_id': 'PRIVESC-002',
        'description': 'IAM policy version manipulation detected',
        'severity': 'HIGH',
        'mitre': 'T1098 - Account Manipulation',
    },
    {
        'event_names': ['PassRole'],
        'rule_id': 'PRIVESC-003',
        'description': 'IAM PassRole call detected',
        'severity': 'HIGH',
        'mitre': 'T1098 - Account Manipulation',
    },
    {
        'event_names': ['CreateLoginProfile', 'UpdateLoginProfile'],
        'rule_id': 'PRIVESC-004',
        'description': 'IAM login profile creation or update detected',
        'severity': 'HIGH',
        'mitre': 'T1098.001 - Account Manipulation: Additional Cloud Credentials',
    },
    {
        'event_names': ['AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
                        'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy'],
        'rule_id': 'PRIVESC-005',
        'description': 'IAM policy attachment detected',
        'severity': 'HIGH',
        'mitre': 'T1484.002 - Domain Policy Modification',
    },
]

# Build a fast lookup: eventName -> rule
_EVENT_RULE_MAP = {}
for rule in DETECTION_RULES:
    for name in rule['event_names']:
        _EVENT_RULE_MAP[name] = rule


def default_serializer(obj):
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    return str(obj)


def detect(profile, region, start_time, end_time, out_file):
    session = boto3.Session(profile_name=profile, region_name=region)
    ct = session.client('cloudtrail')

    print(f"[*] Scanning CloudTrail for privilege escalation indicators from {start_time} to {end_time}...")

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

                rule = _EVENT_RULE_MAP[event_name]
                detail = {}
                if 'CloudTrailEvent' in event:
                    detail = json.loads(event['CloudTrailEvent'])

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
    print(f"[*] Found {len(findings)} privilege escalation indicators.")

    # Summary by rule
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
        description='Detect privilege escalation indicators in CloudTrail')
    parser.add_argument('--profile', required=True, help='AWS profile name')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--start', required=True, help='ISO8601 Start Time')
    parser.add_argument('--end', required=True, help='ISO8601 End Time')
    parser.add_argument('--out', default='detect_privesc_findings.json',
                        help='Output JSON file path')

    args = parser.parse_args()
    detect(args.profile, args.region, args.start, args.end, args.out)
