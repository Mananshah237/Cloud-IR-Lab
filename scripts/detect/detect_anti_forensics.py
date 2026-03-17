"""Detect anti-forensics indicators in CloudTrail events.

Queries CloudTrail LookupEvents for API calls that indicate an attacker
is attempting to tamper with or disable logging and audit infrastructure.

MITRE ATT&CK Techniques:
    T1562.008 - Impair Defenses: Disable Cloud Logs
    T1070.002 - Indicator Removal: Clear Linux or Mac System Logs
    T1565.001 - Data Manipulation: Stored Data Manipulation
"""

import boto3
import argparse
import json
import datetime
import os
from botocore.exceptions import ClientError

DETECTION_RULES = [
    {
        'event_names': ['StopLogging'],
        'rule_id': 'ANTIFOR-001',
        'description': 'CloudTrail logging stopped',
        'severity': 'CRITICAL',
        'mitre': 'T1562.008 - Impair Defenses: Disable Cloud Logs',
    },
    {
        'event_names': ['DeleteTrail'],
        'rule_id': 'ANTIFOR-002',
        'description': 'CloudTrail trail deleted',
        'severity': 'CRITICAL',
        'mitre': 'T1562.008 - Impair Defenses: Disable Cloud Logs',
    },
    {
        'event_names': ['PutEventSelectors'],
        'rule_id': 'ANTIFOR-003',
        'description': 'CloudTrail event selectors modified',
        'severity': 'HIGH',
        'mitre': 'T1562.008 - Impair Defenses: Disable Cloud Logs',
    },
    {
        'event_names': ['UpdateTrail'],
        'rule_id': 'ANTIFOR-004',
        'description': 'CloudTrail trail configuration updated',
        'severity': 'HIGH',
        'mitre': 'T1562.008 - Impair Defenses: Disable Cloud Logs',
    },
    {
        'event_names': ['DeleteObject', 'DeleteObjects'],
        'rule_id': 'ANTIFOR-005',
        'description': 'S3 DeleteObject on CloudTrail log bucket',
        'severity': 'CRITICAL',
        'mitre': 'T1070.002 - Indicator Removal: Clear Logs',
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


def detect(profile, region, start_time, end_time, trail_name, out_file):
    session = boto3.Session(profile_name=profile, region_name=region)
    ct = session.client('cloudtrail')

    print(f"[*] Scanning CloudTrail for anti-forensics indicators from {start_time} to {end_time}...")
    if trail_name:
        print(f"[*] Filtering S3 delete events against trail: {trail_name}")

    # Resolve the trail's S3 bucket so we can match DeleteObject events
    trail_bucket = None
    if trail_name:
        try:
            trail_info = ct.describe_trails(trailNameList=[trail_name])
            trails = trail_info.get('trailList', [])
            if trails:
                trail_bucket = trails[0].get('S3BucketName')
                print(f"[*] Trail S3 bucket: {trail_bucket}")
        except ClientError as e:
            print(f"[!] Could not resolve trail bucket: {e}")

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

                # For S3 DeleteObject/DeleteObjects, only flag if it targets the trail bucket
                if event_name in ('DeleteObject', 'DeleteObjects'):
                    req_params = detail.get('requestParameters', {})
                    bucket_name = req_params.get('bucketName', '')
                    if trail_bucket and bucket_name != trail_bucket:
                        continue
                    if not trail_bucket:
                        # Without a known trail bucket, flag all S3 deletes
                        # from cloudtrail event source as suspicious
                        pass

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
    print(f"[*] Found {len(findings)} anti-forensics indicators.")

    # Summary
    rule_counts = {}
    for finding in findings:
        rid = finding['detection']['ruleId']
        rule_counts[rid] = rule_counts.get(rid, 0) + 1

    if rule_counts:
        print("[*] Breakdown:")
        for rid, count in sorted(rule_counts.items()):
            desc = next(r['description'] for r in DETECTION_RULES if r['rule_id'] == rid)
            sev = next(r['severity'] for r in DETECTION_RULES if r['rule_id'] == rid)
            print(f"    {rid} [{sev}]: {count} - {desc}")

    print(f"[*] Results saved to {out_file}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Detect anti-forensics indicators in CloudTrail')
    parser.add_argument('--profile', required=True, help='AWS profile name')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--start', required=True, help='ISO8601 Start Time')
    parser.add_argument('--end', required=True, help='ISO8601 End Time')
    parser.add_argument('--trail-name', default=None,
                        help='CloudTrail trail name (used to resolve S3 bucket for delete detection)')
    parser.add_argument('--out', default='detect_anti_forensics_findings.json',
                        help='Output JSON file path')

    args = parser.parse_args()
    detect(args.profile, args.region, args.start, args.end, args.trail_name, args.out)
