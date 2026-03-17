"""Detect data exfiltration indicators in CloudTrail events.

Queries CloudTrail LookupEvents for API calls commonly associated with
data exfiltration from AWS, including bulk S3 downloads, bucket
reconnaissance, and replication configuration changes.

MITRE ATT&CK Techniques:
    T1530 - Data from Cloud Storage Object
    T1537 - Transfer Data to Cloud Account
    T1119 - Automated Collection

Note: Pre-signed URL generation (s3:GetObject via pre-signed URL) is
performed client-side and is NOT always recorded in CloudTrail. Detection
of pre-signed URL abuse typically requires S3 server access logging or
VPC flow logs as supplementary data sources.
"""

import boto3
import argparse
import json
import datetime
import os
from collections import defaultdict
from botocore.exceptions import ClientError

DETECTION_RULES = [
    {
        'rule_id': 'EXFIL-001',
        'description': 'Bulk S3 GetObject activity exceeds threshold',
        'severity': 'HIGH',
        'mitre': 'T1530 - Data from Cloud Storage Object',
    },
    {
        'rule_id': 'EXFIL-002',
        'description': 'S3 bucket enumeration pattern (ListBuckets + GetBucketAcl)',
        'severity': 'MEDIUM',
        'mitre': 'T1530 - Data from Cloud Storage Object',
    },
    {
        'rule_id': 'EXFIL-003',
        'description': 'S3 replication configuration change detected',
        'severity': 'HIGH',
        'mitre': 'T1537 - Transfer Data to Cloud Account',
    },
]


def default_serializer(obj):
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    return str(obj)


def detect(profile, region, start_time, end_time, threshold, out_file):
    session = boto3.Session(profile_name=profile, region_name=region)
    ct = session.client('cloudtrail')

    print(f"[*] Scanning CloudTrail for exfiltration indicators from {start_time} to {end_time}...")
    print(f"[*] Bulk download threshold: {threshold} GetObject events per principal")

    try:
        s_dt = datetime.datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        e_dt = datetime.datetime.fromisoformat(end_time.replace('Z', '+00:00'))
    except ValueError:
        print("Error: Times must be ISO8601 format (e.g. 2023-10-27T10:00:00Z)")
        return

    # Track events for threshold-based detection
    get_object_events = defaultdict(list)  # principal -> list of events
    recon_principals = defaultdict(set)     # principal -> set of recon event names
    recon_events = []
    replication_events = []
    total_events = 0

    target_events = {'GetObject', 'ListBuckets', 'GetBucketAcl', 'GetBucketPolicy',
                     'PutReplicationConfiguration', 'PutBucketReplication'}

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

                if event_name not in target_events:
                    continue

                detail = {}
                if 'CloudTrailEvent' in event:
                    detail = json.loads(event['CloudTrailEvent'])

                principal = detail.get('userIdentity', {}).get('arn', 'unknown')

                normalized = {
                    'eventTime': event.get('EventTime').isoformat(),
                    'eventName': event_name,
                    'eventSource': event.get('EventSource'),
                    'awsRegion': detail.get('awsRegion', region),
                    'sourceIPAddress': detail.get('sourceIPAddress'),
                    'userAgent': detail.get('userAgent'),
                    'errorCode': detail.get('errorCode'),
                    'errorMessage': detail.get('errorMessage'),
                    'userIdentityArn': principal,
                    'recipientAccountId': detail.get('recipientAccountId'),
                    'requestParameters': detail.get('requestParameters'),
                }

                if event_name == 'GetObject':
                    get_object_events[principal].append(normalized)

                elif event_name in ('ListBuckets', 'GetBucketAcl', 'GetBucketPolicy'):
                    recon_principals[principal].add(event_name)
                    recon_events.append(normalized)

                elif event_name in ('PutReplicationConfiguration', 'PutBucketReplication'):
                    replication_events.append(normalized)

    except ClientError as e:
        print(f"[!] AWS API error: {e}")
        return

    findings = []

    # EXFIL-001: Bulk S3 GetObject
    for principal, events in get_object_events.items():
        if len(events) >= threshold:
            for ev in events:
                ev['detection'] = {
                    'ruleId': 'EXFIL-001',
                    'description': DETECTION_RULES[0]['description'],
                    'severity': DETECTION_RULES[0]['severity'],
                    'mitre': DETECTION_RULES[0]['mitre'],
                    'detail': f'{len(events)} GetObject events by {principal} (threshold: {threshold})',
                }
                findings.append(ev)

    # EXFIL-002: Bucket enumeration pattern (ListBuckets + GetBucketAcl)
    for principal, event_names in recon_principals.items():
        if 'ListBuckets' in event_names and ('GetBucketAcl' in event_names or 'GetBucketPolicy' in event_names):
            for ev in recon_events:
                if ev['userIdentityArn'] == principal:
                    ev['detection'] = {
                        'ruleId': 'EXFIL-002',
                        'description': DETECTION_RULES[1]['description'],
                        'severity': DETECTION_RULES[1]['severity'],
                        'mitre': DETECTION_RULES[1]['mitre'],
                        'detail': f'Recon pattern by {principal}: {sorted(event_names)}',
                    }
                    findings.append(ev)

    # EXFIL-003: Replication configuration changes
    for ev in replication_events:
        ev['detection'] = {
            'ruleId': 'EXFIL-003',
            'description': DETECTION_RULES[2]['description'],
            'severity': DETECTION_RULES[2]['severity'],
            'mitre': DETECTION_RULES[2]['mitre'],
        }
        findings.append(ev)

    # Write output
    out_dir = os.path.dirname(out_file)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir)

    with open(out_file, 'w') as f:
        json.dump(findings, f, indent=2, default=default_serializer)

    print(f"[*] Scanned {total_events} total events.")
    print(f"[*] Found {len(findings)} exfiltration indicators.")

    # Summary
    rule_counts = defaultdict(int)
    for finding in findings:
        rule_counts[finding['detection']['ruleId']] += 1

    if rule_counts:
        print("[*] Breakdown:")
        for rid, count in sorted(rule_counts.items()):
            desc = next(r['description'] for r in DETECTION_RULES if r['rule_id'] == rid)
            print(f"    {rid}: {count} - {desc}")

    print(f"[*] NOTE: Pre-signed URL generation is client-side and may not appear in CloudTrail.")
    print(f"[*]       Review S3 server access logs for complete download visibility.")
    print(f"[*] Results saved to {out_file}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Detect data exfiltration indicators in CloudTrail')
    parser.add_argument('--profile', required=True, help='AWS profile name')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--start', required=True, help='ISO8601 Start Time')
    parser.add_argument('--end', required=True, help='ISO8601 End Time')
    parser.add_argument('--threshold', type=int, default=50,
                        help='Number of GetObject events that indicates bulk download (default: 50)')
    parser.add_argument('--out', default='detect_exfil_findings.json',
                        help='Output JSON file path')

    args = parser.parse_args()
    detect(args.profile, args.region, args.start, args.end, args.threshold, args.out)
