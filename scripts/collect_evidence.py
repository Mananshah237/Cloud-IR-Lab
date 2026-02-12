import boto3
import argparse
import json
import datetime
from botocore.exceptions import ClientError
import os
import subprocess

def default_serializer(obj):
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    return str(obj)

def collect(profile, region, start_time, end_time, filter_username, out_file, case_dir):
    # Case Directory Logic
    if case_dir:
        if not os.path.exists(case_dir):
            os.makedirs(case_dir)
            print(f"[*] Created case directory: {case_dir}")
        
        # If out_file wasn't explicitly changed from default, put it in case_dir
        if out_file == 'sample-output/redacted_cloudtrail.json':
            out_file = os.path.join(case_dir, 'cloudtrail.json')
    
    session = boto3.Session(profile_name=profile, region_name=region)
    ct = session.client('cloudtrail')

    print(f"[*] Collecting CloudTrail events from {start_time} to {end_time}...")
    
    events = []
    
    # We look for events related to our suspect user
    lookup_attributes = []
    if filter_username:
        lookup_attributes.append({'AttributeKey': 'Username', 'AttributeValue': filter_username})

    paginator = ct.get_paginator('lookup_events')
    
    # Convert string times to datetime objects if needed, boto3 handles strings usually but timezone awareness is tricky
    # We will pass them as strings if they are ISO8601, boto3 expects datetime objects usually
    
    try:
        s_dt = datetime.datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        e_dt = datetime.datetime.fromisoformat(end_time.replace('Z', '+00:00'))
    except ValueError:
        print("Error: Times must be ISO8601 format (e.g. 2023-10-27T10:00:00Z)")
        return

    page_iterator = paginator.paginate(
        LookupAttributes=lookup_attributes,
        StartTime=s_dt,
        EndTime=e_dt
    )

    relevant_sources = ['iam.amazonaws.com', 's3.amazonaws.com', 'ec2.amazonaws.com', 'sts.amazonaws.com']

    for page in page_iterator:
        for event in page['Events']:
            # Basic filtering for relevance if not using specific lookup attributes or to filter further
            # CloudTrail LookupEvents is limited in filter complexity, so we filter heavily in client
            
            # Keep if error is AccessDenied OR source is relevant
            is_relevant = False
            
            if event.get('EventSource') in relevant_sources:
                is_relevant = True
            
            # Check for error codes in raw CloudTrailEvent (which is a JSON string)
            if 'CloudTrailEvent' in event:
                detail = json.loads(event['CloudTrailEvent'])
                if detail.get('errorCode') in ['AccessDenied', 'Client.UnauthorizedOperation']:
                     is_relevant = True
            
            if is_relevant:
                # Normalize
                normalized = {
                    'eventTime': event.get('EventTime').isoformat(),
                    'eventName': event.get('EventName'),
                    'eventSource': event.get('EventSource'),
                    'awsRegion': detail.get('awsRegion', region),
                    'sourceIPAddress': detail.get('sourceIPAddress'),
                    'userAgent': detail.get('userAgent'),
                    'errorCode': detail.get('errorCode'),
                    'errorMessage': detail.get('errorMessage'),
                    'resources': event.get('Resources', []),
                    'recipientAccountId': detail.get('recipientAccountId'),
                    'userIdentityArn': detail.get('userIdentity', {}).get('arn')
                }
                events.append(normalized)

    print(f"[*] Found {len(events)} events.")
    
    # Save raw (unredacted) to temp
    temp_file = out_file + ".temp"
    with open(temp_file, 'w') as f:
        json.dump(events, f, indent=2, default=default_serializer)
    
    # Redact
    print(f"[*] Running redaction...")
    # Assume redact.py is in the same directory or accessible
    script_dir = os.path.dirname(os.path.abspath(__file__))
    redact_script = os.path.join(script_dir, 'redact.py')
    
    subprocess.run([sys.executable, redact_script, '--in', temp_file, '--out', out_file], check=True)
    
    os.remove(temp_file)
    print(f"[*] Evidence saved to {out_file}")

import sys

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Collect CloudTrail evidence')
    parser.add_argument('--profile', required=True)
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--start', required=True, help='ISO8601 Start Time')
    parser.add_argument('--end', required=True, help='ISO8601 End Time')
    parser.add_argument('--filter-username', help='Filter by username')
    parser.add_argument('--case-dir', help='Directory to store case evidence (e.g. cases/CASE-2023...)')
    parser.add_argument('--out', default='sample-output/redacted_cloudtrail.json', help='Specific output file path (overrides case-dir default for log file)')

    args = parser.parse_args()
    collect(args.profile, args.region, args.start, args.end, args.filter_username, args.out, args.case_dir)
