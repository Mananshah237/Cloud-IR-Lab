import boto3
import argparse
import json
import os
import sys
import subprocess
from datetime import datetime

def default_serializer(obj):
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    return str(obj)

def get_findings(profile, region, out_file):
    session = boto3.Session(profile_name=profile, region_name=region)
    gd = session.client('guardduty')
    
    detectors = gd.list_detectors()
    if not detectors['DetectorIds']:
        print("No GuardDuty detectors found.")
        return

    detector_id = detectors['DetectorIds'][0]
    
    # List findings (last 1 hour to be safe for lab)
    # real impl would use start/end times more strictly if finding criteria allowed
    findings_list = gd.list_findings(DetectorId=detector_id, FindingCriteria={'Criterion': {}})
    
    if not findings_list['FindingIds']:
        print("No GuardDuty findings found.")
        # Create empty file
        with open(out_file, 'w') as f:
            json.dump([], f)
        return

    findings = gd.get_findings(DetectorId=detector_id, FindingIds=findings_list['FindingIds'])
    
    output = []
    for f in findings['Findings']:
        output.append({
            'type': f['Type'],
            'severity': f['Severity'],
            'createdAt': f['CreatedAt'],
            'updatedAt': f['UpdatedAt'],
            'resource': f['Resource'],
            'service': f['Service'],
            'title': f['Title']
        })

    # Temp write
    temp_file = out_file + ".temp"
    with open(temp_file, 'w') as f:
        json.dump(output, f, indent=2, default=default_serializer)
        
    # Redact
    print(f"[*] Redacting GuardDuty findings...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    redact_script = os.path.join(script_dir, 'redact.py')
    
    subprocess.run([sys.executable, redact_script, '--in', temp_file, '--out', out_file], check=True)
    os.remove(temp_file)
    print(f"[*] Findings saved to {out_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', required=True)
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--out', default='sample-output/redacted_guardduty.json')
    
    args = parser.parse_args()
    get_findings(args.profile, args.region, args.out)
