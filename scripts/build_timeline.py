import argparse
import json
import csv
from datetime import datetime
import os

def build(infile, timeline_csv, timeline_md, iocs_md):
    with open(infile, 'r') as f:
        events = json.load(f)

    # Sort by time
    events.sort(key=lambda x: x['eventTime'])

    # 1. CSV
    headers = ['time', 'eventSource', 'eventName', 'region', 'ip', 'userAgent', 'errorCode', 'identityArn']
    
    with open(timeline_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        for e in events:
            writer.writerow([
                e.get('eventTime'),
                e.get('eventSource'),
                e.get('eventName'),
                e.get('awsRegion'),
                e.get('sourceIPAddress'),
                e.get('userAgent'),
                e.get('errorCode', 'Success'),
                e.get('userIdentityArn')
            ])
    print(f"[*] Timeline CSV written to {timeline_csv}")

    # 2. Markdown
    with open(timeline_md, 'w') as md:
        md.write("# Incident Timeline\n\n")
        md.write("| Time (UTC) | Action | Source | IP | Status |\n")
        md.write("|---|---|---|---|---|\n")
        for e in events:
            status = "✅ Allowed" if not e.get('errorCode') else f"❌ {e.get('errorCode')}"
            action = f"**{e.get('eventName')}**"
            md.write(f"| {e.get('eventTime')} | {action} | {e.get('eventSource')} | {e.get('sourceIPAddress')} | {status} |\n")
    print(f"[*] Timeline MD written to {timeline_md}")

    # 3. IOCs
    ips = set()
    user_agents = set()
    principals = set()
    regions = set()
    
    for e in events:
        if e.get('sourceIPAddress'): ips.add(e.get('sourceIPAddress'))
        if e.get('userAgent'): user_agents.add(e.get('userAgent'))
        if e.get('userIdentityArn'): principals.add(e.get('userIdentityArn'))
        if e.get('awsRegion'): regions.add(e.get('awsRegion'))

    with open(iocs_md, 'w') as ioc:
        ioc.write("# Indicators of Compromise (IOCs)\n\n")
        
        ioc.write("## 1. Principals Involved\n")
        for p in principals:
            ioc.write(f"- `{p}`\n")
            
        ioc.write("\n## 2. IP Addresses\n")
        for i in ips:
            ioc.write(f"- `{i}`\n")

        ioc.write("\n## 3. User Agents\n")
        for u in user_agents:
            ioc.write(f"- `{u}`\n")

        ioc.write("\n## 4. Regions Touched\n")
        for r in regions:
            ioc.write(f"- `{r}`\n")
            
    print(f"[*] IOCs MD written to {iocs_md}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--in', dest='infile', required=True, help='Redacted CloudTrail JSON')
    parser.add_argument('--timeline-csv', default='sample-output/timeline.csv')
    parser.add_argument('--timeline-md', default='sample-output/timeline.md')
    parser.add_argument('--iocs-md', default='sample-output/iocs.md')
    
    args = parser.parse_args()
    
    # Smart output paths based on input directory
    input_dir = os.path.dirname(args.infile)
    if input_dir and args.timeline_csv == 'sample-output/timeline.csv':
         args.timeline_csv = os.path.join(input_dir, 'timeline.csv')
    if input_dir and args.timeline_md == 'sample-output/timeline.md':
         args.timeline_md = os.path.join(input_dir, 'timeline.md')
    if input_dir and args.iocs_md == 'sample-output/iocs.md':
         args.iocs_md = os.path.join(input_dir, 'iocs.md')

    build(args.infile, args.timeline_csv, args.timeline_md, args.iocs_md)
