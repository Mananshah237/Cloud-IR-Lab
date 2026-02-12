import argparse
import json
import csv
import re
import os

def redact(text):
    if not text: return text
    # Mask Account IDs (12 digits)
    text = re.sub(r'\b\d{12}\b', '000000000000', text)
    
    # Mask IPs (IPv4) - simple mask of last octet
    text = re.sub(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b', r'\1.xxx', text)
    
    # Mask Access Keys (AKIA...) - Keep first 4, last 4
    # Regex for Access Key ID: AKIA[0-9A-Z]{16}
    def mask_key(match):
        k = match.group(0)
        return k[:4] + "X" * 12 + k[-4:]
    text = re.sub(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b', mask_key, text)

    return text

def redact_json_structure(data):
    if isinstance(data, dict):
        return {k: redact_json_structure(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [redact_json_structure(i) for i in data]
    elif isinstance(data, str):
        return redact(data)
    else:
        return data

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--in', dest='infile', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()

    with open(args.infile, 'r') as f:
        data = json.load(f)

    redacted_data = redact_json_structure(data)

    with open(args.out, 'w') as f:
        json.dump(redacted_data, f, indent=2)
    
    print(f"Redacted file written to {args.out}")
