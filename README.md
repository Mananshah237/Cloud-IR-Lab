# Cloud Incident Response Lab (AWS) — Detection, Triage, Forensics, Containment

A safe, reproducible environment for practicing AWS Incident Response. This project provisions a "suspect" IAM user and infrastructure, simulates an attack scenario (reconnaissance + unauthorized access attempts), and provides tooling to collect and analyze the forensic artifacts.

**Target Audience:** Security Engineers, SOC Analysts, and Cloud Forensic specialists.

## Architecture

1.  **Terraform:** Provisions S3 Logging, CloudTrail, GuardDuty, and a constrained IAM User (`ir-lab-suspect`).
2.  **Simulation Script:** Generates realistic "attacker" noise (API discovery, failed data access).
3.  **Forensics Scripts:** Python tools to pull logs, normalize data, and build a timeline.

## Quickstart

### Prerequisites
- AWS CLI installed and configured.
- Terraform installed.
- Python 3.9+ installed.

### 1. Provision Infrastructure
```bash
cd infra/terraform
terraform init
terraform apply
# Note: The secret access key is NOT output by Terraform for security.
```

### 2. Configure Suspect Credentials
Create the access key manually and configure the profile. This ensures secrets are not stored in state or logs.

```bash
# Create access key
aws iam create-access-key --user-name ir-lab-suspect

# Add to your local credentials file (~/.aws/credentials)
[ir-lab-suspect]
aws_access_key_id = <YOUR_NEW_KEY_ID>
aws_secret_access_key = <YOUR_NEW_SECRET>
region = us-east-1
```
Ensure you have an `admin` profile (or use default) to run the investigation tools.

### 3. Simulate Incident
Generate the noise. This script mimics a compromised key performing discovery.
```bash
cd ../../
pip install -r requirements.txt
python scripts/simulate_activity.py --profile ir-lab-suspect --test-bucket <TEST_BUCKET_NAME>
```

### 4. Collect Evidence
**Note:** CloudTrail logs may take ~15 minutes to deliver to S3. `LookupEvents` (API) often appears faster.

```bash
# Collect logs to a specific case folder
python scripts/collect_evidence.py \
    --profile admin \
    --start <ISO_START> \
    --end <ISO_END> \
    --filter-username ir-lab-suspect \
    --case-dir cases/CASE-001
```

### 5. Build Timeline
```bash
python scripts/build_timeline.py --in cases/CASE-001/cloudtrail.json
```

### 6. Review
Open `cases/CASE-001/timeline.md` and `docs/REPORT.md` to see the analysis.

## Cleanup
Destroy all resources to stop costs.
```bash
cd infra/terraform
terraform destroy
```

## Safety & Security
- **No Malware:** This lab uses standard AWS APIs. No binaries or exploits are used.
- **Cost Controlled:** Uses S3 lifecycle policies (30 days) and standard CloudTrail. Destroy resources when done (`terraform destroy`).
- **Redaction:** The `collect_evidence.py` script automatically redacts Account IDs and full Access Keys before saving JSON to `sample-output/`.

## License
MIT
