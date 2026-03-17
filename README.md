# Cloud-IR-Lab — AWS Adversarial Simulation & Incident Response

A hands-on AWS lab that implements real attack techniques — IAM privilege escalation, S3 data exfiltration, CloudTrail tampering, and lateral movement — alongside their corresponding detections and forensic analysis. All attacks use legitimate AWS APIs (boto3), requiring no third-party exploit tools. This demonstrates that real cloud threats are API calls, not malware. The most dangerous cloud threats are misconfigurations exploited through standard interfaces.

**Target Audience:** Red Teamers, Security Engineers, SOC Analysts, and Cloud Forensic Specialists.

## Attack Scenarios

| Attack Script | MITRE Technique | MITRE ID | Description |
|---|---|---|---|
| `iam_privesc.py` | Valid Accounts: Cloud Accounts | T1078.004 | Exploits IAM misconfigurations to escalate privileges via policy version manipulation, login profile creation, and role chaining |
| `iam_privesc.py` | Account Manipulation | T1098 | Creates new policy versions and login profiles to persist elevated access |
| `iam_privesc.py` | Abuse Elevation Control Mechanism | T1548 | Chains PassRole + CreateFunction to gain permissions of a more privileged role |
| `s3_exfil.py` | Data from Cloud Storage | T1530 | Bulk-downloads objects from S3 buckets, simulating data theft |
| `s3_exfil.py` | Transfer Data to Cloud Account | T1537 | Configures cross-account replication to silently exfiltrate data |
| `lateral_movement.py` | Use Alternate Authentication Material | T1550 | Assumes roles in other AWS accounts using stolen or chained credentials |
| `lateral_movement.py` | Remote Services | T1021 | Executes commands on EC2 instances via SSM and injects SSH keys |
| `anti_forensics.py` | Impair Defenses: Disable Cloud Logs | T1562.008 | Stops CloudTrail logging and deletes trails to blind defenders |
| `anti_forensics.py` | Indicator Removal | T1070 | Modifies event selectors, updates trail configurations, and deletes S3 log objects |

## Architecture

The lab follows a four-stage pipeline:

1. **Terraform** provisions the attack surface: an IAM user (`ir-lab-suspect`) with intentionally misconfigured permissions, S3 buckets with logging enabled, CloudTrail trails, and GuardDuty detectors.
2. **Attack scripts** (`scripts/attacks/`) exploit the misconfigurations using boto3, generating realistic adversarial telemetry against live AWS infrastructure.
3. **Detection scripts** (`scripts/detect/`) query CloudTrail events via `LookupEvents` and S3 log analysis to identify indicators of compromise from each attack category.
4. **Forensic tools** (`collect_evidence.py`, `build_timeline.py`) aggregate logs, build chronological timelines, extract IOCs, and produce incident reports.

```
Terraform (infra/)          Attack Scripts (scripts/attacks/)
       |                              |
       v                              v
  AWS Resources  <--- boto3 --->  CloudTrail Events
       |                              |
       v                              v
  Detection Scripts (scripts/detect/)
       |
       v
  Forensic Analysis (collect_evidence.py, build_timeline.py)
       |
       v
  Incident Report (cases/CASE-XXX/, docs/REPORT.md)
```

## Quickstart

The full cycle: Provision, Attack, Detect, Analyze, Cleanup.

### 1. Provision Infrastructure
```bash
cd infra/terraform
terraform init
terraform apply
```

### 2. Configure Suspect Credentials
Create the access key manually to keep secrets out of Terraform state:
```bash
aws iam create-access-key --user-name ir-lab-suspect

# Add to ~/.aws/credentials
[ir-lab-suspect]
aws_access_key_id = <KEY_ID>
aws_secret_access_key = <SECRET>
region = us-east-1
```

### 3. Attack — Simulate the Kill Chain
```bash
pip install -r requirements.txt

# Reconnaissance
python scripts/simulate_activity.py --profile ir-lab-suspect --test-bucket <BUCKET>

# Privilege escalation
python scripts/attacks/iam_privesc.py --profile ir-lab-suspect

# Data exfiltration
python scripts/attacks/s3_exfil.py --profile ir-lab-suspect --bucket <TARGET_BUCKET>

# Lateral movement
python scripts/attacks/lateral_movement.py --profile ir-lab-suspect

# Cover tracks
python scripts/attacks/anti_forensics.py --profile ir-lab-suspect
```

### 4. Detect — Query for IOCs
```bash
python scripts/detect/detect_privesc.py --profile admin
python scripts/detect/detect_exfil.py --profile admin
python scripts/detect/detect_lateral.py --profile admin
python scripts/detect/detect_anti_forensics.py --profile admin
```

### 5. Analyze — Build Forensic Timeline
CloudTrail logs may take ~15 minutes to deliver to S3. `LookupEvents` (API) often appears faster.
```bash
python scripts/collect_evidence.py \
    --profile admin \
    --start <ISO_START> \
    --end <ISO_END> \
    --filter-username ir-lab-suspect \
    --case-dir cases/CASE-001

python scripts/build_timeline.py --in cases/CASE-001/cloudtrail.json
```

### 6. Cleanup
```bash
cd infra/terraform
terraform destroy
```

## Attack Playbooks

### IAM Privilege Escalation (`iam_privesc.py`)
Exploits a common AWS misconfiguration: an IAM user with `iam:CreatePolicyVersion` permission can write a new policy version granting themselves full admin access and set it as default. The script also demonstrates PassRole abuse (attaching a privileged role to a Lambda function) and login profile creation for console access persistence. These work because IAM policies are evaluated at request time, not at attachment time.

### S3 Data Exfiltration (`s3_exfil.py`)
Performs bulk `GetObject` calls to download sensitive data from S3 buckets. Also configures cross-account replication rules to establish a persistent, silent exfiltration channel. This works because overly permissive bucket policies and missing S3 Block Public Access settings are among the most common AWS misconfigurations.

### Lateral Movement (`lateral_movement.py`)
Uses `AssumeRole` to pivot into other AWS accounts via trust relationships, and leverages SSM `SendCommand` and EC2 Instance Connect `SendSSHPublicKey` to execute commands on EC2 instances. This works because cross-account role trust policies often use overly broad principal specifications.

### Anti-Forensics (`anti_forensics.py`)
Disables CloudTrail logging (`StopLogging`, `DeleteTrail`), modifies event selectors to filter out management events, and deletes log objects from S3. This works because many organizations do not have alerts on CloudTrail configuration changes, and the attacker with sufficient IAM permissions can blind the entire logging pipeline.

## Detection & Response

Each attack is detected through CloudTrail event analysis:

| Attack | Key CloudTrail Events | Detection Approach |
|---|---|---|
| Privilege Escalation | `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `CreateLoginProfile`, `AssumeRole` | Flag policy modifications by non-admin principals; alert on unexpected AssumeRole callers |
| Data Exfiltration | `GetObject` (bulk), `PutReplicationConfiguration` | Threshold-based alerting on S3 data access volume; monitor replication config changes |
| Lateral Movement | `AssumeRole` (cross-account), `SendCommand`, `SendSSHPublicKey` | Baseline normal cross-account patterns; alert on new account pairs or SSM usage |
| Anti-Forensics | `StopLogging`, `DeleteTrail`, `PutEventSelectors`, `DeleteObject` (log buckets) | Immediate high-severity alerts on any CloudTrail configuration modification |

## Forensic Analysis

The forensic pipeline produces:

- **Timeline** (`cases/CASE-XXX/timeline.md`): Chronological sequence of all API calls by the suspect principal, with source IP, user agent, and error codes.
- **IOC Extraction**: Access key IDs, source IPs, user agents, and role ARNs involved in the incident.
- **Incident Report** (`docs/REPORT.md`): Structured writeup covering scope, impact, root cause, and remediation recommendations.
- **Redaction**: `collect_evidence.py` automatically redacts Account IDs and full Access Keys before saving to `sample-output/`.

## Documentation

| Document | Description |
|---|---|
| [docs/REPORT.md](docs/REPORT.md) | Incident report template and sample analysis |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Step-by-step IR procedures for each attack type |
| [docs/QUERIES.md](docs/QUERIES.md) | CloudTrail query library for threat hunting |
| [docs/ATTACK_MAPPING.md](docs/ATTACK_MAPPING.md) | MITRE ATT&CK technique mapping for all attack scripts |

## Safety & Cost

All operations use legitimate AWS APIs (boto3) — no third-party exploit tools required. This demonstrates that real cloud attacks are API calls, not malware. The most dangerous cloud threats are misconfigurations exploited through standard interfaces.

- **Terraform Lifecycle**: All infrastructure is managed by Terraform. Run `terraform destroy` to remove everything.
- **Cost Control**: S3 buckets use 30-day lifecycle policies. CloudTrail uses standard (free-tier) event logging. Destroy resources when not actively testing.
- **Credential Safety**: Suspect access keys are created manually, never stored in Terraform state or logs. The `redact.py` script sanitizes output artifacts.

## Requirements

- Python 3.9+
- Terraform 1.0+
- AWS CLI (configured with admin and suspect profiles)
- boto3 (installed via `requirements.txt`)

## License

MIT
