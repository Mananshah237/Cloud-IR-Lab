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

## Attack & Forensics Console (web UI)

A local web console (`ui/app.py`) drives the whole lab from the browser:

- **Lab lifecycle** — Provision / Destroy buttons (GuardDuty stays off → **$0**).
- **Five simulation cards** — Reconnaissance, IAM Privilege Escalation, S3 Data
  Exfiltration, Lateral Movement, Anti-Forensics — each launches the real boto3 script
  and **streams its output live** into an in-browser terminal, so you watch every API
  call (and every `AccessDenied`) as it happens.
- **Detection & timeline** — one click runs the four detection scripts + evidence
  collection + timeline build.
- **Forensics tab** — SOC-style incident view: kill-chain timeline (allowed vs.
  `AccessDenied`), detections by MITRE tactic, IOC panel, and severity stats.

```bash
pip install -r ui/requirements.txt
uvicorn ui.app:app --port 8003        # open http://localhost:8003
```

Runs on port **8003** alongside the other project demos (VEXIS 3000/8000,
AegisScan 3001/8001, PhishNet 3002/8002). It resolves `terraform`/`aws` automatically
(including winget install locations) and uses the `admin` profile for lifecycle/detection
and the auto-created `ir-lab-suspect` profile for attacks. Everything it does is also
available headless via `run_lab.ps1`.

## One-command runner

`run_lab.ps1` wraps the whole cycle:

```powershell
./run_lab.ps1 all        # provision -> attack -> detect -> forensic timeline (GuardDuty stays off, $0)
./run_lab.ps1 destroy    # tear everything down -> back to $0
```

Individual phases: `provision`, `attack`, `analyze`, `destroy`.

## Documentation

| Document | Description |
|---|---|
| [docs/REPORT.md](docs/REPORT.md) | Incident report template and sample analysis |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Step-by-step IR procedures for each attack type |
| [docs/QUERIES.md](docs/QUERIES.md) | CloudTrail query library for threat hunting |
| [docs/ATTACK_MAPPING.md](docs/ATTACK_MAPPING.md) | MITRE ATT&CK technique mapping for all attack scripts |

## Safety & Cost

All operations use legitimate AWS APIs (boto3) — no third-party exploit tools required. This demonstrates that real cloud attacks are API calls, not malware. The most dangerous cloud threats are misconfigurations exploited through standard interfaces.

- **$0 by design.** Every resource the lab provisions is free-tier eligible: the first CloudTrail trail's **management events are free**, IAM users/keys/policies are always free, and the two S3 buckets hold a few KB with a 30-day lifecycle. **GuardDuty is the only resource that can ever bill**, so it is now **opt-in and disabled by default** (`var.enable_guardduty = false`). Enable it only deliberately with `terraform apply -var enable_guardduty=true`.
- **Detection needs no paid infrastructure.** The detection and forensic scripts read CloudTrail via `LookupEvents`, which queries **CloudTrail Event History** — always on, free, and retained 90 days **independent of any trail or S3 bucket**. You can `terraform destroy` the trail/buckets and still build a real timeline from Event History.
- **Terraform Lifecycle**: All infrastructure is managed by Terraform. Run `terraform destroy` to remove everything; verify with `aws s3 ls`, `aws iam get-user --user-name ir-lab-suspect`, `aws cloudtrail list-trails`, and `aws guardduty list-detectors`.
- **Credential Safety**: The `redact.py` script sanitizes Account IDs, IPs, and access keys in output artifacts. The suspect secret key is available via `terraform output -raw suspect_secret_access_key` (sensitive) for configuring the `ir-lab-suspect` profile.

### Recent fixes (so it actually runs)

- **`infra/terraform/main.tf`** — fixed a malformed data source (`data.aws_iam_policy_document "..."` → `data "aws_iam_policy_document" "..."`) that prevented `terraform apply` from parsing; added the `filter {}` block now required by AWS provider v5 lifecycle rules; made GuardDuty opt-in.
- **`outputs.tf`** — added a sensitive `suspect_secret_access_key` output so the attack profile can be configured straight from Terraform.
- **`scripts/detect/detect_lateral.py`** — fixed an `AttributeError` crash when CloudTrail records `requestParameters`/`userIdentity` as JSON `null`.
- **`scripts/build_timeline.py`** — fixed a `UnicodeEncodeError` on Windows by writing all report files as UTF-8 (the timeline uses ✅/❌ status glyphs).

### Verified run (real telemetry, locked-down suspect)

Against a freshly provisioned lab, the suspect profile ran recon (allowed) plus privesc/exfil/anti-forensics attempts (denied by the intentionally restrictive policy). The pipeline produced real artifacts in `cases/CASE-001/`:

- **detect_privesc**: 7 indicators (4 × `AssumeRole`, 3 × IAM policy events)
- **detect_exfil**: 3 indicators (S3 bucket enumeration)
- **detect_anti_forensics**: 2 indicators incl. `ANTIFOR-001 [CRITICAL]` (CloudTrail `StopLogging` attempt)
- **timeline.md / iocs.md**: full chronological kill chain + redacted IOCs (principal, source IP, user agents, regions)

> Denied attempts are not a failure — `errorCode: AccessDenied` events are exactly the high-signal telemetry a SOC alerts on, and keeping the suspect locked down means the lab never creates a real working backdoor in your account.

## Optimization & improvement roadmap

1. **One-shot orchestrator.** Add a `scripts/run_lab.sh` that runs apply → configure suspect profile from outputs → attacks → detection → `collect_evidence` → `build_timeline` → (optional) destroy, with a single time window computed automatically.
2. **EC2/SSM targets for lateral movement.** `main.tf` provisions no EC2 instance, so `lateral_movement.py` has nothing to pivot to. Add an optional `t3.micro` (free-tier) + SSM role behind a variable to exercise `SendCommand`/`SendSSHPublicKey`.
3. **Generate `docs/REPORT.md` automatically** from the detection JSON + timeline, instead of keeping it as a manual template.
4. **Tag every resource** (`tags = { project = "cloud-ir-lab" }`) for trivial cost tracking and cleanup verification.
5. **CI lint.** Run `terraform validate` + `flake8`/`ruff` on the scripts in GitHub Actions to catch syntax regressions like the ones fixed above.

## Requirements

- Python 3.9+
- Terraform 1.0+
- AWS CLI (configured with admin and suspect profiles)
- boto3 (installed via `requirements.txt`)

## License

MIT
