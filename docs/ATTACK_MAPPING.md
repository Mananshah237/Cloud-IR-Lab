# MITRE ATT&CK Mapping — Cloud-IR-Lab

This document maps each attack script in the lab to the corresponding MITRE ATT&CK techniques, along with their detection counterparts.

## Attack-to-Detection Matrix

| Attack Script | Technique | MITRE ID | Detection Script | Detection Logic |
|---|---|---|---|---|
| `iam_privesc.py` | Valid Accounts: Cloud Accounts | T1078.004 | `detect_privesc.py` | AssumeRole events from unexpected principals |
| `iam_privesc.py` | Account Manipulation | T1098 | `detect_privesc.py` | CreatePolicyVersion, SetDefaultPolicyVersion, CreateLoginProfile events |
| `iam_privesc.py` | Abuse Elevation Control Mechanism | T1548 | `detect_privesc.py` | PassRole + CreateFunction event sequences |
| `s3_exfil.py` | Data from Cloud Storage | T1530 | `detect_exfil.py` | Bulk GetObject events exceeding threshold |
| `s3_exfil.py` | Transfer Data to Cloud Account | T1537 | `detect_exfil.py` | PutReplicationConfiguration events |
| `lateral_movement.py` | Use Alternate Authentication Material | T1550 | `detect_lateral.py` | Cross-account AssumeRole events |
| `lateral_movement.py` | Remote Services | T1021 | `detect_lateral.py` | SSM SendCommand, EC2 SendSSHPublicKey events |
| `anti_forensics.py` | Impair Defenses: Disable Cloud Logs | T1562.008 | `detect_anti_forensics.py` | StopLogging, DeleteTrail events |
| `anti_forensics.py` | Indicator Removal | T1070 | `detect_anti_forensics.py` | PutEventSelectors, UpdateTrail, S3 log deletion events |

## Attack Chain Narrative

A realistic adversary operating in AWS would follow this kill chain:

1. **Initial Access** — Compromised IAM credentials (simulated by `ir-lab-suspect` user)
2. **Discovery** — `simulate_activity.py` performs reconnaissance (ListUsers, ListBuckets, DescribeInstances)
3. **Privilege Escalation** — `iam_privesc.py` exploits IAM misconfigurations to elevate permissions
4. **Lateral Movement** — `lateral_movement.py` pivots across accounts and compute resources
5. **Collection & Exfiltration** — `s3_exfil.py` extracts sensitive data from S3 buckets
6. **Defense Evasion** — `anti_forensics.py` tampers with CloudTrail to cover tracks

## References

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Rhino Security Labs — AWS IAM Privilege Escalation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
