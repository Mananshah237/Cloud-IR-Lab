# Cloud-IR-Lab — Status

_Last updated: 2026-06-10_

## State: working & verified, $0 cost, infra destroyed

Ran the full cycle on a real AWS account (us-east-1), produced real results, then
**destroyed everything** — account verified clean (no buckets, IAM user, trails, or
GuardDuty detectors). Cost: **$0** (GuardDuty disabled before it could bill).

## Recent fixes

1. `infra/terraform/main.tf` — malformed `data` source block (would not parse); added
   AWS provider v5 `filter {}` on the lifecycle rule; **made GuardDuty opt-in**
   (`var.enable_guardduty`, default `false`) — the only billable resource.
2. `infra/terraform/outputs.tf` — added sensitive `suspect_secret_access_key` output.
3. `scripts/detect/detect_lateral.py` — fixed `AttributeError` on `null`
   `requestParameters`/`userIdentity`.
4. `scripts/build_timeline.py` — fixed Windows `UnicodeEncodeError` (UTF-8 file writes).

## Verified results (`cases/CASE-001/`)

- detect_privesc: 7 indicators · detect_exfil: 3 · detect_anti_forensics: 2 (incl. CRITICAL StopLogging)
- `timeline.md`, `timeline.csv`, `iocs.md` — full redacted kill-chain timeline + IOCs.

## How to re-run

```powershell
./run_lab.ps1 all       # provision -> attack -> detect -> forensic timeline ($0, GuardDuty off)
./run_lab.ps1 destroy   # tear down -> back to $0
```

## Forensic dashboard (web UI)

Read-only SOC console on port **8003** (timeline, detections by MITRE tactic, IOCs, stats):

```bash
pip install -r ui/requirements.txt
uvicorn ui.app:app --port 8003   # http://localhost:8003
```

## Next (see README → Optimization roadmap)

`run_lab.sh` orchestrator · optional EC2/SSM target for lateral movement · auto-generate
`docs/REPORT.md` · resource tagging · CI `terraform validate`.
