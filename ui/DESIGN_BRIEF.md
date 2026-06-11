# Cloud-IR-Lab Console — Frontend Design Brief

Hand this file **plus `ui/console.html`** to a design pass. The goal is to restyle the
frontend while keeping it a **drop-in single HTML file**. Return an updated
`console.html` and I'll wire it back in.

---

## 1. What this is

A local **AWS Attack & Forensics Console**. The operator provisions a deliberately
misconfigured AWS lab, launches one of five attack simulations and watches its output
stream **live** in an in-browser terminal, then runs detection and reviews a SOC-style
forensic timeline. Audience: red-teamers / SOC analysts. Aesthetic: premium dark
"security console."

## 2. The file to redesign

- **`ui/console.html`** — a single self-contained file: `<style>` block + markup +
  vanilla-JS `<script>` at the bottom. It is served **as-is** by FastAPI
  (`ui/app.py` reads it into memory). 

**Hard constraints (do not break these):**
- Keep it **one HTML file, no build step, no framework** (vanilla JS, `fetch`,
  `EventSource`). React/Vue/Tailwind-CLI are NOT available at runtime.
- External resources are fine via CDN `<link>` (Google Fonts already used).
- Keep all the element hooks the script needs, or update the script to match — the
  **API contract in §4 must keep working**.

## 3. Screens / structure to preserve

1. **Header**: logo, title "Cloud-IR-Lab", subtitle, and a right-aligned **status pill**
   ("Lab provisioned · us-east-1" green, or "Not provisioned" grey).
2. **Two tabs** (deep-linkable via `#console` / `#forensics`): **Attack Console** and
   **Forensics**.
3. **Attack Console tab**:
   - **Lifecycle bar**: Provision + Destroy buttons + a "$0 / GuardDuty off" note.
   - **Five simulation cards** (see §5) — each: icon, title, MITRE IDs, description,
     "Run simulation" button. Buttons disabled until provisioned.
   - **Detection & forensics bar**: "Run Detection & Timeline" button.
   - **Live terminal**: dark console area that appends streamed output lines; a status
     indicator ("idle" / "running…"). Color-codes lines (commands, `[+]` success,
     `AccessDenied`/errors, headers).
4. **Forensics tab**:
   - 4 **stat cards**: Events, Denied attempts, Detections, Severity.
   - **Kill-chain timeline**: rows of `time · event · source · tactic+MITRE · allowed/denied pill`.
   - **Detections by tactic**: name + count.
   - **IOC panel**: principals, source IPs, regions, user agents (chips; long values truncate).

## 4. API contract (the JS calls these — keep them working)

| Method | Path | Returns |
|--------|------|---------|
| GET | `/api/status` | lab status (below) |
| POST | `/api/run/{action}` | `{ "job": "<id>" }` — action ∈ `provision, recon, privesc, s3_exfil, lateral, anti_forensics, analyze, destroy` |
| GET | `/api/stream/{job}` | **SSE**: each msg is `data: {"line":"..."}`; final msg `data: {"status":"done"|"error","action":"..."}` |
| GET | `/api/case` | forensic case (below), or `{"empty":true}` |
| GET | `/api/cases` | `{ "cases": ["CASE-001"] }` |

**`GET /api/status` example**
```json
{ "provisioned": true, "region": "us-east-1", "admin_profile": "admin",
  "bucket": "cloud-ir-lab-testdata-…", "tools": {"terraform":"terraform.exe","aws":"aws.exe"},
  "cases": ["CASE-001"] }
```

**`GET /api/case` example (shape)**
```json
{
  "case": "CASE-001",
  "stats": { "events": 7, "denied": 5, "allowed": 2, "detections": 5,
             "severities": {"critical":0,"high":4,"medium":0,"low":1,"info":2} },
  "tactics": [ {"name":"Privilege Escalation","count":5} ],
  "timeline": [
    {"time":"2026-06-11T04:19:14Z","event":"AssumeRole","source":"sts.amazonaws.com",
     "tactic":"Privilege Escalation","mitre":"T1078.004","severity":"high",
     "allowed":false,"errorCode":"AccessDenied","ip":"99.100.98.xxx"}
  ],
  "iocs": {
    "principals": ["arn:aws:iam::000000000000:user/ir-lab-suspect"],
    "ips": ["99.100.98.xxx"], "regions": ["us-east-1"],
    "userAgents": ["Boto3/1.43.27 md/Botocore#1.43.27 …"]
  }
}
```

**Live-stream usage**: `POST /api/run/{action}` → get `job` → open
`new EventSource('/api/stream/'+job)` → on each `message`, parse JSON; if `line`, append
to terminal; if `status`, close the stream and (for `analyze`) refresh the Forensics tab.

## 5. The five simulations (content for the cards)

| id | Title | MITRE | One-liner |
|----|-------|-------|-----------|
| `recon` | Reconnaissance | T1580 | Enumerate IAM/S3/EC2 + a few denied probes (baseline telemetry). |
| `privesc` | IAM Privilege Escalation | T1078.004 · T1098 · T1548 | AssumeRole chaining, policy rollback, PassRole→Lambda, CreateLoginProfile. |
| `s3_exfil` | S3 Data Exfiltration | T1530 · T1537 | Bucket enum, bulk GetObject, pre-signed-URL / cross-account replication. |
| `lateral` | Lateral Movement | T1021 · T1550 | Cross-account AssumeRole + SSM SendCommand / EC2 Instance Connect. |
| `anti_forensics` | Anti-Forensics | T1562.008 · T1070 | StopLogging, DeleteTrail, PutEventSelectors, trail redirection. |

## 6. Current design tokens (change freely)

```
bg #070b16 · surface #0f1626 / #151e33 · line #233150 · text #eaf0fb · muted #8a9bc0
accent #38bdf8 → #818cf8 (gradient) · ok #2dd4a7
severity: critical #fb3a5d · high #fb923c · medium #fbbf24 · low #38bdf8 · info #94a3b8
fonts: Inter (UI), JetBrains Mono (code/terminal)
```

## 7. Suggested prompt to give the designer

> Redesign the attached `console.html` for an "AWS Attack & Forensics Console." Keep it a
> single self-contained HTML file with vanilla JS (fetch + EventSource) — no frameworks or
> build step — and keep every API call, the SSE live-terminal behavior, the two
> deep-linkable tabs, the five simulation cards, and the forensic timeline/IOC views
> working exactly as described in the brief. Make it look like a premium, modern security
> operations console: strong visual hierarchy, refined dark theme, great typography,
> tasteful motion, and a terminal that feels alive. Preserve the data shapes in §4.

## 8. Handing it back

Just send me the new `console.html` (or the changed `<style>` / markup / `<script>`).
If the redesign renames element IDs or changes the JSON it expects, tell me and I'll
reconcile it with `ui/app.py`. If it needs new backend fields, list them and I'll add the
endpoints.
