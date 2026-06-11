"""
Cloud-IR-Lab — Interactive Attack & Forensics Console.

A local control panel for the lab: provision infra, launch any of the four attack
simulations (IAM privilege escalation, S3 exfiltration, lateral movement,
anti-forensics) while streaming their output LIVE, then run detection and view the
forensic timeline / IOCs — all from the browser.

Drives the same boto3 scripts + Terraform used on the CLI. Everything is $0
(GuardDuty stays disabled); a prominent Destroy button tears the lab down.

Run:
    pip install -r ui/requirements.txt
    uvicorn ui.app:app --port 8003       # http://localhost:8003
"""
from __future__ import annotations

import asyncio
import glob
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

ROOT = Path(__file__).resolve().parent.parent
TF_DIR = ROOT / "infra" / "terraform"
CASES_DIR = ROOT / "cases"
SCRIPTS = ROOT / "scripts"

ADMIN_PROFILE = os.environ.get("IRLAB_ADMIN_PROFILE", "admin")
SUSPECT_PROFILE = "ir-lab-suspect"
REGION = os.environ.get("IRLAB_REGION", "us-east-1")
TRAIL = "cloud-ir-lab-trail"

app = FastAPI(title="Cloud-IR-Lab Console")

# ── Binary resolution (Windows winget shims aren't always on PATH) ───────────
def _find(name: str, extra: list[str]) -> str:
    p = shutil.which(name)
    if p:
        return p
    for cand in extra:
        if cand and Path(cand).exists():
            return cand
    return name  # let it fail loudly with a clear message


WINGET = os.path.expanduser(r"~\AppData\Local\Microsoft\WinGet\Links")
WINGET_PKGS = os.path.expanduser(r"~\AppData\Local\Microsoft\WinGet\Packages")
TERRAFORM = _find("terraform", [
    os.path.join(WINGET, "terraform.exe"),
    *glob.glob(os.path.join(WINGET_PKGS, "Hashicorp.Terraform*", "terraform.exe")),
])
AWS = _find("aws", [
    r"C:\Program Files\Amazon\AWSCLIV2\aws.exe",
    os.path.join(WINGET, "aws.exe"),
    *glob.glob(os.path.join(WINGET_PKGS, "Amazon.AWSCLI*", "**", "aws.exe"), recursive=True),
])
PY = sys.executable


def _env(profile: str | None) -> dict[str, str]:
    e = os.environ.copy()
    if profile:
        e["AWS_PROFILE"] = profile
    e["AWS_REGION"] = REGION
    e["AWS_DEFAULT_REGION"] = REGION
    e["TF_IN_AUTOMATION"] = "1"
    return e


def _capture(argv: list[str], cwd: Path | None = None, profile: str | None = None) -> str:
    try:
        r = subprocess.run(argv, cwd=cwd, env=_env(profile), capture_output=True, text=True, timeout=60)
        return r.stdout.strip()
    except Exception:
        return ""


def tf_outputs() -> dict[str, Any]:
    raw = _capture([TERRAFORM, "output", "-json"], cwd=TF_DIR, profile=ADMIN_PROFILE)
    if not raw:
        return {}
    try:
        return {k: v.get("value") for k, v in json.loads(raw).items()}
    except Exception:
        return {}


def account_id() -> str:
    return _capture([AWS, "sts", "get-caller-identity", "--profile", ADMIN_PROFILE,
                     "--query", "Account", "--output", "text"]) or "000000000000"


# ── Job manager (live-streamed subprocess sequences) ─────────────────────────
Step = tuple[list[str], Path, str | None] | Callable[[str], None]
JOBS: dict[str, dict[str, Any]] = {}
LOCK = threading.Lock()


def _emit(jid: str, line: str) -> None:
    with LOCK:
        JOBS[jid]["lines"].append(line)


def _run_proc(jid: str, argv: list[str], cwd: Path, profile: str | None) -> int:
    _emit(jid, f"$ {Path(argv[0]).name} {' '.join(argv[1:])}")
    proc = subprocess.Popen(
        argv, cwd=str(cwd), env=_env(profile),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    with LOCK:
        JOBS[jid]["proc"] = proc
    assert proc.stdout
    for line in proc.stdout:
        _emit(jid, line.rstrip("\n"))
    proc.wait()
    return proc.returncode


def _worker(jid: str, steps: list[Step]) -> None:
    try:
        for step in steps:
            if callable(step):
                step(jid)
            else:
                argv, cwd, profile = step
                code = _run_proc(jid, argv, cwd, profile)
                if code not in (0,):
                    _emit(jid, f"» process exited with code {code}")
        with LOCK:
            JOBS[jid]["status"] = "done"
    except Exception as e:  # noqa: BLE001
        _emit(jid, f"✖ error: {e}")
        with LOCK:
            JOBS[jid]["status"] = "error"


def start_job(action: str, steps: list[Step]) -> str:
    jid = uuid.uuid4().hex[:12]
    with LOCK:
        JOBS[jid] = {"action": action, "lines": [], "status": "running", "proc": None}
    threading.Thread(target=_worker, args=(jid, steps), daemon=True).start()
    return jid


# ── Step builders ────────────────────────────────────────────────────────────
def _configure_suspect(jid: str) -> None:
    out = tf_outputs()
    akid, secret = out.get("suspect_access_key_id"), out.get("suspect_secret_access_key")
    if not akid or not secret:
        _emit(jid, "[!] could not read suspect credentials from terraform outputs")
        return
    for k, v in [("aws_access_key_id", akid), ("aws_secret_access_key", secret),
                 ("region", REGION), ("output", "json")]:
        subprocess.run([AWS, "configure", "set", k, str(v), "--profile", SUSPECT_PROFILE],
                       capture_output=True, text=True)
    _emit(jid, f"[+] Configured '{SUSPECT_PROFILE}' profile from Terraform outputs.")
    _emit(jid, "[*] Waiting 8s for IAM credential propagation...")
    time.sleep(8)


def steps_provision() -> list[Step]:
    return [
        ([TERRAFORM, "init", "-input=false", "-no-color"], TF_DIR, ADMIN_PROFILE),
        ([TERRAFORM, "apply", "-auto-approve", "-no-color", "-var", f"aws_region={REGION}"], TF_DIR, ADMIN_PROFILE),
        _configure_suspect,
    ]


def steps_destroy() -> list[Step]:
    def clear_suspect(jid: str) -> None:
        for k in ("aws_access_key_id", "aws_secret_access_key"):
            subprocess.run([AWS, "configure", "set", k, "", "--profile", SUSPECT_PROFILE],
                           capture_output=True, text=True)
        _emit(jid, "[+] Cleared suspect profile credentials.")
    return [
        ([TERRAFORM, "destroy", "-auto-approve", "-no-color", "-var", f"aws_region={REGION}"], TF_DIR, ADMIN_PROFILE),
        clear_suspect,
    ]


def steps_attack(action: str) -> list[Step]:
    out = tf_outputs()
    bucket = out.get("testdata_bucket_name", "")
    acct = account_id()
    A = SCRIPTS / "attacks"
    if action == "recon":
        return [([PY, str(SCRIPTS / "simulate_activity.py"), "--profile", SUSPECT_PROFILE,
                  "--test-bucket", bucket, "--alt-region", "us-west-2"], ROOT, None)]
    if action == "privesc":
        return [([PY, str(A / "iam_privesc.py"), "--profile", SUSPECT_PROFILE,
                  "--role-arn", f"arn:aws:iam::{acct}:role/ir-lab-admin-target"], ROOT, None)]
    if action == "s3_exfil":
        return [([PY, str(A / "s3_exfil.py"), "--profile", SUSPECT_PROFILE,
                  "--target-bucket", bucket], ROOT, None)]
    if action == "lateral":
        return [([PY, str(A / "lateral_movement.py"), "--profile", SUSPECT_PROFILE], ROOT, None)]
    if action == "anti_forensics":
        return [([PY, str(A / "anti_forensics.py"), "--profile", SUSPECT_PROFILE,
                  "--trail-name", TRAIL], ROOT, None)]
    raise HTTPException(400, f"unknown attack {action}")


def steps_analyze() -> list[Step]:
    start = (datetime.now(timezone.utc) - timedelta(minutes=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    case = CASES_DIR / "CASE-001"
    steps: list[Step] = []
    for d in ("detect_privesc", "detect_exfil", "detect_lateral", "detect_anti_forensics"):
        steps.append(([PY, str(SCRIPTS / "detect" / f"{d}.py"), "--profile", ADMIN_PROFILE,
                       "--start", start, "--end", end], ROOT, None))
    steps.append(([PY, str(SCRIPTS / "collect_evidence.py"), "--profile", ADMIN_PROFILE,
                   "--start", start, "--end", end, "--filter-username", SUSPECT_PROFILE,
                   "--case-dir", str(case)], ROOT, None))
    steps.append(([PY, str(SCRIPTS / "build_timeline.py"), "--in", str(case / "cloudtrail.json")], ROOT, None))
    return steps


ATTACKS = {"recon", "privesc", "s3_exfil", "lateral", "anti_forensics"}


# ── API ──────────────────────────────────────────────────────────────────────
@app.get("/api/status")
def status() -> dict[str, Any]:
    out = tf_outputs()
    provisioned = bool(out.get("testdata_bucket_name"))
    return {
        "provisioned": provisioned,
        "region": REGION,
        "admin_profile": ADMIN_PROFILE,
        "bucket": out.get("testdata_bucket_name"),
        "tools": {"terraform": Path(TERRAFORM).name, "aws": Path(AWS).name},
        "cases": list_cases(),
    }


@app.post("/api/run/{action}")
def run(action: str) -> dict[str, str]:
    if action == "provision":
        steps = steps_provision()
    elif action == "destroy":
        steps = steps_destroy()
    elif action == "analyze":
        steps = steps_analyze()
    elif action in ATTACKS:
        if not tf_outputs().get("testdata_bucket_name"):
            raise HTTPException(409, "Lab is not provisioned. Run Provision first.")
        steps = steps_attack(action)
    else:
        raise HTTPException(404, f"unknown action {action}")
    return {"job": start_job(action, steps)}


@app.get("/api/stream/{jid}")
async def stream(jid: str) -> StreamingResponse:
    async def gen():
        idx = 0
        while True:
            with LOCK:
                job = JOBS.get(jid)
            if not job:
                yield f"data: {json.dumps({'status': 'error', 'line': 'no such job'})}\n\n"
                return
            lines = job["lines"]
            while idx < len(lines):
                yield f"data: {json.dumps({'line': lines[idx]})}\n\n"
                idx += 1
            if job["status"] != "running":
                yield f"data: {json.dumps({'status': job['status'], 'action': job['action']})}\n\n"
                return
            await asyncio.sleep(0.2)

    return StreamingResponse(gen(), media_type="text/event-stream")


# ── Forensic case data (read-only) ───────────────────────────────────────────
TACTICS: dict[str, tuple[str, str, str]] = {
    "StopLogging": ("Anti-Forensics", "T1562.008", "critical"),
    "DeleteTrail": ("Anti-Forensics", "T1562.008", "critical"),
    "UpdateTrail": ("Anti-Forensics", "T1070", "high"),
    "PutEventSelectors": ("Anti-Forensics", "T1070", "high"),
    "GetEventSelectors": ("Anti-Forensics", "T1070", "low"),
    "DescribeTrails": ("Anti-Forensics", "T1070", "low"),
    "AssumeRole": ("Privilege Escalation", "T1078.004", "high"),
    "CreatePolicyVersion": ("Privilege Escalation", "T1098", "high"),
    "SetDefaultPolicyVersion": ("Privilege Escalation", "T1098", "high"),
    "CreateLoginProfile": ("Privilege Escalation", "T1098", "high"),
    "CreateAccessKey": ("Privilege Escalation", "T1098", "high"),
    "CreateFunction20150331": ("Privilege Escalation", "T1548", "high"),
    "CreateFunction": ("Privilege Escalation", "T1548", "high"),
    "AttachUserPolicy": ("Privilege Escalation", "T1098", "high"),
    "PutUserPolicy": ("Privilege Escalation", "T1098", "high"),
    "ListPolicies": ("Privilege Escalation", "T1098", "low"),
    "CreateUser": ("Privilege Escalation", "T1136", "high"),
    "GetObject": ("Data Exfiltration", "T1530", "high"),
    "GetBucketAcl": ("Data Exfiltration", "T1530", "medium"),
    "ListBuckets": ("Data Exfiltration", "T1530", "low"),
    "PutReplicationConfiguration": ("Data Exfiltration", "T1537", "high"),
    "SendCommand": ("Lateral Movement", "T1021", "high"),
    "SendSSHPublicKey": ("Lateral Movement", "T1021", "high"),
}
RECON_PREFIXES = ("List", "Describe", "Get")


def classify(name: str) -> tuple[str, str, str]:
    if name in TACTICS:
        return TACTICS[name]
    if name.startswith(RECON_PREFIXES):
        return ("Reconnaissance", "T1580", "info")
    return ("Other", "-", "info")


def list_cases() -> list[str]:
    if not CASES_DIR.exists():
        return []
    return sorted((p.name for p in CASES_DIR.iterdir() if (p / "cloudtrail.json").exists()), reverse=True)


def build_case(case: str) -> dict[str, Any]:
    ct = CASES_DIR / case / "cloudtrail.json"
    if not ct.exists():
        raise HTTPException(404, f"no cloudtrail.json for {case}")
    events = json.loads(ct.read_text(encoding="utf-8"))
    events.sort(key=lambda e: e.get("eventTime", ""))
    timeline, tcounts = [], {}
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    ips, agents, principals, regions, denied = set(), set(), set(), set(), 0
    for e in events:
        name = e.get("eventName", "?")
        tactic, mitre, s = classify(name)
        allowed = not e.get("errorCode")
        if not allowed:
            denied += 1
        if tactic == "Reconnaissance" and allowed:
            s = "info"
        sev[s] = sev.get(s, 0) + 1
        if tactic not in ("Reconnaissance", "Other"):
            tcounts[tactic] = tcounts.get(tactic, 0) + 1
        for src, dst in (("sourceIPAddress", ips), ("userAgent", agents),
                         ("userIdentityArn", principals), ("awsRegion", regions)):
            if e.get(src):
                dst.add(e[src])
        timeline.append({"time": e.get("eventTime"), "event": name, "source": e.get("eventSource"),
                         "tactic": tactic, "mitre": mitre, "severity": s, "allowed": allowed,
                         "errorCode": e.get("errorCode"), "ip": e.get("sourceIPAddress")})
    return {"case": case,
            "stats": {"events": len(events), "denied": denied, "allowed": len(events) - denied,
                      "detections": sum(tcounts.values()), "severities": sev},
            "tactics": [{"name": k, "count": v} for k, v in sorted(tcounts.items(), key=lambda x: -x[1])],
            "timeline": timeline,
            "iocs": {"principals": sorted(principals), "ips": sorted(ips),
                     "regions": sorted(regions), "userAgents": sorted(agents)}}


@app.get("/api/cases")
def api_cases() -> dict[str, Any]:
    return {"cases": list_cases()}


@app.get("/api/case")
def api_case(name: str | None = None) -> JSONResponse:
    cases = list_cases()
    if not cases:
        return JSONResponse({"empty": True})
    return JSONResponse(build_case(name or cases[0]))


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML


INDEX_HTML = (Path(__file__).resolve().parent / "console.html").read_text(encoding="utf-8")
