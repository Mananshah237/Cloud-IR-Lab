<#
.SYNOPSIS
  One-command runner for Cloud-IR-Lab. Provisions infra, simulates the attack
  kill-chain as the suspect, runs detection + forensics, and tears everything down.

.DESCRIPTION
  Actions:
    provision  terraform init + apply (GuardDuty stays OFF -> $0), then configures
               the ir-lab-suspect AWS CLI profile from terraform outputs.
    attack     runs recon + privesc/exfil/lateral/anti-forensics as the suspect.
    analyze    runs the 4 detection scripts, collects evidence, builds the timeline.
    destroy    terraform destroy (back to $0) and clears the suspect profile.
    all        provision -> attack -> analyze (leaves infra up; run 'destroy' after).

  Cost: every resource is free-tier; GuardDuty (the only billable one) is disabled.

.PARAMETER Action   provision | attack | analyze | destroy | all
.PARAMETER AdminProfile   AWS CLI profile with admin rights (default: admin)
.PARAMETER Region        AWS region (default: us-east-1)

.EXAMPLE
  ./run_lab.ps1 all          # full cycle, then later:
  ./run_lab.ps1 destroy
#>
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('provision', 'attack', 'analyze', 'destroy', 'all')]
  [string]$Action,
  [string]$AdminProfile = 'admin',
  [string]$Region = 'us-east-1'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$tf = Join-Path $root 'infra/terraform'
$suspect = 'ir-lab-suspect'

function Need($cmd) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    throw "$cmd not found on PATH. Install it (terraform / aws / python) and retry."
  }
}

function Provision {
  Need terraform; Need aws
  Push-Location $tf
  try {
    terraform init -input=false
    $env:AWS_PROFILE = $AdminProfile
    terraform apply -auto-approve -var "aws_region=$Region"   # enable_guardduty defaults false
    $akid = terraform output -raw suspect_access_key_id
    $secret = terraform output -raw suspect_secret_access_key
    aws configure set aws_access_key_id     $akid   --profile $suspect
    aws configure set aws_secret_access_key $secret --profile $suspect
    aws configure set region                $Region --profile $suspect
    aws configure set output                json    --profile $suspect
    Write-Host "[+] Suspect profile '$suspect' configured. Waiting for IAM propagation..."
    Start-Sleep -Seconds 10
  } finally { Pop-Location }
}

function Attack {
  Need python
  Push-Location $tf
  $bucket = terraform output -raw testdata_bucket_name
  $acct = (aws sts get-caller-identity --profile $AdminProfile --query Account --output text)
  Pop-Location
  python "$root/scripts/simulate_activity.py" --profile $suspect --test-bucket $bucket --alt-region us-west-2
  python "$root/scripts/attacks/iam_privesc.py"     --profile $suspect --role-arn "arn:aws:iam::${acct}:role/ir-lab-admin-target"
  python "$root/scripts/attacks/s3_exfil.py"        --profile $suspect --target-bucket $bucket
  python "$root/scripts/attacks/anti_forensics.py"  --profile $suspect --trail-name cloud-ir-lab-trail
  python "$root/scripts/attacks/lateral_movement.py" --profile $suspect
  Write-Host "[+] Attacks complete. CloudTrail Event History is queryable immediately."
}

function Analyze {
  Need python
  $start = (Get-Date).ToUniversalTime().AddMinutes(-45).ToString('yyyy-MM-ddTHH:mm:ssZ')
  $end = (Get-Date).ToUniversalTime().AddMinutes(5).ToString('yyyy-MM-ddTHH:mm:ssZ')
  $case = Join-Path $root 'cases/CASE-001'
  foreach ($d in 'detect_privesc', 'detect_exfil', 'detect_lateral', 'detect_anti_forensics') {
    python "$root/scripts/detect/$d.py" --profile $AdminProfile --start $start --end $end
  }
  python "$root/scripts/collect_evidence.py" --profile $AdminProfile --start $start --end $end --filter-username $suspect --case-dir $case
  python "$root/scripts/build_timeline.py" --in "$case/cloudtrail.json"
  Write-Host "[+] Results in $case  (timeline.md, timeline.csv, iocs.md)"
}

function Destroy {
  Need terraform; Need aws
  Push-Location $tf
  try {
    $env:AWS_PROFILE = $AdminProfile
    terraform destroy -auto-approve -var "aws_region=$Region"
  } finally { Pop-Location }
  aws configure set aws_access_key_id     '' --profile $suspect
  aws configure set aws_secret_access_key '' --profile $suspect
  Write-Host "[+] Destroyed. Account back to `$0."
}

switch ($Action) {
  'provision' { Provision }
  'attack' { Attack }
  'analyze' { Analyze }
  'destroy' { Destroy }
  'all' { Provision; Attack; Analyze; Write-Host "`n[!] Infra still UP. Run './run_lab.ps1 destroy' when done." }
}
