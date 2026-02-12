# Incident Response Runbook: Suspicious IAM Activity

## 1. Trigger
- GuardDuty finding: `Recon:IAM/User/MaliciousIP` or `UnauthorizedAccess:IAM/User/MaliciousIP`.
- CloudWatch Alarm: High rate of `AccessDenied` errors.
- Manual observation of strange API calls.

## 2. Triage (First 10 Minutes)
- [ ] **Verify User:** Is `ir-lab-suspect` a known human or service account?
- [ ] **Check Scope:** use CloudTrail to see what they successfully accessed.
    - Filter: `EventName != 'ConsoleLogin'` and `ErrorCode is None`.
- [ ] **Check Source:** Is the IP address known (VPN, office) or anomalous?

## 3. Investigation
**Questions to Answer:**
1. **WHO:** Which principal? (`userIdentity.arn`)
2. **WHAT:** What did they do? (`eventName`, `resources`)
3. **WHEN:** Start and end time of activity?
4. **WHERE:** Which regions? (`awsRegion`)

**Command:**
```bash
python scripts/collect_evidence.py \
    --profile admin \
    --start <Time> \
    --end <Time> \
    --filter-username ir-lab-suspect \
    --case-dir cases/CASE-001
```

## 4. Containment
If malicious intent is confirmed:
1. **Disable Access Key:**
   ```bash
   aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name ir-lab-suspect
   ```
2. **Attach Deny-All Policy:**
   Attach the `AWSDenyAll` inline policy to the user for immediate lockout.
3. **Revoke Sessions:**
   ```bash
   aws iam put-user-policy --user-name ir-lab-suspect --policy-name RevokeOldSessions --policy-document file://revoke-policy.json
   ```

## 5. Recovery
- Rotate credentials.
- Analyze impact (did they see anything sensitive?).
- Restore any modified resources (none in this lab).

## 6. Lessons Learned
- Update PIR with findings.
- Improve least-privilege policies.
