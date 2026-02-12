# Incident Timeline

| Time (UTC) | Action | Source | IP | Status |
|---|---|---|---|---|
| 2023-10-27T10:00:00+00:00 | **ListUsers** | iam.amazonaws.com | 203.0.113.xxx | ✅ Allowed |
| 2023-10-27T10:00:02+00:00 | **ListRoles** | iam.amazonaws.com | 203.0.113.xxx | ✅ Allowed |
| 2023-10-27T10:00:05+00:00 | **ListBuckets** | s3.amazonaws.com | 203.0.113.xxx | ✅ Allowed |
| 2023-10-27T10:00:08+00:00 | **GetObject** | s3.amazonaws.com | 203.0.113.xxx | ❌ AccessDenied |
| 2023-10-27T10:00:12+00:00 | **CreateUser** | iam.amazonaws.com | 203.0.113.xxx | ❌ AccessDenied |
