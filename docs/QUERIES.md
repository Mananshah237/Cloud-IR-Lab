# CloudTrail Analysis Queries

## CloudTrail LookupEvents (CLI)
Quickly find Access Denied errors:
```bash
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AccessDenied \
    --start-time 2023-10-27T00:00:00Z \
    --end-time 2023-10-27T01:00:00Z
```

## Athena (SQL) - Future Enhancement
Create a table for CloudTrail logs and run:

```sql
SELECT 
    eventTime, 
    eventName, 
    userIdentity.arn, 
    sourceIPAddress, 
    errorCode, 
    errorMessage
FROM cloudtrail_logs
WHERE errorCode IN ('AccessDenied', 'Client.UnauthorizedOperation')
AND eventTime > '2023-10-27 00:00:00'
ORDER BY eventTime DESC;
```
