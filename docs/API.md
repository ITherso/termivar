# VENOM API Documentation

## Overview

Venom v0.9.0-alpha exposes an experimental REST API for supported scanner capabilities.

**Base URL:** `http://localhost:3000/api`  
**Version:** 1.0.0  
**Authentication:** API Key (Bearer token)

---

## Authentication

```bash
# Include API key in header
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:3000/api/scans
```

---

## Scanning Endpoints

### Start Scan
```http
POST /api/scans/start
Content-Type: application/json

{
  "target": "https://example.com",
  "type": "full",
  "aggressive": true
}

Response: 201 Created
{
  "scan_id": "scan_abc123",
  "target": "https://example.com",
  "status": "running",
  "started_at": "2026-07-15T10:30:00Z"
}
```

### Get Scan Status
```http
GET /api/scans/{scan_id}

Response: 200 OK
{
  "scan_id": "scan_abc123",
  "status": "running",
  "progress": 45,
  "vulnerabilities_found": 8,
  "started_at": "2026-07-15T10:30:00Z"
}
```

### List Scans
```http
GET /api/scans?page=1&limit=10

Response: 200 OK
{
  "scans": [
    {
      "scan_id": "scan_abc123",
      "target": "https://example.com",
      "status": "completed",
      "vulnerabilities": 12
    }
  ],
  "total": 42,
  "page": 1
}
```

### Cancel Scan
```http
POST /api/scans/{scan_id}/cancel

Response: 204 No Content
```

---

## Findings Endpoints

### Get Findings
```http
GET /api/scans/{scan_id}/findings?severity=high

Response: 200 OK
{
  "findings": [
    {
      "id": "finding_001",
      "type": "SQL Injection",
      "severity": "High",
      "cvss": 8.5,
      "description": "Unvalidated SQL input",
      "remediation": "Use parameterized queries"
    }
  ]
}
```

### Get Finding Details
```http
GET /api/findings/{finding_id}

Response: 200 OK
{
  "id": "finding_001",
  "type": "SQL Injection",
  "severity": "High",
  "evidence": ["Parameter: id", "Payload: ' OR '1'='1"],
  "proof_of_concept": "...",
  "remediation": "..."
}
```

---

## Team Endpoints

### Create Team
```http
POST /api/teams
Content-Type: application/json

{
  "name": "Security Team A",
  "description": "Main pentesting team"
}

Response: 201 Created
{
  "team_id": "team_123",
  "name": "Security Team A",
  "created_at": "2026-07-15T10:30:00Z"
}
```

### Add Team Member
```http
POST /api/teams/{team_id}/members
Content-Type: application/json

{
  "user_id": "user_456",
  "role": "member"
}

Response: 201 Created
```

### Share Scan
```http
POST /api/scans/{scan_id}/share
Content-Type: application/json

{
  "team_id": "team_123",
  "permission": "view"
}

Response: 201 Created
```

---

## Export Endpoints

### Export Scan Results
```http
GET /api/scans/{scan_id}/export?format=json

Response: 200 OK
Content-Type: application/json

{
  "scan_id": "scan_abc123",
  "findings": [...],
  "report": {...}
}
```

### Export as PDF
```http
GET /api/scans/{scan_id}/export?format=pdf

Response: 200 OK
Content-Type: application/pdf
```

---

## Compliance Endpoints

### Get Compliance Status
```http
GET /api/compliance/status

Response: 200 OK
{
  "gdpr": {
    "status": "compliant",
    "findings": 0
  },
  "hipaa": {
    "status": "partially_compliant",
    "findings": 2
  },
  "soc2": {
    "status": "compliant",
    "findings": 0
  }
}
```

### Generate Compliance Report
```http
POST /api/compliance/report
Content-Type: application/json

{
  "framework": "gdpr",
  "period": "monthly"
}

Response: 201 Created
{
  "report_id": "report_789",
  "framework": "gdpr",
  "status": "compliant",
  "compliance_percentage": 95.5
}
```

---

## Error Codes

| Code | Message | Meaning |
|------|---------|---------|
| 400 | Bad Request | Invalid parameters |
| 401 | Unauthorized | Missing/invalid API key |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |

---

## Rate Limiting

- **Standard:** 1,000 requests/hour
- **Premium:** 10,000 requests/hour
- **Enterprise:** Unlimited

Headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1626360000
```

---

## Examples

### Python
```python
import requests

api_key = "your_api_key"
headers = {"Authorization": f"Bearer {api_key}"}

# Start scan
response = requests.post(
    "http://localhost:3000/api/scans/start",
    json={"target": "https://example.com"},
    headers=headers
)
scan = response.json()
print(f"Scan ID: {scan['scan_id']}")

# Get results
response = requests.get(
    f"http://localhost:3000/api/scans/{scan['scan_id']}/findings",
    headers=headers
)
findings = response.json()
```

### JavaScript
```javascript
const apiKey = "your_api_key";
const headers = { "Authorization": `Bearer ${apiKey}` };

async function startScan(target) {
  const response = await fetch("http://localhost:3000/api/scans/start", {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify({ target })
  });
  return response.json();
}

const scan = await startScan("https://example.com");
console.log(`Scan ID: ${scan.scan_id}`);
```

### Rust
```rust
use reqwest::Client;

#[tokio::main]
async fn main() {
    let client = Client::new();
    let api_key = "your_api_key";
    
    let response = client
        .post("http://localhost:3000/api/scans/start")
        .bearer_auth(api_key)
        .json(&json!({
            "target": "https://example.com"
        }))
        .send()
        .await
        .unwrap();
    
    let scan = response.json::<Value>().await.unwrap();
    println!("Scan ID: {}", scan["scan_id"]);
}
```

---

## Webhook Events

Subscribe to webhook events:

```bash
POST /api/webhooks
{
  "url": "https://your-server.com/webhook",
  "events": ["scan.completed", "finding.discovered"]
}
```

Events:
- `scan.started` - Scan begins
- `scan.completed` - Scan finishes
- `finding.discovered` - New vulnerability found
- `report.generated` - Report ready

---

**For more information:** `https://github.com/ITherso/venom`
