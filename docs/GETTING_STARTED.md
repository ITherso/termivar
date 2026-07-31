# VENOM Getting Started Guide

Welcome to Venom v0.9.0-alpha. This guide covers a local development build.

---

## Prerequisites

- **Rust:** 1.70+ ([install](https://rustup.rs/))
- **Docker:** Optional (for containerized deployment)
- **Modern Browser:** Chrome, Firefox, Safari, or Edge
- **Linux/macOS:** Recommended (Windows via WSL2)

---

## Installation

### Option 1: Build from Source

```bash
# Clone repository
git clone https://github.com/ITherso/venom.git
cd venom

# Build release binary
cargo build --release

# Binary location
./target/release/venom
```

### Option 2: Docker

```bash
# Build image
docker build -t venom:latest .

# Run container
docker run -p 8080:8080 -p 3000:3000 venom:latest
```

---

## Quick Start (5 Minutes)

### Step 1: Start VENOM Proxy
```bash
./target/release/venom proxy --host 127.0.0.1 --port 8080
```

Output:
```
Venom - modular web security testing framework v0.9.0-alpha
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[+] CA Generated: ~/.venom/ca.crt
[+] Database: ~/.venom/history.db
[+] Proxy: http://127.0.0.1:8080
[+] API: http://127.0.0.1:3000
[+] Dashboard: http://127.0.0.1:3000/dashboard
```

### Step 2: Trust Certificate

**Firefox:**
1. Open Preferences → Privacy & Security → Certificates
2. Click "View Certificates" → Authorities → Import
3. Select `~/.venom/ca.crt` → Trust for identifying websites

**Chrome:**
1. Settings → Privacy and security → Security
2. Manage certificates → Authorities → Import
3. Select `~/.venom/ca.crt` → Trust

**macOS/Safari:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.venom/ca.crt
```

### Step 3: Configure Proxy

**Firefox:**
1. Settings → Network → Manual proxy configuration
2. HTTP Proxy: `127.0.0.1` Port: `8080`
3. HTTPS Proxy: `127.0.0.1` Port: `8080`

**Chrome:**
```bash
# macOS
open -a Google\ Chrome --args --proxy-server="127.0.0.1:8080"

# Linux
google-chrome --proxy-server="127.0.0.1:8080"
```

### Step 4: Test Configuration

```bash
# In browser, visit:
https://httpbin.org/get

# In VENOM terminal, you should see:
[+] REQUEST: GET https://httpbin.org/get
[+] RESPONSE: 200 OK
[+] Captured and logged to database
```

### Step 5: Open Dashboard

Open browser to: `http://127.0.0.1:3000/dashboard`

You should see:
- System status (CPU, Memory, Disk)
- Active scans
- Recent audit logs
- SLA metrics

---

## First Scan (10 Minutes)

### Via Dashboard

1. Click "Security Scans"
2. Click "Start New Scan"
3. Enter target: `https://httpbin.org`
4. Select "Full Scan"
5. Click "Start"

Monitor progress in real-time on dashboard.

### Via CLI

```bash
# List available commands
./target/release/venom help

# Start a scan
./target/release/venom scan:start --target https://httpbin.org --type full

# Check status
./target/release/venom scan:status scan_abc123

# View results
./target/release/venom scan:results scan_abc123
```

### Via API

```bash
# Generate API key first
./target/release/venom user:create admin --role admin

# Start scan via API
curl -X POST http://localhost:3000/api/scans/start \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://httpbin.org",
    "type": "full"
  }'
```

---

## Understanding Results

### Vulnerability Severity

| Level | CVSS | Action |
|-------|------|--------|
| Critical | 9.0-10.0 | Fix immediately |
| High | 7.0-8.9 | Fix within 1 week |
| Medium | 4.0-6.9 | Fix within 1 month |
| Low | 0.1-3.9 | Fix within quarter |

### Findings Details

Each finding includes:
- **Type:** Vulnerability class
- **Location:** Affected parameter/endpoint
- **Evidence:** Proof of vulnerability
- **Remediation:** How to fix

Example:
```
Type: SQL Injection
Location: /api/users?id=
Evidence: Response time difference detected
CVSS: 8.5
Remediation: Use parameterized queries
```

---

## Team Collaboration

### Create a Team

```bash
./target/release/venom team:create "Security Squad"
```

### Add Members

```bash
./target/release/venom team:add-member team_123 user_456 --role analyst
```

### Share Scans

```bash
./target/release/venom scan:share scan_abc123 --team team_123 --permission view
```

---

## Common Use Cases

### Security Assessment
```bash
# 1. Start comprehensive scan
./target/release/venom scan:start --target target.com --aggressive

# 2. Wait for completion (monitor via dashboard)

# 3. Generate report
./target/release/venom report:generate scan_abc123 --format pdf

# 4. Share with stakeholders
./target/release/venom scan:share scan_abc123 --team stakeholders
```

### Compliance Audit
```bash
# 1. Start compliance scan
./target/release/venom compliance:scan --framework gdpr

# 2. View compliance status
./target/release/venom compliance:status

# 3. Generate audit report
./target/release/venom compliance:report --framework gdpr --period monthly
```

### Load Testing
```bash
# 1. Create load profile
./target/release/venom loadtest:create --target target.com --concurrent 100

# 2. Run test
./target/release/venom loadtest:run profile_123

# 3. View results
./target/release/venom loadtest:report profile_123
```

---

## Troubleshooting

### Certificate Issues
```bash
# Reset certificates
rm -rf ~/.venom/ca

# Restart VENOM
./target/release/venom proxy --host 127.0.0.1 --port 8080

# Re-import CA certificate to browser
```

### Proxy Not Intercepting
```bash
# Check proxy is running
curl -v http://127.0.0.1:8080

# Check browser proxy settings
# Verify certificate is trusted

# Check firewall isn't blocking
sudo lsof -i :8080
```

### Database Issues
```bash
# Check database
sqlite3 ~/.venom/history.db ".tables"

# Clear database (if needed)
rm ~/.venom/history.db

# Restart VENOM
```

---

## Next Steps

1. **Read API Docs:** [docs/API.md](API.md)
2. **Learn Architecture:** [docs/architecture.md](architecture.md)
3. **CLI Reference:** [README Quick Start](https://github.com/ITherso/venom#quick-start)
4. **Advanced Guide:** [Scanner](scanner.md)
5. **Security Best Practices:** [Security policy](https://github.com/ITherso/venom/blob/main/SECURITY.md)

---

## Support

- **Documentation:** https://github.com/ITherso/venom/docs
- **Issues:** https://github.com/ITherso/venom/issues
- **Discussions:** https://github.com/ITherso/venom/discussions

---

**Happy Pentesting! 🔍**
