# 🧠 Introspector

**Your target made a request. You learned how it thinks.**

A ready-to-use Out-of-Band (OOB) operations framework for offensive security. Not just a callback server — Introspector **Fingerprints client behavior, assesses attack surface and delivers exploits"**.

![Python](https://img.shields.io/badge/python-3.8+-blue)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docs](https://img.shields.io/badge/docs-introspector.sh-green)](https://introspector.sh)

---

## The Concept

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Traditional OOB:  "Did I get a callback?"     → Yes/No                     │
│                                                                             │
│  Introspector:     "What can I learn about this client?"                    │
└─────────────────────────────────────────────────────────────────────────────┘

    You send:     ?url=http://introspector.sh/anything
                              │
                              ▼
    Backend:      Fetches /anything
                              │
                  But also auto-requests /robots.txt, /favicon.ico
                              │
                              ▼
    Introspector: Responds with strategic 302 redirect
                              │
                ┌─────────────┴─────────────────┐
                ▼                               ▼
        Second request               No second request
        to /roboted.txt              
                │                               │
                ▼                               ▼
        ✓ Follows redirects            ✗ Doesn't follow
        → SSRF bypass viable           → Try other techniques
```

Routes like `/robots.txt` and `/favicon.ico` are fetched **automatically** by browsers, crawlers, and HTTP libraries. By serving strategic responses, you're introspecting client behavior passively — from request #1.

---

## Quick Start

```bash
git clone https://github.com/DeepSecurityResearch/Introspector.git
cd Introspector
pip3 install -r requirements.txt
sudo python3 Introspector.py
```

```
[introspector]> introspect enable follow-redirect
[+] Scan module 'follow-redirect' enabled

[introspector]> run create xxe1
[+] Created /run/a8x2k1.xml
```

---

## Features

| | Feature | Description |
|---|---------|-------------|
| 📡 | HTTP/DNS Listeners | Unified callback capture |
| 🔍 | Passive Scanners | Detect redirect behavior, timeout thresholds |
| 🧬 | Payload Arsenal | XXE, SVG bombs, CSV injection, pixel floods |
| 📁 | File Hosting | Serve any file with correct MIME types |
| 🎨 | Response Designer | Craft custom HTTP responses |
| 🌍 | GeoIP + WHOIS | Real-time intel on every request |
| 💾 | Persistence | Sessions survive restarts |

---

## Documentation

Full documentation, use cases, and examples at **[introspector.sh](https://introspector.sh)**

---

## Legal

**Authorized testing only.**

---

<p align="center">
  <i>Built for hunters.</i>
</p>
