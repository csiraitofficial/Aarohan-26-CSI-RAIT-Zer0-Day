# ThreatSense — AI-Powered Threat Analysis Platform

<div align="center">

**Aarohan '26 | CSI RAIT | Zer0-Day**

*Intelligent malware analysis, threat intelligence, and incident response — powered by local AI*

</div>

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Our Solution](#our-solution)
- [Architecture Overview](#architecture-overview)
- [Feature Set](#feature-set)
- [Technology Stack](#technology-stack)
- [Module Breakdown](#module-breakdown)
- [Threat Intelligence Engine](#threat-intelligence-engine)
- [Compliance & Regulatory Alignment](#compliance--regulatory-alignment)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)

---

## Problem Statement

Cybersecurity threats are growing at an unprecedented scale. The global average cost of a data breach in 2024 reached **\$4.88 million** (IBM). Small and medium enterprises are particularly vulnerable — they lack the budget for enterprise-grade SOC platforms like CrowdStrike, Palo Alto Cortex, or Splunk SOAR.

**Key challenges this platform addresses:**

1. **Delayed Detection** — Traditional antivirus relies on signature databases, missing zero-day threats and novel malware variants entirely.
2. **Manual Analysis Bottleneck** — Security analysts spend hours manually reverse-engineering suspicious files. There aren't enough skilled analysts to meet demand.
3. **No Source Tracking** — When a file is downloaded, most tools don't track *where* it came from or whether that source has a history of serving malicious files.
4. **No Propagation Visibility** — When malware spreads from host to host (Friend 1 → Friend 2 → Friend 3), there's no automated way to detect and visualize the attack chain.
5. **Fragmented Tooling** — Analysts juggle between VirusTotal, static analysis tools, IOC databases, and reporting tools. No unified pipeline exists.

---

## Our Solution

**ThreatSense** is a fully local, AI-powered threat analysis platform that automates the entire incident response pipeline — from file detection to AI-synthesized reports — without sending sensitive data to external clouds.

### How It Works

```
File Downloaded → Monitor Detects → Static Analysis → VirusTotal Check
    → IOC Extraction → Correlation Engine → AI Report Generation
        → Source Reputation Update → Propagation Chain Detection
            → PDF Report + Real-time Dashboard
```

### Key Differentiators

| Feature | ThreatSense | Traditional AV |
|---------|-------------|----------------|
| Analysis type | Static + behavioral + AI | Signature matching |
| Zero-day detection | ✅ Entropy + heuristic + LLM | ❌ Requires signature update |
| Source tracking | ✅ Tracks download origin | ❌ No source awareness |
| Attack chain detection | ✅ Propagation chain visualization | ❌ Not available |
| Report generation | ✅ Professional PDF + dashboard | ❌ Basic logs |
| Data privacy | ✅ 100% local (Ollama) | ❌ Cloud-dependent |
| IOC correlation | ✅ Cross-incident matching | ❌ Isolated scans |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                      FRONTEND (React + Vite)                 │
│  ┌───────────┐  ┌──────────┐  ┌───────────┐  ┌───────────┐  │
│  │ File Drop │  │ History  │  │  Report   │  │ PDF Export│  │
│  │ Upload UI │  │  Modal   │  │  View     │  │  Download │  │
│  └─────┬─────┘  └────┬─────┘  └─────┬─────┘  └─────┬─────┘  │
│        └──────────────┴──────────────┴──────────────┘        │
└────────────────────────────┬─────────────────────────────────┘
                             │ HTTP REST API
┌────────────────────────────┴─────────────────────────────────┐
│                    BACKEND (FastAPI + Uvicorn)                │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                  ANALYSIS PIPELINE                      │ │
│  │                                                         │ │
│  │  Binary Analyzer    Script Analyzer    Email Analyzer   │ │
│  │  (PE headers,       (PS, Python, JS,   (Headers, SPF,   │ │
│  │   imports, IOCs)     Bash, Batch)       phishing, DKIM) │ │
│  │         │                  │                  │         │ │
│  │         └──────────────────┴──────────────────┘         │ │
│  │                            │                            │ │
│  │                    VirusTotal Lookup                     │ │
│  │                            │                            │ │
│  │                   Correlation Engine                     │ │
│  │                   (IOC matching +                        │ │
│  │                    propagation chain)                    │ │
│  │                            │                            │ │
│  │                   Ollama LLM Synthesis                   │ │
│  │                  (Severity + Report)                     │ │
│  │                            │                            │ │
│  │             Source Reputation Engine                     │ │
│  │                            │                            │ │
│  │               PDF Report Generator                      │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────┐    ┌───────────────────────────────────┐ │
│  │   SQLite DB    │    │      File Monitor (Watchdog)      │ │
│  │  (incidents,   │    │   Watches Downloads folder        │ │
│  │   reputation)  │    │   Auto-detects new files          │ │
│  └────────────────┘    │   GUI popups for scan/result      │ │
│                        └───────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                             │
                    ┌────────┴────────┐
                    │   Ollama (LLM)  │
                    │  Local AI Model │
                    │  (deepseek-r1)  │
                    └─────────────────┘
```

---

## Feature Set

### 1. Multi-Format File Analysis

| File Type | Analyzer | Capabilities |
|-----------|----------|-------------|
| **PE Executables** (.exe, .dll) | `analyzer.py` | PE header parsing, import table analysis, dangerous API detection (50+ APIs), section entropy, file type mismatch detection |
| **Scripts** (.ps1, .py, .js, .sh, .bat) | `script_analyzer.py` | 200+ dangerous function signatures, obfuscation detection (base64, XOR, string concatenation), language-specific threat patterns |
| **Emails** (.eml, .msg) | `email_analyzer.py` | SPF/DKIM/DMARC validation, phishing keyword scoring, deceptive link detection, attachment risk analysis, header spoofing detection |
| **URLs** | `url_analyzer.py` | Domain reputation, suspicious TLD detection, redirect chain analysis |
| **All files** | Core pipeline | SHA256/MD5/SHA1 hashing, Shannon entropy calculation, string extraction (ASCII + UTF-16LE), IOC extraction |

### 2. IOC Extraction & Correlation Engine

Automatically extracts and cross-references:
- **IP addresses** (filtered for private/reserved ranges to prevent false positives)
- **Domains** (filtered for benign CDNs and CAs)
- **URLs** (C2 server candidates)
- **Registry keys** (persistence indicators)
- **File paths** (dropper targets)

The **correlation engine** compares current IOCs against all historical incidents. When shared IOCs are found across 2+ incidents, it flags a **campaign detection** — indicating a coordinated attack using the same infrastructure.

### 3. AI-Powered Threat Synthesis (Ollama)

Using a **locally hosted LLM** (via Ollama), ThreatSense generates:
- **Severity classification**: CRITICAL / HIGH / MEDIUM / LOW / BENIGN
- **Threat classification**: e.g., "Trojan Downloader", "Ransomware", "Benign File"
- **Confidence score**: 0–100%
- **Executive summary**: Human-readable analysis narrative
- **Technical analysis**: Behavioral breakdown
- **IOC highlights**: Most critical indicators
- **Recommended actions**: Incident response steps

> **Privacy advantage**: The LLM runs entirely locally. No file content, hashes, or IOCs are ever sent to external APIs (except optional VirusTotal hash lookups).

### 4. Source Reputation Engine

ThreatSense tracks **where files were downloaded from** by reading Chrome browser history. Each source (domain/IP) gets a reputation score:

| Score Range | Label | Meaning |
|-------------|-------|---------|
| 0 | CLEAN | No malicious files observed |
| 1–30 | SUSPICIOUS | Some risky files detected |
| 31–60 | MALICIOUS | Multiple malicious files served |
| 61+ | BLACKLISTED | Known malware distribution source |

Scoring formula:
- CRITICAL file → +40 points
- HIGH file → +30 points
- MEDIUM file → +20 points
- LOW/BENIGN → total file count incremented (no score change)

The reputation is **live** — it updates with every scan and is always up-to-date when viewing old reports.

### 5. Attack Propagation Chain Detection

**The signature feature.** When the same malware (same SHA256 hash) is scanned from **different sources** over time, ThreatSense detects the propagation path:

```
192.168.1.10 (#5, 14:00) → 192.168.1.20 (#8, 14:30) → 192.168.1.30 (#12, 15:00)
     Friend 1                    Friend 2                    Friend 3
   (compromised)             (forwarded file)           (current scan)
```

This is exactly how real-world threat intelligence works — tracking malware lateral movement across hosts. The chain is visualized in both the PDF report (red banner) and the frontend (interactive node pills with arrows).

### 6. Real-Time Download Monitor

`file_monitor.py` uses **watchdog** to monitor the Downloads folder in real-time:
1. New file detected → GUI popup asks "Scan this file?"
2. If yes → animated progress window with 5-step pipeline visualization
3. Analysis complete → result popup with severity, summary, and IOCs
4. Options: **Delete File** | **View Report** (PDF) | **Done**
5. Automatically opens the frontend dashboard

### 7. Professional PDF Reports

Full incident reports generated with **ReportLab**, featuring:
- Color-coded severity header with risk score
- Correlation warning banner (if campaign detected)
- **Source reputation section** with color-coded score
- **Propagation chain banner** with visual flow
- File metadata table (hashes, entropy, type)
- Executive summary
- Technical behavioral analysis
- IOC highlights + full IOC table
- VirusTotal cross-reference results
- Recommendations section
- Classification footer

### 8. Modern Dark-Theme Dashboard

React frontend (`ThreatSenseV2.jsx`) with:
- Drag-and-drop file upload with animated analysis
- Incident history modal with severity badges
- Full report view with all analysis sections
- Source reputation card with animated score bar
- Propagation chain visualization
- One-click PDF export
- Statistics navbar (total incidents by severity)

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | React 18 + Vite | SPA dashboard |
| **Backend** | FastAPI + Uvicorn | REST API server |
| **AI/LLM** | Ollama (deepseek-r1) | Local threat synthesis |
| **Database** | SQLite | Incident + reputation storage |
| **PDF** | ReportLab | Professional report generation |
| **Monitor** | watchdog + customtkinter | Real-time file detection + GUI |
| **Threat Intel** | VirusTotal API v3 | Hash reputation lookup |
| **Language** | Python 3.12 + JavaScript | Backend + Frontend |

---

## Module Breakdown

| Module | Lines | Description |
|--------|-------|-------------|
| `analyzer.py` | 896 | Binary/PE file analyzer — import table scanning, 50+ dangerous API signatures, magic byte detection, section entropy analysis |
| `script_analyzer.py` | 1,429 | Script analyzer for 6 languages — 200+ dangerous function patterns, obfuscation detection (base64, XOR, char codes), persistence indicators |
| `email_analyzer.py` | 1,132 | Email security analyzer — header spoofing, SPF/DKIM/DMARC, phishing keywords, deceptive links, attachment risk scoring |
| `correlation.py` | 225+ | IOC correlation engine + propagation chain detection |
| `database.py` | 360+ | SQLite ORM — incident CRUD, source reputation, schema migrations |
| `main.py` | 690+ | FastAPI orchestrator — analysis pipeline, REST API, enrichment |
| `ollama_client.py` | 750+ | Ollama LLM integration — prompt engineering, JSON parsing, retry logic |
| `pdf_generator.py` | 1,100+ | ReportLab PDF builder — professional incident reports |
| `file_monitor.py` | 780+ | Download monitor — watchdog + customtkinter GUI popups |
| `virustotal.py` | 130+ | VirusTotal API v3 hash lookup |
| `url_analyzer.py` | 180+ | URL/domain analysis |
| `ThreatSenseV2.jsx` | 1,000+ | React frontend — dashboard, report view, history |

**Total codebase**: ~7,500+ lines of production code

---

## Threat Intelligence Engine

### How Correlation Works

```
Current File IOCs: {ip: "193.42.11.23", domain: "evil-domain.ru"}
                        ↓
    Query all past incidents for matching IOCs
                        ↓
    Found: Incident #3 shares "193.42.11.23" (same C2 server)
    Found: Incident #7 shares "evil-domain.ru" (same domain)
                        ↓
    CAMPAIGN DETECTED: 3 incidents share same C2 infrastructure
```

### How Propagation Detection Works

```
Scan #1: file_hash=abc123, source=192.168.1.10  ← Friend 1
Scan #2: file_hash=abc123, source=192.168.1.20  ← Friend 2 (same file!)
Scan #3: file_hash=abc123, source=192.168.1.30  ← Friend 3 (same file!)
                        ↓
    ATTACK CHAIN: 192.168.1.10 → 192.168.1.20 → 192.168.1.30
    "This malware has spread across 3 distinct sources"
```

### Risk Scoring Formula

```python
risk_score = 0
risk_score += dangerous_imports_score      # Each API call has a weight (5-40)
risk_score += obfuscation_score            # Base64, XOR, string concat detected
risk_score += entropy_penalty              # High entropy → likely packed/encrypted
risk_score += ioc_score                    # Suspicious IPs, domains, registry keys
risk_score += file_type_mismatch_penalty   # Extension doesn't match magic bytes
risk_score = min(risk_score, 100)          # Capped at 100
```

---

## Compliance & Regulatory Alignment

ThreatSense is designed with regulatory compliance as a core architectural principle. The platform supports organizations in meeting their obligations under:

### GDPR (General Data Protection Regulation)

| GDPR Article | How ThreatSense Helps |
|-------------|----------------------|
| **Art. 5(1)(f)** — Integrity & Confidentiality | All analysis runs **100% locally**. No file content, PII, or hashes are transmitted to external clouds. The Ollama LLM runs on-premises. |
| **Art. 32** — Security of Processing | Automated threat detection reduces human error. Incident reports provide audit trails for security measures. |
| **Art. 33** — Breach Notification (72hr)** | Automated analysis + instant PDF reports enable rapid breach assessment within the 72-hour notification window. |
| **Art. 35** — Data Protection Impact Assessment | Comprehensive incident reports with severity classification and IOC documentation support DPIA requirements. |
| **Art. 30** — Records of Processing | Every scan is recorded with timestamps, hashes, and source information — creating a complete processing log. |

### HIPAA (Health Insurance Portability and Accountability Act)

| HIPAA Requirement | How ThreatSense Helps |
|-------------------|----------------------|
| **§164.308(a)(1)** — Security Management | Automated risk analysis of files entering the network. Source reputation flags known-bad origins before files can affect PHI systems. |
| **§164.308(a)(5)** — Security Awareness | AI-generated executive summaries explain threats in plain language, supporting staff awareness. |
| **§164.308(a)(6)** — Security Incident Procedures | Full incident response pipeline: detect → analyze → classify → report → remediate. Each incident gets a unique ID and PDF report. |
| **§164.312(b)** — Audit Controls | Complete audit trail: file hash, source IP/domain, timestamp, severity, IOCs, correlation results, and AI analysis — all stored and exportable. |
| **§164.312(c)** — Integrity | SHA256 hash verification ensures file integrity. Any modification to a tracked file is detectable. |

### SOC 2 Type II

| Trust Principle | How ThreatSense Helps |
|----------------|----------------------|
| **Security** | Real-time monitoring of downloaded files with automated threat classification. Source reputation blacklisting prevents repeat infections. |
| **Availability** | Propagation chain detection identifies lateral movement early, enabling isolation before widespread compromise. |
| **Processing Integrity** | Deterministic hashing (SHA256) + multi-engine analysis (static + AI) ensures consistent, repeatable results. |
| **Confidentiality** | Local-only processing. VirusTotal lookups use only the hash (not the file content). No data leaves the network. |

### NIST Cybersecurity Framework (CSF)

| Function | Mapping |
|----------|---------|
| **Identify** | Automated file classification, source tracking, asset awareness |
| **Protect** | Download monitoring, source reputation blacklisting, file deletion |
| **Detect** | Real-time file monitoring, IOC extraction, entropy anomaly detection |
| **Respond** | AI-generated incident reports, severity classification, recommended actions |
| **Recover** | Campaign detection enables root cause analysis; propagation chains identify all affected hosts |

### ISO 27001

ThreatSense supports implementation of:
- **A.12.2** — Protection from malware (automated detection + analysis)
- **A.12.4** — Logging and monitoring (complete incident audit trail)
- **A.16.1** — Information security incident management (full incident lifecycle)
- **A.18.1** — Compliance with legal and contractual requirements (exportable reports for auditors)

### Key Privacy Architecture Decisions

1. **Local-first AI** — Ollama runs the LLM entirely on localhost. No API keys, no cloud inference.
2. **Hash-only external lookups** — VirusTotal receives only SHA256 hashes, never file content.
3. **No telemetry** — The platform sends zero analytics, usage data, or crash reports.
4. **No PII collection** — File analysis extracts IOCs (IPs, domains), not personal data.
5. **Data sovereignty** — All data stays in the local SQLite database under the user's control.

---

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+
- [Ollama](https://ollama.ai) installed locally
- (Optional) VirusTotal API key

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd project

# Backend setup
cd backend
python -m venv venv
.\venv\Scripts\Activate      # Windows
pip install -r requirements.txt

# Frontend setup
cd ../frontend
npm install

# Pull the AI model
ollama pull deepseek-r1:1.5b
```

### Configuration

Create `backend/.env`:
```env
VIRUSTOTAL_API_KEY=your_key_here    # Optional — works without it
OLLAMA_MODEL=deepseek-r1:1.5b       # Or any Ollama model
```

### Running

```bash
# Terminal 1 — Ollama
$env:OLLAMA_HOST="0.0.0.0"; ollama serve

# Terminal 2 — Backend
cd backend
.\venv\Scripts\Activate
python main.py

# Terminal 3 — Frontend
cd frontend
npm run dev

# Terminal 4 — Download Monitor (optional)
cd backend
.\venv\Scripts\Activate
python file_monitor.py
```

Access the dashboard at **http://localhost:3000**

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze` | Upload file for analysis (multipart form) |
| `GET` | `/incidents` | List all incidents (history) |
| `GET` | `/incidents/{id}` | Full incident details (enriched with live reputation + chain) |
| `GET` | `/incidents/{id}/pdf` | Download PDF report |
| `GET` | `/stats` | Dashboard statistics |
| `GET` | `/reputation/{source}` | Source reputation lookup |
| `GET` | `/reputation/blacklisted` | All blacklisted sources |
| `GET` | `/` | Health check |

---

<div align="center">

**Built with 🔒 by Team Zer0-Day — CSI RAIT, Aarohan '26**

</div>