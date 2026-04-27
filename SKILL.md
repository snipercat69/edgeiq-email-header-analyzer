# Email Header Analyzer

**Skill Name:** `email-header-analyzer`
**Version:** `1.0.0`
**Category:** Security / Email Forensics
**Price:** **Lifetime: $39** / Optional Monthly: $7/mo (includes all Pro features permanently)
**Author:** EdgeIQ Labs
**OpenClaw Compatible:** Yes — Python 3, pure stdlib, WSL + Linux

---

## What It Does

Parses and analyzes email headers (RFC 5322) to detect spoofing, phishing indicators, SPF/DKIM/DMARC authentication failures, routing anomalies, and suspicious origin servers. Extracts forensic details from headers to determine if an email is legitimate or a spoof/impersonation attempt.

> ⚠️ **Legal Notice:** Only analyze emails you own or have explicit authorization to audit. Not for intercepting or analyzing others' communications without consent.

---

## Features

- **SPF validation** — checks Sender Policy Framework authentication result
- **DKIM verification** — parses DKIM signature and verification result
- **DMARC analysis** — evaluates Domain-based Message Authentication policy
- **From/Reply-To mismatch detection** — flags when reply address differs from sender
- **Received headers path analysis** — traces email route across mail servers
- **Suspicious routing anomalies** — detects forged hops, unexpected relay chain
- **IP reputation lookup** — checks originating mail server IP against blocklists
- **Domain age/check** — flags newly registered domains in headers
- **Attachment analysis** — checks filenames, MIME types, content disposition
- **JSON export** — structured forensic report

---

## Tier Comparison

| Feature | Free | **Lifetime ($39)** | Optional Monthly ($7/mo) |
|---------|------|----------------|----------------------|
| Full header parse | ✅ (5 emails) | ✅ (unlimited) | ✅ (unlimited) |
| SPF/DKIM/DMARC check | ✅ | ✅ | ✅ |
| From/Reply-To mismatch | ✅ | ✅ | ✅ |
| Mail server IP reputation | ✅ | ✅ | ✅ |
| Domain age lookup | ✅ | ✅ | ✅ |
| Received path analysis | ✅ | ✅ | ✅ |
| Attachment metadata | ✅ | ✅ | ✅ |
| JSON export | ✅ | ✅ | ✅ |

---

## Installation

```bash
cp -r /home/guy/.openclaw/workspace/apps/email-header-analyzer ~/.openclaw/skills/email-header-analyzer
```

---

## Usage

### Basic header scan (free tier)

```bash
python3 email_analyzer.py --header "Received: from mail.example.com..."
```

### Paste raw headers from email (Pro)

```bash
EDGEIQ_EMAIL=your_email@gmail.com python3 email_analyzer.py \
  --file /path/to/raw_headers.txt --pro
```

### JSON report output

```bash
EDGEIQ_EMAIL=your_email@gmail.com python3 email_analyzer.py \
  --header "$(pbpaste)" --bundle --output email-report.json
```

### As OpenClaw Discord Command

In `#edgeiq-support` channel:
```
!emailheader Received: from server... Authentication-Results: spf=fail...
!emailheader --file /path/to/headers.txt --pro
```

---

## Parameters

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--header` | string | — | Raw email headers (single line or multi-line) |
| `--file` | string | — | Path to text file containing raw headers |
| `--pro` | flag | False | Enable Pro features |
| `--bundle` | flag | False | Enable Bundle features |
| `--output` | string | — | Write JSON report to file |

---

## Output Example

```
=== Email Header Analyzer ===
Analyzing headers for: phishing-suspicion@attacker.com

  [1m[91m🔴 SPF FAIL — sender IP not authorized[0m
    SPF Result: fail
    From domain: company.com
    Sender IP: 203.0.113.45 (not in SPF允许列表)
    Recommendation: Block or mark as suspicious

  [1m[93m🟡 DKIM: NONE (no signature found)[0m
    Risk: Email has no cryptographic authentication

  [1m[91m🔴 DMARC POLICY FAIL[0m
    Policy: reject
    Alignment: relaxed
    Result: SPF fail + DKIM none = DMARC fail

  [1m[93m🟡 FROM/REPLY-TO MISMATCH[0m
    From:  legitimate@company.com
    Reply-To: refund@attacker-domain.com
    Risk: Likely phishing or business email compromise

  [1m[92m✔[0m Received path looks normal (3 hops)
    Hop 1: mail.attacker.com [203.0.113.45]
    Hop 2: relay.example.net [198.51.100.23]
    Hop 3: mail.company.com [203.0.113.1]

  Threat Level: HIGH — Multiple authentication failures + Reply-To mismatch
```

---

## Authentication Results Explained

| Result | Meaning |
|--------|---------|
| SPF pass | Sender IP is authorized by the domain's SPF record |
| SPF fail | Sender IP is NOT authorized — likely spoofing |
| DKIM pass | Email digitally signed, signature valid |
| DKIM fail | Signature tampered or invalid |
| DMARC pass | Both SPF and DKIM aligned and passing |
| DMARC fail | Alignment failed — domain claimed but auth didn't match |

---

## Pro Upgrade

Full forensic analysis + IP reputation + domain age + path analysis:

👉 [Buy Lifetime — $39](https://buy.stripe.com/5kQ9AV65RfNHbQobMQ7wA0R)
👉 [Subscribe Monthly — $7/mo](https://buy.stripe.com/dRm7sN3XJdFzcUs2cg7wA1c)

---

## Support

Open a ticket in [#edgeiq-support](https://discord.gg/PaP7nsFUJT) or email [gpalmieri21@gmail.com](mailto:gpalmieri21@gmail.com)

---

## 🔗 More from EdgeIQ Labs

**edgeiqlabs.com** — Security tools, OSINT utilities, and micro-SaaS products for developers and security professionals.

- 🛠️ **Subdomain Hunter** — Passive subdomain enumeration via Certificate Transparency
- 📸 **Screenshot API** — URL-to-screenshot API for developers
- 🔔 **uptime.check** — URL uptime monitoring with alerts
- 🛡️ **headers.check** — HTTP security headers analyzer

👉 [Visit edgeiqlabs.com →](https://edgeiqlabs.com)
