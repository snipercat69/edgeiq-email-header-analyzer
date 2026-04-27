# 📧 EdgeIQ Email Header Analyzer

**Parse email headers to detect spoofing, phishing, and authentication failures.**

RFC 5322 header parsing, SPF/DKIM/DMARC analysis, From/Reply-To mismatch detection, Received path tracing, and IP reputation lookup — forensic email analysis in pure Python.

[![Project Stage](https://img.shields.io/badge/Stage-Beta-blue)](https://edgeiqlabs.com)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)

---

## What It Does

Parses raw email headers and produces a forensic report: SPF/DKIM/DMARC authentication results, routing anomalies, suspicious origin servers, and indicators of spoofing or impersonation.

> ⚠️ **Legal Notice:** Only analyze emails you own or have explicit authorization to audit.

---

## Key Features

- **SPF validation** — extracts and interprets SPF authentication results
- **DKIM verification** — parses DKIM signature and verification status
- **DMARC analysis** — evaluates Domain-based Message Authentication policy
- **From/Reply-To mismatch** — flags when reply address differs from sender
- **Received path analysis** — traces email route across mail servers
- **IP reputation lookup** — checks originating server IP against blocklists
- **Domain age analysis** — flags newly registered domains
- **JSON export** — structured forensic report

---

## Prerequisites

- Python 3.8+
- **Pure stdlib** — no external dependencies

---

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-email-header-analyzer.git
cd edgeiq-email-header-analyzer
# No pip install needed!
```

---

## Quick Start

```bash
# Analyze email headers from file
python3 email_analyzer.py --file headers.txt

# Analyze from stdin
cat headers.txt | python3 email_analyzer.py

# Verbose forensic output
python3 email_analyzer.py --file headers.txt --verbose --format json
```

---

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | 5 emails/month, basic analysis |
| **Lifetime** | $39 one-time | Unlimited, full forensic report, IP reputation |
| **Monthly** | $7/mo | All Lifetime features, billed monthly |

---

## Support

Open an issue at: https://github.com/snipercat69/edgeiq-email-header-analyzer/issues

---

*Part of EdgeIQ Labs — [edgeiqlabs.com](https://edgeiqlabs.com)*
