# PhishLens

An email header analyzer that parses raw email headers and produces a clear, visual breakdown of the full delivery chain, authentication results, and phishing indicators. Paste headers, get answers. Part of the [SentinelKit](https://github.com/EmberGuild-Labs/sentinelkit) ecosystem.

Live at: **[phishlens.proxnode.xyz](https://phishlens.proxnode.xyz)**

---

## Features

- Full `Received` header chain visualization — every server hop with timestamps and delays
- SPF result parsing — pass, fail, softfail, neutral, permerror
- DKIM signature validation status and selector display
- DMARC policy evaluation — p=none / quarantine / reject, and whether it passed
- `From` vs `Return-Path` vs `Reply-To` mismatch detection (common spoofing indicator)
- Message-ID analysis — checks if the domain matches the sending server
- X-Mailer and X-Originating-IP extraction
- Delay analysis — flags unusual gaps between hops that may indicate queuing or evasion
- Phishing indicator score — aggregates all findings into a risk rating
- Raw header display with syntax highlighting

---

## Tech Stack

| Layer | Tech |
|---|---|
| Backend | Python 3, Flask |
| Header parsing | Python `email` stdlib + custom parser |
| Frontend | Vanilla JS, HTML/CSS |
| Hosting | proxnode.xyz via ProxDeploy + Cloudflare Tunnel |

---

## Project Structure

```
phishlens/
├── app.py               # Flask app and routes
├── parser.py            # Raw header ingestion and field extraction
├── chain.py             # Received header chain builder and delay calculator
├── auth.py              # SPF, DKIM, DMARC result extractor
├── indicators.py        # Phishing indicator scoring logic
├── static/
│   ├── style.css
│   └── main.js
├── templates/
│   ├── index.html       # Header paste input page
│   └── results.html     # Analysis results page
├── requirements.txt
└── README.md
```

---

## Setup

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/EmberGuild-Labs/phishlens
cd phishlens
pip install -r requirements.txt
```

### Run locally

```bash
python app.py
```

App runs at `http://localhost:5000`.

### Deploy via ProxDeploy

1. Push to GitHub under EmberGuild-Labs
2. Open ProxDeploy at `proxnode.xyz`
3. Name: `phishlens`, Repo: `EmberGuild-Labs/phishlens`
4. Subdomain: `phishlens.proxnode.xyz`
5. Deploy

---

## How It Works

1. User pastes raw email headers into the input box
2. `parser.py` ingests the raw text using Python's `email` stdlib and extracts all named fields
3. `chain.py` pulls all `Received` headers, parses the `from`/`by`/`with`/`for` fields and timestamps, builds an ordered hop chain, and calculates delays between hops
4. `auth.py` extracts `Authentication-Results` headers and parses SPF, DKIM, and DMARC sub-results
5. `indicators.py` checks for mismatches between `From`, `Return-Path`, `Reply-To`, and the originating server; scores each finding by severity
6. Results are rendered as a visual delivery timeline plus an authentication summary and indicator report

---

## How to Get Raw Email Headers

**Gmail:** Open email → three-dot menu → "Show original" → copy the full text above the email body

**Outlook (web):** Open email → three-dot menu → "View" → "View message source"

**Apple Mail:** Open email → View menu → Message → "All Headers", or cmd+shift+H

**Thunderbird:** Open email → View menu → "Message Source" (ctrl+U)

---

## Phishing Indicator Scoring

Each finding is weighted and summed into a 0–100 risk score:

| Indicator | Weight |
|---|---|
| SPF fail or softfail | High |
| DKIM fail | High |
| DMARC fail | High |
| From/Return-Path domain mismatch | High |
| Reply-To redirects to different domain | Medium |
| Message-ID domain doesn't match sender | Medium |
| Unusual hop delay (>1 hour between servers) | Low |
| X-Originating-IP in a known bad range | Medium |
| Missing Authentication-Results entirely | Low |

---

## Use Cases

- Triaging suspicious emails without opening links or attachments
- Learning how email authentication (SPF/DKIM/DMARC) works in practice
- Investigating whether a sender address was spoofed
- Checking if your own domain's outbound email is authenticating correctly
- CTF email forensics challenges

---

## Roadmap

- [ ] IP reputation lookup on originating IPs
- [ ] Link extraction from header metadata and flagging against known phishing domains
- [ ] Side-by-side comparison of two email headers
- [ ] Export analysis as PDF report
- [ ] Sample phishing headers for demo/testing mode

---

## Part of SentinelKit

| Tool | URL | Purpose |
|---|---|---|
| **SentinelKit** | sentinelkit.proxnode.xyz | Hub |
| **ReconKit** | recon.proxnode.xyz | WHOIS + DNS |
| **ChainTrace** | trace.proxnode.xyz | Redirect tracing |
| **PhishLens** | phishlens.proxnode.xyz | Email header analysis |
| **TLSpy** | tlspy.proxnode.xyz | TLS inspection |

---

## License

MIT © EmberGuild-Labs
