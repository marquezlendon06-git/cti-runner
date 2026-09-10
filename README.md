```
╔══════════════════════════════════════════════════════════════════════════════╗
║   ____  ____  ___       ____                                                ║
║  / ___|_   _||_ _|     |  _ \ _   _ _ __  _ __   ___ _ __                  ║
║ | |     | |  | |  ___  | |_) | | | | '_ \| '_ \ / _ \ '__|                 ║
║ | |___  | |  | | |___| |  _ <| |_| | | | | | | |  __/ |                    ║
║  \____|_|_| |___|      |_| \_\\__,_|_| |_|_| |_|\___|_|                    ║
║                                                                              ║
║          AI-Powered Cyber Threat Intelligence Agent  v1.0                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

An AI-powered CTI investigation agent. Drop in a seed indicator — domain, IP, file hash, or crypto wallet — and Claude pivots through cert transparency, passive DNS, WHOIS history, Shodan, VirusTotal, AlienVault OTX, urlscan.io, Intelligence X, and blockchain explorers to build a threat actor/campaign picture, then produces a finished Diamond Model intelligence report.

Built to **teach the CTI investigation workflow** by doing it:

> **Seed → infrastructure → malware → dark web → actor → campaign → finished report**

---

## The Pivot Methodology

This is what every pivot in the agent teaches. Read this before you run it.

### Phase 1 — Initial Enrichment

You have a single indicator. Your first job is to understand the landscape, not find the answer.

**What to check:**
- VirusTotal reputation and detection history
- AlienVault OTX pulses (has anyone written this up?)
- urlscan.io screenshots (what does it look like live?)

**What you're deciding:** Is this benign (stop early), known-bad with existing attribution (skip to verification), or unknown-bad (proceed with full investigation)?

---

### Phase 2 — Infrastructure Mapping

The goal is to find **more infrastructure linked to the same actor**. Actors reuse patterns.

#### Passive DNS
*"What IPs did this domain resolve to? What else resolved to those IPs?"*

- **Tool:** VT domain lookup → `passive_dns` field
- **Pivot:** Each IP in passive DNS → VT IP lookup → `domains_at_this_ip`
- **What you're looking for:** Multiple actor domains sharing the same IP = same campaign infrastructure

#### Certificate Transparency
*"What subdomains were issued certs? Do multiple actor domains share a certificate?"*

- **Tool:** crt.sh search
- **Pivot:** Each subdomain is a new lead; identical cert patterns across domains = same cert/actor
- **What you're looking for:** `staging.evil-c2.com`, `api.evil-c2.com`, `panel.evil-c2.com` = active C2 kit layout

#### WHOIS History
*"Same registrar? Same nameservers? Same registration date window?"*

- **Tool:** WHOIS lookup
- **Pivot:** Same registrar + nameserver pattern across multiple domains = infrastructure cluster
- **What you're looking for:** Domains registered on the same day, same registrar = batch registration = actor infrastructure buildout

#### Shodan Fingerprinting
*"What's running on the IP? What's the TLS cert CN? What's the HTTP title?"*

- **Tool:** Shodan IP lookup → Shodan search
- **Critical pivot:** `shodan_search` with `ssl.cert.subject.cn:evil-c2.com` → finds every IP presenting that cert → finds the full C2 cluster
- **Other pivots:** `http.title:"Cobalt Strike"`, `ssl.jarm:<fingerprint>`, custom HTTP headers
- **What you're looking for:** 5-20 IPs presenting identical configuration = actor's full infrastructure

#### urlscan.io Screenshots
*"What does the live infrastructure look like — without visiting it?"*

- **Tool:** urlscan search
- **What you're looking for:** Admin panel login pages, C2 dashboards, phishing kits, control panels with recognizable frameworks

---

### Phase 3 — Malware Linkage

Find the malware that connects this infrastructure to real intrusions.

- **VT communicating files:** What malware samples called home to this domain/IP?
- **VT hash lookup:** What family? What C2 infrastructure does the sample contact?
- **OTX pulses:** What campaigns use this family? What industry targets?

**The chain:** domain → malware hash → malware family → campaign → actor group

---

### Phase 3b — Dark Web Intelligence

Run Intelligence X on every significant indicator. Dark web hits reveal what surface-web sources miss:

- Ransomware leak site victim listings
- Ransom negotiation transcripts (often contain wallet addresses)
- Stolen credential dumps linked to the actor
- Actor aliases used on underground forums
- Infrastructure details posted in criminal markets

**Scan every preview field** for BTC/ETH wallet addresses — call the blockchain tracer immediately when one is found.

---

### Phase 4 — Actor Clustering

This is where CTI becomes attribution. You're looking for evidence that links multiple pieces of infrastructure to a single threat actor or group.

**Cluster signals (strongest → weakest):**

| Signal | Tool | Why it's strong |
|--------|------|-----------------|
| Same TLS cert CN across multiple IPs | Shodan search | Actors rarely recycle exact certs across campaigns |
| Identical JARM fingerprint cluster | Shodan `ssl.jarm:` | Same C2 framework version = same toolset |
| Same HTTP banner/title across IPs | Shodan search | Actors install the same panel, don't customize defaults |
| Same nameserver across domains | WHOIS | Actors reuse preferred DNS providers |
| Same registrar + creation date window | WHOIS | Batch registration = infrastructure buildout event |
| Same ASN/hosting provider | Shodan/VT | Actors stay with bulletproof hosts they trust |
| OTX pulses name same actor | OTX lookup | Community attribution — verify, don't trust blindly |

---

### Phase 5 — Campaign Mapping

Connect the dots into a timeline and victim picture.

**Questions to answer:**
- When was this infrastructure stood up? (WHOIS creation date)
- When was it first observed malicious? (VT first_seen, OTX first pulse date)
- Who are the victims? (OTX pulse industries, VT submission country data)
- What's the operation? (phishing → credential harvest? drive-by → dropper → RAT C2? ransomware deploy?)
- What's the scale? (number of hosts in Shodan cluster)

---

### Phase 6 — Finished Report

A finished intelligence product is **not a list of IOCs**. It is:
- A Diamond Model assessment (Adversary / Infrastructure / Capabilities / Victims)
- Blockchain wallet traces with transaction hop analysis
- Confidence levels per field (High / Medium / Low)
- Key analytical pivots that led to each finding
- Intelligence gaps — what you couldn't determine and why

The `generate_investigation_report` tool produces this as an HTML report saved to `reports/`.

---

## Blockchain Tracing

For ransomware attribution or crypto-payment tracing:

**Bitcoin pivot chain:**
```
Ransomware C2 domain
  → VT communicating files → malware hash
  → ransom note / IntelX dark web preview → BTC payment address
  → bitcoin_trace → output addresses (hop 1)
  → bitcoin_trace each output → consolidation address
  → consolidation address → exchange deposit address
  → [exchange KYC = actor identity]
```

**What to look for:**
- **Consolidation pattern:** Many inputs → one output = tumbler/mixer
- **Fan-out pattern:** One input → many outputs = payment distribution to laundering network
- **Exchange deposit:** Final address with many incoming, few outgoing = off-ramp

Traced wallets appear in the **Blockchain Traces** section of the report with address, role, balance, transaction count, and notable hops.

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Get API keys (all free tier)

| Service | Signup URL | Used for |
|---------|-----------|---------|
| Anthropic | https://console.anthropic.com | Agent reasoning (required) |
| VirusTotal | https://www.virustotal.com/gui/join-us | Passive DNS, malware |
| Shodan | https://account.shodan.io/register | Infrastructure fingerprinting |
| AlienVault OTX | https://otx.alienvault.com/accounts/register | Threat intel pulses |
| urlscan.io | https://urlscan.io/user/signup | Live scans |
| Intelligence X | https://intelx.io/account?tab=developer | Dark web / leaks / Telegram |
| Etherscan | https://etherscan.io/register | ETH tracing (optional) |

crt.sh and blockchain.info require no API key.

### 3. Configure
```bash
cp config.example.yaml config.yaml
# Edit config.yaml — add your API keys
```

### 4. Run
```bash
# Domain investigation
python cti-runner.py evil-c2.com

# IP investigation
python cti-runner.py 185.220.101.42 --type ip

# File hash investigation
python cti-runner.py d41d8cd98f00b204e9800998ecf8427e --type hash

# Bitcoin address tracing (ransomware attribution)
python cti-runner.py 115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn --type btc

# Ethereum address tracing
python cti-runner.py 0xAbC123... --type eth

# Custom config file
python cti-runner.py evil-c2.com --config /path/to/config.yaml
```

Reports go to `reports/`, raw pivot logs to `investigations/`.

---

## Practice Targets

Use these public, already-documented indicators to practice without hitting live malicious infrastructure:

| Target | Where to get indicators |
|--------|------------------------|
| APT28 / Fancy Bear | CISA Advisory AA23-108A — domains and IPs are public |
| Lazarus Group / North Korea | CISA Advisory AA22-011A |
| WannaCry ransomware | BTC wallet `115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn` (OFAC-listed) |
| Cobalt Strike C2s | Shodan: `product:"Cobalt Strike Beacon"` |
| Active malware distribution | https://urlhaus.abuse.ch/browse/ |
| Current phishing | https://openphish.com/feed.txt |
| Ransomware IOCs | https://github.com/MISP/misp-warninglists |

**Learning exercise:** Run the agent on a domain from a published threat report, then read the report afterward. Did the agent find the same infrastructure? Miss anything? Why?

---

## Learning Path

1. **Run alongside** — as the agent pivots, do the same pivots manually in the browser (crt.sh, VT, Shodan web UI). Compare what you find vs. what the agent finds.

2. **Write before reading** — after collecting data but before the agent generates the report, write your own 3-sentence assessment with confidence levels. Compare to the agent's report.

3. **Extend the agent** — add GreyNoise, Censys, RiskIQ Community, or Maltego lookups as new tools. Each extension teaches a new data source.

4. **Read finished reports** — study published CTI reports from Mandiant, CrowdStrike, Recorded Future, Microsoft MSTIC, or The DFIR Report. Reverse-engineer what pivots the analyst made from the indicators they list.

---

## Architecture

```
cti-runner.py
    │
    ├── SYSTEM_PROMPT — teaches investigation methodology to Claude
    ├── TOOLS — tool definitions (Claude selects which to call)
    │
    └── Investigation loop
          │
          ├── Claude reasons → selects tool + explains why
          ├── Tool executes → real API call
          ├── Result returned to Claude
          ├── Claude states finding + confidence + next pivot
          └── Repeat until generate_investigation_report
                    │
                    └── report.py → Diamond Model HTML → reports/
                                    ├── Infrastructure table
                                    ├── Blockchain Traces table
                                    ├── Capabilities & Victims
                                    └── Pivot chain + Gaps
```

---

## Reading List

- **The Diamond Model of Intrusion Analysis** (Caltagirone et al., 2013) — the reporting framework used here
- **SANS FOR578: Cyber Threat Intelligence** — gold standard CTI training
- **Recorded Future University** — free CTI fundamentals
- **Intelligence-Driven Incident Response** (Threat Intelligence book, 2017)
- **MITRE ATT&CK Groups** — actor profiles with technique mappings
- **The DFIR Report** — real intrusion cases with full technical detail
- **Mandiant APT reports** — reference-quality finished intelligence
