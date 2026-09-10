#!/usr/bin/env python3
"""
CTI-Runner Agent
----------------
AI-powered CTI investigation agent. Takes a seed indicator and pivots
through cert transparency, passive DNS, WHOIS, Shodan, VirusTotal, OTX,
and urlscan.io to build a threat actor/campaign picture, then produces
a finished Diamond Model intelligence report.

Usage:
    python cti-runner.py evil-c2.com
    python cti-runner.py 185.220.101.42 --type ip
    python cti-runner.py d41d8cd98f00b204e9800998ecf8427e --type hash
    python cti-runner.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfna --type btc
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
import yaml

from tools import crt_sh, virustotal, whois_tool, shodan_tool, urlscan_tool, otx_tool, blockchain, intelx
import report as report_gen


# ── Config ─────────────────────────────────────────────────────────────────────

def load_config(path: str = "config.yaml") -> dict:
    p = Path(path)
    if not p.exists():
        print(f"[!] {path} not found.\n    Copy config.example.yaml → config.yaml and add your API keys.")
        sys.exit(1)
    with open(p) as f:
        return yaml.safe_load(f)


# ── Tool definitions (Claude sees these) ──────────────────────────────────────

TOOLS = [
    {
        "name": "cert_transparency_search",
        "description": (
            "Search certificate transparency logs (crt.sh) for a domain. "
            "Returns subdomains and certificate issuance history. "
            "Use to discover actor infrastructure: staging servers, C2 panels, "
            "phishing domains sharing the same certificate pattern. No API key required."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Root domain (e.g. 'example.com')"}
            },
            "required": ["domain"],
        },
    },
    {
        "name": "virustotal_domain",
        "description": (
            "Query VirusTotal for a domain: reputation score, passive DNS history "
            "(which IPs it resolved to and when), communicating malware files, "
            "and detection verdicts. "
            "Use to check if a domain is malicious, find the IPs it resolved to "
            "(pivot to those IPs), and find malware that called home to it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    {
        "name": "virustotal_ip",
        "description": (
            "Query VirusTotal for an IP: reputation, passive DNS (domains that resolved "
            "to this IP and when), communicating malware files, ASN, and organization. "
            "Use to find what else was hosted at this IP — actor infrastructure cluster discovery."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    },
    {
        "name": "virustotal_hash",
        "description": (
            "Query VirusTotal for a file hash: malware family name, detection ratio, "
            "C2 domains and IPs the file contacts (extracted from sandbox behavior). "
            "Use to identify malware family and pivot to live C2 infrastructure."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "MD5, SHA1, or SHA256"}
            },
            "required": ["hash"],
        },
    },
    {
        "name": "whois_lookup",
        "description": (
            "Query WHOIS for domain registration data: registrar, creation date, "
            "expiration, nameservers, registrant org and email. "
            "Use to cluster infrastructure (actors often register domains in batches "
            "with the same registrar/nameservers), identify privacy-protected vs. exposed "
            "registrants, and find registration date patterns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    {
        "name": "shodan_ip_lookup",
        "description": (
            "Query Shodan for a host: open ports, running services, software versions, "
            "TLS certificate details, HTTP banners, ASN, and organization. "
            "Use to fingerprint actor infrastructure — what C2 framework are they running? "
            "What's the SSL cert CN? These become pivot points to find related hosts."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    },
    {
        "name": "shodan_search",
        "description": (
            "Search Shodan to find hosts matching a query string. "
            "Use to cluster infrastructure by shared attributes: "
            "TLS cert CN ('ssl.cert.subject.cn:evil-c2.com'), "
            "HTTP title ('http.title:\"Cobalt Strike Team Server\"'), "
            "banner strings ('Havoc'), or JARM fingerprints ('ssl.jarm:...'). "
            "This is the pivot that turns one host into a campaign-wide infrastructure map."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Shodan search query"}
            },
            "required": ["query"],
        },
    },
    {
        "name": "urlscan_search",
        "description": (
            "Search urlscan.io for scans matching a domain, IP, or page characteristic. "
            "Returns live/historical scan results with screenshots, page titles, and "
            "network connections — without visiting the site yourself. "
            "Example queries: 'domain:evil-c2.com', 'page.title:\"Admin Panel\"', 'ip:1.2.3.4'. "
            "Use to see C2 panels, phishing kits, or actor infrastructure in action."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "urlscan.io search query"}
            },
            "required": ["query"],
        },
    },
    {
        "name": "otx_lookup",
        "description": (
            "Query AlienVault OTX for community threat intelligence pulses related to "
            "a domain, IP, file hash, or URL. Shows which threat actors or campaigns have "
            "used this indicator, malware families, industry targeting, and passive DNS. "
            "Use to get actor name candidates and cross-reference with MITRE ATT&CK groups."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string"},
                "indicator_type": {
                    "type": "string",
                    "enum": ["domain", "ip", "file", "url"],
                },
            },
            "required": ["indicator", "indicator_type"],
        },
    },
    {
        "name": "bitcoin_trace",
        "description": (
            "Trace a Bitcoin address: balance, transaction count, and the last 10 transactions "
            "with input/output addresses. Use for ransomware attribution, crypto payment tracing, "
            "or following laundering hops. Input/output addresses are pivot points."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Bitcoin address"}
            },
            "required": ["address"],
        },
    },
    {
        "name": "ethereum_trace",
        "description": (
            "Trace an Ethereum address: balance, transaction history, and counterparty addresses. "
            "Use to follow ETH/ERC-20 payments, identify exchange off-ramps, or trace "
            "smart contract interactions linked to threat actor infrastructure payments."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Ethereum address (0x...)"}
            },
            "required": ["address"],
        },
    },
    {
        "name": "intelx_search",
        "description": (
            "Search Intelligence X for an indicator across dark web forums, paste sites, "
            "Telegram channels, leak/dump databases, I2P, Freenet, and GitHub. "
            "Returns source type, date, and a short text preview of each hit. "
            "Use on every domain, IP, hash, actor name, or email you find — dark web hits "
            "reveal victim lists, ransom negotiation logs, stolen credentials, actor aliases, "
            "and wallet addresses not visible on the surface web. "
            "Always scan preview text for BTC/ETH addresses and call bitcoin_trace/ethereum_trace "
            "on any wallet found."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "Domain, IP, hash, actor name, email, or any string to search",
                }
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "generate_investigation_report",
        "description": (
            "Generate a finished Diamond Model intelligence report from all investigation findings. "
            "Call this when you have gathered sufficient evidence for attribution, or have "
            "exhausted useful pivots. Produces a Markdown report with confidence levels per field."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "narrative": {
                    "type": "string",
                    "description": (
                        "Plain-prose analyst narrative, 3-5 sentences. "
                        "Tell the story of what was found: name the seed indicator, what the actor was doing "
                        "(campaign/operation), the infrastructure (IP, hosting provider), the malware families, "
                        "the actor attribution, and the pivot chain that connected them "
                        "(e.g. 'seed domain → C2 IP → malware family → actor attribution'). "
                        "Write it as a human analyst would brief a colleague — specific, factual, no bullet points."
                    ),
                },
                "summary": {
                    "type": "string",
                    "description": "2-4 sentence executive summary of what was found and the bottom-line assessment.",
                },
                "adversary": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "aliases": {"type": "array", "items": {"type": "string"}},
                        "confidence": {
                            "type": "string",
                            "enum": ["High", "Medium", "Low", "Unattributed"],
                        },
                    },
                    "required": ["name", "confidence"],
                },
                "infrastructure": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "indicator": {"type": "string"},
                            "type": {"type": "string", "description": "domain, ip, hash, url, btc_address, etc."},
                            "role": {"type": "string", "description": "C2, phishing, dropper-hosting, proxy, payment-wallet, etc."},
                            "confidence": {"type": "string", "enum": ["High", "Medium", "Low"]},
                        },
                        "required": ["indicator", "type", "role", "confidence"],
                    },
                },
                "capabilities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "type": {"type": "string", "description": "malware, tool, TTP"},
                            "mitre_technique": {"type": "string", "description": "e.g. T1059.001 or null"},
                            "confidence": {"type": "string", "enum": ["High", "Medium", "Low"]},
                        },
                        "required": ["name", "type", "confidence"],
                    },
                },
                "victims": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "sector": {"type": "string"},
                            "region": {"type": "string"},
                            "confidence": {"type": "string", "enum": ["High", "Medium", "Low"]},
                        },
                        "required": ["sector", "region", "confidence"],
                    },
                },
                "pivots": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Key analytical pivots that led to findings, in order performed.",
                },
                "key_findings": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Top 5-8 findings, each a complete analytical statement.",
                },
                "overall_confidence": {
                    "type": "string",
                    "enum": ["High", "Medium", "Low"],
                },
                "gaps": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Known gaps: what could not be determined and why.",
                },
                "blockchain": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "address": {"type": "string"},
                            "coin": {"type": "string", "description": "btc or eth"},
                            "role": {"type": "string", "description": "e.g. ransom payment wallet, consolidation address, exchange deposit, mixer"},
                            "balance": {"type": "string", "description": "Current balance with unit, e.g. '0.52 BTC'"},
                            "total_received": {"type": "string", "description": "Total received with unit"},
                            "tx_count": {"type": "integer"},
                            "notable_hops": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Key transaction hops, e.g. 'victim payment → consolidation wallet → Binance deposit'",
                            },
                            "confidence": {"type": "string", "enum": ["High", "Medium", "Low"]},
                        },
                        "required": ["address", "coin", "role", "confidence"],
                    },
                    "description": "Cryptocurrency wallet traces from bitcoin_trace / ethereum_trace calls.",
                },
            },
            "required": [
                "narrative", "summary", "adversary", "infrastructure", "capabilities",
                "victims", "pivots", "key_findings", "overall_confidence", "gaps",
            ],
        },
    },
]


# ── System prompt — teaches the methodology ────────────────────────────────────

SYSTEM_PROMPT = """You are a senior Cyber Threat Intelligence analyst. Your task is to conduct a structured CTI investigation from a seed indicator, following professional analytical tradecraft.

## Investigation Methodology

### Phase 1 — Initial Enrichment
Check the seed indicator across multiple sources immediately. Goal: understand what you're dealing with and decide which pivots have the most analytical value.
- Is it known malicious? Since when?
- What context do OTX pulses provide?
- What data sources have the most signal for this indicator type?

### Phase 2 — Infrastructure Mapping
Find the hosting infrastructure and cluster it to the same actor.
- **Passive DNS** (VT, OTX): What IPs did this domain resolve to? What else resolved to those same IPs?
- **Cert transparency** (crt.sh): What subdomains exist? Do multiple actor domains share a certificate pattern?
- **WHOIS**: Same registrar? Same nameservers? Same registration date batch?
- **Shodan**: What's running on the IP? Use SSL cert CN, HTTP title, or JARM fingerprint to find related hosts.
- **urlscan.io**: Screenshot the infrastructure — C2 panel? Phishing kit? Admin page?

### Phase 3 — Malware Linkage
Find the malware. Find the C2 chain.
- **VT communicating files**: What samples called this domain/IP?
- **VT hash lookup**: What malware family? What C2 infrastructure does it contact?
- **OTX pulses**: What campaigns use this malware family?

### Phase 3b — Dark Web Intelligence
Run `intelx_search` on every significant indicator: the seed, any actor name surfaced by OTX, key C2 domains, and file hashes. Dark web hits reveal what surface-web sources miss:
- Ransomware leak site victim listings
- Ransom negotiation transcripts (often contain wallet addresses)
- Stolen credential dumps linked to the actor
- Actor aliases used on underground forums
- Infrastructure details posted in criminal markets
Always scan every `preview` field returned by IntelX for BTC/ETH wallet addresses and call the appropriate trace tool immediately when one is found.

### Phase 4 — Actor Clustering
Connect infrastructure to a threat group. Look for:
- Shared TLS certificate CN across multiple IPs
- Identical Shodan banners, HTTP headers, or page titles
- JARM fingerprint clusters (same C2 framework version = same actor)
- Registration pattern reuse (same registrar, nameserver, creation date window)
- ASN/hosting provider reuse (some actors strongly prefer certain bullet-proof hosts)

### Phase 5 — Campaign Mapping
- Timeline: when was infrastructure active? (WHOIS dates, first VT/OTX seen)
- Victims: who submitted samples to VT? What sectors/regions in OTX pulses?
- Scale: how many hosts? How distributed?

### Phase 6 — Report
Call generate_investigation_report when you have enough for a defensible assessment.
Populate the `blockchain` array with every wallet you traced via bitcoin_trace or ethereum_trace:
include the address, coin type, role, balance, tx_count, and the key transaction hops you observed.

## Analyst Communication Format

Before each tool call, state in 1-2 lines:
**Why:** what analytical question this answers
**Expected:** what you expect to find

After each result, state:
**Finding:** what the data shows
**Confidence:** High/Medium/Low
**Next pivot:** what this unlocks

## Confidence Levels
- **High**: Confirmed by 2+ independent sources; no significant alternative explanation
- **Medium**: Supported by available data; gaps remain
- **Low**: Single source or inference; assess with caution
- **Unattributed**: Insufficient data

## Blockchain Tracing

Actively scan ALL text returned by every tool — OTX pulse descriptions, VT tags, urlscan page content, WHOIS emails — for cryptocurrency wallet addresses:
- Bitcoin: starts with `1`, `3`, or `bc1` — typically 26-62 characters
- Ethereum: starts with `0x` — 42 characters

When you find a wallet address in any result, call `bitcoin_trace` or `ethereum_trace` on it immediately. Do not wait. Ransomware groups always move money through wallets — finding and tracing a wallet is a key investigative step.

After tracing, look at the output addresses and trace the most significant hop (largest value, fewest outputs) one level deeper to find consolidation or exchange deposit addresses.

## Stopping Criteria
Stop pivoting and generate the report when:
- You have attributed to a known actor with Medium+ confidence, OR
- You have mapped the full infrastructure cluster and malware family, OR
- You have made 15+ pivots with diminishing returns, OR
- You hit dead ends on all remaining pivot candidates

Do NOT generate the report after fewer than 4 tool calls unless the indicator is clearly benign."""


# ── Tool dispatcher ────────────────────────────────────────────────────────────

def dispatch(name: str, inp: dict, cfg: dict, seed: str) -> str:
    vt  = cfg.get("virustotal_api_key", "")
    sh  = cfg.get("shodan_api_key", "")
    otx = cfg.get("otx_api_key", "")
    url = cfg.get("urlscan_api_key", "")
    eth = cfg.get("etherscan_api_key", "")
    ix  = cfg.get("intelx_api_key", "")

    try:
        if name == "cert_transparency_search":
            result = crt_sh.search(inp["domain"])
        elif name == "virustotal_domain":
            result = virustotal.domain_report(inp["domain"], vt)
        elif name == "virustotal_ip":
            result = virustotal.ip_report(inp["ip"], vt)
        elif name == "virustotal_hash":
            result = virustotal.hash_report(inp["hash"], vt)
        elif name == "whois_lookup":
            result = whois_tool.lookup(inp["domain"])
        elif name == "shodan_ip_lookup":
            result = shodan_tool.ip_lookup(inp["ip"], sh)
        elif name == "shodan_search":
            result = shodan_tool.search(inp["query"], sh)
        elif name == "urlscan_search":
            result = urlscan_tool.search(inp["query"], url)
        elif name == "otx_lookup":
            result = otx_tool.lookup(inp["indicator"], inp["indicator_type"], otx)
        elif name == "intelx_search":
            result = intelx.search(inp["indicator"], ix)
        elif name == "bitcoin_trace":
            result = blockchain.bitcoin_address(inp["address"])
        elif name == "ethereum_trace":
            result = blockchain.ethereum_address(inp["address"], eth)
        elif name == "generate_investigation_report":
            # Claude sometimes flattens the adversary object into top-level keys
            # or sends adversary as a plain string — normalize before calling.
            if isinstance(inp.get("adversary"), str):
                inp["adversary"] = {
                    "name": inp.get("adversary", "Unknown").strip().lstrip("\n"),
                    "aliases": inp.pop("aliases", []),
                    "confidence": inp.pop("confidence", "Low"),
                }
            elif isinstance(inp.get("adversary"), dict):
                # Hoist any stray top-level aliases/confidence into the object
                if "aliases" in inp and "aliases" not in inp["adversary"]:
                    inp["adversary"]["aliases"] = inp.pop("aliases")
                if "confidence" in inp and "confidence" not in inp["adversary"]:
                    inp["adversary"]["confidence"] = inp.pop("confidence")

            # Fill in any missing required fields so a partial call still produces a report
            inp.setdefault("infrastructure", [])
            inp.setdefault("capabilities", [])
            inp.setdefault("victims", [])
            inp.setdefault("pivots", [])
            inp.setdefault("key_findings", [])
            inp.setdefault("overall_confidence",
                           inp.get("adversary", {}).get("confidence", "Low"))
            inp.setdefault("gaps", [
                "Report was generated from a partial tool call — "
                "some fields may be incomplete. See investigation log for full pivot chain."
            ])
            inp.setdefault("narrative", inp.get("summary", ""))

            # Print the narrative prominently before saving the report
            narrative = inp.get("narrative", "")
            if narrative:
                width = 60
                print("\n" + "=" * width)
                print("  ANALYST NARRATIVE")
                print("=" * width)
                # Word-wrap to fit terminal
                import textwrap
                for line in textwrap.wrap(narrative, width=width - 2):
                    print(f"  {line}")
                print("=" * width + "\n")

            html = report_gen.generate_report(seed_indicator=seed, **inp)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            safe_seed = seed.replace("/", "_").replace(":", "_")[:40]
            out = Path("reports") / f"{safe_seed}_{ts}.html"
            out.parent.mkdir(exist_ok=True)
            out.write_text(html, encoding="utf-8")
            print(f"\n{'='*60}")
            print(f"  Report saved: {out}")
            print(f"{'='*60}\n")
            import webbrowser
            webbrowser.open(out.resolve().as_uri())
            return json.dumps({"status": "report_generated", "path": str(out)})
        else:
            return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return json.dumps({"error": f"{name} failed: {type(e).__name__}: {e}"})

    return json.dumps(result, default=str)


# ── Main investigation loop ────────────────────────────────────────────────────

def run(seed: str, seed_type: str, cfg: dict):
    client = anthropic.Anthropic(api_key=cfg["anthropic_api_key"])

    print(f"\n{'='*60}")
    print(f"  CTI-Pivot Agent")
    print(f"  Seed: {seed} [{seed_type}]")
    print(f"  Started: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*60}\n")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_seed = seed.replace("/", "_").replace(":", "_")[:40]
    log_path = Path("investigations") / f"{safe_seed}_{ts}.jsonl"
    log_path.parent.mkdir(exist_ok=True)

    messages = [
        {
            "role": "user",
            "content": (
                f"Conduct a CTI investigation from this seed indicator:\n\n"
                f"**{seed_type.upper()}:** `{seed}`\n\n"
                f"Follow the investigation methodology. Pivot through available sources, "
                f"build the infrastructure and actor picture, and generate a finished "
                f"Diamond Model report when ready."
            ),
        }
    ]

    iteration = 0
    max_iterations = 35

    while iteration < max_iterations:
        iteration += 1

        response = client.messages.create(
            model="claude-sonnet-5",
            max_tokens=8192,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"i": iteration, "stop": response.stop_reason}) + "\n")

        for block in response.content:
            if block.type == "text" and block.text.strip():
                print(f"\n[Analyst]\n{block.text}\n")

        if response.stop_reason == "end_turn":
            print("[+] Investigation complete.")
            break

        # When max_tokens is hit, inject a wrap-up prompt so the next
        # iteration triggers report generation rather than more pivots.
        if response.stop_reason == "max_tokens":
            print("[!] max_tokens hit — prompting agent to wrap up.")
            messages.append({"role": "assistant", "content": response.content})
            messages.append({
                "role": "user",
                "content": (
                    "You hit the output limit mid-response. "
                    "Summarize what you have found so far and call "
                    "generate_investigation_report now with the evidence collected."
                ),
            })
            continue

        if response.stop_reason != "tool_use":
            print(f"[!] Unexpected stop: {response.stop_reason}")
            break

        tool_results = []
        report_done = False

        for block in response.content:
            if block.type != "tool_use":
                continue

            print(f"  → {block.name}({json.dumps(block.input, separators=(',',':'))})")
            result_str = dispatch(block.name, block.input, cfg, seed)

            try:
                rd = json.loads(result_str)
                if "error" in rd:
                    print(f"     [!] {rd['error']}")
                elif "status" in rd:
                    print(f"     [+] {rd['status']}: {rd.get('path', '')}")
                else:
                    print(f"     [+] {list(rd.keys())[:5]}")
            except Exception:
                pass

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result_str,
            })

            if block.name == "generate_investigation_report":
                report_done = True

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

        if report_done:
            print(f"[+] Investigation log: {log_path}")
            return

    if iteration >= max_iterations:
        print(f"[!] Reached max iterations ({max_iterations}).")

    print(f"[+] Investigation log: {log_path}")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CTI-Runner: AI-powered CTI investigation agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("indicator", help="Seed indicator to investigate")
    parser.add_argument(
        "--type",
        choices=["domain", "ip", "hash", "url", "btc", "eth"],
        default="domain",
        help="Indicator type (default: domain)",
    )
    parser.add_argument("--config", default="config.yaml", help="Config file path")
    args = parser.parse_args()

    cfg = load_config(args.config)
    run(args.indicator, args.type, cfg)


if __name__ == "__main__":
    main()
