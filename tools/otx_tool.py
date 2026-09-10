"""AlienVault OTX — community threat intelligence pulses."""
import requests

_BASE = "https://otx.alienvault.com/api/v1"

_TYPE_MAP = {
    "domain": "domain",
    "ip": "IPv4",
    "file": "file",
    "url": "url",
}


def lookup(indicator: str, indicator_type: str, api_key: str) -> dict:
    otx_type = _TYPE_MAP.get(indicator_type, "domain")
    headers = {"X-OTX-API-KEY": api_key}

    sections = ["general", "passive_dns"] if indicator_type != "file" else ["general", "analysis"]

    raw = {}
    for section in sections:
        try:
            r = requests.get(
                f"{_BASE}/indicators/{otx_type}/{indicator}/{section}",
                headers=headers,
                timeout=15,
            )
            if r.status_code == 200:
                raw[section] = r.json()
        except Exception:
            pass

    general = raw.get("general", {})
    pulse_info = general.get("pulse_info", {})
    pulses = pulse_info.get("pulses", [])

    pulse_summary = []
    for p in pulses[:15]:
        pulse_summary.append({
            "name": p.get("name"),
            "tlp": p.get("tlp"),
            "adversary": p.get("adversary", ""),
            "malware_families": [m.get("display_name") for m in p.get("malware_families", [])],
            "tags": p.get("tags", [])[:10],
            "created": p.get("created"),
            "industries": p.get("industries", []),
        })

    passive_dns = []
    for record in raw.get("passive_dns", {}).get("passive_dns", [])[:15]:
        passive_dns.append({
            "hostname": record.get("hostname"),
            "address": record.get("address"),
            "first_seen": record.get("first"),
            "last_seen": record.get("last"),
        })

    adversaries = list({p["adversary"] for p in pulse_summary if p.get("adversary")})
    malware_families = list({f for p in pulse_summary for f in p.get("malware_families", []) if f})

    return {
        "pulse_count": pulse_info.get("count", 0),
        "adversaries_mentioned": adversaries,
        "malware_families_mentioned": malware_families,
        "pulses": pulse_summary,
        "passive_dns": passive_dns,
        "pivot_note": (
            "adversaries_mentioned gives actor name candidates. "
            "Cross-reference pulse tags with MITRE ATT&CK group pages. "
            "malware_families_mentioned → look up those families for more C2 IOCs."
        ),
    }
