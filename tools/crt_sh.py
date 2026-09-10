"""Certificate transparency lookup via crt.sh — no API key required."""
import requests


def search(domain: str) -> dict:
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20,
            headers={"User-Agent": "CTI-Pivot-Agent/1.0"},
        )
        r.raise_for_status()
        results = r.json()

        names = set()
        issuers = set()
        for cert in results[:200]:
            for name in cert.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and name != domain and not name.startswith("*"):
                    names.add(name)
            raw_issuer = cert.get("issuer_name", "")
            for part in raw_issuer.split(","):
                if part.strip().startswith("O="):
                    issuers.add(part.strip()[2:])

        dates = [c.get("not_before", "") for c in results if c.get("not_before")]

        return {
            "total_certs": len(results),
            "unique_subdomains": sorted(names)[:60],
            "issuers": sorted(issuers - {""}),
            "oldest_cert": min(dates) if dates else None,
            "newest_cert": max(dates) if dates else None,
            "pivot_note": "Check unique_subdomains for staging/C2/panel subdomains that reveal actor infrastructure naming conventions.",
        }
    except Exception as e:
        return {"error": str(e)}
