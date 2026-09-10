"""WHOIS lookup — registration data for actor infrastructure analysis."""
import whois


def lookup(domain: str) -> dict:
    try:
        w = whois.whois(domain)

        def _first(val):
            if isinstance(val, list):
                return str(val[0]) if val else None
            return str(val) if val else None

        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": _first(w.creation_date),
            "expiration_date": _first(w.expiration_date),
            "updated_date": _first(w.updated_date),
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "registrant_org": w.org,
            "registrant_country": w.country,
            "emails": w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else []),
            "status": w.status if isinstance(w.status, list) else ([w.status] if w.status else []),
            "pivot_note": (
                "Cluster on: registrar, name_servers, registrant_org, emails. "
                "Actors often register domains in batches (same date, same registrar). "
                "Shared nameservers across domains = strong infrastructure link."
            ),
        }
    except Exception as e:
        return {"error": str(e), "domain": domain}
