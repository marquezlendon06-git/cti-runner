"""Shodan — infrastructure fingerprinting and cluster discovery."""
import shodan as shodan_lib


def ip_lookup(ip: str, api_key: str) -> dict:
    try:
        api = shodan_lib.Shodan(api_key)
        host = api.host(ip)
        services = []
        for svc in host.get("data", [])[:10]:
            services.append({
                "port": svc.get("port"),
                "transport": svc.get("transport"),
                "product": svc.get("product"),
                "version": svc.get("version"),
                "banner": (svc.get("data", "")[:300] if svc.get("data") else None),
                "ssl_cn": svc.get("ssl", {}).get("cert", {}).get("subject", {}).get("CN") if svc.get("ssl") else None,
            })
        return {
            "ip": ip,
            "hostnames": host.get("hostnames", []),
            "org": host.get("org"),
            "isp": host.get("isp"),
            "asn": host.get("asn"),
            "country": host.get("country_name"),
            "city": host.get("city"),
            "ports": host.get("ports", []),
            "services": services,
            "tags": host.get("tags", []),
            "vulns": list(host.get("vulns", {}).keys())[:10],
            "last_update": host.get("last_update"),
            "pivot_note": (
                "Pivot: use SSL CN, unique banners, or HTTP titles in shodan_search to find "
                "other hosts with identical configuration. JARM fingerprint clusters reveal "
                "C2 framework reuse across actor infrastructure."
            ),
        }
    except shodan_lib.APIError as e:
        return {"error": str(e)}


def search(query: str, api_key: str) -> dict:
    try:
        api = shodan_lib.Shodan(api_key)
        results = api.search(query, limit=15)
        hosts = []
        for match in results.get("matches", []):
            hosts.append({
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "org": match.get("org"),
                "country": match.get("location", {}).get("country_name"),
                "hostnames": match.get("hostnames", []),
                "banner": (match.get("data", "")[:200] if match.get("data") else None),
                "asn": match.get("asn"),
            })
        return {
            "total_results": results.get("total", 0),
            "returned": len(hosts),
            "hosts": hosts,
            "pivot_note": (
                "High total_results on a specific query = actor has large infrastructure footprint. "
                "Low total (2-5) = tight, targeted deployment. Each host is a pivot candidate."
            ),
        }
    except shodan_lib.APIError as e:
        return {"error": str(e)}
