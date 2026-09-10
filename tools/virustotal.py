"""VirusTotal v3 API — passive DNS, malware relationships, hash reports."""
import requests

_BASE = "https://www.virustotal.com/api/v3"


def _get(path: str, api_key: str) -> dict:
    r = requests.get(
        f"{_BASE}/{path}",
        headers={"x-apikey": api_key},
        timeout=20,
    )
    if r.status_code == 404:
        return {"error": "Not found in VirusTotal"}
    if r.status_code == 401:
        return {"error": "Invalid VirusTotal API key"}
    r.raise_for_status()
    return r.json()


def domain_report(domain: str, api_key: str) -> dict:
    data = _get(f"domains/{domain}", api_key)
    if "error" in data:
        return data

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    dns_data = _get(f"domains/{domain}/resolutions?limit=20", api_key)
    resolutions = []
    for item in dns_data.get("data", []):
        a = item.get("attributes", {})
        resolutions.append({
            "ip": a.get("ip_address"),
            "date": a.get("date"),
        })

    files_data = _get(f"domains/{domain}/communicating_files?limit=10", api_key)
    comm_files = []
    for item in files_data.get("data", []):
        a = item.get("attributes", {})
        threat = a.get("popular_threat_classification", {})
        comm_files.append({
            "sha256": item.get("id"),
            "name": a.get("meaningful_name") or (a.get("names") or ["unknown"])[0],
            "malware_label": threat.get("suggested_threat_label", "unknown"),
            "detection_ratio": f"{a.get('last_analysis_stats', {}).get('malicious', 0)}/{sum(a.get('last_analysis_stats', {}).values())}",
        })

    return {
        "reputation": attrs.get("reputation", 0),
        "malicious_detections": stats.get("malicious", 0),
        "total_engines": sum(stats.values()),
        "categories": attrs.get("categories", {}),
        "registrar": attrs.get("registrar"),
        "creation_date": attrs.get("creation_date"),
        "passive_dns": resolutions,
        "communicating_malware": comm_files,
        "tags": attrs.get("tags", []),
        "pivot_note": "Pivot: check each IP in passive_dns, look up each sha256 in communicating_malware for C2 network IOCs.",
    }


def ip_report(ip: str, api_key: str) -> dict:
    data = _get(f"ip_addresses/{ip}", api_key)
    if "error" in data:
        return data

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    dns_data = _get(f"ip_addresses/{ip}/resolutions?limit=20", api_key)
    domains_at_ip = []
    for item in dns_data.get("data", []):
        a = item.get("attributes", {})
        domains_at_ip.append({"domain": a.get("host_name"), "date": a.get("date")})

    files_data = _get(f"ip_addresses/{ip}/communicating_files?limit=10", api_key)
    comm_files = []
    for item in files_data.get("data", []):
        a = item.get("attributes", {})
        threat = a.get("popular_threat_classification", {})
        comm_files.append({
            "sha256": item.get("id"),
            "malware_label": threat.get("suggested_threat_label", "unknown"),
        })

    return {
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "network": attrs.get("network"),
        "reputation": attrs.get("reputation", 0),
        "malicious_detections": stats.get("malicious", 0),
        "domains_at_this_ip": domains_at_ip,
        "communicating_malware": comm_files,
        "tags": attrs.get("tags", []),
        "pivot_note": "Pivot: domains_at_this_ip reveals what else actor hosted here. Cross-reference with crt.sh on those domains.",
    }


def hash_report(file_hash: str, api_key: str) -> dict:
    data = _get(f"files/{file_hash}", api_key)
    if "error" in data:
        return data

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    domains_data = _get(f"files/{file_hash}/contacted_domains?limit=20", api_key)
    contacted_domains = [item.get("id") for item in domains_data.get("data", [])]

    ips_data = _get(f"files/{file_hash}/contacted_ips?limit=20", api_key)
    contacted_ips = [item.get("id") for item in ips_data.get("data", [])]

    threat = attrs.get("popular_threat_classification", {})

    return {
        "sha256": attrs.get("sha256"),
        "name": attrs.get("meaningful_name") or (attrs.get("names") or ["unknown"])[0],
        "file_type": attrs.get("type_description"),
        "size_bytes": attrs.get("size"),
        "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
        "malware_family": threat.get("suggested_threat_label", "unknown"),
        "first_seen": attrs.get("first_submission_date"),
        "last_seen": attrs.get("last_submission_date"),
        "contacted_domains": contacted_domains,
        "contacted_ips": contacted_ips,
        "tags": attrs.get("tags", []),
        "pivot_note": "Pivot: contacted_domains and contacted_ips are live C2 infrastructure. Look each up in Shodan and crt.sh.",
    }
