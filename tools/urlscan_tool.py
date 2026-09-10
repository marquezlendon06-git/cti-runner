"""urlscan.io — live and historical infrastructure scans with screenshots."""
import requests


def search(query: str, api_key: str = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["API-Key"] = api_key

    try:
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q={query}&size=10",
            headers=headers,
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()

        results = []
        for item in data.get("results", []):
            page = item.get("page", {})
            results.append({
                "url": page.get("url"),
                "domain": page.get("domain"),
                "ip": page.get("ip"),
                "title": page.get("title"),
                "status_code": page.get("status"),
                "scan_time": item.get("task", {}).get("time"),
                "screenshot_url": item.get("screenshot"),
                "scan_uuid": item.get("_id"),
                "result_url": f"https://urlscan.io/result/{item.get('_id')}/",
            })

        return {
            "total": data.get("total"),
            "results": results,
            "pivot_note": (
                "screenshot_url lets you see live C2 panels or phishing kits without visiting them. "
                "result_url gives full network map. Shared page titles across IPs = same actor kit."
            ),
        }
    except Exception as e:
        return {"error": str(e)}
