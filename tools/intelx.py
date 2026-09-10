"""
Intelligence X (intelx.io) — dark web, paste sites, leaks, Telegram, forums.

Free API key: https://intelx.io/account?tab=developer
Free tier gives limited results per search but covers all source types.
"""
import time
import requests

_BASE = "https://free.intelx.io"

MEDIA_LABELS = {
    1:  "Paste Sites",
    2:  "C2 URLs",
    7:  "Dark Web",
    8:  "Forums",
    9:  "IRC",
    10: "GitHub",
    13: "Leaks / Dumps",
    14: "Telegram",
    21: "I2P",
    22: "Freenet",
}


def search(indicator: str, api_key: str, max_results: int = 10) -> dict:
    headers = {"x-key": api_key, "User-Agent": "CTI-Runner/1.0"}

    # Step 1 — submit search
    try:
        r = requests.post(
            f"{_BASE}/intelligent/search",
            headers=headers,
            json={
                "term": indicator,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": max_results,
                "timeout": 0,
                "datefrom": "",
                "dateto": "",
                "sort": 4,  # newest first
                "media": 0,
                "terminate": [],
            },
            timeout=20,
        )
        r.raise_for_status()
        search_id = r.json().get("id")
        if not search_id:
            return {"error": "IntelX returned no search ID", "raw": r.json()}
    except Exception as e:
        return {"error": f"IntelX search failed: {e}"}

    # Step 2 — poll for results (up to 3 attempts, 1 s apart)
    records = []
    for _ in range(3):
        time.sleep(1)
        try:
            res = requests.get(
                f"{_BASE}/intelligent/search/result",
                params={"id": search_id, "limit": max_results, "offset": 0},
                headers=headers,
                timeout=20,
            )
            res.raise_for_status()
            data = res.json()
            records = data.get("records") or []
            if records or data.get("status") == 0:
                break
        except Exception as e:
            return {"error": f"IntelX result fetch failed: {e}"}

    # Step 3 — fetch a short text preview for each record
    results = []
    for rec in records[:8]:
        media    = rec.get("media", 0)
        storage  = rec.get("storageid", "")
        bucket   = rec.get("bucket", "")
        preview  = None

        if storage and bucket:
            try:
                p = requests.get(
                    f"{_BASE}/file/preview",
                    params={
                        "f": 0,
                        "storageid": storage,
                        "bucket": bucket,
                        "e": 1,
                        "lines": 10,
                        "maxlines": 10,
                        "k": api_key,
                    },
                    headers=headers,
                    timeout=10,
                )
                if p.status_code == 200 and p.text.strip():
                    preview = p.text.strip()[:600]
            except Exception:
                pass

        results.append({
            "name":       rec.get("name", ""),
            "date":       rec.get("date", ""),
            "source":     MEDIA_LABELS.get(media, f"type-{media}"),
            "bucket":     bucket,
            "storage_id": storage,
            "size_bytes": rec.get("size", 0),
            "preview":    preview,
        })

    # Summarise hit distribution by source type
    source_counts: dict[str, int] = {}
    for r in results:
        src = r["source"]
        source_counts[src] = source_counts.get(src, 0) + 1

    return {
        "indicator":     indicator,
        "total_hits":    len(results),
        "sources":       source_counts,
        "results":       results,
        "pivot_note": (
            "Scan every preview field for: BTC/ETH wallet addresses, victim org names, "
            "negotiation chat excerpts, actor aliases, credentials, and infrastructure "
            "not visible on the surface web. Dark Web and Leaks hits are highest value."
        ),
    }
