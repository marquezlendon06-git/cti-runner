"""
Blockchain tracing — Bitcoin and Ethereum address investigation.

Relevant for ransomware attribution, crypto-enabled C2 payments,
and sanctions/laundering path analysis (TRM-style work).
"""
import requests


def bitcoin_address(address: str) -> dict:
    """Query blockchain.info for BTC address activity — no API key needed."""
    try:
        r = requests.get(
            f"https://blockchain.info/rawaddr/{address}?limit=20",
            timeout=20,
            headers={"User-Agent": "CTI-Pivot-Agent/1.0"},
        )
        if r.status_code == 404:
            return {"error": "Address not found"}
        r.raise_for_status()
        data = r.json()

        txs = []
        for tx in data.get("txs", [])[:10]:
            inputs = [
                inp["prev_out"]["addr"]
                for inp in tx.get("inputs", [])
                if inp.get("prev_out") and inp["prev_out"].get("addr")
            ]
            outputs = [
                {"addr": out.get("addr"), "value_btc": out.get("value", 0) / 1e8}
                for out in tx.get("out", [])
                if out.get("addr")
            ]
            txs.append({
                "hash": tx.get("hash"),
                "time": tx.get("time"),
                "inputs": inputs,
                "outputs": outputs,
            })

        return {
            "address": address,
            "total_received_btc": data.get("total_received", 0) / 1e8,
            "total_sent_btc": data.get("total_sent", 0) / 1e8,
            "balance_btc": data.get("final_balance", 0) / 1e8,
            "transaction_count": data.get("n_tx"),
            "transactions": txs,
            "pivot_note": (
                "Pivot: follow output addresses across transactions to trace laundering hops. "
                "Look for consolidation addresses (many inputs, one output) = mixer/tumbler pattern. "
                "Check output addresses against known exchange deposit addresses."
            ),
        }
    except Exception as e:
        return {"error": str(e)}


def ethereum_address(address: str, api_key: str) -> dict:
    """Query Etherscan for ETH address activity."""
    try:
        r = requests.get(
            f"https://api.etherscan.io/api?module=account&action=txlist"
            f"&address={address}&sort=desc&apikey={api_key}&offset=20",
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()

        if data.get("status") == "0":
            return {"error": data.get("message", "Etherscan error"), "address": address}

        txs = []
        for tx in (data.get("result") or [])[:15]:
            txs.append({
                "hash": tx.get("hash"),
                "from": tx.get("from"),
                "to": tx.get("to"),
                "value_eth": int(tx.get("value", 0)) / 1e18,
                "timestamp": tx.get("timeStamp"),
                "function": tx.get("functionName", ""),
            })

        # Get balance
        bal_r = requests.get(
            f"https://api.etherscan.io/api?module=account&action=balance"
            f"&address={address}&tag=latest&apikey={api_key}",
            timeout=10,
        )
        balance_eth = 0
        if bal_r.status_code == 200:
            bal_data = bal_r.json()
            if bal_data.get("status") == "1":
                balance_eth = int(bal_data.get("result", 0)) / 1e18

        unique_counterparties = list({
            tx["to"] if tx["from"].lower() == address.lower() else tx["from"]
            for tx in txs
            if tx.get("from") and tx.get("to")
        })

        return {
            "address": address,
            "balance_eth": balance_eth,
            "transaction_count": len(txs),
            "transactions": txs,
            "unique_counterparties": unique_counterparties[:20],
            "pivot_note": (
                "Pivot: unique_counterparties → check each on Etherscan for exchange labels. "
                "Large inbound from many addresses = ransomware payment collection wallet. "
                "Single outbound to exchange = off-ramp attempt."
            ),
        }
    except Exception as e:
        return {"error": str(e)}
