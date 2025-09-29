#!/usr/bin/env python3
"""
Scan Bitcoin blocks for reused ECDSA r-values (same 'r' across
different signatures) using the Blockstream public API.

Run:  python r_scan.py
"""

import requests, time, sys, collections

# -------- USER SETTINGS ----------
START_BLOCK = 69500      # change as needed
END_BLOCK   = 69600      # inclusive
PAUSE       = 1.0        # base seconds between block fetches
OUTPUT_FILE = "r_results.txt"
# ---------------------------------

# Simple exponential backoff on HTTP 429 or network errors
def get_with_backoff(url, retries=10, timeout=30):
    delay = PAUSE
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 429:
                print(f"429 Too Many Requests. Sleeping {delay:.1f}s...")
                time.sleep(delay)
                delay = min(delay * 2, 60)  # cap at 60s
                continue
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if attempt == retries - 1:
                raise
            print(f"Error {e}, retrying in {delay:.1f}s...")
            time.sleep(delay)
            delay = min(delay * 2, 60)

def extract_r_values(sigscript_hex):
    """Return list of r-values from a DER-encoded sigscript."""
    rvals = []
    i = 0
    while i + 4 < len(sigscript_hex):
        if sigscript_hex[i:i+2] != "30":
            break
        # total length
        total_len = int(sigscript_hex[i+2:i+4], 16) * 2
        der = sigscript_hex[i:i+4+total_len]
        # first integer (r)
        if der[4:6] == "02":
            rlen = int(der[6:8], 16) * 2
            rhex = der[8:8+rlen]
            rvals.append(rhex.lstrip("0"))
        i += 4 + total_len
    return rvals

def scan_blocks(start, end):
    repeated = collections.defaultdict(list)
    r_map = {}
    for h in range(start, end + 1):
        print(f"Block {h}")
        block = get_with_backoff(f"https://blockstream.info/api/block-height/{h}")
        block_hash = block if isinstance(block, str) else block.get("id", "")
        txids = get_with_backoff(f"https://blockstream.info/api/block/{block_hash}/txids")
        for txid in txids:
            tx = get_with_backoff(f"https://blockstream.info/api/tx/{txid}")
            for vin in tx.get("vin", []):
                sig = vin.get("scriptsig", "")
                if sig:
                    for rhex in extract_r_values(sig):
                        if rhex in r_map:
                            repeated[rhex].append((txid, vin.get("txid", "")))
                        else:
                            r_map[rhex] = txid
        time.sleep(PAUSE)  # polite pause
    return repeated

def main():
    reps = scan_blocks(START_BLOCK, END_BLOCK)
    if reps:
        with open(OUTPUT_FILE, "w") as f:
            for r, txs in reps.items():
                f.write(f"r={r}\n")
                for pair in txs:
                    f.write(f"   seen in: {pair}\n")
        print(f"\nDone. Reused r-values written to {OUTPUT_FILE}")
    else:
        print("\nNo reused r-values found in this range.")

if __name__ == "__main__":
    main()