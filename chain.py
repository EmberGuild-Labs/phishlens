import re
from email.utils import parsedate_to_datetime


def build_chain(received_headers):
    """Parse Received headers into an ordered delivery chain with delays."""
    hops = []

    for i, raw in enumerate(received_headers):
        hop = {
            "index": i,
            "raw": raw.strip(),
            "from_server": _extract_field(raw, "from"),
            "by_server": _extract_field(raw, "by"),
            "with_protocol": _extract_with(raw),
            "timestamp": None,
            "datetime": None,
        }

        ts = _extract_timestamp(raw)
        if ts:
            hop["timestamp"] = ts.isoformat()
            hop["datetime"] = ts

        hops.append(hop)

    # Received headers are in reverse order (most recent first)
    hops.reverse()

    for i in range(len(hops)):
        hops[i]["hop_number"] = i + 1

    delays = []
    for i in range(1, len(hops)):
        prev_dt = hops[i - 1].get("datetime")
        curr_dt = hops[i].get("datetime")
        if prev_dt and curr_dt:
            delta = (curr_dt - prev_dt).total_seconds()
            delays.append({
                "from_hop": i,
                "to_hop": i + 1,
                "delay_seconds": delta,
                "is_suspicious": delta > 3600,
            })
        else:
            delays.append({
                "from_hop": i,
                "to_hop": i + 1,
                "delay_seconds": None,
                "is_suspicious": False,
            })

    for hop in hops:
        hop.pop("datetime", None)

    return {"hops": hops, "delays": delays, "total_hops": len(hops)}


def _extract_field(text, field):
    pattern = rf'\b{field}\s+([\w.\-\[\]:]+(?:\s*\([^)]*\))?)'
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _extract_with(text):
    match = re.search(r'\bwith\s+(\w+)', text, re.IGNORECASE)
    return match.group(1) if match else None


def _extract_timestamp(text):
    match = re.search(r';\s*(.+)$', text, re.MULTILINE)
    if match:
        ts_str = match.group(1).strip()
        try:
            return parsedate_to_datetime(ts_str)
        except (ValueError, TypeError):
            pass
    return None
