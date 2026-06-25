from parser import extract_email_domain


WEIGHTS = {
    "spf_fail": 25,
    "dkim_fail": 25,
    "dmarc_fail": 25,
    "from_return_path_mismatch": 20,
    "reply_to_mismatch": 10,
    "message_id_mismatch": 10,
    "suspicious_delay": 5,
    "no_auth_results": 8,
    "x_originating_ip_present": 5,
}


def score_indicators(parsed_headers, auth_results, chain_data):
    """Score phishing indicators and return findings with a total risk score."""
    findings = []
    total = 0

    spf = auth_results["spf"]["result"]
    if spf in ("fail", "softfail"):
        findings.append({
            "indicator": "SPF " + spf,
            "severity": "high",
            "detail": f"SPF returned {spf} — the sending server is not authorized to send for this domain.",
            "weight": WEIGHTS["spf_fail"],
        })
        total += WEIGHTS["spf_fail"]

    dkim = auth_results["dkim"]["result"]
    if dkim == "fail":
        findings.append({
            "indicator": "DKIM fail",
            "severity": "high",
            "detail": "DKIM signature verification failed — the email may have been modified in transit.",
            "weight": WEIGHTS["dkim_fail"],
        })
        total += WEIGHTS["dkim_fail"]

    dmarc = auth_results["dmarc"]["result"]
    if dmarc == "fail":
        findings.append({
            "indicator": "DMARC fail",
            "severity": "high",
            "detail": "DMARC evaluation failed — the email did not pass alignment checks.",
            "weight": WEIGHTS["dmarc_fail"],
        })
        total += WEIGHTS["dmarc_fail"]

    from_domain = extract_email_domain(parsed_headers.get("from"))
    return_path_domain = extract_email_domain(parsed_headers.get("return_path"))
    if from_domain and return_path_domain and from_domain != return_path_domain:
        findings.append({
            "indicator": "From / Return-Path mismatch",
            "severity": "high",
            "detail": f"From domain ({from_domain}) doesn't match Return-Path domain ({return_path_domain}).",
            "weight": WEIGHTS["from_return_path_mismatch"],
        })
        total += WEIGHTS["from_return_path_mismatch"]

    reply_to_domain = extract_email_domain(parsed_headers.get("reply_to"))
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        findings.append({
            "indicator": "Reply-To redirects to different domain",
            "severity": "medium",
            "detail": f"Reply-To ({reply_to_domain}) differs from From ({from_domain}).",
            "weight": WEIGHTS["reply_to_mismatch"],
        })
        total += WEIGHTS["reply_to_mismatch"]

    msg_id = parsed_headers.get("message_id", "")
    if msg_id and from_domain:
        msg_id_domain = None
        if "@" in msg_id:
            msg_id_domain = msg_id.split("@")[1].strip(">").strip().lower()
        if msg_id_domain and msg_id_domain != from_domain:
            findings.append({
                "indicator": "Message-ID domain mismatch",
                "severity": "medium",
                "detail": f"Message-ID domain ({msg_id_domain}) differs from From domain ({from_domain}).",
                "weight": WEIGHTS["message_id_mismatch"],
            })
            total += WEIGHTS["message_id_mismatch"]

    for delay in chain_data.get("delays", []):
        if delay.get("is_suspicious"):
            secs = delay["delay_seconds"]
            mins = round(secs / 60)
            findings.append({
                "indicator": f"Unusual delay between hop {delay['from_hop']} → {delay['to_hop']}",
                "severity": "low",
                "detail": f"{mins} minute delay between servers — may indicate queuing, greylisting, or evasion.",
                "weight": WEIGHTS["suspicious_delay"],
            })
            total += WEIGHTS["suspicious_delay"]

    if not auth_results["raw_results"]:
        findings.append({
            "indicator": "No Authentication-Results header",
            "severity": "low",
            "detail": "No Authentication-Results header found — SPF/DKIM/DMARC status unknown.",
            "weight": WEIGHTS["no_auth_results"],
        })
        total += WEIGHTS["no_auth_results"]

    if parsed_headers.get("x_originating_ip"):
        findings.append({
            "indicator": "X-Originating-IP present",
            "severity": "low",
            "detail": f"Originating IP: {parsed_headers['x_originating_ip']}",
            "weight": WEIGHTS["x_originating_ip_present"],
        })
        total += WEIGHTS["x_originating_ip_present"]

    total = min(total, 100)

    if total >= 50:
        risk_level = "high"
    elif total >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "score": total,
        "risk_level": risk_level,
        "findings": findings,
    }
