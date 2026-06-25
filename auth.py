import re


def parse_auth_results(auth_headers, dkim_headers=None):
    """Parse Authentication-Results headers for SPF, DKIM, DMARC results."""
    result = {
        "spf": {"result": None, "detail": None},
        "dkim": {"result": None, "detail": None, "selector": None},
        "dmarc": {"result": None, "detail": None, "policy": None},
        "raw_results": [],
    }

    for header in auth_headers:
        result["raw_results"].append(header)
        _parse_spf(header, result["spf"])
        _parse_dkim(header, result["dkim"])
        _parse_dmarc(header, result["dmarc"])

    if dkim_headers:
        for dkim_sig in dkim_headers:
            sel_match = re.search(r's=([^;\s]+)', dkim_sig)
            if sel_match and not result["dkim"]["selector"]:
                result["dkim"]["selector"] = sel_match.group(1)

    return result


def _parse_spf(header, spf_result):
    match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', header, re.IGNORECASE)
    if match and not spf_result["result"]:
        spf_result["result"] = match.group(1).lower()
        detail = re.search(r'spf=\S+\s+([^;]+)', header, re.IGNORECASE)
        if detail:
            spf_result["detail"] = detail.group(1).strip()


def _parse_dkim(header, dkim_result):
    match = re.search(r'dkim=(pass|fail|none|neutral|temperror|permerror|policy)', header, re.IGNORECASE)
    if match and not dkim_result["result"]:
        dkim_result["result"] = match.group(1).lower()
        detail = re.search(r'dkim=\S+\s+([^;]+)', header, re.IGNORECASE)
        if detail:
            dkim_result["detail"] = detail.group(1).strip()

        sel_match = re.search(r'header\.\w*s=([^;\s]+)', header)
        if sel_match and not dkim_result["selector"]:
            dkim_result["selector"] = sel_match.group(1)


def _parse_dmarc(header, dmarc_result):
    match = re.search(r'dmarc=(pass|fail|none|bestguesspass|temperror|permerror)', header, re.IGNORECASE)
    if match and not dmarc_result["result"]:
        dmarc_result["result"] = match.group(1).lower()
        detail = re.search(r'dmarc=\S+\s+([^;]+)', header, re.IGNORECASE)
        if detail:
            dmarc_result["detail"] = detail.group(1).strip()

        policy_match = re.search(r'p=(none|quarantine|reject)', header, re.IGNORECASE)
        if policy_match:
            dmarc_result["policy"] = policy_match.group(1).lower()
