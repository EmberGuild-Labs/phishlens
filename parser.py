import email
from email.policy import default as default_policy


def parse_headers(raw_text):
    """Parse raw email header text into a structured dict of all fields."""
    msg = email.message_from_string(raw_text, policy=default_policy)

    headers = {}
    for key in msg.keys():
        k = key.lower()
        val = msg.get_all(key, [])
        cleaned = [str(v).strip() for v in val]
        if k in headers:
            headers[k].extend(cleaned)
        else:
            headers[k] = cleaned

    result = {
        "all_headers": headers,
        "from": _first(headers, "from"),
        "to": _first(headers, "to"),
        "subject": _first(headers, "subject"),
        "date": _first(headers, "date"),
        "return_path": _first(headers, "return-path"),
        "reply_to": _first(headers, "reply-to"),
        "message_id": _first(headers, "message-id"),
        "x_mailer": _first(headers, "x-mailer"),
        "x_originating_ip": _first(headers, "x-originating-ip"),
        "received": headers.get("received", []),
        "authentication_results": headers.get("authentication-results", []),
        "dkim_signature": headers.get("dkim-signature", []),
    }

    return result


def _first(headers, key):
    vals = headers.get(key, [])
    return vals[0] if vals else None


def extract_email_domain(addr):
    """Extract the domain from an email address string like 'Name <user@domain.com>'."""
    if not addr:
        return None
    if "<" in addr and ">" in addr:
        addr = addr.split("<")[1].split(">")[0]
    if "@" in addr:
        return addr.split("@")[1].strip().lower()
    return None
