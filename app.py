from flask import Flask, render_template, request, jsonify
from parser import parse_headers
from chain import build_chain
from auth import parse_auth_results
from indicators import score_indicators

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    raw_headers = data.get("headers", "").strip() if data else ""

    if not raw_headers:
        return jsonify({"error": "No headers provided"}), 400

    if len(raw_headers) > 100000:
        return jsonify({"error": "Headers too large (max 100KB)"}), 400

    parsed = parse_headers(raw_headers)
    chain_data = build_chain(parsed["received"])
    auth_results = parse_auth_results(
        parsed["authentication_results"],
        parsed["dkim_signature"],
    )
    indicator_results = score_indicators(parsed, auth_results, chain_data)

    return jsonify({
        "summary": {
            "from": parsed["from"],
            "to": parsed["to"],
            "subject": parsed["subject"],
            "date": parsed["date"],
            "return_path": parsed["return_path"],
            "reply_to": parsed["reply_to"],
            "message_id": parsed["message_id"],
            "x_mailer": parsed["x_mailer"],
            "x_originating_ip": parsed["x_originating_ip"],
        },
        "chain": chain_data,
        "auth": auth_results,
        "indicators": indicator_results,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
