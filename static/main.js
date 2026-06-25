const form = document.getElementById("analyze-form");
const headersInput = document.getElementById("headers-input");
const analyzeBtn = document.getElementById("analyze-btn");
const loading = document.getElementById("loading");
const errorMsg = document.getElementById("error-msg");
const results = document.getElementById("results");

document.getElementById("how-to-toggle").addEventListener("click", () => {
    document.getElementById("how-to-content").classList.toggle("hidden");
});

form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const headers = headersInput.value.trim();
    if (!headers) return;

    loading.classList.remove("hidden");
    results.classList.add("hidden");
    errorMsg.classList.add("hidden");
    analyzeBtn.disabled = true;

    try {
        const resp = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ headers }),
        });

        const data = await resp.json();

        if (!resp.ok) {
            showError(data.error || "Something went wrong.");
            return;
        }

        renderResults(data);
    } catch {
        showError("Failed to connect to the server.");
    } finally {
        loading.classList.add("hidden");
        analyzeBtn.disabled = false;
    }
});

function showError(msg) {
    errorMsg.textContent = msg;
    errorMsg.classList.remove("hidden");
}

function esc(str) {
    if (!str) return "";
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

function renderResults(data) {
    renderRisk(data.indicators);
    renderSummary(data.summary);
    renderAuth(data.auth);
    renderFindings(data.indicators);
    renderChain(data.chain);
    results.classList.remove("hidden");
}

function renderRisk(indicators) {
    const el = document.getElementById("risk-display");
    el.innerHTML = `
        <div class="risk-meter risk-${indicators.risk_level}">
            <div class="risk-score">${indicators.score}</div>
            <div class="risk-bar-container">
                <div class="risk-bar-bg">
                    <div class="risk-bar-fill" style="width: ${indicators.score}%"></div>
                </div>
                <div class="risk-label">${indicators.risk_level} risk</div>
            </div>
        </div>
    `;
}

function renderSummary(summary) {
    const el = document.getElementById("summary-display");
    const fields = [
        ["From", summary.from],
        ["To", summary.to],
        ["Subject", summary.subject],
        ["Date", summary.date],
        ["Return-Path", summary.return_path],
        ["Reply-To", summary.reply_to],
        ["Message-ID", summary.message_id],
        ["X-Mailer", summary.x_mailer],
        ["X-Originating-IP", summary.x_originating_ip],
    ];

    const rows = fields
        .filter(([, v]) => v)
        .map(([k, v]) => `<div class="summary-row"><div class="summary-key">${esc(k)}</div><div class="summary-val">${esc(v)}</div></div>`)
        .join("");

    el.innerHTML = `<div class="summary-table">${rows || '<div class="summary-row"><div class="summary-val" style="color:var(--text-muted)">No summary fields found</div></div>'}</div>`;
}

function renderAuth(auth) {
    const el = document.getElementById("auth-display");

    function authCard(name, result, detail, extra) {
        let cls = "auth-none";
        let display = "N/A";
        if (result) {
            display = result;
            if (result === "pass") cls = "auth-pass";
            else if (result === "fail") cls = "auth-fail";
            else if (result === "softfail" || result === "neutral") cls = "auth-warn";
            else cls = "auth-none";
        }
        let extraHTML = extra ? `<div class="auth-detail">${esc(extra)}</div>` : "";
        let detailHTML = detail ? `<div class="auth-detail">${esc(detail)}</div>` : "";
        return `<div class="auth-card"><h3>${esc(name)}</h3><div class="auth-result ${cls}">${esc(display)}</div>${detailHTML}${extraHTML}</div>`;
    }

    const dkimExtra = auth.dkim.selector ? `Selector: ${auth.dkim.selector}` : null;
    const dmarcExtra = auth.dmarc.policy ? `Policy: p=${auth.dmarc.policy}` : null;

    el.innerHTML = `<div class="auth-grid">
        ${authCard("SPF", auth.spf.result, auth.spf.detail)}
        ${authCard("DKIM", auth.dkim.result, auth.dkim.detail, dkimExtra)}
        ${authCard("DMARC", auth.dmarc.result, auth.dmarc.detail, dmarcExtra)}
    </div>`;
}

function renderFindings(indicators) {
    const el = document.getElementById("findings-display");

    if (indicators.findings.length === 0) {
        el.innerHTML = '<div class="no-findings">No phishing indicators found</div>';
        return;
    }

    el.innerHTML = indicators.findings
        .map((f) => `
            <div class="finding-card">
                <span class="finding-severity severity-${f.severity}">${f.severity}</span>
                <div class="finding-text">
                    <div class="finding-name">${esc(f.indicator)}</div>
                    <div class="finding-detail">${esc(f.detail)}</div>
                </div>
            </div>
        `)
        .join("");
}

function renderChain(chain) {
    const el = document.getElementById("chain-display");

    if (chain.total_hops === 0) {
        el.innerHTML = '<div class="no-findings">No Received headers found</div>';
        return;
    }

    let html = '<div class="chain-timeline">';

    chain.hops.forEach((hop, i) => {
        if (i > 0) {
            const delay = chain.delays[i - 1];
            let delayText = "";
            let delayCls = "delay-normal";
            if (delay && delay.delay_seconds !== null) {
                const secs = Math.round(delay.delay_seconds);
                if (secs < 60) delayText = `${secs}s`;
                else if (secs < 3600) delayText = `${Math.round(secs / 60)}m`;
                else delayText = `${(secs / 3600).toFixed(1)}h`;
                if (delay.is_suspicious) delayCls = "delay-suspicious";
            }
            html += `<div class="chain-connector">
                <span class="arrow">↓</span>
                ${delayText ? `<span class="chain-delay ${delayCls}">${delayText}</span>` : ""}
            </div>`;
        }

        const rawId = `raw-${i}`;
        html += `
            <div class="chain-hop">
                <div class="hop-label">
                    <span class="hop-num">HOP ${hop.hop_number}</span>
                    ${hop.with_protocol ? `<span class="hop-protocol">${esc(hop.with_protocol)}</span>` : ""}
                    ${hop.timestamp ? `<span class="hop-timestamp">${esc(hop.timestamp)}</span>` : ""}
                </div>
                <div class="hop-servers">
                    ${hop.from_server ? `<span>from </span>${esc(hop.from_server)} ` : ""}
                    ${hop.by_server ? `<span>by </span>${esc(hop.by_server)}` : ""}
                </div>
                <button class="hop-raw-toggle" onclick="document.getElementById('${rawId}').classList.toggle('hidden')">Show raw</button>
                <div id="${rawId}" class="hop-raw hidden">${esc(hop.raw)}</div>
            </div>
        `;
    });

    html += "</div>";
    el.innerHTML = html;
}
