//! The browser viewer. Every value from a finding is written with
//! `textContent` (never `innerHTML`), and only the escaped `display` form of
//! tainted DDS names is shown (SR-TAINT); the CSP allows no inline script.

pub const INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RoboDR demo SOC</title>
<link rel="stylesheet" href="/app.css">
</head>
<body>
<header>
  <h1>RoboDR demo SOC</h1>
  <p class="sub">Findings received over the robodr.ingest API, signatures verified by the reference consumer. Demo only.</p>
</header>
<section class="tiles">
  <div class="tile"><span class="k">Findings</span><span class="v" id="m-total">0</span></div>
  <div class="tile"><span class="k">Verified</span><span class="v" id="m-verified">0</span></div>
  <div class="tile"><span class="k">Time to SOC p50</span><span class="v" id="m-p50">-</span></div>
  <div class="tile"><span class="k">Time to SOC p99</span><span class="v" id="m-p99">-</span></div>
</section>
<section>
  <h2>Rule ids</h2>
  <table id="rules"><thead><tr><th>Rule id</th><th>Count</th></tr></thead><tbody></tbody></table>
</section>
<section>
  <h2>Latest findings</h2>
  <table id="findings">
    <thead><tr><th>Received</th><th>Robot</th><th>Severity</th><th>Rule id</th><th>Title</th><th>Source</th><th>Topic</th><th>Signature</th><th>Time to SOC</th></tr></thead>
    <tbody></tbody>
  </table>
</section>
<script src="/app.js"></script>
</body>
</html>
"##;

pub const APP_CSS: &str = r##":root { --bg: #0f1419; --fg: #e6e6e6; --muted: #8b949e; --line: #30363d; --crit: #f85149; --high: #f0883e; --med: #d29922; --low: #3fb950; }
@media (prefers-color-scheme: light) { :root { --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --line: #d1d9e0; } }
body { background: var(--bg); color: var(--fg); font: 14px/1.4 system-ui, sans-serif; margin: 0 16px 32px; }
h1 { font-size: 20px; margin: 16px 0 4px; } h2 { font-size: 16px; margin: 24px 0 8px; }
.sub { color: var(--muted); margin: 0; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-top: 16px; }
.tile { border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px; }
.tile .k { display: block; color: var(--muted); font-size: 12px; } .tile .v { font-size: 22px; font-variant-numeric: tabular-nums; }
section { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; } th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); white-space: nowrap; }
th { color: var(--muted); font-weight: 600; font-size: 12px; }
td.title { white-space: normal; min-width: 240px; }
.sev-critical { color: var(--crit); font-weight: 600; } .sev-high { color: var(--high); } .sev-medium { color: var(--med); } .sev-low { color: var(--low); }
.unsigned { color: var(--crit); }
"##;

pub const APP_JS: &str = r##""use strict";
function cell(tr, text, cls) {
  const td = document.createElement("td");
  td.textContent = text == null ? "" : String(text);
  if (cls) td.className = cls;
  tr.appendChild(td);
}
function ms(v) { return v == null ? "-" : (v < 1000 ? v + " ms" : (v / 1000).toFixed(2) + " s"); }
function disp(f, k) { const r = ((f.entity_context || {}).ros || {})[k]; return r ? r.display : ""; }
async function refresh() {
  try {
    const [m, list] = await Promise.all([
      fetch("/api/metrics").then(r => r.json()),
      fetch("/api/findings?limit=200").then(r => r.json()),
    ]);
    document.getElementById("m-total").textContent = String(m.findings);
    document.getElementById("m-verified").textContent = String((m.by_verification || {}).verified || 0);
    document.getElementById("m-p50").textContent = ms(m.time_to_soc_ms.p50);
    document.getElementById("m-p99").textContent = ms(m.time_to_soc_ms.p99);
    const rb = document.querySelector("#rules tbody");
    rb.replaceChildren();
    for (const [rule, n] of Object.entries(m.by_rule || {})) {
      const tr = document.createElement("tr"); cell(tr, rule); cell(tr, n); rb.appendChild(tr);
    }
    const fb = document.querySelector("#findings tbody");
    fb.replaceChildren();
    for (const e of list) {
      const f = e.finding || {}, ec = f.entity_context || {};
      const tr = document.createElement("tr");
      cell(tr, new Date(e.received_unix_ms).toISOString());
      cell(tr, (ec.robot || {}).id);
      cell(tr, f.severity, "sev-" + f.severity);
      cell(tr, ec.rule_id);
      cell(tr, f.title, "title");
      cell(tr, disp(f, "src_ip"));
      cell(tr, disp(f, "topic"));
      cell(tr, e.verification.status, e.verification.status === "verified" ? "" : "unsigned");
      cell(tr, ms(e.time_to_soc_ms));
      fb.appendChild(tr);
    }
  } catch (err) { /* the next refresh retries */ }
}
refresh();
setInterval(refresh, 2000);
"##;
