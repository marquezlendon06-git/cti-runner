"""HTML intelligence report generator — Diamond Model format."""
from datetime import datetime, timezone


def _badge(confidence: str) -> str:
    css = confidence.lower() if confidence.lower() in (
        "high", "medium", "low", "unattributed"
    ) else "unattributed"
    return f'<span class="badge badge-{css}">{confidence}</span>'


def _infra_rows(infrastructure: list) -> str:
    if not infrastructure:
        return '<tr><td colspan="4" class="muted-cell">No infrastructure identified.</td></tr>'
    return "".join(
        f"""<tr>
          <td><code class="ioc">{i.get('indicator','')}</code></td>
          <td><span class="type-tag">{i.get('type','')}</span></td>
          <td>{i.get('role','')}</td>
          <td>{_badge(i.get('confidence','Low'))}</td>
        </tr>"""
        for i in infrastructure
    )


def _cap_rows(capabilities: list) -> str:
    if not capabilities:
        return '<tr><td colspan="4" class="muted-cell">No capabilities identified.</td></tr>'
    return "".join(
        f"""<tr>
          <td>{c.get('name','')}</td>
          <td><span class="type-tag">{c.get('type','')}</span></td>
          <td><code class="mitre">{c.get('mitre_technique') or '—'}</code></td>
          <td>{_badge(c.get('confidence','Low'))}</td>
        </tr>"""
        for c in capabilities
    )


def _victim_rows(victims: list) -> str:
    if not victims:
        return '<tr><td colspan="3" class="muted-cell">No victims identified.</td></tr>'
    return "".join(
        f"""<tr>
          <td>{v.get('sector','Unknown')}</td>
          <td>{v.get('region','Unknown')}</td>
          <td>{_badge(v.get('confidence','Low'))}</td>
        </tr>"""
        for v in victims
    )


def _pivot_chain(pivots: list) -> str:
    if not pivots:
        return '<p class="muted-cell">No pivots recorded.</p>'
    items = "".join(
        f'<div class="pivot-item">'
        f'<span class="pivot-num">{i+1:02d}</span>'
        f'<span class="pivot-text">{p}</span>'
        f'</div>'
        for i, p in enumerate(pivots)
    )
    return f'<div class="pivot-chain">{items}</div>'


def _blockchain_rows(wallets: list) -> str:
    if not wallets:
        return '<tr><td colspan="6" class="muted-cell">No cryptocurrency wallets traced.</td></tr>'
    rows = []
    for w in wallets:
        hops = w.get("notable_hops") or []
        hops_html = (
            "<ol style='margin:0;padding-left:16px;font-size:12px;'>"
            + "".join(f"<li>{h}</li>" for h in hops)
            + "</ol>"
        ) if hops else '<span style="color:var(--muted);font-style:italic">—</span>'
        rows.append(f"""<tr>
          <td><code class="ioc">{w.get('address','')}</code></td>
          <td><span class="type-tag">{w.get('coin','').upper()}</span></td>
          <td>{w.get('role','')}</td>
          <td>{w.get('balance','—')}</td>
          <td>{w.get('tx_count','—')}</td>
          <td>{hops_html}</td>
          <td>{_badge(w.get('confidence','Low'))}</td>
        </tr>""")
    return "".join(rows)


def generate_report(
    seed_indicator: str = "",
    narrative: str = "",
    summary: str = "",
    adversary: dict = None,
    infrastructure: list = None,
    capabilities: list = None,
    victims: list = None,
    pivots: list = None,
    key_findings: list = None,
    overall_confidence: str = "Low",
    gaps: list = None,
    blockchain: list = None,
    **_,
) -> str:
    adversary      = adversary or {}
    infrastructure = infrastructure or []
    capabilities   = capabilities or []
    victims        = victims or []
    pivots         = pivots or []
    key_findings   = key_findings or []
    gaps           = gaps or []
    blockchain     = blockchain or []

    now            = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    adversary_name = adversary.get("name", "Unknown")
    aliases        = adversary.get("aliases", [])
    adv_confidence = adversary.get("confidence", "Unattributed")

    narrative_block = f"""
      <div class="narrative-block">
        <div class="narrative-label">Analyst Narrative</div>
        <p class="narrative-text">{narrative}</p>
      </div>""" if narrative else ""

    aliases_html = (
        "".join(f'<span class="alias">{a}</span>' for a in aliases)
        or '<span class="muted-cell">None identified</span>'
    )

    findings_html = "".join(
        f'<li class="finding-item">{f}</li>' for f in key_findings
    ) or '<li class="muted-cell">No findings recorded.</li>'

    gaps_html = "".join(
        f'<li class="gap-item">{g}</li>' for g in gaps
    ) or '<li class="muted-cell">No gaps recorded.</li>'

    cap_preview = ", ".join(c.get("name", "") for c in capabilities[:3]) or "None identified"
    if len(capabilities) > 3:
        cap_preview += "…"
    vic_preview = ", ".join(v.get("sector", "") for v in victims[:3]) or "Unknown"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTI Report — {seed_indicator}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=Source+Serif+4:ital,opsz,wght@0,8..60,300;0,8..60,400;0,8..60,600;1,8..60,300;1,8..60,400&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* ── Tokens ─────────────────────────────────────── */
:root {{
  --ground:    #eaecf3;
  --surface:   #ffffff;
  --surface2:  #f0f1f7;
  --border:    #d2d5e0;
  --border2:   #b8bccb;
  --text:      #1a1d2e;
  --muted:     #646880;
  --accent:    #3a5ce4;
  --accent-bg: #eaedfc;

  --conf-high-c:   #1a7f37; --conf-high-bg:  #dafbe1;
  --conf-med-c:    #7d4e00; --conf-med-bg:   #fef3c7;
  --conf-low-c:    #cf222e; --conf-low-bg:   #ffebe9;
  --conf-un-c:     #57606a; --conf-un-bg:    #eaecf3;

  --ff-display: 'Syne', system-ui, sans-serif;
  --ff-body:    'Source Serif 4', Georgia, serif;
  --ff-mono:    'JetBrains Mono', 'Cascadia Code', monospace;
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --ground:    #0d1117;
    --surface:   #161b22;
    --surface2:  #1c2128;
    --border:    #21262d;
    --border2:   #30363d;
    --text:      #e6edf3;
    --muted:     #7d8590;
    --accent:    #58a6ff;
    --accent-bg: #1c3352;

    --conf-high-c:   #3fb950; --conf-high-bg:  #162a1a;
    --conf-med-c:    #d29922; --conf-med-bg:   #261f0c;
    --conf-low-c:    #f85149; --conf-low-bg:   #2a1111;
    --conf-un-c:     #7d8590; --conf-un-bg:    #1c2128;
  }}
}}
:root[data-theme="dark"] {{
    --ground:    #0d1117;
    --surface:   #161b22;
    --surface2:  #1c2128;
    --border:    #21262d;
    --border2:   #30363d;
    --text:      #e6edf3;
    --muted:     #7d8590;
    --accent:    #58a6ff;
    --accent-bg: #1c3352;

    --conf-high-c:   #3fb950; --conf-high-bg:  #162a1a;
    --conf-med-c:    #d29922; --conf-med-bg:   #261f0c;
    --conf-low-c:    #f85149; --conf-low-bg:   #2a1111;
    --conf-un-c:     #7d8590; --conf-un-bg:    #1c2128;
}}

/* ── Reset ───────────────────────────────────────── */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--ground);
  color: var(--text);
  font-family: var(--ff-body);
  font-size: 15px;
  line-height: 1.75;
  font-weight: 300;
  -webkit-font-smoothing: antialiased;
}}
.page {{ max-width: 980px; margin: 0 auto; padding: 52px 32px 88px; }}

/* ── Report header ───────────────────────────────── */
.report-header {{
  border-bottom: 1px solid var(--border);
  padding-bottom: 36px;
  margin-bottom: 0;
}}
.eyebrow {{
  font-family: var(--ff-mono);
  font-size: 10.5px;
  font-weight: 500;
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 14px;
}}
.report-title {{
  font-family: var(--ff-display);
  font-size: clamp(18px, 2.5vw, 26px);
  font-weight: 800;
  line-height: 1.15;
  color: var(--text);
  word-break: break-all;
  text-wrap: balance;
  margin-bottom: 20px;
}}
.meta-row {{
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 20px;
  font-family: var(--ff-mono);
  font-size: 11.5px;
  color: var(--muted);
}}
.meta-sep {{ color: var(--border2); }}
.meta-val {{ color: var(--text); }}
.tlp {{
  background: #7d4e00;
  color: #fef3c7;
  font-family: var(--ff-mono);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .1em;
  padding: 2px 8px;
  border-radius: 3px;
  text-transform: uppercase;
  flex-shrink: 0;
}}

/* ── Narrative ───────────────────────────────────── */
.narrative-block {{
  margin: 36px 0 0;
  padding: 22px 26px;
  background: var(--accent-bg);
  border-left: 3px solid var(--accent);
  border-radius: 0 8px 8px 0;
}}
.narrative-label {{
  font-family: var(--ff-mono);
  font-size: 10px;
  font-weight: 500;
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 10px;
}}
.narrative-text {{
  font-family: var(--ff-body);
  font-size: 15.5px;
  font-style: italic;
  font-weight: 400;
  line-height: 1.8;
  color: var(--text);
}}

/* ── Section ─────────────────────────────────────── */
.section {{ margin-top: 52px; }}
.section-head {{
  display: flex;
  align-items: baseline;
  gap: 10px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 22px;
}}
.section-title {{
  font-family: var(--ff-display);
  font-size: 17px;
  font-weight: 700;
  color: var(--text);
  letter-spacing: -.01em;
}}
.section-sub {{
  font-family: var(--ff-mono);
  font-size: 10.5px;
  color: var(--muted);
  letter-spacing: .04em;
}}

/* ── Summary ─────────────────────────────────────── */
.summary-text {{
  font-size: 15px;
  line-height: 1.85;
  color: var(--text);
  max-width: 72ch;
}}

/* ── Diamond grid ────────────────────────────────── */
.diamond-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}}
@media (max-width: 580px) {{ .diamond-grid {{ grid-template-columns: 1fr; }} }}
.diamond-card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px 22px;
}}
.card-label {{
  font-family: var(--ff-mono);
  font-size: 10px;
  font-weight: 500;
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 10px;
}}
.card-value {{
  font-family: var(--ff-display);
  font-size: 19px;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 10px;
  word-break: break-word;
  line-height: 1.25;
}}
.card-sub {{
  font-size: 12.5px;
  color: var(--muted);
  line-height: 1.5;
}}
.alias-row {{ display: flex; flex-wrap: wrap; gap: 5px; margin-top: 10px; }}
.alias {{
  font-family: var(--ff-mono);
  font-size: 10.5px;
  padding: 2px 7px;
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: 4px;
  color: var(--muted);
}}

/* ── Tables ──────────────────────────────────────── */
.table-wrap {{ overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; }}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 13.5px;
  font-variant-numeric: tabular-nums;
}}
thead tr {{ background: var(--surface); }}
th {{
  text-align: left;
  padding: 11px 16px;
  font-family: var(--ff-mono);
  font-size: 10px;
  font-weight: 500;
  letter-spacing: .1em;
  text-transform: uppercase;
  color: var(--muted);
  white-space: nowrap;
  border-bottom: 1px solid var(--border2);
}}
td {{
  padding: 11px 16px;
  border-bottom: 1px solid var(--border);
  color: var(--text);
  vertical-align: top;
  line-height: 1.55;
}}
tr:last-child td {{ border-bottom: none; }}
tbody tr:hover {{ background: var(--surface); }}
.muted-cell {{ color: var(--muted); font-style: italic; padding: 14px 16px; }}

code.ioc {{
  font-family: var(--ff-mono);
  font-size: 12px;
  background: var(--surface2);
  padding: 2px 6px;
  border-radius: 4px;
  color: var(--accent);
  word-break: break-all;
  display: inline-block;
}}
code.mitre {{
  font-family: var(--ff-mono);
  font-size: 11.5px;
  background: var(--surface2);
  padding: 2px 6px;
  border-radius: 4px;
  color: var(--muted);
}}
.type-tag {{
  font-family: var(--ff-mono);
  font-size: 11px;
  color: var(--muted);
  white-space: nowrap;
}}

/* ── Badges ──────────────────────────────────────── */
.badge {{
  display: inline-block;
  font-family: var(--ff-mono);
  font-size: 10px;
  font-weight: 500;
  padding: 2px 9px;
  border-radius: 20px;
  letter-spacing: .05em;
  text-transform: uppercase;
  white-space: nowrap;
}}
.badge-high         {{ color: var(--conf-high-c); background: var(--conf-high-bg); }}
.badge-medium       {{ color: var(--conf-med-c);  background: var(--conf-med-bg); }}
.badge-low          {{ color: var(--conf-low-c);  background: var(--conf-low-bg); }}
.badge-unattributed {{ color: var(--conf-un-c);   background: var(--conf-un-bg); }}

/* ── Key findings ────────────────────────────────── */
.findings-list {{ list-style: none; display: flex; flex-direction: column; gap: 9px; }}
.finding-item {{
  padding: 13px 16px;
  background: var(--surface);
  border-left: 3px solid var(--accent);
  border-radius: 0 6px 6px 0;
  font-size: 14px;
  line-height: 1.65;
  font-weight: 300;
  counter-increment: findings;
  position: relative;
}}
.finding-item::before {{
  content: counter(findings, decimal-leading-zero);
  position: absolute;
  right: 14px;
  top: 13px;
  font-family: var(--ff-mono);
  font-size: 10px;
  color: var(--muted);
  opacity: .5;
}}
.findings-list {{ counter-reset: findings; }}

/* ── Pivot chain ─────────────────────────────────── */
.pivot-chain {{ display: flex; flex-direction: column; }}
.pivot-item {{
  display: flex;
  align-items: flex-start;
  gap: 16px;
  padding: 13px 0;
  border-bottom: 1px solid var(--border);
}}
.pivot-item:last-child {{ border-bottom: none; }}
.pivot-num {{
  font-family: var(--ff-mono);
  font-size: 11px;
  color: var(--accent);
  font-weight: 500;
  min-width: 22px;
  padding-top: 1px;
  flex-shrink: 0;
}}
.pivot-text {{ font-size: 13.5px; color: var(--text); line-height: 1.6; }}

/* ── Gaps ────────────────────────────────────────── */
.gaps-list {{ list-style: none; display: flex; flex-direction: column; gap: 8px; }}
.gap-item {{
  padding: 11px 15px;
  background: var(--surface);
  border-left: 3px solid var(--conf-med-c);
  border-radius: 0 6px 6px 0;
  font-size: 13.5px;
  color: var(--muted);
  line-height: 1.55;
}}
.gap-item::before {{
  content: "Gap · ";
  font-family: var(--ff-mono);
  font-size: 9.5px;
  font-weight: 500;
  letter-spacing: .08em;
  text-transform: uppercase;
  color: var(--conf-med-c);
  margin-right: 2px;
}}

/* ── Footer ──────────────────────────────────────── */
.footer {{
  margin-top: 72px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
  font-family: var(--ff-mono);
  font-size: 11px;
  color: var(--muted);
}}
</style>
</head>
<body>
<div class="page">

  <header class="report-header">
    <div class="eyebrow">Cyber Threat Intelligence &middot; Investigation Report</div>
    <h1 class="report-title">{seed_indicator}</h1>
    <div class="meta-row">
      <span class="meta-val">{now}</span>
      <span class="meta-sep">/</span>
      <span>Confidence</span>
      <span class="meta-val">{overall_confidence}</span>
      <span class="meta-sep">/</span>
      <span class="tlp">TLP:AMBER</span>
    </div>
    {narrative_block}
  </header>

  <div class="section">
    <div class="section-head">
      <h2 class="section-title">Executive Summary</h2>
    </div>
    <p class="summary-text">{summary}</p>
  </div>

  <div class="section">
    <div class="section-head">
      <h2 class="section-title">Diamond Model</h2>
      <span class="section-sub">Intrusion Analysis Framework</span>
    </div>
    <div class="diamond-grid">
      <div class="diamond-card">
        <div class="card-label">Adversary</div>
        <div class="card-value">{adversary_name}</div>
        {_badge(adv_confidence)}
        <div class="alias-row">{aliases_html}</div>
      </div>
      <div class="diamond-card">
        <div class="card-label">Infrastructure</div>
        <div class="card-value">{len(infrastructure)} indicator{'s' if len(infrastructure) != 1 else ''}</div>
        <span class="card-sub">See infrastructure table below</span>
      </div>
      <div class="diamond-card">
        <div class="card-label">Capabilities</div>
        <div class="card-value">{len(capabilities)} identified</div>
        <span class="card-sub">{cap_preview}</span>
      </div>
      <div class="diamond-card">
        <div class="card-label">Victims</div>
        <div class="card-value">{len(victims)} profile{'s' if len(victims) != 1 else ''}</div>
        <span class="card-sub">{vic_preview}</span>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-head">
      <h2 class="section-title">Infrastructure</h2>
      <span class="section-sub">{len(infrastructure)} indicators</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Indicator</th><th>Type</th><th>Role</th><th>Confidence</th></tr></thead>
        <tbody>{_infra_rows(infrastructure)}</tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-head">
      <h2 class="section-title">Capabilities</h2>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Capability</th><th>Type</th><th>MITRE Technique</th><th>Confidence</th></tr></thead>
        <tbody>{_cap_rows(capabilities)}</tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-head">
      <h2 class="section-title">Victims</h2>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Sector</th><th>Region</th><th>Confidence</th></tr></thead>
        <tbody>{_victim_rows(victims)}</tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-head">
      <h2 class="section-title">Blockchain Traces</h2>
      <span class="section-sub">{len(blockchain)} wallet{'s' if len(blockchain) != 1 else ''} traced</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Address</th><th>Coin</th><th>Role</th><th>Balance</th><th>Txns</th><th>Notable Hops</th><th>Confidence</th></tr></thead>
        <tbody>{_blockchain_rows(blockchain)}</tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-head">
      <h2 class="section-title">Key Findings</h2>
    </div>
    <ol class="findings-list">{findings_html}</ol>
  </div>

  <div class="section">
    <div class="section-head">
      <h2 class="section-title">Investigation Pivots</h2>
      <span class="section-sub">{len(pivots)} performed</span>
    </div>
    {_pivot_chain(pivots)}
  </div>

  <div class="section">
    <div class="section-head">
      <h2 class="section-title">Intelligence Gaps</h2>
    </div>
    <ul class="gaps-list">{gaps_html}</ul>
  </div>

  <div class="section">
    <div class="section-head">
      <h2 class="section-title">Confidence Framework</h2>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Level</th><th>Meaning</th></tr></thead>
        <tbody>
          <tr><td>{_badge('High')}</td><td>Confirmed by 2+ independent sources; no significant doubt</td></tr>
          <tr><td>{_badge('Medium')}</td><td>Supported by available information; some gaps remain</td></tr>
          <tr><td>{_badge('Low')}</td><td>Based on limited information or single-source inference</td></tr>
          <tr><td>{_badge('Unattributed')}</td><td>Insufficient data to assess actor</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <footer class="footer">
    <span>CTI-Runner Agent</span>
    <span>TLP:AMBER &mdash; Handle accordingly</span>
  </footer>

</div>
</body>
</html>"""
