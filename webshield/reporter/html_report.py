"""
HTML Report Generator — Lighthouse-style shareable report.
"""

from __future__ import annotations
from pathlib import Path
from datetime import datetime, timezone
from webshield.core.models import ScanResult, Severity

SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}

SEV_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fefce8",
    "LOW":      "#eff6ff",
    "INFO":     "#f9fafb",
}

GRADE_COLOR = {
    "A+": "#16a34a", "A": "#16a34a", "A-": "#16a34a",
    "B+": "#0891b2", "B": "#0891b2", "B-": "#0891b2",
    "C+": "#ca8a04", "C": "#ca8a04", "C-": "#ca8a04",
    "D":  "#ea580c", "F": "#dc2626",
}


def _finding_html(f, idx: int) -> str:
    sc = SEV_COLOR.get(f.severity.value, "#6b7280")
    sb = SEV_BG.get(f.severity.value, "#f9fafb")
    code_section = ""
    if f.code_fix:
        escaped = f.code_fix.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        code_section = f"""
        <div class="code-block">
          <div class="code-label">Code Fix</div>
          <pre><code>{escaped}</code></pre>
        </div>"""

    ref_section = ""
    if f.reference:
        ref_section = f'<a class="ref-link" href="{f.reference}" target="_blank">📚 Learn more</a>'

    cvss_section = ""
    if f.cvss > 0:
        cvss_color = "#dc2626" if f.cvss >= 7 else "#ca8a04" if f.cvss >= 4 else "#16a34a"
        cvss_section = f'<span class="cvss-badge" style="background:{cvss_color}">CVSS {f.cvss}</span>'

    return f"""
    <div class="finding" style="border-left:4px solid {sc}; background:{sb};">
      <div class="finding-header">
        <span class="sev-badge" style="background:{sc}">{f.severity.emoji} {f.severity.value}</span>
        {cvss_section}
        <span class="finding-title">{f.title}</span>
      </div>
      <p class="finding-desc">{f.description}</p>
      {"<div class='evidence'><strong>Evidence:</strong> " + f.evidence[:300] + "</div>" if f.evidence else ""}
      {"<div class='remediation'><strong>🔧 How to Fix:</strong> " + f.remediation + "</div>" if f.remediation else ""}
      {code_section}
      {ref_section}
    </div>"""


def save_html(result: ScanResult, output_path: str) -> None:
    grade_color = GRADE_COLOR.get(result.grade, "#6b7280")
    score_pct = result.score
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Build findings HTML grouped by severity
    findings_html = ""
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        group = result.by_severity(sev)
        if not group:
            continue
        sc = SEV_COLOR[sev.value]
        findings_html += f"""
        <div class="sev-group">
          <h3 style="color:{sc}">{sev.emoji} {sev.value} <span class="count-badge" style="background:{sc}">{len(group)}</span></h3>
        """
        for i, f in enumerate(group):
            findings_html += _finding_html(f, i)
        findings_html += "</div>"

    summary = result.to_dict()["summary"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WebShield Report — {result.target}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
             background: #f8fafc; color: #1e293b; line-height: 1.6; }}
    .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
               color: white; padding: 40px; text-align: center; }}
    .header h1 {{ font-size: 2rem; margin-bottom: 8px; }}
    .header .target {{ color: #94a3b8; font-size: 1.1rem; }}
    .header .meta {{ color: #64748b; font-size: 0.9rem; margin-top: 8px; }}
    .score-section {{ display: flex; justify-content: center; gap: 40px;
                      padding: 40px; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .score-circle {{ text-align: center; }}
    .score-num {{ font-size: 4rem; font-weight: 900; color: {grade_color}; }}
    .score-label {{ color: #64748b; font-size: 0.9rem; text-transform: uppercase; }}
    .grade-badge {{ font-size: 3rem; font-weight: 900; color: {grade_color};
                    padding: 10px 20px; border: 3px solid {grade_color};
                    border-radius: 12px; display: inline-block; }}
    .progress-bar {{ width: 300px; height: 16px; background: #e2e8f0;
                     border-radius: 8px; overflow: hidden; margin: 10px auto; }}
    .progress-fill {{ height: 100%; background: {grade_color}; border-radius: 8px;
                      width: {score_pct}%; transition: width 0.5s; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr);
                     gap: 16px; padding: 30px; max-width: 1000px; margin: 0 auto; }}
    .summary-card {{ background: white; border-radius: 12px; padding: 20px;
                     text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .summary-card .num {{ font-size: 2rem; font-weight: 800; }}
    .summary-card .label {{ color: #64748b; font-size: 0.85rem; }}
    .main {{ max-width: 1000px; margin: 0 auto; padding: 30px; }}
    .sev-group {{ margin-bottom: 40px; }}
    .sev-group h3 {{ font-size: 1.2rem; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }}
    .count-badge {{ color: white; padding: 2px 10px; border-radius: 20px; font-size: 0.8rem; }}
    .finding {{ border-radius: 8px; padding: 20px; margin-bottom: 12px; }}
    .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; }}
    .sev-badge {{ color: white; padding: 3px 10px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }}
    .cvss-badge {{ color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; }}
    .finding-title {{ font-weight: 700; font-size: 1rem; }}
    .finding-desc {{ color: #475569; margin: 8px 0; font-size: 0.95rem; }}
    .evidence {{ background: rgba(0,0,0,0.05); border-radius: 4px; padding: 8px 12px;
                 font-family: monospace; font-size: 0.85rem; margin: 8px 0; }}
    .remediation {{ background: rgba(22,163,74,0.08); border-radius: 4px; padding: 8px 12px;
                    margin: 8px 0; font-size: 0.9rem; color: #166534; }}
    .code-block {{ margin: 8px 0; }}
    .code-label {{ font-size: 0.75rem; color: #64748b; margin-bottom: 4px; }}
    .code-block pre {{ background: #0f172a; color: #e2e8f0; padding: 12px 16px;
                       border-radius: 6px; font-size: 0.82rem; overflow-x: auto; }}
    .ref-link {{ display: inline-block; margin-top: 8px; color: #3b82f6;
                 font-size: 0.85rem; text-decoration: none; }}
    .footer {{ text-align: center; padding: 30px; color: #94a3b8; font-size: 0.85rem; }}
    @media (max-width: 600px) {{
      .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
      .score-section {{ flex-direction: column; align-items: center; }}
    }}
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ WebShield Security Report</h1>
    <div class="target">{result.target}</div>
    <div class="meta">Generated: {generated} &bull; Scan duration: {result.scan_duration}s &bull; Modules: {len(result.modules_run)}</div>
  </div>

  <div class="score-section">
    <div class="score-circle">
      <div class="score-num">{result.score}</div>
      <div class="progress-bar"><div class="progress-fill"></div></div>
      <div class="score-label">Security Score (out of 100)</div>
    </div>
    <div class="score-circle">
      <div class="grade-badge">{result.grade}</div>
      <div style="margin-top:10px; color:#64748b; font-size:0.9rem;">Letter Grade</div>
    </div>
  </div>

  <div class="summary-grid">
    <div class="summary-card">
      <div class="num" style="color:#dc2626">{summary['critical']}</div>
      <div class="label">🔴 Critical</div>
    </div>
    <div class="summary-card">
      <div class="num" style="color:#ea580c">{summary['high']}</div>
      <div class="label">🟠 High</div>
    </div>
    <div class="summary-card">
      <div class="num" style="color:#ca8a04">{summary['medium']}</div>
      <div class="label">🟡 Medium</div>
    </div>
    <div class="summary-card">
      <div class="num" style="color:#2563eb">{summary['low']}</div>
      <div class="label">🔵 Low</div>
    </div>
    <div class="summary-card">
      <div class="num" style="color:#6b7280">{summary['info']}</div>
      <div class="label">⚪ Info</div>
    </div>
  </div>

  <div class="main">
    {"<p style='color:#16a34a;font-size:1.1rem;text-align:center;padding:40px'>✅ No security issues found! Your site looks clean.</p>" if not result.findings else findings_html}
  </div>

  <div class="footer">
    WebShield v1.0.1 &bull; by AKIBUZZAMAN AKIB &bull;
    <a href="https://github.com/AKIB473/webshield" style="color:#3b82f6">github.com/AKIB473/webshield</a>
  </div>
</body>
</html>"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    print(f"[+] HTML report saved to: {output_path}")
