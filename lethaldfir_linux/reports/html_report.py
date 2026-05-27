"""
reports.html_report
===================

Self-contained HTML investigation report. No external assets - all CSS
and JavaScript embedded inline so the file is portable and works
offline (analyst laptops, air-gapped lab networks, etc.).

Contains:

  * LethalDFIR-branded header
  * Case summary card (host info, evidence root, run timestamp)
  * Severity dashboard (CRITICAL / HIGH / MEDIUM / LOW / INFO counts)
  * Per-parser run statistics
  * Findings table (severity-coloured, filterable)
  * Timeline browser (filterable, paginated)
"""

from __future__ import annotations

import html
import json
from datetime import timezone
from pathlib import Path

from .. import __version__, __brand__


# --------------------------------------------------------------------------
# CSS
# --------------------------------------------------------------------------
_CSS = """
:root {
  --bg:       #0b0e14;
  --bg-soft:  #11151d;
  --bg-card:  #161b25;
  --border:   #232a37;
  --fg:       #e6e9ef;
  --fg-dim:   #8a93a3;
  --accent:   #ff3b3b;
  --accent-2: #ff7a59;
  --info:     #5a9bf5;
  --low:      #4ad295;
  --medium:   #f0b400;
  --high:     #ff7a39;
  --critical: #ff2e4e;
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--bg); color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               Oxygen-Sans, Ubuntu, Cantarell, sans-serif;
  font-size: 14px; line-height: 1.5;
}
header.brand {
  background: linear-gradient(90deg, #0b0e14 0%, #1a0a0a 100%);
  border-bottom: 1px solid var(--border);
  padding: 18px 28px;
  display: flex; align-items: center; gap: 14px;
}
header.brand .logo {
  font-family: "JetBrains Mono", "Fira Code", Menlo, Consolas, monospace;
  font-weight: 800; font-size: 20px; letter-spacing: 1px;
  color: var(--fg);
}
header.brand .logo .red { color: var(--accent); }
header.brand .tagline {
  color: var(--fg-dim); font-size: 12px; margin-left: 4px;
  border-left: 1px solid var(--border); padding-left: 14px;
}
header.brand .ver { margin-left: auto; color: var(--fg-dim); font-size: 12px; }
main { padding: 24px 28px 60px; max-width: 1400px; margin: 0 auto; }

h2 {
  margin: 28px 0 14px;
  font-size: 16px; text-transform: uppercase; letter-spacing: 1.5px;
  color: var(--fg);
  border-left: 3px solid var(--accent); padding-left: 10px;
}

.grid { display: grid; gap: 14px; }
.grid.cols-2 { grid-template-columns: repeat(2, 1fr); }
.grid.cols-3 { grid-template-columns: repeat(3, 1fr); }
.grid.cols-5 { grid-template-columns: repeat(5, 1fr); }

.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px 16px;
}
.card h3 {
  margin: 0 0 10px;
  font-size: 12px; text-transform: uppercase; letter-spacing: 1px;
  color: var(--fg-dim);
}
.card .big { font-size: 28px; font-weight: 700; }
.card .kv { display: flex; justify-content: space-between; gap: 8px; padding: 3px 0;
            border-bottom: 1px dashed var(--border); }
.card .kv:last-child { border-bottom: none; }
.card .kv .k { color: var(--fg-dim); }
.card .kv .v { color: var(--fg); font-family: "JetBrains Mono", Menlo, monospace; font-size: 12px; }

.sev { display: inline-block; padding: 2px 8px; border-radius: 3px;
       font-size: 11px; font-weight: 700; letter-spacing: 1px; }
.sev-INFO     { background: rgba(90,155,245,.15); color: var(--info); }
.sev-LOW      { background: rgba(74,210,149,.15); color: var(--low); }
.sev-MEDIUM   { background: rgba(240,180,0,.18);  color: var(--medium); }
.sev-HIGH     { background: rgba(255,122,57,.18); color: var(--high); }
.sev-CRITICAL { background: rgba(255,46,78,.20);  color: var(--critical); }

.dash .card.sev-card { border-left: 3px solid var(--border); }
.dash .card.sev-card.INFO     { border-left-color: var(--info); }
.dash .card.sev-card.LOW      { border-left-color: var(--low); }
.dash .card.sev-card.MEDIUM   { border-left-color: var(--medium); }
.dash .card.sev-card.HIGH     { border-left-color: var(--high); }
.dash .card.sev-card.CRITICAL { border-left-color: var(--critical); }

table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 8px 10px; background: var(--bg-soft);
     border-bottom: 1px solid var(--border); color: var(--fg-dim);
     font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
td { padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:hover td { background: var(--bg-soft); }
td.mono { font-family: "JetBrains Mono", Menlo, monospace; font-size: 12px;
          color: var(--fg-dim); }
.evidence { font-family: "JetBrains Mono", Menlo, monospace; font-size: 11.5px;
            color: var(--fg-dim); white-space: pre-wrap;
            background: var(--bg); padding: 6px 8px; border-radius: 3px;
            border: 1px solid var(--border); margin-top: 6px;
            max-height: 200px; overflow: auto; }
details summary { cursor: pointer; color: var(--fg-dim); font-size: 12px;
                  user-select: none; }

.controls { display: flex; gap: 10px; margin: 12px 0; flex-wrap: wrap; }
.controls input, .controls select {
  background: var(--bg-soft); color: var(--fg);
  border: 1px solid var(--border); border-radius: 4px;
  padding: 6px 10px; font-size: 13px; font-family: inherit;
}
.controls input { min-width: 280px; }
.controls .count { color: var(--fg-dim); font-size: 12px; align-self: center; }

.pager { display: flex; gap: 8px; align-items: center; margin-top: 10px; }
.pager button {
  background: var(--bg-soft); color: var(--fg);
  border: 1px solid var(--border); border-radius: 4px;
  padding: 5px 12px; cursor: pointer; font-family: inherit; font-size: 12px;
}
.pager button:hover:not(:disabled) { border-color: var(--accent); }
.pager button:disabled { opacity: .35; cursor: not-allowed; }

footer { margin: 50px 28px 30px; color: var(--fg-dim); font-size: 11px;
         text-align: center; border-top: 1px solid var(--border); padding-top: 18px; }
"""


# --------------------------------------------------------------------------
# JS
# --------------------------------------------------------------------------
_JS = """
(function(){
  // ---- Findings filter ----------------------------------------------------
  const fInput = document.getElementById("f-search");
  const fSev   = document.getElementById("f-sev");
  const fCat   = document.getElementById("f-cat");
  const fRows  = Array.from(document.querySelectorAll("#findings-table tbody tr"));
  const fCount = document.getElementById("f-count");

  function applyFindingFilter(){
    const q   = (fInput.value || "").toLowerCase();
    const sev = fSev.value;
    const cat = fCat.value;
    let shown = 0;
    for (const r of fRows){
      const text = r.dataset.search;
      const okQ   = !q   || text.includes(q);
      const okSev = !sev || r.dataset.sev === sev;
      const okCat = !cat || r.dataset.cat === cat;
      const ok = okQ && okSev && okCat;
      r.style.display = ok ? "" : "none";
      if (ok) shown++;
    }
    fCount.textContent = shown + " / " + fRows.length;
  }
  if (fInput){ fInput.addEventListener("input", applyFindingFilter); }
  if (fSev){   fSev.addEventListener("change", applyFindingFilter); }
  if (fCat){   fCat.addEventListener("change", applyFindingFilter); }

  // ---- Timeline filter + pagination --------------------------------------
  const tInput = document.getElementById("t-search");
  const tSrc   = document.getElementById("t-src");
  const tType  = document.getElementById("t-type");
  const tBody  = document.getElementById("timeline-body");
  const tPrev  = document.getElementById("t-prev");
  const tNext  = document.getElementById("t-next");
  const tInfo  = document.getElementById("t-info");
  const tCount = document.getElementById("t-count");
  const PAGE = 100;

  if (!tBody) return;
  const tRows = Array.from(tBody.querySelectorAll("tr"));
  let filtered = tRows.slice();
  let page = 0;

  function applyTimeline(){
    const q    = (tInput.value || "").toLowerCase();
    const src  = tSrc.value;
    const type = tType.value;
    filtered = tRows.filter(r=>{
      const okQ    = !q    || r.dataset.search.includes(q);
      const okSrc  = !src  || r.dataset.src === src;
      const okType = !type || r.dataset.type === type;
      return okQ && okSrc && okType;
    });
    page = 0;
    render();
  }
  function render(){
    for (const r of tRows) r.style.display = "none";
    const start = page * PAGE;
    const end   = Math.min(start + PAGE, filtered.length);
    for (let i = start; i < end; i++) filtered[i].style.display = "";
    tCount.textContent = filtered.length + " / " + tRows.length;
    const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
    tInfo.textContent = "Page " + (page + 1) + " of " + pages;
    tPrev.disabled = page === 0;
    tNext.disabled = page >= pages - 1;
  }
  tInput.addEventListener("input", applyTimeline);
  tSrc.addEventListener("change", applyTimeline);
  tType.addEventListener("change", applyTimeline);
  tPrev.addEventListener("click", ()=>{ page = Math.max(0, page - 1); render(); });
  tNext.addEventListener("click", ()=>{ page += 1; render(); });
  applyTimeline();
})();
"""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _esc(x) -> str:
    if x is None:
        return ""
    return html.escape(str(x))


def _fmt_ts(ts) -> str:
    if ts is None:
        return ""
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# --------------------------------------------------------------------------
# Section builders
# --------------------------------------------------------------------------
def _build_summary(case) -> str:
    hi = case.host_info or {}
    rows = [
        ("Case",         case.case_name),
        ("Evidence",     str(case.evidence_root)),
        ("Generated",    case.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")),
        ("Hostname",     hi.get("hostname") or "(unknown)"),
        ("Distro",       hi.get("distro") or "(unknown)"),
        ("OS Release",   hi.get("os_release") or "(unknown)"),
        ("Kernel",       hi.get("kernel") or "(unknown)"),
    ]
    inner = "".join(
        f'<div class="kv"><span class="k">{_esc(k)}</span>'
        f'<span class="v">{_esc(v)}</span></div>'
        for k, v in rows
    )
    return f'<div class="card"><h3>Case Summary</h3>{inner}</div>'


def _build_severity_dashboard(case) -> str:
    counts = case.severity_counts()
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    cards = []
    for sev in order:
        n = counts.get(sev, 0)
        cards.append(
            f'<div class="card sev-card {sev}">'
            f'<h3>{sev}</h3>'
            f'<div class="big">{n}</div>'
            f'</div>'
        )
    return (
        '<div class="dash grid cols-5">'
        + "".join(cards)
        + "</div>"
    )


def _build_parser_stats(case) -> str:
    if not case.stats:
        return '<div class="card"><h3>Parser Stats</h3>'\
               '<div class="kv"><span class="k">No parsers ran</span></div></div>'
    rows = ["<table><thead><tr>"
            "<th>Parser</th><th>Files</th><th>Events</th>"
            "<th>Findings</th><th>Errors</th></tr></thead><tbody>"]
    for name in sorted(case.stats):
        s = case.stats[name]
        errs = s.get("errors") or []
        err_cell = (
            f'<details><summary>{len(errs)}</summary>'
            f'<div class="evidence">{_esc(chr(10).join(errs))}</div></details>'
            if errs else "0"
        )
        rows.append(
            f"<tr><td class='mono'>{_esc(name)}</td>"
            f"<td>{s.get('files',0)}</td>"
            f"<td>{s.get('events',0)}</td>"
            f"<td>{s.get('findings',0)}</td>"
            f"<td>{err_cell}</td></tr>"
        )
    rows.append("</tbody></table>")
    return "".join(rows)


def _build_findings(case) -> str:
    findings = case.findings_sorted()
    if not findings:
        return '<div class="card"><h3>Findings</h3>'\
               '<div class="kv"><span class="k">No findings recorded.</span></div></div>'

    cats = sorted({f.category for f in findings})
    cat_opts = "".join(f'<option value="{_esc(c)}">{_esc(c)}</option>' for c in cats)

    sev_opts = "".join(
        f'<option value="{s}">{s}</option>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    controls = (
        '<div class="controls">'
        '<input id="f-search" type="text" placeholder="Search findings...">'
        f'<select id="f-sev"><option value="">All severities</option>{sev_opts}</select>'
        f'<select id="f-cat"><option value="">All categories</option>{cat_opts}</select>'
        '<span class="count" id="f-count"></span>'
        '</div>'
    )

    rows = ["<table id='findings-table'><thead><tr>"
            "<th style='width:90px'>Severity</th>"
            "<th style='width:130px'>Category</th>"
            "<th>Title</th>"
            "<th>Artifact</th>"
            "<th style='width:170px'>Time (UTC)</th>"
            "</tr></thead><tbody>"]

    for f in findings:
        ts = _fmt_ts(f.timestamp)
        ev_block = ""
        if f.evidence:
            ev_text = "\n".join(f.evidence)
            ev_block = (
                f'<details><summary>evidence ({len(f.evidence)} line(s))</summary>'
                f'<div class="evidence">{_esc(ev_text)}</div></details>'
            )
        meta_block = ""
        if f.metadata:
            meta_text = json.dumps(f.metadata, indent=2, default=str)
            meta_block = (
                f'<details><summary>metadata</summary>'
                f'<div class="evidence">{_esc(meta_text)}</div></details>'
            )

        search_blob = (
            f"{f.severity} {f.category} {f.title} {f.description} {f.artifact}"
        ).lower()

        rows.append(
            f'<tr data-sev="{_esc(f.severity)}" data-cat="{_esc(f.category)}" '
            f'data-search="{_esc(search_blob)}">'
            f'<td><span class="sev sev-{_esc(f.severity)}">{_esc(f.severity)}</span></td>'
            f'<td class="mono">{_esc(f.category)}</td>'
            f'<td><strong>{_esc(f.title)}</strong>'
            f'<div style="color:var(--fg-dim);font-size:12px;margin-top:3px">'
            f'{_esc(f.description)}</div>'
            f'{ev_block}{meta_block}</td>'
            f'<td class="mono">{_esc(f.artifact)}</td>'
            f'<td class="mono">{_esc(ts)}</td>'
            f'</tr>'
        )
    rows.append("</tbody></table>")
    return controls + "".join(rows)


def _build_timeline(case) -> str:
    events = case.sorted_events()
    if not events:
        return '<div class="card"><h3>Timeline</h3>'\
               '<div class="kv"><span class="k">No timeline events.</span></div></div>'

    sources = sorted({e.source for e in events})
    types = sorted({e.event_type for e in events})

    src_opts = "".join(f'<option value="{_esc(s)}">{_esc(s)}</option>' for s in sources)
    type_opts = "".join(f'<option value="{_esc(t)}">{_esc(t)}</option>' for t in types)

    controls = (
        '<div class="controls">'
        '<input id="t-search" type="text" placeholder="Search timeline...">'
        f'<select id="t-src"><option value="">All sources</option>{src_opts}</select>'
        f'<select id="t-type"><option value="">All types</option>{type_opts}</select>'
        '<span class="count" id="t-count"></span>'
        '</div>'
    )

    rows = ["<table><thead><tr>"
            "<th style='width:170px'>Time (UTC)</th>"
            "<th style='width:130px'>Source</th>"
            "<th style='width:140px'>Event</th>"
            "<th style='width:110px'>User</th>"
            "<th>Description</th>"
            "</tr></thead><tbody id='timeline-body'>"]

    for e in events:
        ts = _fmt_ts(e.timestamp)
        search = (
            f"{ts} {e.source} {e.event_type} {e.user or ''} {e.host or ''} {e.description}"
        ).lower()
        rows.append(
            f'<tr data-src="{_esc(e.source)}" data-type="{_esc(e.event_type)}" '
            f'data-search="{_esc(search)}" style="display:none">'
            f'<td class="mono">{_esc(ts)}</td>'
            f'<td class="mono">{_esc(e.source)}</td>'
            f'<td class="mono">{_esc(e.event_type)}</td>'
            f'<td class="mono">{_esc(e.user or "")}</td>'
            f'<td>{_esc(e.description)}</td>'
            f'</tr>'
        )
    rows.append("</tbody></table>")
    pager = (
        '<div class="pager">'
        '<button id="t-prev">&larr; Prev</button>'
        '<button id="t-next">Next &rarr;</button>'
        '<span class="count" id="t-info"></span>'
        '</div>'
    )
    return controls + "".join(rows) + pager


# --------------------------------------------------------------------------
# Public entrypoint
# --------------------------------------------------------------------------
def write_html(case, path) -> Path:
    path = Path(path)

    body = []
    body.append(
        '<header class="brand">'
        '<div class="logo"><span class="red">[</span>Lethal'
        '<span class="red">DFIR</span><span class="red">]</span></div>'
        '<div class="tagline">Linux Forensics &middot; Offline Triage Report</div>'
        f'<div class="ver">v{_esc(__version__)}</div>'
        '</header>'
    )
    body.append('<main>')

    body.append('<h2>Overview</h2>')
    body.append('<div class="grid cols-2">')
    body.append(_build_summary(case))
    body.append('<div class="card"><h3>Severity Dashboard</h3>'
                + _build_severity_dashboard(case) + '</div>')
    body.append('</div>')

    body.append('<h2>Parser Run Statistics</h2>')
    body.append(_build_parser_stats(case))

    body.append('<h2>Findings</h2>')
    body.append(_build_findings(case))

    body.append('<h2>Super-Timeline</h2>')
    body.append(_build_timeline(case))

    body.append('</main>')
    body.append(
        f'<footer>Report generated by {_esc(__brand__)} '
        f'v{_esc(__version__)} &middot; '
        f'{_esc(case.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"))}</footer>'
    )

    page = (
        "<!doctype html>\n"
        "<html lang='en'><head><meta charset='utf-8'>\n"
        f"<title>LethalDFIR Linux Forensics &mdash; {_esc(case.case_name)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head><body>\n"
        + "".join(body)
        + f"\n<script>{_JS}</script>\n"
        "</body></html>\n"
    )
    path.write_text(page, encoding="utf-8")
    return path
