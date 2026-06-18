"""
ChocoScan — Générateur de rapport HTML/JSON.
Dashboard interactif avec graphiques, filtres dynamiques et recherche en temps réel.
"""

import json
from datetime import datetime
from pathlib import Path
from functools import lru_cache

ASSETS_DIR = Path(__file__).parent.parent / "assets"

from modules.contextual_scorer import score_to_html_badge, CTX_CSS
try:
    from modules.tag_definitions import html_badges as _tag_html_badges, TAG_CSS as _TAG_CSS
    _TAGS_AVAILABLE = True
except ImportError:
    _TAGS_AVAILABLE = False
    def _tag_html_badges(tags): return ""
    _TAG_CSS = ""

def _tag_csv(tags: list) -> str:
    """Convertit une liste de tags en chaîne CSV pour data-tags HTML."""
    return ",".join(tags) if tags else ""



@lru_cache(maxsize=2)
def _load_logo_b64(filename: str) -> str:
    path = ASSETS_DIR / filename
    with open(path, "rb") as f:
        import base64
        return base64.b64encode(f.read()).decode()


def get_logo_data_uri(found_cves: bool) -> str:
    filename = "chocowake.png" if found_cves else "chocosleep.png"
    b64 = _load_logo_b64(filename)
    return f"data:image/png;base64,{b64}"


def get_severity_order(severity: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}.get(
        severity.upper(), 5
    )


def safe_float(val) -> float:
    try:
        return float(str(val).replace("N/A", "0") or 0)
    except (ValueError, TypeError):
        return 0.0


def export_json(results: list, output_file: str, target: str, scan_date: str):
    report = {
        "metadata": {
            "target": target,
            "scan_date": scan_date,
            "tool": "ChocoScan by Kinder-Bueno",
            "total_services": len(results),
            "total_cves": sum(len(r["cves"]) for r in results),
        },
        "results": results,
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def export_html(results: list, output_file: str, target: str, scan_date: str, chains: list | None = None, ad_ctx=None, bh_data=None):
    total_cves   = sum(len(r["cves"]) for r in results)
    total_svc    = len(results)
    svc_vuln     = sum(1 for r in results if r["cves"])
    logo_uri     = get_logo_data_uri(found_cves=total_cves > 0)

    # Comptages par sévérité
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        for c in r["cves"]:
            s = str(c.get("severity", "")).upper()
            if s in counts:
                counts[s] += 1

    # CVEs avec exploit dispo
    exploit_count = sum(
        1 for r in results for c in r["cves"]
        if c.get("exploit_available") or c.get("exploits")
    )

    # Données JSON pour les graphiques JS
    chart_data = json.dumps({
        "CRITICAL": counts["CRITICAL"],
        "HIGH":     counts["HIGH"],
        "MEDIUM":   counts["MEDIUM"],
        "LOW":      counts["LOW"],
    })

    # Données pour la bar chart CVSS par service
    service_chart = json.dumps([
        {
            "port":  r["service"]["port"],
            "svc":   r["service"]["service_name"],
            "worst": max((safe_float(c.get("cvss", 0)) for c in r["cves"]), default=0),
            "count": len(r["cves"]),
        }
        for r in results if r["cves"]
    ])

    # ── Génération des cards ──────────────────────────────────────────────────
    cards_html = ""
    for idx, result in enumerate(results):
        svc   = result["service"]
        cves  = sorted(result["cves"], key=lambda c: get_severity_order(str(c.get("severity", "UNKNOWN"))))
        host  = result.get("host", target)

        if not cves:
            cards_html += f"""
        <div class="svc-card no-cve" data-port="{svc['port']}">
          <div class="svc-head">
            <div class="svc-left">
              <span class="port-tag">{svc['port']}/{svc['protocol']}</span>
              <span class="svc-name">{svc['service_name']}</span>
              <span class="svc-banner">{svc.get('banner') or 'Version inconnue'}</span>
            </div>
            <span class="badge-clean">Aucune CVE</span>
          </div>
        </div>"""
            continue

        worst_sev = cves[0].get("severity", "UNKNOWN").upper() if cves else "UNKNOWN"
        worst_score = safe_float(cves[0].get("cvss", 0)) if cves else 0

        sev_colors = {
            "CRITICAL": "#ef4444", "HIGH": "#f97316",
            "MEDIUM":   "#eab308", "LOW":  "#22c55e",
            "UNKNOWN":  "#6b7280",
        }
        border_color = sev_colors.get(worst_sev, "#6b7280")

        # Lignes CVE
        rows = ""
        for c in cves:
            cid   = c.get("id", "N/A")
            score = safe_float(c.get("cvss", 0))
            sev   = str(c.get("severity", "UNKNOWN")).upper()
            color = sev_colors.get(sev, "#6b7280")
            desc  = (c.get("description") or "")[:280]
            desc_fr = (c.get("description_fr") or "")[:280]
            aff   = ", ".join(c.get("affected_versions", [])[:3])
            has_exp = c.get("exploit_available") or bool(c.get("exploits"))
            exp_icon = '<span class="exp-yes" title="PoC disponible">⚡ PoC</span>' if has_exp else '<span class="exp-no">—</span>'
            year  = cid.split("-")[1] if cid.startswith("CVE-") and len(cid.split("-")) > 1 else ""

            # Badge score contextuel
            ctx_badge = score_to_html_badge(c) if c.get("ctx_score") is not None else ""
            cve_tags  = c.get("tags", []) or c.get("ctx_tags", [])
            tags_html = _tag_html_badges(cve_tags) if cve_tags else ""

            nvd_link = f'<a href="https://nvd.nist.gov/vuln/detail/{cid}" target="_blank" class="cve-link">{cid}</a>' if cid.startswith("CVE-") else f'<span class="cve-link-plain">{cid}</span>'

            # Exploits
            exploit_links = ""
            for exp in (c.get("exploits") or [])[:3]:
                exp_url  = exp.get("url", "")
                exp_name = exp.get("repo", exp_url.split("/")[-1] if exp_url else "PoC")[:32]
                exp_star = exp.get("stars", "")
                star_str = f"★{exp_star} " if exp_star else ""
                if exp_url:
                    exploit_links += f'<a href="{exp_url}" target="_blank" class="exp-link">{star_str}{exp_name}</a>'

            # Refs (hors nvd)
            other_refs = [r for r in c.get("references", []) if "nvd.nist.gov" not in r][:2]
            ref_links = " ".join(
                f'<a href="{ref}" target="_blank" class="ref-link">ref</a>'
                for ref in other_refs
            )

            rows += f"""
              <tr class="cve-row" data-sev="{sev}" data-score="{score}" data-year="{year}"
                  data-id="{cid.lower()}" data-desc="{desc.lower()[:80]}"
                  data-ctx="{c.get('ctx_score', score)}"
                  data-tags="{_tag_csv(cve_tags)}">
                <td class="td-cve">
                  {nvd_link}
                  {ref_links}
                  <span class="cve-year">{year}</span>
                </td>
                <td class="td-sev">
                  <span class="sev-pill" style="background:{color}22;color:{color};border:1px solid {color}44">{sev}</span>
                </td>
                <td class="td-score">
                  <span class="score-num" style="color:{color}">{c.get('cvss','N/A')}</span>
                </td>
                <td class="td-ctx">{ctx_badge}</td>
                <td class="td-desc">
                  <div class="desc-en">{desc or '<em>N/A</em>'}</div>
                  <div class="desc-fr">{desc_fr or ''}</div>
                  {('<div class="cve-tags">' + tags_html + '</div>') if tags_html else ''}
                </td>
                <td class="td-aff">
                  <span class="aff-text">{aff or '—'}</span>
                </td>
                <td class="td-exp">
                  {exp_icon}
                  {exploit_links}
                </td>
              </tr>"""

        cards_html += f"""
      <div class="svc-card" id="svc-{idx}"
           data-port="{svc['port']}" data-svc="{svc['service_name']}"
           data-worst="{worst_sev}" data-count="{len(cves)}">
        <div class="svc-head" onclick="toggleCard({idx})">
          <div class="svc-left">
            <span class="port-tag" style="border-color:{border_color}44;color:{border_color}">{svc['port']}/{svc['protocol']}</span>
            <div class="svc-text">
              <span class="svc-name">{svc['service_name']}</span>
              <span class="svc-banner">{svc.get('banner') or 'Version inconnue'}</span>
            </div>
          </div>
          <div class="svc-right">
            <span class="sev-pill worst-pill"
                  style="background:{border_color}22;color:{border_color};border:1px solid {border_color}55">
              {worst_sev} {worst_score}
            </span>
            <span class="cve-badge">{len(cves)} CVE{'s' if len(cves)>1 else ''}</span>
            <span class="chevron" id="chev-{idx}">▼</span>
          </div>
        </div>
        <div class="svc-body" id="body-{idx}">
          <div class="table-toolbar">
            <input type="text" class="row-search" placeholder="Filtrer cette table…"
                   oninput="filterRows({idx}, this.value)">
            <div class="sev-filters">
              <button class="sf-btn active" data-sev="ALL"   onclick="filterSev({idx},'ALL',this)">Tout</button>
              <button class="sf-btn crit"   data-sev="CRITICAL" onclick="filterSev({idx},'CRITICAL',this)">CRITICAL</button>
              <button class="sf-btn high"   data-sev="HIGH"  onclick="filterSev({idx},'HIGH',this)">HIGH</button>
              <button class="sf-btn med"    data-sev="MEDIUM" onclick="filterSev({idx},'MEDIUM',this)">MEDIUM</button>
            </div>
            <div class="year-filter">
              <label>Depuis : <select onchange="filterYear({idx}, this.value)">
                <option value="0">Toutes années</option>
                <option value="2024">2024+</option>
                <option value="2025">2025+</option>
                <option value="2026">2026+</option>
              </select></label>
            </div>
          </div>
          <div class="table-wrap">
            <table class="cve-table" id="tbl-{idx}">
              <thead>
                <tr>
                  <th class="sortable" onclick="sortTable({idx},0)">CVE ID ↕</th>
                  <th class="sortable" onclick="sortTable({idx},1)">Sévérité ↕</th>
                  <th class="sortable" onclick="sortTable({idx},2)">CVSS ↕</th>
                  <th class="sortable" onclick="sortTable({idx},3)">Score CTX ↕</th>
                  <th>Description</th>
                  <th>Versions affectées</th>
                  <th>Exploit</th>
                </tr>
              </thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>
      </div>"""

    # ── HTML final ────────────────────────────────────────────────────────────
    # Stat card chaînes
    chains_stat_html = ""
    if chains:
        n = len(chains)
        chains_stat_html = f'''<div class="stat stat-chain" style="--chain-color:#a855f7">
      <div class="stat-lbl">Chaînes détectées</div>
      <div class="stat-val" style="color:#a855f7">{n}</div>
    </div>'''

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ChocoScan — {target}</title>
  <style>
    /* ── Reset & base ─────────────────────────────────────── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg0:   #080916;
      --bg1:   #0d0f1f;
      --bg2:   #111428;
      --bg3:   #171b30;
      --bg4:   #1e243a;
      --line:  #1c2240;
      --text0: #dce8f8;
      --text1: #8aaad0;
      --text2: #4a6488;
      --acc:   #4090f0;
      --acc2:  #80c0f8;
      --crit:  #ef4444;
      --high:  #f97316;
      --med:   #eab308;
      --low:   #22c55e;
      --exp:   #38bdf8;
      --radius: 8px;
      --shadow: 0 4px 24px rgba(0,0,0,.45);
    }}
    body {{
      font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
      background: var(--bg0);
      color: var(--text0);
      min-height: 100vh;
      font-size: 14px;
    }}
    a {{ color: inherit; text-decoration: none; }}

    /* ── Topbar ────────────────────────────────────────────── */
    .topbar {{
      background: #101030;
      border-bottom: 1px solid #1e2050;
      padding: 0 2rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      height: 64px;
      position: sticky;
      top: 0;
      z-index: 100;
    }}
    .logo-wrap img {{ height: 44px; width: auto; display: block; }}
    .topbar-meta {{
      display: flex;
      gap: 2rem;
      font-size: 12px;
      color: var(--text2);
    }}
    .topbar-meta span {{ display: flex; flex-direction: column; }}
    .topbar-meta strong {{ color: var(--text1); font-size: 13px; margin-top: 1px; }}

    /* ── Hero stats ───────────────────────────────────────── */
    .hero {{
      background: linear-gradient(170deg, #101030 0%, #0a0c1e 55%, var(--bg0) 100%);
      border-bottom: 1px solid #1e2050;
      padding: 2rem 2rem 1.5rem;
    }}
    .hero-target {{
      font-family: 'Courier New', monospace;
      font-size: 1.4rem;
      font-weight: 700;
      color: var(--acc2);
      margin-bottom: 1.25rem;
      display: flex;
      align-items: center;
      gap: .5rem;
    }}
    .hero-target::before {{
      content: '▶';
      color: var(--acc);
      font-size: .9rem;
    }}
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: .75rem;
      max-width: 900px;
    }}
    .stat {{
      background: var(--bg2);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: .9rem 1.1rem;
      position: relative;
      overflow: hidden;
    }}
    .stat::before {{
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 2px;
    }}
    .stat-crit::before  {{ background: var(--crit); }}
    .stat-high::before  {{ background: var(--high); }}
    .stat-med::before   {{ background: var(--med); }}
    .stat-low::before   {{ background: var(--low); }}
    .stat-exp::before   {{ background: var(--exp); }}
    .stat-svc::before   {{ background: var(--acc); }}
    .stat-lbl {{
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: .07em;
      color: var(--text2);
      margin-bottom: .3rem;
    }}
    .stat-val {{
      font-size: 2rem;
      font-weight: 800;
      line-height: 1;
    }}
    .stat-crit .stat-val  {{ color: var(--crit); }}
    .stat-high .stat-val  {{ color: var(--high); }}
    .stat-med  .stat-val  {{ color: var(--med);  }}
    .stat-low  .stat-val  {{ color: var(--low);  }}
    .stat-exp  .stat-val  {{ color: var(--exp);  }}
    .stat-svc  .stat-val  {{ color: var(--acc2); }}

    /* ── Charts row ───────────────────────────────────────── */
    .charts-row {{
      display: grid;
      grid-template-columns: 220px 1fr;
      gap: 1rem;
      padding: 1.5rem 2rem;
      background: #0d0f1f;
      border-bottom: 1px solid #1e2050;
    }}
    .chart-box {{
      background: var(--bg2);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 1rem 1.25rem;
    }}
    .chart-title {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: .07em;
      color: var(--text2);
      margin-bottom: .85rem;
    }}
    #donut-canvas {{ display: block; margin: 0 auto; }}
    .donut-legend {{ display: flex; flex-wrap: wrap; gap: .4rem .9rem; margin-top: .75rem; justify-content: center; }}
    .dl-item {{ display: flex; align-items: center; gap: .3rem; font-size: 11px; color: var(--text1); }}
    .dl-dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}
    #bar-canvas {{ display: block; width: 100%; height: 130px; }}

    /* ── Global toolbar ───────────────────────────────────── */
    .toolbar {{
      display: flex;
      gap: .75rem;
      align-items: center;
      flex-wrap: wrap;
      padding: 1rem 2rem;
      background: #0d0f1f;
      border-bottom: 1px solid #1e2050;
      position: sticky;
      top: 64px;
      z-index: 90;
    }}
    .g-search {{
      flex: 1;
      min-width: 200px;
      background: var(--bg3);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: .4rem .9rem;
      color: var(--text0);
      font-size: 13px;
      outline: none;
      transition: border-color .15s;
    }}
    .g-search:focus {{ border-color: var(--acc); }}
    .g-search::placeholder {{ color: var(--text2); }}
    .filter-group {{ display: flex; gap: .4rem; }}
    .g-btn {{
      background: var(--bg3);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: .35rem .75rem;
      color: var(--text1);
      font-size: 12px;
      cursor: pointer;
      transition: all .15s;
    }}
    .g-btn:hover {{ background: var(--bg4); color: var(--text0); }}
    .g-btn.active {{ background: #4090f022; border-color: #4090f0; color: #80c0f8; }}
    .g-btn.crit.active {{ background: #ef444422; border-color: var(--crit); color: var(--crit); }}
    .g-btn.high.active {{ background: #f9731622; border-color: var(--high); color: var(--high); }}
    .g-btn.med.active  {{ background: #eab30822; border-color: var(--med);  color: var(--med);  }}
    .g-btn.only-exp {{ margin-left: .25rem; }}
    .results-count {{ font-size: 12px; color: var(--text2); margin-left: auto; }}

    /* ── Main content ─────────────────────────────────────── */
    .main {{ padding: 1.25rem 2rem 3rem; max-width: 1500px; margin: 0 auto; }}

    /* ── Service cards ───────────────────────────────────── */
    .svc-card {{
      background: var(--bg2);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      margin-bottom: .85rem;
      overflow: hidden;
      transition: box-shadow .2s;
    }}
    .svc-card:hover {{ box-shadow: var(--shadow); }}
    .svc-card.no-cve {{ opacity: .45; }}

    .svc-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: .85rem 1.25rem;
      cursor: pointer;
      user-select: none;
      background: var(--bg3);
      border-bottom: 1px solid transparent;
      transition: background .15s;
      flex-wrap: wrap;
      gap: .5rem;
    }}
    .svc-head:hover {{ background: var(--bg4); }}
    .svc-left {{ display: flex; align-items: center; gap: .65rem; flex-wrap: wrap; }}
    .svc-right {{ display: flex; align-items: center; gap: .6rem; }}

    .port-tag {{
      font-family: 'Courier New', monospace;
      font-size: 12px;
      font-weight: 700;
      padding: .2rem .6rem;
      border-radius: 5px;
      border: 1px solid var(--line);
      background: var(--bg4);
      white-space: nowrap;
    }}
    .svc-text {{ display: flex; flex-direction: column; gap: .1rem; }}
    .svc-name {{
      font-weight: 600;
      color: var(--text0);
      font-size: 14px;
    }}
    .svc-banner {{
      font-family: 'Courier New', monospace;
      font-size: 11px;
      color: var(--text2);
    }}
    .sev-pill {{
      font-size: 11px;
      font-weight: 700;
      padding: .18rem .55rem;
      border-radius: 4px;
      letter-spacing: .04em;
      white-space: nowrap;
    }}
    .worst-pill {{ font-size: 12px; }}
    .cve-badge {{
      background: var(--bg0);
      color: var(--text1);
      font-size: 11px;
      padding: .18rem .6rem;
      border-radius: 20px;
      border: 1px solid var(--line);
    }}
    .badge-clean {{
      font-size: 11px;
      color: var(--text2);
      background: var(--bg4);
      padding: .2rem .6rem;
      border-radius: 4px;
    }}
    .chevron {{
      color: var(--text2);
      font-size: 11px;
      transition: transform .2s;
    }}
    .chevron.open {{ transform: rotate(180deg); }}

    /* ── Table toolbar ───────────────────────────────────── */
    .svc-body {{ display: none; }}
    .svc-body.open {{ display: block; }}
    .table-toolbar {{
      display: flex;
      gap: .6rem;
      align-items: center;
      flex-wrap: wrap;
      padding: .7rem 1.25rem;
      background: var(--bg1);
      border-bottom: 1px solid var(--line);
    }}
    .row-search {{
      background: var(--bg3);
      border: 1px solid var(--line);
      border-radius: 5px;
      padding: .3rem .7rem;
      color: var(--text0);
      font-size: 12px;
      outline: none;
      width: 180px;
      transition: border-color .15s;
    }}
    .row-search:focus {{ border-color: var(--acc); }}
    .row-search::placeholder {{ color: var(--text2); }}
    .sev-filters {{ display: flex; gap: .3rem; }}
    .sf-btn {{
      background: var(--bg3);
      border: 1px solid var(--line);
      border-radius: 5px;
      padding: .25rem .6rem;
      color: var(--text2);
      font-size: 11px;
      cursor: pointer;
      font-weight: 600;
      transition: all .15s;
    }}
    .sf-btn:hover {{ background: var(--bg4); color: var(--text1); }}
    .sf-btn.active {{ background: var(--acc)22; border-color: var(--acc); color: var(--acc2); }}
    .sf-btn.crit.active {{ background: #ef444418; border-color: #ef4444; color: #ef4444; }}
    .sf-btn.high.active {{ background: #f9731618; border-color: #f97316; color: #f97316; }}
    .sf-btn.med.active  {{ background: #eab30818; border-color: #eab308; color: #eab308; }}
    .year-filter {{ font-size: 11px; color: var(--text2); display: flex; align-items: center; gap: .3rem; }}
    .year-filter select {{
      background: var(--bg3);
      border: 1px solid var(--line);
      border-radius: 5px;
      padding: .2rem .5rem;
      color: var(--text1);
      font-size: 11px;
      cursor: pointer;
      outline: none;
    }}

    /* ── CVE Table ────────────────────────────────────────── */
    .table-wrap {{ overflow-x: auto; }}
    .cve-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12.5px;
    }}
    .cve-table thead th {{
      background: var(--bg0);
      color: var(--text2);
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .07em;
      padding: .5rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--line);
      white-space: nowrap;
    }}
    .sortable {{ cursor: pointer; }}
    .sortable:hover {{ color: var(--text0); }}
    .cve-row td {{
      padding: .65rem 1rem;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }}
    .cve-row:last-child td {{ border-bottom: none; }}
    .cve-row:hover {{ background: rgba(255,255,255,.02); }}
    .cve-row.hidden {{ display: none; }}

    .td-cve {{ min-width: 145px; white-space: nowrap; }}
    .cve-link {{
      font-family: 'Courier New', monospace;
      font-size: 12px;
      color: #60a0f0;
      border-bottom: 1px dashed rgba(96,160,240,.3);
      transition: color .15s;
      display: block;
    }}
    .cve-link:hover {{ color: #a0d0f0; border-bottom-color: #a0d0f0; }}
    .cve-link-plain {{
      font-family: 'Courier New', monospace;
      font-size: 12px;
      color: var(--text2);
    }}
    .cve-year {{
      display: inline-block;
      font-size: 10px;
      color: var(--text2);
      background: var(--bg4);
      padding: .05rem .35rem;
      border-radius: 3px;
      margin-top: .2rem;
    }}
    .ref-link {{
      display: inline-block;
      font-size: 10px;
      color: var(--text2);
      border: 1px solid var(--line);
      border-radius: 3px;
      padding: .05rem .3rem;
      margin-top: .2rem;
      margin-right: .2rem;
      transition: color .15s, border-color .15s;
    }}
    .ref-link:hover {{ color: var(--text0); border-color: var(--text2); }}

    .td-score {{ white-space: nowrap; text-align: center; }}
    .td-ctx {{ min-width: 130px; vertical-align: top; padding: .4rem .6rem !important; }}
    .score-num {{
      font-family: 'Courier New', monospace;
      font-size: 1.1rem;
      font-weight: 800;
    }}
    .td-desc {{ max-width: 380px; }}
    .desc-en {{ color: var(--text1); line-height: 1.5; margin-bottom: .25rem; }}
    .desc-fr {{
      color: var(--text2);
      font-size: 11.5px;
      line-height: 1.4;
      padding-top: .25rem;
      border-top: 1px solid var(--line);
      margin-top: .25rem;
    }}
    .desc-fr:empty {{ display: none; }}
    .td-aff {{ max-width: 160px; }}
    .aff-text {{ font-family: 'Courier New', monospace; font-size: 11px; color: var(--text2); line-height: 1.6; }}
    .td-exp {{ min-width: 120px; }}
    .exp-yes {{
      display: inline-block;
      font-size: 11px;
      font-weight: 700;
      color: var(--exp);
      background: rgba(56,189,248,.1);
      border: 1px solid rgba(56,189,248,.3);
      border-radius: 4px;
      padding: .1rem .4rem;
      margin-bottom: .3rem;
    }}
    .exp-no {{ color: var(--text2); font-size: 11px; }}
    .exp-link {{
      display: block;
      font-family: 'Courier New', monospace;
      font-size: 11px;
      color: #4ade80;
      margin-top: .2rem;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 180px;
      border-bottom: 1px dashed rgba(74,222,128,.25);
      transition: color .15s;
    }}
    .exp-link:hover {{ color: #86efac; border-bottom-color: #86efac; }}

    /* ── Footer ──────────────────────────────────────────── */
    .footer {{
      text-align: center;
      padding: 1.5rem;
      color: var(--text2);
      font-size: 11px;
      border-top: 1px solid var(--line);
      margin-top: 2rem;
    }}

    /* ── Responsive ──────────────────────────────────────── */
    @media (max-width: 900px) {{
      .charts-row {{ grid-template-columns: 1fr; }}
      .topbar-meta {{ display: none; }}
      .toolbar, .main, .hero, .charts-row {{ padding-left: 1rem; padding-right: 1rem; }}
    }}
    /* ── Scoring contextuel ─────────────────────────── */
    .ctx-score-block {{ background:#0a0d1a; border:1px solid #1c2240; border-radius:5px; padding:.4rem .6rem; min-width:120px; cursor:help; }}
    .ctx-score-header {{ display:flex; align-items:baseline; gap:.3rem; margin-bottom:.25rem; }}
    .ctx-grade {{ font-size:.85rem; font-weight:900; font-family:monospace; }}
    .ctx-score-val {{ font-size:1rem; font-weight:800; font-family:'Courier New',monospace; }}
    .ctx-label {{ font-size:.65rem; font-weight:700; letter-spacing:.04em; }}
    .ctx-bar-wrap {{ background:#1e243a; border-radius:2px; height:3px; margin-bottom:.3rem; overflow:hidden; }}
    .ctx-bar {{ height:100%; border-radius:2px; }}
    .ctx-flags {{ display:flex; flex-wrap:wrap; gap:.2rem; }}
    .ctx-flag {{ font-size:.62rem; font-weight:600; padding:.05rem .3rem; border-radius:3px; white-space:nowrap; }}
    .ctx-flag.kev    {{ background:rgba(239,68,68,.15);  color:#ef4444; border:1px solid #ef444433; }}
    .ctx-flag.msf    {{ background:rgba(59,130,246,.15); color:#60a5fa; border:1px solid #60a5fa33; }}
    .ctx-flag.edb    {{ background:rgba(249,115,22,.15); color:#fb923c; border:1px solid #fb923c33; }}
    .ctx-flag.gh     {{ background:rgba(156,163,175,.1); color:#9ca3af; border:1px solid #9ca3af22; }}
    .ctx-flag.noauth {{ background:rgba(34,211,238,.1);  color:#22d3ee; border:1px solid #22d3ee33; }}
    .ctx-flag.rce    {{ background:rgba(239,68,68,.1);   color:#fca5a5; border:1px solid #ef444422; }}
    .ctx-flag.lpe    {{ background:rgba(234,179,8,.1);   color:#fde047; border:1px solid #eab30822; }}
    @media print {{
      .toolbar, .table-toolbar, .topbar {{ display: none !important; }}
      .svc-body {{ display: block !important; }}
      body {{ background: #fff; color: #000; }}
    }}
  {_TAG_CSS}
  </style>
</head>
<body>

<!-- TOPBAR -->
<nav class="topbar">
  <div class="logo-wrap"><img src="{logo_uri}" alt="ChocoScan"></div>
  <div class="topbar-meta">
    <span>Cible<strong>{target}</strong></span>
    <span>Date<strong>{scan_date}</strong></span>
    <span>Services<strong>{total_svc}</strong></span>
    <span>CVEs<strong>{total_cves}</strong></span>
  </div>
</nav>

<!-- HERO STATS -->
<div class="hero">
  <div class="hero-target">{target}</div>
  <div class="stats-grid">
    <div class="stat stat-crit"><div class="stat-lbl">Critical (≥9.0)</div><div class="stat-val">{counts["CRITICAL"]}</div></div>
    <div class="stat stat-high"><div class="stat-lbl">High (≥7.0)</div><div class="stat-val">{counts["HIGH"]}</div></div>
    <div class="stat stat-med"><div class="stat-lbl">Medium</div><div class="stat-val">{counts["MEDIUM"]}</div></div>
    <div class="stat stat-low"><div class="stat-lbl">Low</div><div class="stat-val">{counts["LOW"]}</div></div>
    <div class="stat stat-exp"><div class="stat-lbl">Avec PoC</div><div class="stat-val">{exploit_count}</div></div>
    <div class="stat stat-svc"><div class="stat-lbl">Services vulnérables</div><div class="stat-val">{svc_vuln}/{total_svc}</div></div>
    {chains_stat_html}
  </div>
</div>

<!-- CHARTS -->
<div class="charts-row">
  <div class="chart-box">
    <div class="chart-title">Répartition par sévérité</div>
    <canvas id="donut-canvas" width="170" height="170"></canvas>
    <div class="donut-legend">
      <div class="dl-item"><div class="dl-dot" style="background:#ef4444"></div>CRITICAL ({counts["CRITICAL"]})</div>
      <div class="dl-item"><div class="dl-dot" style="background:#f97316"></div>HIGH ({counts["HIGH"]})</div>
      <div class="dl-item"><div class="dl-dot" style="background:#eab308"></div>MEDIUM ({counts["MEDIUM"]})</div>
      <div class="dl-item"><div class="dl-dot" style="background:#22c55e"></div>LOW ({counts["LOW"]})</div>
    </div>
  </div>
  <div class="chart-box">
    <div class="chart-title">Score CVSS maximum par service</div>
    <canvas id="bar-canvas"></canvas>
  </div>
</div>

<!-- GLOBAL TOOLBAR -->
<div class="toolbar">
  <input type="text" class="g-search" id="g-search"
         placeholder="Rechercher une CVE, un service, une description…"
         oninput="globalSearch(this.value)">
  <div class="filter-group">
    <button class="g-btn active" data-sev="ALL"
            onclick="globalSev('ALL',this)">Tout</button>
    <button class="g-btn crit" data-sev="CRITICAL"
            onclick="globalSev('CRITICAL',this)">CRITICAL</button>
    <button class="g-btn high" data-sev="HIGH"
            onclick="globalSev('HIGH',this)">HIGH</button>
    <button class="g-btn med"  data-sev="MEDIUM"
            onclick="globalSev('MEDIUM',this)">MEDIUM</button>
  </div>
  <button class="g-btn only-exp" id="exp-toggle"
          onclick="toggleExploitOnly()">⚡ Avec PoC seulement</button>
  <button class="g-btn" onclick="expandAll()">↕ Tout déplier</button>
  <button class="g-btn" onclick="collapseAll()">↕ Tout replier</button>
  <span class="results-count" id="results-count">{total_cves} CVEs affichées</span>
</div>

<!-- MAIN -->
<main class="main" id="main">
  {cards_html}
</main>

<div class="footer">
  Généré par <strong>ChocoScan</strong> — Projet offensif portfolio |
  Kinder-Bueno (Mathys CASTELLA) — {scan_date}
</div>

<!-- JAVASCRIPT -->
<script>
const CHART_DATA   = {chart_data};
const SERVICE_DATA = {service_chart};

/* ── Donut chart ─────────────────────────────────────── */
(function() {{
  const c  = document.getElementById('donut-canvas');
  if (!c) return;
  const cx = c.getContext('2d');
  const data = [
    {{ val: CHART_DATA.CRITICAL, color: '#ef4444' }},
    {{ val: CHART_DATA.HIGH,     color: '#f97316' }},
    {{ val: CHART_DATA.MEDIUM,   color: '#eab308' }},
    {{ val: CHART_DATA.LOW,      color: '#22c55e' }},
  ];
  const total = data.reduce((s,d)=>s+d.val,0);
  if (!total) {{
    cx.fillStyle='#1e2335'; cx.fillRect(0,0,170,170);
    cx.fillStyle='#5c6585'; cx.font='13px sans-serif';
    cx.textAlign='center'; cx.fillText('Aucune CVE',85,90);
    return;
  }}
  const cx2=85, cy2=85, ro=70, ri=42;
  let angle = -Math.PI/2;
  data.forEach(d=>{{
    if(!d.val) return;
    const slice = (d.val/total)*2*Math.PI;
    cx.beginPath(); cx.moveTo(cx2,cy2);
    cx.arc(cx2,cy2,ro,angle,angle+slice);
    cx.lineTo(cx2,cy2); cx.fillStyle=d.color; cx.fill();
    angle+=slice;
  }});
  cx.beginPath(); cx.arc(cx2,cy2,ri,0,2*Math.PI);
  cx.fillStyle='#10131e'; cx.fill();
  cx.fillStyle='#e8eaf6'; cx.font='bold 28px Courier New';
  cx.textAlign='center'; cx.textBaseline='middle';
  cx.fillText(total,cx2,cy2-4);
  cx.fillStyle='#5c6585'; cx.font='10px sans-serif';
  cx.fillText('CVEs',cx2,cy2+16);
}})();

/* ── Bar chart ────────────────────────────────────────── */
(function(){{
  const c = document.getElementById('bar-canvas');
  if (!c || !SERVICE_DATA.length) return;
  const dpr = window.devicePixelRatio||1;
  const W=c.parentElement.clientWidth-40||600, H=130;
  c.width=W*dpr; c.height=H*dpr; c.style.width=W+'px'; c.style.height=H+'px';
  const cx=c.getContext('2d'); cx.scale(dpr,dpr);
  const pad=30, bw=Math.min(32,(W-pad*2)/SERVICE_DATA.length-6);
  const colorFor=v=>v>=9?'#ef4444':v>=7?'#f97316':v>=4?'#eab308':'#22c55e';
  SERVICE_DATA.forEach((d,i)=>{{
    const x=pad+i*(bw+6), barH=(d.worst/10)*(H-36), y=H-20-barH;
    cx.fillStyle=colorFor(d.worst)+'55';
    cx.fillRect(x,y,bw,barH);
    cx.fillStyle=colorFor(d.worst);
    cx.fillRect(x,y,bw,3);
    cx.fillStyle='#5c6585'; cx.font='9px sans-serif';
    cx.textAlign='center';
    const lbl=(d.port+'/'+d.svc).slice(0,10);
    cx.fillText(lbl,x+bw/2,H-5);
    if(d.worst>0){{
      cx.fillStyle=colorFor(d.worst); cx.font='bold 10px Courier New';
      cx.fillText(d.worst.toFixed(1),x+bw/2,y-4);
    }}
  }});
  cx.strokeStyle='#1f2744'; cx.lineWidth=1;
  cx.beginPath(); cx.moveTo(pad,H-20); cx.lineTo(W-pad,H-20); cx.stroke();
}})();

/* ── Card toggle ──────────────────────────────────────── */
function toggleCard(idx){{
  const body=document.getElementById('body-'+idx);
  const chev=document.getElementById('chev-'+idx);
  if(!body) return;
  body.classList.toggle('open');
  chev && chev.classList.toggle('open');
}}
function expandAll(){{
  document.querySelectorAll('.svc-body').forEach(b=>b.classList.add('open'));
  document.querySelectorAll('.chevron').forEach(c=>c.classList.add('open'));
}}
function collapseAll(){{
  document.querySelectorAll('.svc-body').forEach(b=>b.classList.remove('open'));
  document.querySelectorAll('.chevron').forEach(c=>c.classList.remove('open'));
}}

/* ── Per-card filters ────────────────────────────────── */
function filterRows(idx,val){{
  const q=val.toLowerCase();
  document.querySelectorAll('#tbl-'+idx+' .cve-row').forEach(row=>{{
    const txt=row.dataset.id+' '+row.dataset.desc;
    row.classList.toggle('hidden',q&&!txt.includes(q));
  }});
  updateCount();
}}
function filterSev(idx,sev,btn){{
  btn.closest('.sev-filters').querySelectorAll('.sf-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#tbl-'+idx+' .cve-row').forEach(row=>{{
    row.classList.toggle('hidden', sev!=='ALL' && row.dataset.sev!==sev);
  }});
  updateCount();
}}
function filterYear(idx,year){{
  const y=parseInt(year)||0;
  document.querySelectorAll('#tbl-'+idx+' .cve-row').forEach(row=>{{
    const ry=parseInt(row.dataset.year)||0;
    row.classList.toggle('hidden-year', y>0 && ry<y);
  }});
  updateCount();
}}

/* ── Global search / filter ──────────────────────────── */
let gSev='ALL', gExpOnly=false;
function globalSearch(val){{
  const q=val.toLowerCase();
  document.querySelectorAll('.cve-row').forEach(row=>{{
    const txt=row.dataset.id+' '+row.dataset.desc+' '+(row.dataset.sev||'');
    row.classList.toggle('hidden-gsearch', q&&!txt.includes(q));
  }});
  applyVisibility();
}}
function globalSev(sev,btn){{
  document.querySelectorAll('.toolbar .filter-group .g-btn')
    .forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  gSev=sev;
  document.querySelectorAll('.cve-row').forEach(row=>{{
    row.classList.toggle('hidden-gsev', sev!=='ALL' && row.dataset.sev!==sev);
  }});
  applyVisibility();
}}
function toggleExploitOnly(){{
  gExpOnly=!gExpOnly;
  document.getElementById('exp-toggle').classList.toggle('active',gExpOnly);
  document.querySelectorAll('.cve-row').forEach(row=>{{
    const hasExp=row.querySelector('.exp-yes')!==null;
    row.classList.toggle('hidden-exp', gExpOnly&&!hasExp);
  }});
  applyVisibility();
}}
function applyVisibility(){{
  // Auto-expand cards with visible results
  document.querySelectorAll('.svc-card:not(.no-cve)').forEach(card=>{{
    const visRows=[...card.querySelectorAll('.cve-row')].filter(r=>{{
      return !r.classList.contains('hidden') &&
             !r.classList.contains('hidden-gsearch') &&
             !r.classList.contains('hidden-gsev') &&
             !r.classList.contains('hidden-exp') &&
             !r.classList.contains('hidden-year');
    }});
    if(visRows.length>0) card.querySelector('.svc-body')?.classList.add('open');
  }});
  updateCount();
}}
function updateCount(){{
  const vis=document.querySelectorAll('.cve-row:not(.hidden):not(.hidden-gsearch):not(.hidden-gsev):not(.hidden-exp):not(.hidden-year)').length;
  const el=document.getElementById('results-count');
  if(el) el.textContent=vis+' CVE'+(vis>1?'s':'')+' affichée'+(vis>1?'s':'');
}}

/* ── Table sort ──────────────────────────────────────── */
function sortTable(idx,col){{
  const tbl=document.getElementById('tbl-'+idx);
  if(!tbl) return;
  const rows=[...tbl.querySelectorAll('.cve-row')];
  const dir=tbl.dataset['sort'+col]==='asc'?-1:1;
  tbl.dataset['sort'+col]=dir===1?'asc':'desc';
  rows.sort((a,b)=>{{
    const ta=a.cells[col]?.innerText.trim()||'';
    const tb=b.cells[col]?.innerText.trim()||'';
    if(col===2) return dir*(parseFloat(tb)-parseFloat(ta));
    return dir*ta.localeCompare(tb);
  }});
  const tbody=tbl.querySelector('tbody');
  rows.forEach(r=>tbody.appendChild(r));
}}

/* ── Init: expand CRITICAL cards ────────────────────── */
document.addEventListener('DOMContentLoaded',()=>{{
  document.querySelectorAll('.svc-card[data-worst="CRITICAL"]').forEach(card=>{{
    const id=card.id.replace('svc-','');
    document.getElementById('body-'+id)?.classList.add('open');
    document.getElementById('chev-'+id)?.classList.add('open');
  }});
  updateCount();
}});
</script>
</body>
</html>"""

    # ── Injection section BloodHound ──────────────────────────────────────────
    if bh_data:
        from modules.bloodhound_integration import bloodhound_to_html_section
        bh_html = bloodhound_to_html_section(bh_data)
        main_open = '<main class="main" id="main">'
        if main_open in html:
            html = html.replace(main_open, main_open + "\n" + bh_html, 1)

    # ── Injection section AD ──────────────────────────────────────────────────
    if ad_ctx:
        from modules.ad_detector import ad_context_to_html_section
        ad_html = ad_context_to_html_section(ad_ctx)
        main_open = '<main class="main" id="main">'
        if main_open in html:
            html = html.replace(main_open, main_open + "\n" + ad_html, 1)

    # ── Injection section chaînes ────────────────────────────────────────────
    if chains:
        from modules.chain_analyzer import chains_to_html_section
        chains_html = chains_to_html_section(chains)
        main_open = '<main class="main" id="main">'
        if main_open in html:
            html = html.replace(main_open, main_open + "\n" + chains_html, 1)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
