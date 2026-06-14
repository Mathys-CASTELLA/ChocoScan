"""
Module de génération de rapports (JSON et HTML).
"""

import json
from datetime import datetime
from pathlib import Path
from functools import lru_cache


ASSETS_DIR = Path(__file__).parent.parent / "assets"


@lru_cache(maxsize=2)
def _load_logo_b64(filename: str) -> str:
    """Charge une image du dossier assets et la retourne encodee en base64."""
    path = ASSETS_DIR / filename
    with open(path, "rb") as f:
        import base64
        return base64.b64encode(f.read()).decode()


def get_logo_data_uri(found_cves: bool) -> str:
    """
    Retourne le logo ChocoScan en data URI :
    - Noctali eveille (chocowake.png) si des CVE ont ete trouvees
    - Noctali endormi (chocosleep.png) si rien n'a ete trouve
    """
    filename = "chocowake.png" if found_cves else "chocosleep.png"
    b64 = _load_logo_b64(filename)
    return f"data:image/png;base64,{b64}"


SEVERITY_COLORS = {
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#65a30d",
    "INFO": "#0284c7",
    "UNKNOWN": "#6b7280",
    "N/A": "#6b7280",
}

SEVERITY_BADGE_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH": "#fff7ed",
    "MEDIUM": "#fffbeb",
    "LOW": "#f7fee7",
    "INFO": "#f0f9ff",
    "UNKNOWN": "#f9fafb",
    "N/A": "#f9fafb",
}


def export_json(results: list, output_file: str, target: str, scan_date: str):
    """Exporte les résultats en JSON structuré."""
    report = {
        "metadata": {
            "target": target,
            "scan_date": scan_date,
            "tool": "ChocoScan by Kinder-Bueno",
            "total_services": len(results),
            "total_cves": sum(len(r["cves"]) for r in results),
        },
        "results": results
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def get_severity_order(severity: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5, "N/A": 6}
    return order.get(severity.upper(), 5)


def export_html(results: list, output_file: str, target: str, scan_date: str):
    """Génère un rapport HTML interactif."""

    total_cves = sum(len(r["cves"]) for r in results)
    logo_data_uri = get_logo_data_uri(found_cves=total_cves > 0)
    header_bg = "rgb(19,23,52)" if total_cves > 0 else "rgb(10,12,33)"
    critical_count = sum(
        1 for r in results for c in r["cves"]
        if str(c.get("cvss", 0)) != "N/A" and float(str(c.get("cvss", 0)).replace("N/A", "0") or 0) >= 9.0
    )
    high_count = sum(
        1 for r in results for c in r["cves"]
        if str(c.get("cvss", 0)) != "N/A" and 7.0 <= float(str(c.get("cvss", 0)).replace("N/A", "0") or 0) < 9.0
    )

    # Génération des cards de services
    service_cards = ""
    for result in results:
        service = result["service"]
        cves = result["cves"]

        if not cves:
            continue

        # Trier CVEs par sévérité
        sorted_cves = sorted(cves, key=lambda c: get_severity_order(str(c.get("severity", "UNKNOWN"))))

        cve_rows = ""
        for cve in sorted_cves:
            sev = str(cve.get("severity", "UNKNOWN")).upper()
            color = SEVERITY_COLORS.get(sev, "#6b7280")
            bg = SEVERITY_BADGE_BG.get(sev, "#f9fafb")
            score = cve.get("cvss", "N/A")
            cve_id = cve.get("id", "N/A")
            is_real_cve = cve_id.upper().startswith("CVE-")
            cve_id_html = (
                f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank" class="cve-id">{cve_id}</a>'
                if is_real_cve else f'<span class="cve-id-disabled">{cve_id}</span>'
            )
            desc_en = cve.get("description", "")[:250]
            desc_en_trunc = desc_en + ('...' if len(cve.get('description','')) > 250 else '')
            desc_fr = cve.get("description_fr", "")[:250]
            desc_fr_trunc = (desc_fr + ('...' if len(cve.get('description_fr','')) > 250 else '')) if desc_fr else '<span class="no-fr">Traduction indisponible</span>'
            source_badge = f'<span class="source-badge">{cve.get("source", "")}</span>'

            exploits = cve.get("exploits", [])
            if exploits:
                exploit_links = "".join(
                    f'<a href="{e["url"]}" target="_blank" class="exploit-link">★{e["stars"]} {e["repo"]}</a>'
                    for e in exploits
                )
            else:
                exploit_links = '<span class="no-exploit">—</span>'

            cve_rows += f"""
            <tr class="cve-row">
                <td>{cve_id_html}{source_badge}</td>
                <td>
                    <span class="severity-badge" style="color:{color}; background:{bg}">
                        {sev}
                    </span>
                </td>
                <td class="score-cell">
                    <span class="cvss-score" style="color:{color}">{score}</span>
                </td>
                <td class="desc-cell">{desc_en_trunc}</td>
                <td class="desc-cell">{desc_fr_trunc}</td>
                <td class="exploit-cell">{exploit_links}</td>
            </tr>"""

        # Couleur de la card selon le pire CVE
        worst_sev = sorted_cves[0].get("severity", "UNKNOWN") if sorted_cves else "UNKNOWN"
        card_border = SEVERITY_COLORS.get(str(worst_sev).upper(), "#e5e7eb")

        service_cards += f"""
        <div class="service-card" style="border-left: 4px solid {card_border}">
            <div class="service-header">
                <div class="service-info">
                    <span class="port-badge">{service['port']}/{service['protocol']}</span>
                    <span class="service-name">{service['service_name']}</span>
                    <span class="service-banner">{service['banner'] or 'Version inconnue'}</span>
                </div>
                <div class="service-stats">
                    <span class="cve-count">{len(cves)} CVE{'s' if len(cves) > 1 else ''}</span>
                </div>
            </div>
            <div class="cve-table-wrapper">
                <table class="cve-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Sévérité</th>
                            <th>CVSS</th>
                            <th>Description (EN)</th>
                            <th>Description (FR)</th>
                            <th>Exploit PoC</th>
                        </tr>
                    </thead>
                    <tbody>{cve_rows}</tbody>
                </table>
            </div>
        </div>"""

    if not service_cards:
        service_cards = '<div class="no-results">Aucune CVE trouvée pour les services détectés.</div>'

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ChocoScan — Rapport {target}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0f1117;
            color: #e2e8f0;
            min-height: 100vh;
        }}

        /* Header */
        .header {{
            background: {header_bg};
            border-bottom: 1px solid #312e81;
            padding: 2rem 3rem;
        }}
        .header-top {{
            display: flex;
            align-items: center;
            margin-bottom: 1.5rem;
        }}
        .logo-mark {{
            display: flex;
        }}
        .logo-mark img {{
            max-width: 320px;
            height: auto;
            display: block;
        }}
        .scan-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 2rem;
            font-size: 0.85rem;
            color: #94a3b8;
        }}
        .scan-meta strong {{ color: #c7d2fe; }}

        /* Stats bar */
        .stats-bar {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
            padding: 1.5rem 3rem;
            background: #111827;
            border-bottom: 1px solid #1f2937;
        }}
        .stat-card {{
            background: #1f2937;
            border-radius: 8px;
            padding: 1rem 1.25rem;
            border: 1px solid #374151;
        }}
        .stat-label {{
            font-size: 0.75rem;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.25rem;
        }}
        .stat-value {{
            font-size: 1.75rem;
            font-weight: 700;
            color: #f1f5f9;
        }}
        .stat-value.critical {{ color: #f87171; }}
        .stat-value.high {{ color: #fb923c; }}

        /* Content */
        .content {{ padding: 2rem 3rem; max-width: 1400px; margin: 0 auto; }}

        .section-title {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: #6b7280;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #1f2937;
        }}

        /* Service cards */
        .service-card {{
            background: #1a1f2e;
            border: 1px solid #1f2937;
            border-radius: 10px;
            margin-bottom: 1.25rem;
            overflow: hidden;
            transition: box-shadow 0.2s;
        }}
        .service-card:hover {{
            box-shadow: 0 4px 24px rgba(0,0,0,0.4);
        }}
        .service-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            background: #111827;
            flex-wrap: wrap;
            gap: 0.75rem;
        }}
        .service-info {{ display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }}

        .port-badge {{
            background: #312e81;
            color: #a5b4fc;
            font-family: 'Courier New', monospace;
            font-size: 0.8rem;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-weight: 600;
        }}
        .service-name {{
            font-weight: 600;
            color: #e2e8f0;
            font-size: 1rem;
        }}
        .service-banner {{
            color: #94a3b8;
            font-size: 0.85rem;
            font-family: 'Courier New', monospace;
        }}
        .cve-count {{
            background: #374151;
            color: #d1d5db;
            font-size: 0.8rem;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
        }}

        /* CVE Table */
        .cve-table-wrapper {{ overflow-x: auto; }}
        .cve-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }}
        .cve-table thead th {{
            background: #161b27;
            color: #6b7280;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 0.6rem 1rem;
            text-align: left;
            border-bottom: 1px solid #1f2937;
        }}
        .cve-row td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid #1f2937;
            vertical-align: top;
        }}
        .cve-row:last-child td {{ border-bottom: none; }}
        .cve-row:hover {{ background: rgba(255,255,255,0.02); }}

        .cve-id {{
            font-family: 'Courier New', monospace;
            color: #818cf8;
            font-size: 0.8rem;
            white-space: nowrap;
            text-decoration: none;
            border-bottom: 1px dashed rgba(129,140,248,0.4);
            transition: color 0.15s, border-color 0.15s;
        }}
        .cve-id:hover {{
            color: #a5b4fc;
            border-bottom-color: #a5b4fc;
        }}
        .cve-id-disabled {{
            font-family: 'Courier New', monospace;
            color: #6b7280;
            font-size: 0.8rem;
            white-space: nowrap;
        }}
        .severity-badge {{
            display: inline-block;
            font-size: 0.7rem;
            font-weight: 700;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            letter-spacing: 0.05em;
        }}
        .cvss-score {{
            font-weight: 700;
            font-size: 1rem;
            font-family: 'Courier New', monospace;
        }}
        .desc-cell {{ color: #94a3b8; line-height: 1.5; max-width: 320px; }}
        .score-cell {{ white-space: nowrap; }}
        .no-fr {{ color: #6b7280; font-style: italic; font-size: 0.8rem; }}
        .exploit-cell {{ max-width: 220px; }}
        .exploit-link {{
            display: block;
            color: #4ade80;
            text-decoration: none;
            font-family: 'Courier New', monospace;
            font-size: 0.75rem;
            margin-bottom: 0.3rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            border-bottom: 1px dashed rgba(74,222,128,0.3);
        }}
        .exploit-link:hover {{
            color: #86efac;
            border-bottom-color: #86efac;
        }}
        .no-exploit {{ color: #6b7280; font-style: italic; font-size: 0.8rem; }}
        .source-badge {{
            display: block;
            font-size: 0.65rem;
            background: #1f2937;
            color: #6b7280;
            padding: 0.1rem 0.4rem;
            border-radius: 3px;
            margin-top: 0.35rem;
            width: fit-content;
        }}

        .no-results {{
            text-align: center;
            color: #6b7280;
            padding: 3rem;
            font-style: italic;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 2rem;
            color: #374151;
            font-size: 0.8rem;
            border-top: 1px solid #1f2937;
            margin-top: 3rem;
        }}

        @media (max-width: 768px) {{
            .header, .stats-bar, .content {{ padding-left: 1rem; padding-right: 1rem; }}
        }}
    </style>
</head>
<body>

<div class="header">
    <div class="header-top">
        <div class="logo-mark"><img src="{logo_data_uri}" alt="ChocoScan"></div>
    </div>
    <div class="scan-meta">
        <span><strong>Cible :</strong> {target}</span>
        <span><strong>Date :</strong> {scan_date}</span>
        <span><strong>Services analysés :</strong> {len(results)}</span>
        <span><strong>CVEs trouvées :</strong> {total_cves}</span>
    </div>
</div>

<div class="stats-bar">
    <div class="stat-card">
        <div class="stat-label">Services scannés</div>
        <div class="stat-value">{len(results)}</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">CVEs totales</div>
        <div class="stat-value">{total_cves}</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">Critical (CVSS ≥ 9)</div>
        <div class="stat-value critical">{critical_count}</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">High (CVSS ≥ 7)</div>
        <div class="stat-value high">{high_count}</div>
    </div>
</div>

<div class="content">
    <div class="section-title">Résultats par service</div>
    {service_cards}
</div>

<div class="footer">
    Généré par ChocoScan — Projet offensif portfolio | Kinder-Bueno (Mathys CASTELLA)
</div>

</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
