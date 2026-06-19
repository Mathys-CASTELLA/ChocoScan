"""
ChocoScan — Mode diff entre deux scans.

Compare deux fichiers de scan (tout format supporté) et affiche :
  - Nouveaux ports apparus
  - Ports fermés / disparus
  - Services dont la version a changé
  - Nouvelles CVEs apparues sur des ports existants
  - CVEs résolues (plus présentes)
  - Changements de score CVSS / ctx_score

Usage :
    python chocoscan.py --diff scan_avant.xml scan_apres.xml
    python chocoscan.py --diff scan_j1.xml scan_j2.xml --export-html --min-cvss 9.0

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.rule import Rule
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None


# ─────────────────────────────────────────────────────────────────────────────
# Structures de données
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PortChange:
    """Un port qui a changé de statut entre les deux scans."""
    host:         str
    port:         int
    protocol:     str
    change_type:  str          # "new", "closed", "version_changed"
    service_before: str = ""
    service_after:  str = ""
    banner_before:  str = ""
    banner_after:   str = ""


@dataclass
class CVEChange:
    """Une CVE qui a apparu ou disparu entre les deux scans."""
    cve_id:      str
    service:     str
    port:        int
    change_type: str           # "new", "resolved"
    cvss:        float
    severity:    str
    ctx_score:   Optional[float]
    description: str
    exploit_available: bool


@dataclass
class DiffResult:
    """Résultat complet de la comparaison entre deux scans."""
    scan_before:    str            # chemin du premier fichier
    scan_after:     str            # chemin du second fichier

    port_changes:   list[PortChange]  = field(default_factory=list)
    cve_changes:    list[CVEChange]   = field(default_factory=list)

    # Compteurs
    @property
    def new_ports(self)      -> list[PortChange]:
        return [p for p in self.port_changes if p.change_type == "new"]

    @property
    def closed_ports(self)   -> list[PortChange]:
        return [p for p in self.port_changes if p.change_type == "closed"]

    @property
    def changed_versions(self) -> list[PortChange]:
        return [p for p in self.port_changes if p.change_type == "version_changed"]

    @property
    def new_cves(self)       -> list[CVEChange]:
        return sorted(
            [c for c in self.cve_changes if c.change_type == "new"],
            key=lambda c: -(c.ctx_score or c.cvss)
        )

    @property
    def resolved_cves(self)  -> list[CVEChange]:
        return [c for c in self.cve_changes if c.change_type == "resolved"]

    @property
    def has_changes(self) -> bool:
        return bool(self.port_changes or self.cve_changes)

    @property
    def risk_delta(self) -> float:
        """Variation du risque total (somme CVSS nouvelles - résolues)."""
        added   = sum(c.cvss for c in self.new_cves)
        removed = sum(c.cvss for c in self.resolved_cves)
        return round(added - removed, 1)


# ─────────────────────────────────────────────────────────────────────────────
# Calcul du diff
# ─────────────────────────────────────────────────────────────────────────────

def _service_key(svc) -> str:
    """Clé unique pour un service Nmap (host:port/proto)."""
    return f"{svc.host}:{svc.port}/{svc.protocol}"


def _result_key(result: dict) -> str:
    """Clé unique pour un résultat CVE (port/proto)."""
    svc = result["service"]
    return f"{svc.get('host','?')}:{svc['port']}/{svc['protocol']}"


def _safe_float(val) -> float:
    try:
        return float(str(val).replace("N/A", "0") or 0)
    except (ValueError, TypeError):
        return 0.0


def compute_diff(
    services_before: list,
    services_after:  list,
    results_before:  list[dict],
    results_after:   list[dict],
    scan_before:     str,
    scan_after:      str,
) -> DiffResult:
    """
    Compare deux ensembles de services/CVEs et retourne le diff.

    Args:
        services_before / services_after : listes de NmapService
        results_before  / results_after  : listes de dicts {service, cves}
        scan_before / scan_after         : chemins des fichiers (pour l'affichage)
    """
    diff = DiffResult(scan_before=scan_before, scan_after=scan_after)

    # ── Clés des services ─────────────────────────────────────────────────────
    keys_before = {_service_key(s): s for s in services_before}
    keys_after  = {_service_key(s): s for s in services_after}

    # Ports apparus
    for key, svc in keys_after.items():
        if key not in keys_before:
            diff.port_changes.append(PortChange(
                host=svc.host, port=svc.port, protocol=svc.protocol,
                change_type="new",
                service_after=svc.service_name,
                banner_after=svc.banner,
            ))

    # Ports fermés
    for key, svc in keys_before.items():
        if key not in keys_after:
            diff.port_changes.append(PortChange(
                host=svc.host, port=svc.port, protocol=svc.protocol,
                change_type="closed",
                service_before=svc.service_name,
                banner_before=svc.banner,
            ))

    # Versions modifiées
    for key in keys_before:
        if key in keys_after:
            sb = keys_before[key]
            sa = keys_after[key]
            # Comparer les banners (version + produit)
            if sb.banner.strip() != sa.banner.strip() and sa.banner.strip():
                diff.port_changes.append(PortChange(
                    host=sa.host, port=sa.port, protocol=sa.protocol,
                    change_type="version_changed",
                    service_before=sb.service_name,
                    service_after=sa.service_name,
                    banner_before=sb.banner,
                    banner_after=sa.banner,
                ))

    # ── CVEs ──────────────────────────────────────────────────────────────────
    # Indexer par (port_key, cve_id)
    cves_before: dict[tuple[str, str], dict] = {}
    for r in results_before:
        pkey = _result_key(r)
        for c in r.get("cves", []):
            cid = c.get("id", "")
            if cid:
                cves_before[(pkey, cid)] = c

    cves_after: dict[tuple[str, str], dict] = {}
    for r in results_after:
        pkey = _result_key(r)
        svc  = r["service"]
        for c in r.get("cves", []):
            cid = c.get("id", "")
            if cid:
                cves_after[(pkey, cid)] = c

    # Nouvelles CVEs
    for (pkey, cid), c in cves_after.items():
        if (pkey, cid) not in cves_before:
            port = int(pkey.split(":")[1].split("/")[0]) if ":" in pkey else 0
            # Retrouver le service name depuis results_after
            svc_name = ""
            for r in results_after:
                if _result_key(r) == pkey:
                    svc_name = r["service"].get("service_name", "")
                    break
            diff.cve_changes.append(CVEChange(
                cve_id=cid,
                service=svc_name,
                port=port,
                change_type="new",
                cvss=_safe_float(c.get("cvss", 0)),
                severity=str(c.get("severity", "UNKNOWN")).upper(),
                ctx_score=c.get("ctx_score"),
                description=(c.get("description_fr") or c.get("description") or "")[:160],
                exploit_available=bool(c.get("exploit_available") or c.get("exploits")),
            ))

    # CVEs résolues
    for (pkey, cid), c in cves_before.items():
        if (pkey, cid) not in cves_after:
            port = int(pkey.split(":")[1].split("/")[0]) if ":" in pkey else 0
            svc_name = ""
            for r in results_before:
                if _result_key(r) == pkey:
                    svc_name = r["service"].get("service_name", "")
                    break
            diff.cve_changes.append(CVEChange(
                cve_id=cid,
                service=svc_name,
                port=port,
                change_type="resolved",
                cvss=_safe_float(c.get("cvss", 0)),
                severity=str(c.get("severity", "UNKNOWN")).upper(),
                ctx_score=c.get("ctx_score"),
                description=(c.get("description_fr") or c.get("description") or "")[:160],
                exploit_available=bool(c.get("exploit_available") or c.get("exploits")),
            ))

    return diff


# ─────────────────────────────────────────────────────────────────────────────
# Affichage terminal
# ─────────────────────────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": "bold red", "HIGH": "bold yellow",
    "MEDIUM": "yellow",     "LOW": "green", "UNKNOWN": "dim",
}


def display_diff_terminal(diff: DiffResult, top_n: int = 10):
    """Affiche le diff dans le terminal Rich."""
    if not console:
        return

    console.print()
    console.print(Rule("[bold cyan]🔄 Mode Diff — Comparaison de scans[/bold cyan]"))
    console.print(f"\n  [dim]Avant :[/dim] [bold]{diff.scan_before}[/bold]")
    console.print(f"  [dim]Après :[/dim] [bold]{diff.scan_after}[/bold]")

    if not diff.has_changes:
        console.print("\n  [green]✓ Aucun changement détecté entre les deux scans.[/green]")
        return

    # ── Résumé ──────────────────────────────────────────────────────────────
    console.print()
    summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    summary.add_column("", style="bold")
    summary.add_column("", justify="right")

    if diff.new_ports:
        summary.add_row("[green]Nouveaux ports[/green]",
                        f"[green]+{len(diff.new_ports)}[/green]")
    if diff.closed_ports:
        summary.add_row("[dim]Ports fermés[/dim]",
                        f"[dim]-{len(diff.closed_ports)}[/dim]")
    if diff.changed_versions:
        summary.add_row("[yellow]Versions modifiées[/yellow]",
                        f"[yellow]{len(diff.changed_versions)}[/yellow]")
    if diff.new_cves:
        summary.add_row("[bold red]Nouvelles CVEs[/bold red]",
                        f"[bold red]+{len(diff.new_cves)}[/bold red]")
    if diff.resolved_cves:
        summary.add_row("[bold green]CVEs résolues[/bold green]",
                        f"[bold green]-{len(diff.resolved_cves)}[/bold green]")

    delta = diff.risk_delta
    delta_color = "red" if delta > 0 else "green" if delta < 0 else "dim"
    delta_sign  = "+" if delta > 0 else ""
    summary.add_row(
        "[bold]Variation de risque CVSS[/bold]",
        f"[{delta_color}]{delta_sign}{delta}[/{delta_color}]"
    )

    console.print(Panel(summary, title="[bold]Résumé[/bold]",
                        border_style="cyan", padding=(0, 1)))

    # ── Changements de ports ─────────────────────────────────────────────────
    if diff.port_changes:
        console.print()
        console.print(Rule("[bold]Changements de ports[/bold]", style="dim"))

        pt = Table(box=box.SIMPLE_HEAVY, show_header=True,
                   header_style="bold", padding=(0, 1))
        pt.add_column("Statut",  width=10)
        pt.add_column("Port",    width=12, style="cyan bold")
        pt.add_column("Avant",   max_width=35)
        pt.add_column("Après",   max_width=35)

        for p in sorted(diff.port_changes, key=lambda x: x.port):
            if p.change_type == "new":
                status = "[bold green]▲ OUVERT[/bold green]"
                before = "[dim]—[/dim]"
                after  = f"{p.service_after} {p.banner_after}"[:35]
            elif p.change_type == "closed":
                status = "[dim red]▼ FERMÉ[/dim red]"
                before = f"{p.service_before} {p.banner_before}"[:35]
                after  = "[dim]—[/dim]"
            else:
                status = "[yellow]↔ MODIFIÉ[/yellow]"
                before = p.banner_before[:35] or p.service_before
                after  = p.banner_after[:35] or p.service_after

            pt.add_row(
                status,
                f"{p.port}/{p.protocol}",
                f"[dim]{before}[/dim]",
                after if p.change_type != "closed" else f"[dim]{after}[/dim]",
            )
        console.print(pt)

    # ── Nouvelles CVEs ───────────────────────────────────────────────────────
    if diff.new_cves:
        console.print()
        console.print(Rule("[bold red]Nouvelles CVEs apparues[/bold red]", style="dim"))

        ct = Table(box=box.SIMPLE_HEAVY, show_header=True,
                   header_style="bold", padding=(0, 1), expand=True)
        ct.add_column("CVE ID",    width=20, style="bold")
        ct.add_column("Port",      width=10, style="cyan")
        ct.add_column("Sévérité",  width=10)
        ct.add_column("CVSS",      width=6, justify="center")
        ct.add_column("CTX",       width=7, justify="center")
        ct.add_column("Description", max_width=55)

        for c in diff.new_cves[:top_n]:
            sev_col = SEV_COLORS.get(c.severity, "white")
            exp     = " ⚡" if c.exploit_available else ""
            ctx_str = f"{c.ctx_score:.1f}" if c.ctx_score else "—"
            ct.add_row(
                f"[bold red]+[/bold red] {c.cve_id}{exp}",
                f"{c.port}/{c.service}",
                f"[{sev_col}]{c.severity}[/{sev_col}]",
                str(c.cvss),
                ctx_str,
                c.description[:55],
            )

        if len(diff.new_cves) > top_n:
            ct.add_row(
                f"[dim]… +{len(diff.new_cves)-top_n} autres[/dim]",
                "", "", "", "", ""
            )
        console.print(ct)

    # ── CVEs résolues ────────────────────────────────────────────────────────
    if diff.resolved_cves:
        console.print()
        console.print(Rule("[bold green]CVEs résolues / disparues[/bold green]", style="dim"))

        rt = Table(box=box.SIMPLE_HEAVY, show_header=True,
                   header_style="bold", padding=(0, 1), expand=True)
        rt.add_column("CVE ID",    width=20, style="dim")
        rt.add_column("Port",      width=10, style="dim")
        rt.add_column("Sévérité",  width=10)
        rt.add_column("CVSS",      width=6, justify="center")
        rt.add_column("Description", max_width=60)

        for c in sorted(diff.resolved_cves, key=lambda x: -x.cvss)[:top_n]:
            sev_col = SEV_COLORS.get(c.severity, "white")
            rt.add_row(
                f"[bold green]✓[/bold green] [dim]{c.cve_id}[/dim]",
                f"[dim]{c.port}/{c.service}[/dim]",
                f"[dim][{sev_col}]{c.severity}[/{sev_col}][/dim]",
                f"[dim]{c.cvss}[/dim]",
                f"[dim]{c.description[:60]}[/dim]",
            )
        console.print(rt)


# ─────────────────────────────────────────────────────────────────────────────
# Export HTML
# ─────────────────────────────────────────────────────────────────────────────

def diff_to_html(diff: DiffResult, scan_date: str) -> str:
    """Génère un rapport HTML complet pour le diff entre deux scans."""

    sev_colors = {
        "CRITICAL": "#ef4444", "HIGH": "#f97316",
        "MEDIUM": "#eab308",   "LOW": "#22c55e", "UNKNOWN": "#6b7280",
    }

    # Résumé stats
    delta     = diff.risk_delta
    delta_col = "#ef4444" if delta > 0 else "#22c55e" if delta < 0 else "#6b7280"
    delta_str = f"+{delta}" if delta > 0 else str(delta)

    stats_html = f"""
    <div class="diff-stats">
      <div class="diff-stat new-port">
        <div class="ds-lbl">Nouveaux ports</div>
        <div class="ds-val" style="color:#22c55e">+{len(diff.new_ports)}</div>
      </div>
      <div class="diff-stat closed-port">
        <div class="ds-lbl">Ports fermés</div>
        <div class="ds-val" style="color:#6b7280">-{len(diff.closed_ports)}</div>
      </div>
      <div class="diff-stat changed-ver">
        <div class="ds-lbl">Versions modifiées</div>
        <div class="ds-val" style="color:#eab308">{len(diff.changed_versions)}</div>
      </div>
      <div class="diff-stat new-cve">
        <div class="ds-lbl">Nouvelles CVEs</div>
        <div class="ds-val" style="color:#ef4444">+{len(diff.new_cves)}</div>
      </div>
      <div class="diff-stat res-cve">
        <div class="ds-lbl">CVEs résolues</div>
        <div class="ds-val" style="color:#22c55e">-{len(diff.resolved_cves)}</div>
      </div>
      <div class="diff-stat risk-delta">
        <div class="ds-lbl">Δ Risque CVSS</div>
        <div class="ds-val" style="color:{delta_col}">{delta_str}</div>
      </div>
    </div>"""

    # Changements de ports
    port_rows = ""
    for p in sorted(diff.port_changes, key=lambda x: x.port):
        if p.change_type == "new":
            badge = '<span class="pc-badge new">▲ OUVERT</span>'
            before_cell = '<span style="color:#4a6488">—</span>'
            after_cell  = f'<span style="color:#22c55e">{p.service_after} {p.banner_after}</span>'
        elif p.change_type == "closed":
            badge = '<span class="pc-badge closed">▼ FERMÉ</span>'
            before_cell = f'<span style="color:#6b7280">{p.service_before} {p.banner_before}</span>'
            after_cell  = '<span style="color:#4a6488">—</span>'
        else:
            badge = '<span class="pc-badge changed">↔ MODIFIÉ</span>'
            before_cell = f'<span class="pc-before">{p.banner_before or p.service_before}</span>'
            after_cell  = f'<span style="color:#eab308">{p.banner_after or p.service_after}</span>'

        port_rows += f"""
        <tr>
          <td>{badge}</td>
          <td class="pc-port">{p.port}/{p.protocol}</td>
          <td>{before_cell}</td>
          <td>→</td>
          <td>{after_cell}</td>
        </tr>"""

    ports_section = ""
    if port_rows:
        ports_section = f"""
    <div class="diff-block">
      <h3 class="diff-block-title">Changements de ports</h3>
      <table class="diff-table">
        <thead><tr>
          <th>Statut</th><th>Port</th><th>Avant</th><th></th><th>Après</th>
        </tr></thead>
        <tbody>{port_rows}</tbody>
      </table>
    </div>"""

    # Nouvelles CVEs
    new_cve_rows = ""
    for c in diff.new_cves:
        color   = sev_colors.get(c.severity, "#6b7280")
        exp     = '<span class="diff-exp">⚡ PoC</span>' if c.exploit_available else ""
        ctx_str = f'<span class="diff-ctx">{c.ctx_score:.1f}</span>' if c.ctx_score else ""
        link    = f'<a href="https://nvd.nist.gov/vuln/detail/{c.cve_id}" target="_blank" class="diff-cve-link">{c.cve_id}</a>'
        new_cve_rows += f"""
        <tr class="new-cve-row">
          <td><span class="diff-new-icon">+</span> {link} {exp}</td>
          <td class="dc-port">{c.port}/{c.service}</td>
          <td><span class="sev-pill" style="color:{color};border-color:{color}44;background:{color}11">{c.severity}</span></td>
          <td style="color:{color};font-family:monospace;font-weight:800">{c.cvss}</td>
          <td>{ctx_str}</td>
          <td class="dc-desc">{c.description}</td>
        </tr>"""

    new_cves_section = ""
    if new_cve_rows:
        new_cves_section = f"""
    <div class="diff-block">
      <h3 class="diff-block-title" style="color:#ef4444">
        ▲ Nouvelles CVEs apparues ({len(diff.new_cves)})
      </h3>
      <table class="diff-table">
        <thead><tr>
          <th>CVE ID</th><th>Port / Service</th><th>Sévérité</th>
          <th>CVSS</th><th>Score CTX</th><th>Description</th>
        </tr></thead>
        <tbody>{new_cve_rows}</tbody>
      </table>
    </div>"""

    # CVEs résolues
    res_cve_rows = ""
    for c in sorted(diff.resolved_cves, key=lambda x: -x.cvss):
        color = sev_colors.get(c.severity, "#6b7280")
        res_cve_rows += f"""
        <tr class="res-cve-row">
          <td><span class="diff-res-icon">✓</span>
            <span class="diff-cve-res">{c.cve_id}</span></td>
          <td class="dc-port">{c.port}/{c.service}</td>
          <td><span class="sev-pill" style="color:{color}88;border-color:{color}22;background:{color}08">{c.severity}</span></td>
          <td style="color:{color}88;font-family:monospace">{c.cvss}</td>
          <td class="dc-desc" style="color:#4a6488">{c.description}</td>
        </tr>"""

    res_cves_section = ""
    if res_cve_rows:
        res_cves_section = f"""
    <div class="diff-block">
      <h3 class="diff-block-title" style="color:#22c55e">
        ✓ CVEs résolues / disparues ({len(diff.resolved_cves)})
      </h3>
      <table class="diff-table">
        <thead><tr>
          <th>CVE ID</th><th>Port / Service</th>
          <th>Sévérité</th><th>CVSS</th><th>Description</th>
        </tr></thead>
        <tbody>{res_cve_rows}</tbody>
      </table>
    </div>"""

    no_changes = ""
    if not diff.has_changes:
        no_changes = """
    <div class="diff-no-change">
      ✓ Aucun changement détecté entre les deux scans.
    </div>"""

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ChocoScan Diff — {diff.scan_before} vs {diff.scan_after}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Inter', system-ui, sans-serif; background: #080916; color: #dce8f8; font-size: 14px; padding: 2rem; }}
    a {{ color: #60a0f0; text-decoration: none; }}
    a:hover {{ color: #a0d0f0; }}

    .diff-header {{ margin-bottom: 1.5rem; }}
    .diff-title {{ font-size: 1.3rem; font-weight: 800; color: #60a0f0; margin-bottom: .4rem; }}
    .diff-meta {{ font-size: .8rem; color: #4a6488; }}
    .diff-meta span {{ margin-right: 1.5rem; }}
    .diff-meta strong {{ color: #8aaad0; }}

    .diff-stats {{ display: flex; flex-wrap: wrap; gap: .6rem; margin-bottom: 1.5rem; }}
    .diff-stat {{ background: #111428; border: 1px solid #1c2240; border-radius: 6px; padding: .6rem .9rem; min-width: 110px; }}
    .ds-lbl {{ font-size: .65rem; text-transform: uppercase; letter-spacing: .06em; color: #4a6488; margin-bottom: .2rem; }}
    .ds-val {{ font-size: 1.5rem; font-weight: 800; font-family: monospace; }}
    .risk-delta {{ border-color: #4a6488; }}

    .diff-block {{ background: #111428; border: 1px solid #1c2240; border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }}
    .diff-block-title {{ font-size: .9rem; font-weight: 700; color: #dce8f8; margin-bottom: .85rem; }}

    .diff-table {{ width: 100%; border-collapse: collapse; font-size: .8rem; }}
    .diff-table thead th {{ background: #0d0f1f; color: #4a6488; font-size: .68rem; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; padding: .45rem .75rem; text-align: left; border-bottom: 1px solid #1c2240; }}
    .diff-table tbody tr {{ border-bottom: 1px solid #1c2240; }}
    .diff-table tbody tr:last-child {{ border-bottom: none; }}
    .diff-table tbody tr:hover {{ background: rgba(255,255,255,.02); }}
    .diff-table td {{ padding: .55rem .75rem; vertical-align: top; }}

    .pc-badge {{ font-size: .7rem; font-weight: 700; padding: .15rem .45rem; border-radius: 4px; white-space: nowrap; }}
    .pc-badge.new     {{ background: rgba(34,197,94,.1);  color: #22c55e; border: 1px solid #22c55e44; }}
    .pc-badge.closed  {{ background: rgba(107,114,128,.1);color: #6b7280; border: 1px solid #6b728044; }}
    .pc-badge.changed {{ background: rgba(234,179,8,.1);  color: #eab308; border: 1px solid #eab30844; }}
    .pc-port {{ font-family: monospace; font-size: .8rem; font-weight: 700; color: #60a0f0; }}
    .pc-before {{ color: #4a6488; text-decoration: line-through; }}

    .diff-new-icon {{ color: #ef4444; font-weight: 900; margin-right: .3rem; }}
    .diff-res-icon {{ color: #22c55e; font-weight: 900; margin-right: .3rem; }}
    .diff-cve-link {{ font-family: monospace; font-size: .8rem; border-bottom: 1px dashed rgba(96,160,240,.3); }}
    .diff-cve-res  {{ font-family: monospace; font-size: .8rem; color: #4a6488; text-decoration: line-through; }}
    .diff-exp {{ font-size: .7rem; font-weight: 700; color: #38bdf8; background: rgba(56,189,248,.1); border: 1px solid rgba(56,189,248,.3); border-radius: 3px; padding: .05rem .3rem; margin-left: .3rem; }}
    .diff-ctx {{ font-family: monospace; font-size: .75rem; color: #a78bfa; background: rgba(167,139,250,.1); border: 1px solid rgba(167,139,250,.3); border-radius: 3px; padding: .05rem .3rem; }}
    .sev-pill {{ font-size: .7rem; font-weight: 700; padding: .12rem .4rem; border-radius: 4px; border: 1px solid; white-space: nowrap; }}
    .dc-port {{ font-family: monospace; font-size: .78rem; color: #8aaad0; white-space: nowrap; }}
    .dc-desc {{ color: #4a6488; line-height: 1.4; max-width: 400px; }}
    .new-cve-row {{ background: rgba(239,68,68,.03); }}
    .res-cve-row {{ opacity: .75; }}

    .diff-no-change {{ text-align: center; padding: 2rem; color: #22c55e; font-size: 1rem; font-weight: 600; }}
    .diff-footer {{ margin-top: 2rem; text-align: center; font-size: .72rem; color: #2a3555; }}
  </style>
</head>
<body>
  <div class="diff-header">
    <div class="diff-title">🔄 ChocoScan — Comparaison de scans</div>
    <div class="diff-meta">
      <span>Avant : <strong>{diff.scan_before}</strong></span>
      <span>Après : <strong>{diff.scan_after}</strong></span>
      <span>Généré le : <strong>{scan_date}</strong></span>
    </div>
  </div>

  {stats_html}
  {no_changes}
  {ports_section}
  {new_cves_section}
  {res_cves_section}

  <div class="diff-footer">
    Généré par ChocoScan — Kinder-Bueno (Mathys CASTELLA)
  </div>
</body>
</html>"""
