#!/usr/bin/env python3
"""
ChocoScan - Scanner de vulnérabilités CVE post-Nmap
Par Kinder-Bueno (Mathys CASTELLA) | Portfolio Pentest

Usage:
    python chocoscan.py -x scan.xml
    python chocoscan.py -x scan.xml --no-api
    python chocoscan.py --scan 192.168.1.1
    python chocoscan.py --scan 192.168.1.0/24 --export-html --export-json
    python chocoscan.py -x scan.xml --min-cvss 7.0
    python chocoscan.py -x scan.xml --severity CRITICAL,HIGH
    python chocoscan.py -x scan.xml --exploits --export-html
"""

import argparse
import os
import sys
import json
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    from rich.columns import Columns
    from rich.rule import Rule
except ImportError:
    print("[!] Module 'rich' manquant. Installez-le : pip install rich")
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent))

from modules.nmap_parser import parse_nmap_xml, parse_nmap_text, run_nmap_scan
from modules.input_parser import parse_input_file, detect_format, FORMAT_LABELS
from modules.cve_matcher import get_cves_for_service
from modules.exploit_finder import get_top_exploits
from modules.report_generator import export_html, export_json
from modules.web_enumerator import run_web_enum, enum_results_to_html_section
from modules.chain_analyzer import detect_chains, display_chains_terminal, chains_to_html_section
from modules.ad_detector import detect_ad_context, display_ad_context_terminal, ad_context_to_html_section
from modules.contextual_scorer import inject_scores, format_score_inline, GRADE_COLORS, LABEL_COLORS
from modules.bloodhound_integration import load_bloodhound, cross_with_cves, display_bloodhound_terminal, bloodhound_to_html_section
from modules.diff_engine import compute_diff, display_diff_terminal, diff_to_html
from modules.interactive import run_interactive
from modules.config import (
    apply_to_parser, find_config_file,
    cmd_config_show, cmd_config_init, cmd_config_init_force,
)

console = Console()

from modules.image_art import image_to_rich_art

ASSETS_DIR = Path(__file__).parent / "assets"

BANNER = r"""
   ___ _                  ___
  / __| |_  ___  __ ___  / __| __ __ _ _ _
 | (__| ' \/ _ \/ _/ _ \ \__ \/ _/ _` | ' \
  \___|_||_\___/\__\___/ |___/\__\__,_|_||_|
"""

SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "INFO": "bold blue",
    "UNKNOWN": "dim",
    "N/A": "dim",
}

# Niveaux de sévérité valides pour --severity
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}


def style_severity(severity: str) -> str:
    return SEVERITY_STYLES.get(str(severity).upper(), "dim")


def style_cvss(score) -> str:
    try:
        s = float(score)
        if s >= 9.0: return "bold red"
        if s >= 7.0: return "bold orange1"
        if s >= 4.0: return "bold yellow"
        return "bold green"
    except (ValueError, TypeError):
        return "dim"


def print_banner():
    art = image_to_rich_art(str(ASSETS_DIR / "chocoscan_cli.png"), width=50)
    console.print(art)
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(
        "[bold]ChocoScan[/bold] — Outil de mapping CVE post-Nmap\n"
        "[dim]Développé par Kinder-Bueno (Mathys CASTELLA) | Projet Portfolio Pentest[/dim]"
    )
    console.print(Rule(style="blue"))


def print_result_message(found_cves: bool):
    if found_cves:
        console.print("[bold bright_blue]ChocoScan a repéré des vulnérabilités ![/bold bright_blue]\n")
    else:
        console.print("[dim]ChocoScan n'a rien trouvé... bien joué (ou pas de chance).[/dim]\n")


def parse_severity_filter(severity_str: str) -> set[str] | None:
    """
    Parse l'argument --severity (ex: 'CRITICAL,HIGH') en set de niveaux.
    Retourne None si non fourni (pas de filtre).
    """
    if not severity_str:
        return None
    levels = {s.strip().upper() for s in severity_str.split(",")}
    invalid = levels - VALID_SEVERITIES
    if invalid:
        console.print(f"[bold red][!] Niveaux de sévérité inconnus : {', '.join(invalid)}[/bold red]")
        console.print(f"[dim]Valeurs acceptées : {', '.join(sorted(VALID_SEVERITIES))}[/dim]")
        sys.exit(1)
    return levels


def filter_cves(cves: list, min_cvss: float, severity_filter: set | None, after_year: int | None = None) -> list:
    """
    Applique les filtres CVSS minimum, sévérité et année sur une liste de CVEs.
    Les filtres sont combinés en AND logique.
    """
    import re as _re
    result = []
    for c in cves:
        # Filtre CVSS minimum
        if min_cvss > 0:
            try:
                score = float(str(c.get("cvss", 0)).replace("N/A", "0") or 0)
                if score < min_cvss:
                    continue
            except (ValueError, TypeError):
                continue

        # Filtre sévérité
        if severity_filter:
            sev = str(c.get("severity", "UNKNOWN")).upper()
            if sev not in severity_filter:
                continue

        # Filtre année de publication (extrait depuis l'ID CVE ex: CVE-2025-12345)
        if after_year:
            cve_id = c.get("id", "")
            m = _re.match(r"CVE-(\d{4})-", cve_id, _re.IGNORECASE)
            if not m or int(m.group(1)) < after_year:
                continue

        result.append(c)
    return result


def display_results_terminal(results: list, show_exploits: bool = False, top_cves: int = 5):
    """Affiche les résultats dans le terminal avec rich."""
    if not results:
        console.print("\n[yellow]Aucun service analysé.[/yellow]")
        return

    total_cves = sum(len(r["cves"]) for r in results)
    services_with_cves = sum(1 for r in results if r["cves"])

    print_result_message(found_cves=total_cves > 0)

    # Résumé
    console.print(f"\n[bold]Résumé du scan[/bold]")
    summary_table = Table(box=box.SIMPLE, show_header=False)
    summary_table.add_row("Services détectés", f"[bold]{len(results)}[/bold]")
    summary_table.add_row("Services vulnérables", f"[bold yellow]{services_with_cves}[/bold yellow]")
    summary_table.add_row("CVEs trouvées (total base)", f"[bold red]{total_cves}[/bold red]")
    if top_cves > 0:
        summary_table.add_row(
            "Affichage terminal",
            f"[bold dim]Top {top_cves} par port, triées par CVSS décroissant "
            f"(--top-cves {top_cves} | rapport HTML = toutes)[/bold dim]"
        )
    console.print(summary_table)
    console.print(Rule(style="dim"))

    for result in results:
        service = result["service"]
        cves = result["cves"]

        host_str = f"{service['host']}:{service['port']}/{service['protocol']}"
        banner_str = service["banner"] or "[dim]Version non détectée[/dim]"
        svc_str = f"[bold cyan]{service['service_name']}[/bold cyan]"

        if not cves:
            console.print(
                f"\n[dim]●[/dim] {host_str} — {svc_str} {banner_str} "
                f"[dim]→ Aucune CVE trouvée[/dim]"
            )
            continue

        console.print(f"\n[bold]●[/bold] {host_str} — {svc_str} [dim]{banner_str}[/dim]")

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            expand=False,
        )
        table.add_column("CVE ID", style="bold magenta", min_width=18)
        table.add_column("Sévérité", justify="center", min_width=10)
        table.add_column("CVSS", justify="center", min_width=6)
        table.add_column("Score CTX", justify="center", min_width=9)
        table.add_column("Description", max_width=55)
        table.add_column("Source", style="dim", min_width=10)
        if show_exploits:
            table.add_column("Exploit PoC", style="bright_green", max_width=40)

        sorted_cves = sorted(
            cves,
            key=lambda c: (
                c.get("ctx_score") or
                float(str(c.get("cvss", 0)).replace("N/A", "0") or 0)
            ),
            reverse=True
        )

        # Limiter l'affichage terminal aux N plus critiques
        displayed_cves = sorted_cves[:top_cves] if top_cves > 0 else sorted_cves
        hidden_count   = len(sorted_cves) - len(displayed_cves)

        for cve in displayed_cves:
            sev       = str(cve.get("severity", "UNKNOWN")).upper()
            score     = str(cve.get("cvss", "N/A"))
            ctx_score = cve.get("ctx_score")
            ctx_grade = cve.get("ctx_grade", "")
            ctx_kev   = cve.get("ctx_in_kev", False)
            ctx_exp   = cve.get("ctx_exploit_type", "none")
            desc = cve.get("description_fr") or cve.get("description", "")
            if len(desc) > 110:
                desc = desc[:107] + "..."

            # Cellule Score CTX
            if ctx_score is not None:
                grade_col = {"A+":"bold red","A":"red","B":"bold yellow",
                             "C":"yellow","D":"dim","F":"dim"}.get(ctx_grade,"white")
                kev_flag  = " [magenta]KEV[/magenta]" if ctx_kev else ""
                exp_icons = {"metasploit":"[blue]MSF[/blue]","exploit-db":"[orange1]EDB[/orange1]",
                             "github":"[green]GH[/green]","none":""}
                exp_flag  = " " + exp_icons.get(ctx_exp,"") if ctx_exp != "none" else ""
                ctx_cell  = f"[{grade_col}]{ctx_score:.1f}[/{grade_col}]{kev_flag}{exp_flag}"
            else:
                ctx_cell  = "[dim]—[/dim]"

            row = [
                cve.get("id", "N/A"),
                f"[{style_severity(sev)}]{sev}[/{style_severity(sev)}]",
                f"[{style_cvss(score)}]{score}[/{style_cvss(score)}]",
                ctx_cell,
                desc,
                cve.get("source", ""),
            ]

            if show_exploits:
                exploits = cve.get("exploits", [])
                if exploits:
                    lines = [f"★{e['stars']} {e['repo']}" for e in exploits]
                    row.append("\n".join(lines))
                else:
                    row.append("[dim]—[/dim]")

            table.add_row(*row)

        console.print(table)

        # Indiquer les CVEs masquées
        if hidden_count > 0:
            console.print(
                f"  [dim]… {hidden_count} CVE(s) supplémentaire(s) non affichée(s) "
                f"(ctx score < [bold]{displayed_cves[-1].get('ctx_score') or displayed_cves[-1].get('cvss', '?')}[/bold]). "
                f"Voir le rapport HTML pour toutes les CVEs (--export-html).[/dim]"
            )


def main():
    # ── Sous-commande `config` ────────────────────────────────────────────────
    # Traitée avant le parser principal pour ne pas exiger -x / --scan.
    if len(sys.argv) >= 2 and sys.argv[1] == "config":
        sub = sys.argv[2] if len(sys.argv) >= 3 else "show"
        force = "--force" in sys.argv

        if sub in ("show", "s"):
            cmd_config_show()
        elif sub in ("init", "i"):
            if force:
                cmd_config_init_force()
            else:
                cmd_config_init()
        else:
            console.print(
                "[bold red][!] Sous-commande config inconnue.[/bold red]\n"
                "  [bold]chocoscan config show[/bold]          — afficher la config active\n"
                "  [bold]chocoscan config init[/bold]          — créer ~/.chocoscan.conf\n"
                "  [bold]chocoscan config init --force[/bold]  — écraser ~/.chocoscan.conf"
            )
            sys.exit(1)
        sys.exit(0)

    print_banner()

    parser = argparse.ArgumentParser(
        description="ChocoScan — Mapping CVE à partir de scans Nmap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation :
  python chocoscan.py -x scan.xml
  python chocoscan.py -x masscan.json
  python chocoscan.py --diff scan_j1.xml scan_j2.xml
  python chocoscan.py --diff scan_avant.xml scan_apres.xml --export-html
  python chocoscan.py -x rustscan.txt
  python chocoscan.py -x report.nessus
  python chocoscan.py -x scan.csv --input-format nessus_csv
  python chocoscan.py -x scan.xml --no-api --export-html
  python chocoscan.py --scan 10.10.10.1 --export-html --export-json
  python chocoscan.py -x scan.xml --min-cvss 7.0
  python chocoscan.py -x scan.xml --severity CRITICAL,HIGH
  python chocoscan.py -x scan.xml --exploits --export-html
  python chocoscan.py -x scan.xml --enum-web
  python chocoscan.py -x scan.xml --enum-web --export-html
  python chocoscan.py --scan 10.10.10.1 --enum-web --severity CRITICAL
        """
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-x", "--xml", metavar="FILE",
                              help="Fichier de scan (Nmap XML/texte, Masscan, RustScan, Nessus CSV/.nessus, JSON)")
    input_group.add_argument("--scan", metavar="TARGET", help="Lancer un scan nmap directement sur la cible")
    input_group.add_argument("--diff", nargs=2, metavar=("AVANT", "APRES"),
                              help="Comparer deux fichiers de scan (tout format supporté)")
    parser.add_argument("--input-format", default="auto", metavar="FORMAT",
                        help="Format d\'entrée : auto (défaut), nmap_xml, nmap_text, "
                             "masscan_xml, masscan_json, masscan_text, rustscan_json, "
                             "rustscan_text, nessus_csv, nessus_xml, chocoscan_json")

    parser.add_argument("--no-api", action="store_true", help="Désactiver le fallback API NVD")
    parser.add_argument("--export-html", action="store_true", help="Générer un rapport HTML")
    parser.add_argument("--export-json", action="store_true", help="Générer un rapport JSON")
    parser.add_argument("--output-dir", default="output", help="Dossier de sortie (défaut: output/)")
    parser.add_argument("--min-cvss", type=float, default=0.0,
                        help="Filtrer les CVEs en dessous de ce score CVSS (ex: 7.0)")
    parser.add_argument("--severity", type=str, default="",
                        help="Filtrer par sévérité (ex: CRITICAL,HIGH — valeurs: CRITICAL, HIGH, MEDIUM, LOW)")
    parser.add_argument("--nmap-args", default="", help="Arguments supplémentaires pour nmap (avec --scan)")
    parser.add_argument("--exploits", action="store_true",
                        help="Rechercher des PoC/exploits GitHub pour chaque CVE trouvée")
    parser.add_argument("--enum-web", action="store_true",
                        help="Énumération web intelligente — wordlists adaptées à la stack détectée")
    parser.add_argument("--enum-threads", type=int, default=10, metavar="N",
                        help="Nombre de threads pour l'énumération web (défaut: 10)")
    parser.add_argument("--enum-delay", type=float, default=0.05, metavar="SEC",
                        help="Délai entre requêtes d'énumération en secondes (défaut: 0.05)")
    parser.add_argument("--top-cves", type=int, default=5, metavar="N",
                        help="Nombre de CVEs à afficher par port en terminal, triées par CVSS (défaut: 5, 0 = toutes)")
    parser.add_argument("--bloodhound", default=None, metavar="FILE",
                        help="Fichier BloodHound CE (ZIP SharpHound ou répertoire JSON) à croiser avec les CVEs")
    parser.add_argument("--no-scoring", action="store_true",
                        help="Désactiver le scoring contextuel (utilise uniquement le CVSS)")
    parser.add_argument("--no-ad", action="store_true",
                        help="Désactiver la détection automatique du contexte Active Directory")
    parser.add_argument("--no-chains", action="store_true",
                        help="Désactiver l'analyse des CVEs chaînables")
    parser.add_argument("--after-year", type=int, default=None, metavar="AAAA",
                        help="Filtrer les CVEs publiées à partir de cette année (ex: 2024 → garde CVE-2024-x, CVE-2025-x…)")
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Mode interactif CLI : naviguer, marquer et exporter les CVEs (style fzf)")

    # ── Charger la config ~/.chocoscan.conf ─────────────────────────────────
    _cfg_path = apply_to_parser(parser)

    args = parser.parse_args()

    # Validation et parse des filtres
    severity_filter = parse_severity_filter(args.severity)

    # Affichage des filtres actifs
    active_filters = []
    if args.min_cvss > 0:
        active_filters.append(f"CVSS ≥ {args.min_cvss}")
    if severity_filter:
        active_filters.append(f"Sévérité : {', '.join(sorted(severity_filter))}")
    if args.after_year:
        active_filters.append(f"Année ≥ {args.after_year}")
    if active_filters:
        console.print(f"[dim]Filtres actifs : {' | '.join(active_filters)}[/dim]")

    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Chargement des services nmap
    services = []
    target = ""
    scan_xml_path = None

    # ── Mode Diff ────────────────────────────────────────────────────────────
    if args.diff:
        file_before, file_after = args.diff
        for f in (file_before, file_after):
            if not os.path.exists(f):
                console.print(f"[bold red][!] Fichier introuvable : {f}[/bold red]")
                sys.exit(1)

        console.print(f"\n[cyan][*] Mode diff : comparaison de deux scans[/cyan]")
        console.print(f"    Avant : [bold]{file_before}[/bold]")
        console.print(f"    Après : [bold]{file_after}[/bold]")

        # Parser les deux fichiers
        svc_before, _ = parse_input_file(file_before, fmt=args.input_format)
        svc_after,  _ = parse_input_file(file_after,  fmt=args.input_format)

        # Analyser les CVEs pour chaque scan
        def _run_cve_analysis(svcs):
            res = []
            for svc in svcs:
                cves = get_cves_for_service(
                    svc.service_name, svc.banner, use_api_fallback=not args.no_api
                )
                cves = filter_cves(cves, args.min_cvss, severity_filter, after_year=args.after_year)
                if not args.no_scoring and cves:
                    cves = inject_scores(cves)
                res.append({
                    "service": {
                        "host": svc.host, "port": svc.port,
                        "protocol": svc.protocol,
                        "service_name": svc.service_name,
                        "banner": svc.banner,
                        "product": svc.product, "version": svc.version,
                    },
                    "cves": cves,
                })
            return res

        console.print("[dim]Analyse des CVEs (scan avant)...[/dim]")
        results_before = _run_cve_analysis(svc_before)
        console.print("[dim]Analyse des CVEs (scan après)...[/dim]")
        results_after  = _run_cve_analysis(svc_after)

        # Calculer et afficher le diff
        diff_result = compute_diff(
            svc_before, svc_after,
            results_before, results_after,
            file_before, file_after
        )
        display_diff_terminal(diff_result, top_n=args.top_cves or 10)

        # Export HTML du diff
        if args.export_html:
            os.makedirs(args.output_dir, exist_ok=True)
            diff_html_path = os.path.join(
                args.output_dir,
                f"diff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            )
            with open(diff_html_path, 'w', encoding='utf-8') as _f:
                _f.write(diff_to_html(diff_result, scan_date))
            console.print(f"[green][+] Rapport diff HTML : {diff_html_path}[/green]")

        sys.exit(0)

    if _cfg_path:
        console.print(f"[dim][config] {_cfg_path}[/dim]")

    if args.xml:
        if not os.path.exists(args.xml):
            console.print(f"[bold red][!] Fichier introuvable : {args.xml}[/bold red]")
            sys.exit(1)
        fmt = args.input_format
        services, fmt_detected = parse_input_file(args.xml, fmt=fmt)
        fmt_label = FORMAT_LABELS.get(fmt_detected, fmt_detected)
        console.print(f"\n[*] Fichier : [bold]{args.xml}[/bold]")
        console.print(f"[*] Format  : [bold cyan]{fmt_label}[/bold cyan]")
        target = args.xml
        scan_xml_path = args.xml if fmt_detected == 'nmap_xml' else None

    elif args.scan:
        target = args.scan
        scan_xml_path = f"output/scan_{target.replace('/', '_').replace('.', '_')}.xml"
        os.makedirs("output", exist_ok=True)
        console.print(f"\n[*] Lancement du scan sur [bold]{target}[/bold]...")
        result = run_nmap_scan(target, scan_xml_path, args.nmap_args)
        if result is None:
            console.print("[bold red][!] Scan échoué. Vérifiez que nmap est installé et que vous avez les droits.[/bold red]")
            sys.exit(1)
        services = result

    if not services:
        console.print("[yellow][!] Aucun service ouvert trouvé dans le scan.[/yellow]")
        sys.exit(0)

    console.print(f"[green][+] {len(services)} service(s) ouvert(s) détecté(s)[/green]")

    # Matching CVE
    results = []
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    use_api = not args.no_api

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Recherche de CVEs...", total=len(services))

        for svc in services:
            progress.update(task, description=f"Analyse {svc.service_name}:{svc.port}...")
            cves = get_cves_for_service(svc.service_name, svc.banner, use_api_fallback=use_api)

            # Filtrage combiné (CVSS + sévérité)
            cves = filter_cves(cves, args.min_cvss, severity_filter, after_year=args.after_year)

            if args.exploits:
                for c in cves:
                    cve_id = c.get("id", "")
                    if cve_id.upper().startswith("CVE-"):
                        c["exploits"] = get_top_exploits(cve_id, max_results=2)

            # Scoring contextuel
            if not args.no_scoring and cves:
                cves = inject_scores(cves)
            results.append({
                "service": {
                    "host": svc.host,
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "service_name": svc.service_name,
                    "banner": svc.banner,
                    "product": svc.product,
                    "version": svc.version,
                },
                "cves": cves,
            })
            progress.advance(task)

    # Affichage terminal
    display_results_terminal(results, show_exploits=args.exploits, top_cves=args.top_cves)

    # ── Mode interactif ─────────────────────────────────────────────────────
    if args.interactive:
        run_interactive(results, output_dir=args.output_dir)
        # On laisse continuer pour les exports éventuels

    # ── Contexte Active Directory ────────────────────────────────────────────
    ad_ctx = None
    if not args.no_ad:
        import json as _json
        _db_path = Path(__file__).parent / 'data' / 'cve_db.json'
        with open(_db_path, encoding='utf-8') as _f:
            _cve_db = _json.load(_f)
        ad_ctx = detect_ad_context(services, results, _cve_db)
        if ad_ctx:
            display_ad_context_terminal(ad_ctx)

    # ── Analyse BloodHound CE ───────────────────────────────────────────────
    bh_data = None
    if args.bloodhound:
        import json as _json2
        _db_path2 = Path(__file__).parent / 'data' / 'cve_db.json'
        with open(_db_path2, encoding='utf-8') as _f2:
            _cve_db2 = _json2.load(_f2)
        bh_data = load_bloodhound(args.bloodhound)
        if bh_data:
            bh_data = cross_with_cves(bh_data, _cve_db2)
            display_bloodhound_terminal(bh_data)
        else:
            console.print(f'[yellow][!] BloodHound : impossible de lire {args.bloodhound}[/yellow]')

    # ── Analyse des CVEs chaînables ─────────────────────────────────────────
    chains = []
    if not args.no_chains:
        chains = detect_chains(results)
        display_chains_terminal(chains, max_display=5)

    # Export des rapports
    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(".", "_").replace(":", "_")

    if args.export_json:
        json_path = os.path.join(args.output_dir, f"report_{safe_target}_{timestamp}.json")
        export_json(results, json_path, target, scan_date)
        console.print(f"\n[green][+] Rapport JSON exporté : {json_path}[/green]")

    if args.export_html:
        html_path = os.path.join(args.output_dir, f"report_{safe_target}_{timestamp}.html")
        export_html(results, html_path, target, scan_date, chains=chains, ad_ctx=ad_ctx, bh_data=bh_data)
        console.print(f"[green][+] Rapport HTML exporté : {html_path}[/green]")

    # ── Énumération web intelligente ─────────────────────────────────────────
    if args.enum_web:
        console.print()
        console.print(Rule("[bold cyan]Énumération Web[/bold cyan]"))
        enum_results = run_web_enum(
            services=services,
            threads=args.enum_threads,
            delay=args.enum_delay,
            output_dir=args.output_dir,
        )

        # Injecter dans le rapport HTML si demandé
        if args.export_html and enum_results:
            try:
                html_section = enum_results_to_html_section(enum_results)
                with open(html_path, "r", encoding="utf-8") as f:
                    html_content = f.read()
                # Insérer la section avant </body>
                html_content = html_content.replace(
                    "</body>",
                    html_section + "\n</body>"
                )
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html_content)
                console.print(f"[green][+] Section énumération web ajoutée au rapport HTML.[/green]")
            except Exception as e:
                console.print(f"[yellow][!] Impossible d'injecter dans HTML : {e}[/yellow]")

        # Export JSON séparé pour l'enum web
        if enum_results:
            enum_json_path = os.path.join(
                args.output_dir,
                f"enum_web_{safe_target}_{timestamp}.json"
            )
            os.makedirs(args.output_dir, exist_ok=True)
            with open(enum_json_path, "w", encoding="utf-8") as f:
                import json as _json
                _json.dump(enum_results, f, indent=2, ensure_ascii=False)
            console.print(f"[green][+] Résultats énumération web : {enum_json_path}[/green]")

    console.print(Rule(style="dim"))
    console.print("[dim]Scan terminé.[/dim]\n")


if __name__ == "__main__":
    main()
