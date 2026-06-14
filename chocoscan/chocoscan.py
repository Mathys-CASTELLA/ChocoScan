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
from modules.cve_matcher import get_cves_for_service
from modules.exploit_finder import get_top_exploits
from modules.report_generator import export_html, export_json

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


def filter_cves(cves: list, min_cvss: float, severity_filter: set | None) -> list:
    """
    Applique les filtres CVSS minimum et sévérité sur une liste de CVEs.
    Les deux filtres sont combinés en AND logique.
    """
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

        result.append(c)
    return result


def display_results_terminal(results: list, show_exploits: bool = False):
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
    summary_table.add_row("CVEs trouvées", f"[bold red]{total_cves}[/bold red]")
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
        table.add_column("Description", max_width=65)
        table.add_column("Source", style="dim", min_width=10)
        if show_exploits:
            table.add_column("Exploit PoC", style="bright_green", max_width=45)

        sorted_cves = sorted(
            cves,
            key=lambda c: float(str(c.get("cvss", 0)).replace("N/A", "0") or 0),
            reverse=True
        )

        for cve in sorted_cves:
            sev = str(cve.get("severity", "UNKNOWN")).upper()
            score = str(cve.get("cvss", "N/A"))
            desc = cve.get("description_fr") or cve.get("description", "")
            if len(desc) > 120:
                desc = desc[:117] + "..."

            row = [
                cve.get("id", "N/A"),
                f"[{style_severity(sev)}]{sev}[/{style_severity(sev)}]",
                f"[{style_cvss(score)}]{score}[/{style_cvss(score)}]",
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


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="ChocoScan — Mapping CVE à partir de scans Nmap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation :
  python chocoscan.py -x scan.xml
  python chocoscan.py -x scan.xml --no-api --export-html
  python chocoscan.py --scan 10.10.10.1 --export-html --export-json
  python chocoscan.py -x scan.xml --min-cvss 7.0
  python chocoscan.py -x scan.xml --severity CRITICAL,HIGH
  python chocoscan.py -x scan.xml --exploits --export-html
        """
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-x", "--xml", help="Fichier XML nmap (-oX)")
    input_group.add_argument("--scan", metavar="TARGET", help="Lancer un scan nmap directement sur la cible")

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

    args = parser.parse_args()

    # Validation et parse des filtres
    severity_filter = parse_severity_filter(args.severity)

    # Affichage des filtres actifs
    active_filters = []
    if args.min_cvss > 0:
        active_filters.append(f"CVSS ≥ {args.min_cvss}")
    if severity_filter:
        active_filters.append(f"Sévérité : {', '.join(sorted(severity_filter))}")
    if active_filters:
        console.print(f"[dim]Filtres actifs : {' | '.join(active_filters)}[/dim]")

    # Chargement des services nmap
    services = []
    target = ""
    scan_xml_path = None

    if args.xml:
        if not os.path.exists(args.xml):
            console.print(f"[bold red][!] Fichier XML introuvable : {args.xml}[/bold red]")
            sys.exit(1)
        console.print(f"\n[*] Parsing du fichier XML : [bold]{args.xml}[/bold]")
        services = parse_nmap_xml(args.xml)
        target = args.xml
        scan_xml_path = args.xml

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
            cves = filter_cves(cves, args.min_cvss, severity_filter)

            if args.exploits:
                for c in cves:
                    cve_id = c.get("id", "")
                    if cve_id.upper().startswith("CVE-"):
                        c["exploits"] = get_top_exploits(cve_id, max_results=2)

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
    display_results_terminal(results, show_exploits=args.exploits)

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
        export_html(results, html_path, target, scan_date)
        console.print(f"[green][+] Rapport HTML exporté : {html_path}[/green]")

    console.print(Rule(style="dim"))
    console.print("[dim]Scan terminé.[/dim]\n")


if __name__ == "__main__":
    main()
