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
import getpass
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
from modules.ignore_list import load_ignore_list, filter_ignored, find_ignore_file
from modules.msf_mapper import get_msf_modules, has_msf_module, generate_msf_scripts
from modules.default_creds import get_default_creds, enrich_results_with_creds
from modules.misconfig_detector import detect_misconfigs, Misconfig
from modules.gtfobins import collect_gtfobins_via_ssh, analyze_ssh_findings, get_static_gtfobins_for_service
from modules.kill_chain import generate_kill_chain
from modules.reverse_shell import build_shells, best_shells, save_all_shells
from modules.loot_collector import collect_loot
from modules.ad_enum import analyze_ad, detect_ad_context
from modules.hash_cracker import detect_hash_type, generate_crack_commands, detect_hashes_in_text
from modules.vhost_discovery import analyze_vhosts
from modules.privesc_checker import get_privesc_checklist, get_quick_checks
from modules.shell_upgrader import get_linux_upgrade_guides, get_windows_upgrade_guides, get_quick_upgrade
from modules.web_payload_gen import analyze_web_payloads
from modules.pivot_helper    import generate_pivot_commands
from modules.cipher_decoder  import analyze_cipher
from modules.brute_helper    import generate_brute_commands
from modules.smb_helper      import generate_smb_commands
from modules.subdomain_enum  import (enumerate_subdomains,
                                      display_subdomain_results,
                                      subdomain_results_to_html_section)
from modules.token_helper     import (get_token_checks,
                                       get_checks_for_privilege,
                                       analyze_whoami_priv)
from modules.cloud_enum         import enumerate_cloud, get_all_cloud_checks
from modules.lateral_movement  import generate_lateral_commands, get_all_lateral_techniques
from modules.web_fingerprinter import (fingerprint_all,
                                        fingerprints_to_synthetic_results)
from update_db               import auto_fetch_if_missing, auto_fetch_service
from modules.wordlist_builder import build_wordlists
from modules.container_escape import (get_container_escape_checklist,
                                       get_quick_container_checks,
                                       analyze_container_host)
from modules.credentialed_scan import (
    collect_packages_ssh, packages_to_services,
    SSHCredentialError, SSHConnectionError,
)
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
    art = image_to_rich_art(str(ASSETS_DIR / "chocoscan_cli.png"), width=70)
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
        # Fallback si _new_cves_session non défini (chemins alternatifs)
        if "_new_cves_session" not in dir():
            _new_cves_session = set()
        table.add_column("CVE ID", style="bold magenta", min_width=18)
        table.add_column("Sévérité", justify="center", min_width=10)
        table.add_column("CVSS", justify="center", min_width=6)
        table.add_column("Score CTX", justify="center", min_width=9)
        table.add_column("Description", max_width=50)
        table.add_column("Source", style="dim", min_width=10)
        if show_exploits:
            table.add_column("Exploit PoC", style="bright_green", max_width=35)
        # Colonne MSF — affichée si au moins une CVE du service a un module MSF
        show_msf_col = any(cve.get("msf_modules") for cve in cves)
        if show_msf_col:
            table.add_column("MSF", style="bold blue", min_width=12)

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

            _cve_id   = cve.get("id", "N/A")
            _is_new   = _cve_id in _new_cves_session
            _id_cell  = (
                f"[bold bright_cyan]{_cve_id}[/bold bright_cyan] "
                f"[on dark_blue bold bright_cyan] ✦ NEW [/on dark_blue bold bright_cyan]"
                if _is_new else _cve_id
            )
            row = [
                _id_cell,
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

            if show_msf_col:
                msf_mods = cve.get("msf_modules", [])
                if msf_mods:
                    # Affiche le premier module sur une ligne courte
                    mod_path = msf_mods[0]["path"]
                    short = mod_path.split("/")[-1][:20]
                    rank_color = {"excellent": "green", "great": "green",
                                  "good": "yellow", "normal": "dim",
                                  "average": "dim", "manual": "dim"}.get(
                        msf_mods[0].get("rank", ""), "white")
                    extra = f" +{len(msf_mods)-1}" if len(msf_mods) > 1 else ""
                    row.append(f"[{rank_color}]{short}{extra}[/{rank_color}]")
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
    input_group.add_argument("--ssh-scan", metavar="TARGET",
                              help="Scan authentifié via SSH : liste les paquets installés sur la cible "
                                   "(dpkg/rpm/pacman) et matche les CVE correspondantes. "
                                   "Nécessite --ssh-user (et --ssh-pass ou --ssh-key)")
    input_group.add_argument("--diff", nargs=2, metavar=("AVANT", "APRES"),
                              help="Comparer deux fichiers de scan (tout format supporté)")
    parser.add_argument("--input-format", default="auto", metavar="FORMAT",
                        help="Format d\'entrée : auto (défaut), nmap_xml, nmap_text, "
                             "masscan_xml, masscan_json, masscan_text, rustscan_json, "
                             "rustscan_text, nessus_csv, nessus_xml, chocoscan_json")
    parser.add_argument("--ssh-user", default=None, metavar="USER",
                        help="Utilisateur SSH pour --ssh-scan")
    parser.add_argument("--ssh-pass", default=None, metavar="PASS",
                        help="Mot de passe SSH pour --ssh-scan (si omis : tentative par clé, "
                             "puis prompt masqué)")
    parser.add_argument("--ssh-key", default=None, metavar="FILE",
                        help="Chemin vers une clé privée SSH pour --ssh-scan")
    parser.add_argument("--ssh-port", type=int, default=22, metavar="PORT",
                        help="Port SSH pour --ssh-scan (défaut: 22)")

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
    parser.add_argument("--msf", action="store_true",
                        help="Afficher les modules Metasploit disponibles pour chaque CVE trouvée")
    parser.add_argument("--msf-script", action="store_true",
                        help="Générer des scripts .rc Metasploit prêts à lancer avec msfconsole -r")
    parser.add_argument("--lhost", default=None, metavar="IP",
                        help="Votre IP locale pour les payloads reverse shell (LHOST dans les scripts MSF)")
    parser.add_argument("--default-creds", action="store_true",
                        help="Afficher les credentials par défaut connus pour chaque service "
                             "et générer les commandes Hydra associées")
    parser.add_argument("--misconfig", action="store_true",
                        help="Détecter les mauvaises configurations réseau (Redis sans auth, "
                             "FTP anonyme, MongoDB ouvert, NFS, SNMP community string...)")
    parser.add_argument("--gtfobins", action="store_true",
                        help="Afficher les vecteurs GTFOBins statiques pour les services détectés "
                             "(sudo, SUID). Avec --ssh-scan, exécute sudo -l et find SUID sur la cible.")
    parser.add_argument("--kill-chain", action="store_true",
                        help="Générer une narrative complète du chemin d'exploitation vers root/SYSTEM "
                             "(combine CVE, misconfigs, creds par défaut, GTFOBins)")
    parser.add_argument("--revshell", nargs="?", const="auto", metavar="SERVICE:PORT",
                        help="Générer un reverse shell adapté au service (auto = service le plus vulnérable). "
                             "Ex: --revshell php:80 | --revshell auto")
    parser.add_argument("--all-shells", action="store_true",
                        help="Générer un fichier avec tous les formats de reverse shell disponibles")
    parser.add_argument("--lport", type=int, default=4444, metavar="PORT",
                        help="Port d'écoute pour les reverse shells (défaut: 4444)")
    parser.add_argument("--loot", action="store_true",
                        help="Collecter les fichiers sensibles sur la cible via SSH "
                             "(clés SSH, historiques, configs, secrets, flags CTF). "
                             "Nécessite --ssh-scan.")
    parser.add_argument("--ad-enum", action="store_true",
                        help="Détecter le contexte Active Directory et afficher les commandes "
                             "impacket/ldapsearch/BloodHound pré-remplies")
    parser.add_argument("--ad-auto", action="store_true",
                        help="Exécuter automatiquement les énumérations AD sûres "
                             "(smbclient, ldapsearch, AS-REP scan anonyme). "
                             "Implique --ad-enum.")
    parser.add_argument("--hashcrack", nargs="?", const="auto", metavar="HASH",
                        help="Détecter le type de hash et générer les commandes hashcat/john. "
                             "Ex: --hashcrack '$6$salt$hash...' | --hashcrack auto (depuis le loot)")
    parser.add_argument("--vhost", nargs="?", const="auto", metavar="DOMAIN",
                        help="Générer les commandes ffuf/gobuster pour vhost et subdomain discovery. "
                             "Ex: --vhost target.htb | --vhost auto (détection depuis le scan)")
    parser.add_argument("--privesc", action="store_true",
                        help="Afficher la checklist de privilege escalation contextuelle "
                             "(Linux ou Windows selon l'OS détecté dans le scan)")
    parser.add_argument("--upgrade-shell", action="store_true",
                        help="Afficher les commandes complètes pour upgrader un reverse shell "
                             "basique en shell interactif stable (python3 PTY, socat, stty raw)")
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
    parser.add_argument("--ignore-file", default=None, metavar="FILE",
                        help="Fichier de CVE ID à exclure des résultats (défaut: .chocoscanignore "
                             "dans le répertoire courant, puis ~/.chocoscanignore)")
    parser.add_argument("--no-ignore", action="store_true",
                        help="Désactiver la prise en compte du fichier .chocoscanignore")
    parser.add_argument("--after-year", type=int, default=None, metavar="AAAA",
                        help="Filtrer les CVEs publiées à partir de cette année (ex: 2024 → garde CVE-2024-x, CVE-2025-x…)")
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Mode interactif CLI : naviguer, marquer et exporter les CVEs (style fzf)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Affiche les services dont le nom n'a matché aucun alias connu "
                             "(diagnostic des trous de couverture de la base locale)")

    # ── Web Payload Generator ────────────────────────────────────────────────
    parser.add_argument("--web-payloads", nargs="?", const="auto", metavar="SERVICE:PORT",
                        help="Payloads web offensifs selon le stack détecté "
                             "(LFI, SSTI, SQLi, SSRF, XXE, XSS + sqlmap). "
                             "Ex: --web-payloads auto | --web-payloads http:8080")
    parser.add_argument("--pivot", nargs="?", const="auto", metavar="LHOST",
                        help="Commandes de pivoting et tunneling "
                             "(SSH local/remote/dynamic, Chisel, Ligolo-ng, socat, sshuttle). "
                             "Ex: --pivot 10.10.14.5 | --pivot auto")
    parser.add_argument("--cipher", default=None, metavar="TEXT",
                        help="Identifier et décoder un encodage ou chiffrement "
                             "(Base64, Hex, ROT13/47, Caesar, Morse, JWT, hashes...). "
                             "Ex: --cipher 'aGVsbG8='")
    parser.add_argument("--brute", action="store_true",
                        help="Commandes hydra/medusa/crackmapexec/ncrack par service détecté.")
    parser.add_argument("--tokens", nargs="?", const="all", metavar="WHOAMI_OUTPUT",
                        help="Guide d\'exploitation des token privileges Windows "
                             "(SeImpersonatePrivilege → Potato, SeDebugPrivilege → LSASS dump...). "
                             "Optionnel : coller la sortie de 'whoami /priv' pour filtrer. "
                             "Ex: --tokens | --tokens 'SeImpersonatePrivilege  Enabled'")
    parser.add_argument("--cloud", action="store_true",
                        help="Énumération cloud : S3 buckets ouverts, Azure Blob, GCS, "
                             "metadata service via SSRF (IMDSv1/v2), IAM enumération, "
                             "credentials leakés, ScoutSuite, cloud_enum. "
                             "Détecte automatiquement AWS/Azure/GCP depuis le scan.")
    parser.add_argument("--lateral", action="store_true",
                        help="Techniques de mouvement latéral Windows post-compromise : "
                             "DCOM, WMI, MSSQL linked servers, LAPS, délégation Kerberos, "
                             "coercition (PrinterBug/PetitPotam), AD CS (certipy ESC1/ESC8), "
                             "Shadow Credentials, RDP hijacking. "
                             "Adapté au contexte (DC/MSSQL/RDP détectés).")
    parser.add_argument("--web-fingerprint", action="store_true",
                        help="Fingerprinte activement les services web pour identifier "
                             "le CMS/framework exact (Craft CMS, WordPress, Jenkins...) "
                             "et retrouver les CVE correspondantes. "
                             "Résout le problème : nmap voit nginx → ChocoScan ne voit pas Craft CMS.")
    parser.add_argument("--wordlist", nargs="?", const="auto", metavar="OUTPUT",
                        help="Génère une wordlist ciblée depuis le scan : domaine, "
                             "hostname, produits détectés + mutations (années, symboles, "
                             "leet, patterns enterprise). "
                             "Ex: --wordlist | --wordlist /tmp/cible.txt")
    parser.add_argument("--custom-words", nargs="+", metavar="WORD", default=[],
                        help="Mots supplémentaires à inclure dans la wordlist "
                             "(noms d'employés, projets...). Ex: --custom-words acme john")
    parser.add_argument("--container", nargs="?", const="all", metavar="MODE",
                        help="Checklist d\'évasion de conteneurs (Docker/LXC/K8s). "
                             "Modes : all (défaut), quick (vérifs rapides uniquement). "
                             "Détecte aussi les services conteneurs dans le scan "
                             "(Docker API 2375, K8s 6443, Kubelet 10250). "
                             "Ex: --container | --container quick")
    parser.add_argument("--smb", action="store_true",
                        help="Enumération SMB complète + impacket "
                             "(secretsdump, wmiexec, psexec, relay, PTH, Kerberoasting).")
    parser.add_argument("--subdomain", nargs="?", const="auto", metavar="DOMAIN",
                        help="Enumération de sous-domaines (passif + bruteforce DNS). "
                             "Ex: --subdomain target.htb | --subdomain (auto-détecte depuis le scan)")
    parser.add_argument("--sub-passive", action="store_true",
                        help="Recon passive uniquement (crt.sh, HackerTarget, RapidDNS). "
                             "Zéro bruit réseau vers la cible.")
    parser.add_argument("--sub-active", action="store_true",
                        help="Bruteforce DNS actif uniquement (pas de recon externe).")
    parser.add_argument("--sub-threads", type=int, default=30, metavar="N",
                        help="Threads pour le bruteforce DNS (défaut config/30).")
    parser.add_argument("--sub-wordlist", default=None, metavar="FILE",
                        help="Wordlist externe pour le bruteforce. "
                             "Ex: --sub-wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")

    # ── Charger la config ~/.chocoscan.conf ─────────────────────────────────
    _cfg_path = apply_to_parser(parser)

    args = parser.parse_args()

    # Validation et parse des filtres
    severity_filter = parse_severity_filter(args.severity)

    # Chargement de la whitelist .chocoscanignore
    ignored_cves: set[str] = set()
    if not args.no_ignore:
        ignored_cves = load_ignore_list(args.ignore_file)
        if ignored_cves:
            resolved_path = find_ignore_file(args.ignore_file)
            console.print(
                f"[dim]Whitelist : {len(ignored_cves)} CVE ignorée(s) "
                f"depuis {resolved_path}[/dim]"
            )

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

    elif args.ssh_scan:
        target = args.ssh_scan
        scan_xml_path = None

        if not args.ssh_user:
            console.print("[bold red][!] --ssh-scan nécessite --ssh-user.[/bold red]")
            sys.exit(1)

        ssh_password = args.ssh_pass
        if not ssh_password and not args.ssh_key:
            # Pas de password ni de clé fournis : tente l'agent/clé par défaut,
            # avec fallback sur un prompt masqué si la connexion échoue.
            console.print(
                "[dim][*] Aucun --ssh-pass/--ssh-key fourni, tentative via clé SSH par défaut...[/dim]"
            )

        console.print(f"\n[cyan][*] Scan authentifié SSH sur [bold]{target}[/bold] "
                      f"(user: {args.ssh_user})...[/cyan]")

        try:
            packages, distro = collect_packages_ssh(
                host=target,
                username=args.ssh_user,
                password=ssh_password,
                key_filename=args.ssh_key,
                port=args.ssh_port,
            )
        except SSHCredentialError as e:
            console.print(f"[bold red][!] {e}[/bold red]")
            # Fallback : prompt masqué si rien n'avait été fourni du tout
            if not ssh_password and not args.ssh_key:
                ssh_password = getpass.getpass(f"Mot de passe SSH pour {args.ssh_user}@{target} : ")
                try:
                    packages, distro = collect_packages_ssh(
                        host=target, username=args.ssh_user,
                        password=ssh_password, port=args.ssh_port,
                    )
                except (SSHCredentialError, SSHConnectionError) as e2:
                    console.print(f"[bold red][!] {e2}[/bold red]")
                    sys.exit(1)
            else:
                sys.exit(1)
        except SSHConnectionError as e:
            console.print(f"[bold red][!] {e}[/bold red]")
            sys.exit(1)
        except RuntimeError as e:
            console.print(f"[bold red][!] {e}[/bold red]")
            sys.exit(1)

        console.print(
            f"[green][+] Distribution détectée : [bold]{distro}[/bold] — "
            f"{len(packages)} paquet(s) installé(s)[/green]"
        )
        services = packages_to_services(packages, target)

    if not services:
        console.print("[yellow][!] Aucun service ouvert trouvé dans le scan.[/yellow]")
        sys.exit(0)

    console.print(f"[green][+] {len(services)} service(s) ouvert(s) détecté(s)[/green]")

    # Matching CVE
    results = []
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    use_api = not args.no_api
    total_ignored_hits = 0
    unmatched_services = []  # services dont le nom n'a matché aucun alias SERVICE_ALIASES

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Recherche de CVEs...", total=len(services))

        # Cache partagé pour éviter de requêter NVD 2x pour le même service
        _autofetch_cache: set = set()
        # Set des CVE IDs nouvellement téléchargés dans cette session
        _new_cves_session: set = set()

        for svc in services:
            progress.update(task, description=f"Analyse {svc.service_name}:{svc.port}...")

            # ── Auto-fetch CVE pour ce service (base vide OU mise à jour) ──
            if not args.no_api:
                from modules.cve_matcher import extract_service_key as _esk
                from modules.cve_matcher import SERVICE_ALIASES as _aliases
                _skey = _esk(svc.service_name, svc.banner)
                if _skey:
                    # Construire les mots-clés depuis SERVICE_SEARCH_TERMS ou le banner
                    try:
                        from update_db import SERVICE_SEARCH_TERMS as _sst
                        _kws = _sst.get(_skey, [svc.product or svc.service_name])
                    except Exception:
                        _kws = [svc.product or svc.service_name]
                    if _kws and _kws[0]:  # ne pas appeler avec un keyword vide
                        auto_fetch_service(
                            _skey, _kws,
                            min_cvss=args.min_cvss or 5.0,
                            silent=True,
                            session_cache=_autofetch_cache,
                            new_cves_out=_new_cves_session,
                            after_year=getattr(args, 'after_year', None),
                        )

            cves = get_cves_for_service(svc.service_name, svc.banner, use_api_fallback=use_api)

            if args.verbose:
                service_key = extract_service_key(svc.service_name, svc.banner)
                if service_key is None:
                    unmatched_services.append(svc)

            # Filtrage combiné (CVSS + sévérité)
            cves = filter_cves(cves, args.min_cvss, severity_filter, after_year=args.after_year)

            # Whitelist .chocoscanignore (CVE déjà traitées / faux positifs connus)
            if ignored_cves:
                cves, skipped = filter_ignored(cves, ignored_cves)
                total_ignored_hits += skipped

            if args.exploits:
                for c in cves:
                    cve_id = c.get("id", "")
                    if cve_id.upper().startswith("CVE-"):
                        c["exploits"] = get_top_exploits(cve_id, max_results=2)

            if args.msf or args.msf_script:
                for c in cves:
                    cve_id = c.get("id", "")
                    if cve_id.upper().startswith("CVE-"):
                        msf_mods = get_msf_modules(cve_id)
                        if msf_mods:
                            c["msf_modules"] = [
                                {"path": m.path, "type": m.type, "rank": m.rank,
                                 "description": m.description, "needs_lhost": m.needs_lhost}
                                for m in msf_mods
                            ]

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

    if total_ignored_hits > 0:
        console.print(
            f"[dim]({total_ignored_hits} CVE masquée(s) par la whitelist .chocoscanignore)[/dim]"
        )


    # ── Affichage détaillé des modules Metasploit ────────────────────────────
    if args.msf or args.msf_script:
        _msf_hits: list[tuple[str, str, dict]] = []  # (svc_label, cve_id, msf_mod)
        for _r in results:
            _svc  = _r.get("service", {})
            _label = f"{_svc.get('host','')}:{_svc.get('port','')} {_svc.get('product','') or _svc.get('service_name','')}"
            for _c in _r.get("cves", []):
                for _m in _c.get("msf_modules", []):
                    _msf_hits.append((_label, _c.get("id", ""), _m))

        if _msf_hits:
            console.print(f"\n[bold blue]{'='*62}[/bold blue]")
            console.print(f"[bold blue]  MODULES METASPLOIT[/bold blue]")
            console.print(f"[bold blue]{'='*62}[/bold blue]")
            _lhost = args.lhost or "LHOST"
            _lport = getattr(args, 'lport', 4444) or 4444

            for _label, _cve_id, _mod in _msf_hits:
                _rank_col = {"excellent": "green", "great": "green",
                             "good": "yellow"}.get(_mod.get("rank", ""), "dim")
                console.print(
                    f"\n  [cyan]{_cve_id}[/cyan]  [{_rank_col}]{_mod.get('rank','').upper()}[/{_rank_col}]"
                    f"  [bold]{_mod.get('description', _mod.get('path',''))}[/bold]"
                )
                console.print(f"  [dim]{_label}[/dim]")
                console.print(f"\n  [green]msfconsole -q[/green]")
                console.print(f"  [yellow]use {_mod.get('path','')}[/yellow]")
                console.print(f"  [yellow]set RHOSTS {_svc.get('host', 'TARGET')}[/yellow]")
                console.print(f"  [yellow]set RPORT {_mod.get('default_rport') or _svc.get('port', '')}[/yellow]")
                if _mod.get("needs_lhost"):
                    console.print(f"  [yellow]set LHOST {_lhost}[/yellow]")
                    console.print(f"  [yellow]set LPORT {_lport}[/yellow]")
                console.print(f"  [yellow]set VERBOSE true[/yellow]")
                console.print(f"  [yellow]run[/yellow]")

            console.print(f"\n  [dim]→ --msf-script pour générer un fichier .rc prêt à lancer[/dim]")
            console.print(f"  [dim]   msfconsole -r chocoscan_msf_TARGET.rc[/dim]")
            console.print(f"[bold blue]{'='*62}[/bold blue]\n")
        else:
            console.print(
                f"\n[dim][MSF] Aucun module Metasploit trouvé pour les CVE détectées.[/dim]"
                f"\n[dim]      La table statique couvre ~80 CVE CTF classiques (vsftpd, EternalBlue, Log4Shell...).[/dim]"
                f"\n[dim]      Pour les CVE récentes, chercher manuellement : msfconsole -q -x 'search {results[0]["cves"][0]["id"] if results and results[0]["cves"] else "CVE-ID"}'[/dim]\n"
                if results else ""
            )

    # ── Credentials par défaut ────────────────────────────────────────────────
    if args.default_creds:
        results = enrich_results_with_creds(results, target=target)
        creds_found = [r for r in results if r.get("default_creds")]
        if creds_found:
            console.print(f"\n[bold yellow]● Credentials par défaut ({len(creds_found)} service(s))[/bold yellow]")
            for result in creds_found:
                svc = result["service"]
                dc  = result["default_creds"]
                console.print(f"\n  [cyan]{svc['service_name']}:{svc['port']}[/cyan]")
                for c in dc["creds"][:4]:
                    note = f"  [dim]← {c['note']}[/dim]" if c.get("note") else ""
                    pwd  = c["password"] if c["password"] else "[dim](vide)[/dim]"
                    console.print(f"    [white]{c['username']}[/white] : {pwd}{note}")
                if dc.get("quick_test"):
                    console.print(f"  [dim]Test rapide :[/dim] [green]{dc['quick_test']}[/green]")
                if dc.get("hydra_cmd"):
                    console.print(f"  [dim]Hydra       :[/dim] [yellow]{dc['hydra_cmd']}[/yellow]")

    # ── Misconfigurations ─────────────────────────────────────────────────────
    misconfig_list = []
    if args.misconfig:
        from modules.nmap_parser import NmapService as _NmapService
        svc_objects = []
        for result in results:
            svc = result.get("service", {})
            svc_objects.append(_NmapService(
                host=svc.get("host", ""), port=svc.get("port", 0),
                protocol=svc.get("protocol", "tcp"), state="open",
                service_name=svc.get("service_name", ""), product=svc.get("product", ""),
                version=svc.get("version", ""), extrainfo=svc.get("extrainfo", ""),
                banner=svc.get("banner", ""),
            ))
        misconfig_list = detect_misconfigs(svc_objects)
        if misconfig_list:
            console.print(f"\n[bold red]● Misconfigurations détectées ({len(misconfig_list)})[/bold red]")
            for mc in misconfig_list:
                sev_color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue"}.get(mc.severity, "white")
                console.print(f"\n  [{sev_color}][{mc.severity}][/{sev_color}] [bold]{mc.title}[/bold]")
                console.print(f"  [dim]{mc.description[:120]}[/dim]")
                console.print(f"  [dim]Impact      :[/dim] {mc.impact[:100]}")
                console.print(f"  [dim]Vérifier    :[/dim] [green]{mc.check_cmd}[/green]")
                console.print(f"  [dim]Remédiation :[/dim] {mc.remediation[:100]}")
        else:
            console.print("\n[dim]Aucune misconfiguration évidente détectée.[/dim]")

    # ── GTFOBins ──────────────────────────────────────────────────────────────
    gtfo_findings = []
    if args.gtfobins:
        console.print("\n[bold blue]● GTFOBins — vecteurs de privesc statiques[/bold blue]")
        gtfo_shown = False
        for result in results:
            svc      = result.get("service", {})
            svc_name = svc.get("service_name", "")
            port     = svc.get("port", 0)
            static_entries = get_static_gtfobins_for_service(svc_name)
            if static_entries:
                gtfo_shown = True
                console.print(f"\n  [cyan]{svc_name}:{port}[/cyan] — sudo {svc_name} potentiellement exploitable")
                for entry in static_entries[:1]:
                    console.print(f"  [green]{entry.command.split(chr(10))[0]}[/green]")
        if not gtfo_shown:
            console.print("  [dim]Aucun binaire GTFOBins identifié statiquement depuis le scan réseau.[/dim]")
            console.print("  [dim]Utilisez --ssh-scan --gtfobins pour collecter sudo -l et SUID sur la cible.[/dim]")

    # ── Kill Chain ────────────────────────────────────────────────────────────
    if args.kill_chain:
        kill_chain = generate_kill_chain(
            results=results, target=target,
            misconfigs=misconfig_list, gtfo_findings=gtfo_findings,
        )
        console.print(f"\n[bold magenta]{'=' * 62}[/bold magenta]")
        console.print(f"[bold magenta]  KILL CHAIN — {target}[/bold magenta]")
        console.print(f"[bold magenta]{'=' * 62}[/bold magenta]")
        for line in kill_chain.narrative.split("\n"):
            if line.startswith("===") or line.startswith("──"):
                console.print(f"[bold]{line}[/bold]")
            elif line.startswith("[!]") or line.startswith("[CVE]"):
                console.print(f"[yellow]{line}[/yellow]")
            elif line.startswith("[GTFOBins]"):
                console.print(f"[blue]{line}[/blue]")
            elif line.strip().startswith(">"):
                console.print(f"[green]{line}[/green]")
            else:
                console.print(line)
        console.print(f"[bold magenta]{'=' * 62}[/bold magenta]\n")

    # ── Reverse Shell Generator ───────────────────────────────────────────────
    lhost = args.lhost or ""
    lport = getattr(args, "lport", 4444) or 4444

    if args.revshell or args.all_shells:
        if not lhost:
            console.print("[yellow][!] --lhost requis pour générer des reverse shells. "
                          "Ex: --lhost 10.10.14.5[/yellow]")
        else:
            if args.all_shells:
                import os as _os
                _os.makedirs(args.output_dir, exist_ok=True)
                out_file = f"{args.output_dir}/chocoscan_revshells_{target.replace('.','_')}.md"
                save_all_shells(lhost, lport, out_file)
                console.print(f"\n[bold green]● Reverse shells → [cyan]{out_file}[/cyan][/bold green]")
                console.print(f"[dim]  {sum(1 for _ in open(out_file) if _.startswith('## '))-1} formats générés[/dim]")
            else:
                # Sélection automatique ou par service
                svc_target = args.revshell if args.revshell != "auto" else None
                svc_name, svc_port = "auto", 0
                if svc_target and ":" in svc_target:
                    svc_name, svc_port_str = svc_target.split(":", 1)
                    svc_port = int(svc_port_str)
                elif not svc_target and results:
                    # Service le plus vulnérable (premier résultat trié par CVSS)
                    best = sorted(results, key=lambda r: max(
                        (float(str(c.get("cvss", 0)).replace("N/A", "0"))
                         for c in r.get("cves", [{"cvss": 0}])), default=0
                    ), reverse=True)
                    if best:
                        svc_name = best[0].get("service", {}).get("service_name", "bash")

                shells = best_shells(svc_name, lhost, lport)
                console.print(f"\n[bold green]● Reverse shells pour {svc_name} "
                              f"(LHOST={lhost} LPORT={lport})[/bold green]")
                for sh in shells[:3]:
                    console.print(f"\n  [cyan]{sh.name}[/cyan] — {sh.description}")
                    console.print(f"  [green]{sh.payload[:120]}{'...' if len(sh.payload)>120 else ''}[/green]")
                    if sh.b64_cmd:
                        console.print(f"  [dim]Base64 : {sh.b64_cmd[:100]}...[/dim]")
                    if sh.listener:
                        console.print(f"  [yellow]Listener : {sh.listener.split(chr(10))[0]}[/yellow]")
                console.print(f"\n  [dim]→ --all-shells pour tous les formats dans un fichier[/dim]")

    # ── Loot Collector ────────────────────────────────────────────────────────
    if args.loot:
        if not getattr(args, "ssh_scan", None):
            console.print("[yellow][!] --loot nécessite --ssh-scan pour se connecter à la cible.[/yellow]")
        elif "_ssh_client_obj" in globals():
            console.print(f"\n[bold yellow]● Loot Collector — {target}[/bold yellow]")
            from modules.loot_collector import collect_loot as _collect_loot
            loot_items = _collect_loot(globals()["_ssh_client_obj"], target)
            if loot_items:
                cat_colors = {"ctf":"bold red","ssh_key":"red","secret":"yellow",
                              "system":"orange1","config":"blue","web":"cyan",
                              "history":"dim","interesting":"green"}
                for item in loot_items:
                    col = cat_colors.get(item.category, "white")
                    crit = " [bold red][CRITIQUE][/bold red]" if item.is_critical else ""
                    console.print(f"\n  [{col}][{item.category.upper()}][/{col}]{crit} {item.path}")
                    console.print(f"  [dim]{item.description}[/dim]")
                    if item.preview:
                        preview = item.preview[:200].replace("\n", " | ")
                        console.print(f"  [green]{preview}[/green]")
            else:
                console.print("  [dim]Aucun fichier sensible trouvé.[/dim]")
        else:
            console.print("[yellow][!] Session SSH non disponible. Lancez d'abord --ssh-scan.[/yellow]")

    # ── AD Enumeration ────────────────────────────────────────────────────────
    if args.ad_enum or args.ad_auto:
        ad_result = analyze_ad(
            results=results, output_dir=args.output_dir,
            auto=args.ad_auto,
        )
        if ad_result is None:
            console.print("\n[dim][AD] Aucun indicateur Active Directory détecté dans le scan.[/dim]")
            console.print("[dim]     Ports AD attendus : 88 (Kerberos), 389 (LDAP), 445 (SMB), 3268 (GC)[/dim]")
        else:
            ad = ad_result.ad_info
            console.print(f"\n[bold cyan]{'=' * 62}[/bold cyan]")
            console.print(f"[bold cyan]  ACTIVE DIRECTORY — {ad.domain} ({ad.dc_ip})[/bold cyan]")
            console.print(f"[bold cyan]{'=' * 62}[/bold cyan]")
            console.print(f"  DC       : [bold]{ad.dc_ip}[/bold]")
            console.print(f"  Domaine  : [bold]{ad.domain}[/bold]")
            console.print(f"  NetBIOS  : [bold]{ad.domain_nb}[/bold]")
            if ad.hostname:
                console.print(f"  Hostname : {ad.hostname}")
            console.print("")

            for cmd in ad_result.commands:
                console.print(f"[bold blue]── {cmd.title}[/bold blue]")
                console.print(f"[dim]   {cmd.description}[/dim]")
                for line in cmd.command.split("\n")[:4]:
                    console.print(f"   [green]{line}[/green]")
                console.print("")

            if ad_result.auto_results:
                console.print(f"[bold yellow]── Résultats --ad-auto[/bold yellow]")
                for title, output in ad_result.auto_results.items():
                    if output and "[!]" not in output:
                        console.print(f"\n  [cyan]{title}[/cyan]")
                        for line in output.split("\n")[:8]:
                            console.print(f"  {line}")
            console.print(f"[bold cyan]{'=' * 62}[/bold cyan]\n")

    # ── Hash Cracker ──────────────────────────────────────────────────────────
    if args.hashcrack:
        console.print("\n[bold yellow]● Hash Cracker[/bold yellow]")
        import os as _os
        _os.makedirs(args.output_dir, exist_ok=True)
        if args.hashcrack != "auto":
            # Hash fourni directement
            info = detect_hash_type(args.hashcrack)
            if info:
                console.print(f"\n  Type détecté : [cyan]{info.hash_type}[/cyan] "
                              f"(hashcat -m {info.hashcat_mode})")
                console.print(f"  Difficulté   : [{'red' if info.difficulty=='hard' else 'yellow' if info.difficulty=='medium' else 'green'}]{info.difficulty.upper()}[/{'red' if info.difficulty=='hard' else 'yellow' if info.difficulty=='medium' else 'green'}]")
                hash_file = f"{args.output_dir}/hash.txt"
                with open(hash_file, "w") as hf:
                    hf.write(args.hashcrack + "\n")
                cmds = generate_crack_commands(hash_file, info, args.output_dir)
                for line in cmds:
                    if line.startswith("#"):
                        console.print(f"  [dim]{line}[/dim]")
                    elif line:
                        console.print(f"  [green]{line}[/green]")
                    else:
                        console.print("")
            else:
                console.print(f"  [yellow]Type de hash non reconnu : {args.hashcrack[:60]}[/yellow]")
        else:
            # Cherche dans les résultats et le loot
            all_text = " ".join(
                str(r.get("service", {}).get("banner", "")) for r in results
            )
            found = detect_hashes_in_text(all_text)
            if found:
                for h, info in found[:5]:
                    console.print(f"\n  [cyan]{info.hash_type}[/cyan] (mode {info.hashcat_mode})")
                    console.print(f"  [dim]{h[:60]}...[/dim]" if len(h) > 60 else f"  [dim]{h}[/dim]")
                    hash_file = f"{args.output_dir}/hashes_{info.hash_type.lower().replace(' ','_')}.txt"
                    with open(hash_file, "a") as hf:
                        hf.write(h + "\n")
                    console.print(f"  [green]hashcat -m {info.hashcat_mode} {hash_file} /usr/share/wordlists/rockyou.txt -O[/green]")
            else:
                console.print("  [dim]Aucun hash détecté automatiquement. "
                              "Fournissez le hash directement : --hashcrack '$6$...'[/dim]")

    # ── Vhost Discovery ───────────────────────────────────────────────────────
    if args.vhost:
        custom_domain = "" if args.vhost == "auto" else args.vhost
        vhost_results = analyze_vhosts(results, custom_domain=custom_domain)
        if vhost_results:
            console.print(f"\n[bold green]● Vhost Discovery ({len(vhost_results)} service(s) HTTP)[/bold green]")
            for vr in vhost_results:
                t = vr.target
                console.print(f"\n  [cyan]{t.protocol}://{t.host}:{t.port}[/cyan]  domaine: [bold]{t.domain}[/bold]")
                for cmd in vr.commands[:3]:  # Top 3 commandes
                    console.print(f"\n  [bold dim]{cmd['title']}[/bold dim]")
                    for line in cmd["cmd"].split("\n")[:4]:
                        if line.startswith("#"):
                            console.print(f"  [dim]{line}[/dim]")
                        elif line.strip():
                            console.print(f"  [green]{line}[/green]")
        else:
            console.print("\n[dim]Aucun service HTTP/HTTPS détecté dans le scan.[/dim]")

    # ── Privesc Checklist ────────────────────────────────────────────────────
    if args.privesc:
        from modules.kill_chain import _guess_os
        os_target = _guess_os(results)
        if os_target == "unknown":
            os_target = "linux"
        checks = get_privesc_checklist(os_target)
        console.print(f"\n[bold magenta]● Privesc Checklist — {os_target.upper()} "
                      f"({len(checks)} vecteurs)[/bold magenta]")
        cat_colors = {"sudo":"yellow","suid":"red","cron":"cyan","path":"blue",
                      "service":"orange1","kernel":"magenta","misc":"green"}
        for check in checks:
            col = cat_colors.get(check.category, "white")
            diff_col = {"easy":"green","medium":"yellow","hard":"red"}.get(check.difficulty,"white")
            console.print(f"\n  [{col}][{check.category.upper()}][/{col}] "
                          f"[{diff_col}]{check.difficulty.upper()}[/{diff_col}]  "
                          f"[bold]{check.title}[/bold]")
            console.print(f"  [dim]{check.description[:100]}[/dim]")
            # Affiche la commande de vérification (première ligne seulement)
            first_cmd = check.check_cmd.split("\n")[0]
            console.print(f"  [green]Check : {first_cmd}[/green]")
            # Affiche l'exploit (première ligne)
            first_exploit = [l for l in check.exploit_cmd.split("\n") if l.strip() and not l.startswith("#")]
            if first_exploit:
                console.print(f"  [yellow]Exploit: {first_exploit[0][:90]}[/yellow]")

    # ── Shell Upgrader ────────────────────────────────────────────────────────
    if args.upgrade_shell:
        from modules.kill_chain import _guess_os
        os_target = _guess_os(results) if results else "linux"
        if os_target == "unknown":
            os_target = "linux"
        lhost = args.lhost or "LHOST"
        lport = getattr(args, "lport", 4445) or 4445

        console.print(f"\n[bold cyan]{'=' * 62}[/bold cyan]")
        console.print(f"[bold cyan]  SHELL UPGRADER — {os_target.upper()}[/bold cyan]")
        console.print(f"[bold cyan]{'=' * 62}[/bold cyan]")

        quick = get_quick_upgrade(os_target)
        console.print(f"\n[bold]One-liner rapide :[/bold]")
        console.print(f"[green]{quick}[/green]\n")

        if os_target == "linux":
            guides = get_linux_upgrade_guides(lhost, lport)
        else:
            guides = get_windows_upgrade_guides(lhost, lport)

        for guide in guides[:2]:  # Top 2 méthodes
            console.print(f"\n[bold blue]── {guide.method.upper()} — {guide.summary}[/bold blue]")
            for step in guide.steps:
                console.print(f"\n  [bold]{step.title}[/bold]")
                if step.on_attacker:
                    console.print("  [dim]Côté attaquant :[/dim]")
                    for cmd in step.on_attacker:
                        if cmd.startswith("#"):
                            console.print(f"    [dim]{cmd}[/dim]")
                        else:
                            console.print(f"    [yellow]{cmd}[/yellow]")
                if step.on_target:
                    console.print("  [dim]Côté cible :[/dim]")
                    for cmd in step.on_target:
                        if cmd.startswith("#"):
                            console.print(f"    [dim]{cmd}[/dim]")
                        else:
                            console.print(f"    [green]{cmd}[/green]")
                for note in step.notes:
                    console.print(f"  [dim]→ {note}[/dim]")

        console.print(f"\n[bold cyan]{'=' * 62}[/bold cyan]\n")

    if args.msf_script and results:
        target_ip = target if hasattr(args, 'scan') and args.scan else (
            results[0].get("host", "TARGET") if results else "TARGET"
        )
        lhost = args.lhost or ""
        if not lhost and args.msf_script:
            console.print("[yellow][!] --lhost non spécifié : les payloads reverse shell seront incomplets dans les scripts .rc[/yellow]")
        created = generate_msf_scripts(results, target=target_ip, lhost=lhost, output_dir=args.output_dir)
        if created:
            console.print(f"\n[bold green][+] {len(created)} script(s) MSF généré(s) :[/bold green]")
            for path in created:
                console.print(f"    [cyan]→ {path}[/cyan]")
            console.print(f"[dim]    Lancer avec : msfconsole -r {created[0]}[/dim]")

    if args.verbose and unmatched_services:
        console.print(
            f"\n[yellow][!] {len(unmatched_services)} service(s) non couvert(s) par la base locale "
            f"(aucun alias dans SERVICE_ALIASES, fallback API NVD utilisé) :[/yellow]"
        )
        for svc in unmatched_services:
            label = svc.service_name or "(nom de service vide)"
            extra = f" — {svc.banner}" if svc.banner and svc.banner != label else ""
            console.print(f"  [dim]•[/dim] {svc.host}:{svc.port}/{svc.protocol}  [bold]{label}[/bold]{extra}")
        console.print(
            "[dim]  → Ajoutez ces services à SERVICE_ALIASES (modules/cve_matcher.py) "
            "pour les couvrir par la base locale.[/dim]"
        )

    # ── Web Fingerprinting — enrichissement de results AVANT interactive ───────
    # Doit tourner avant run_interactive() pour que les CVE applicatives
    # (Craft CMS, WordPress, Jenkins...) apparaissent dans le mode interactif.
    if args.web_fingerprint:
        _fp_all = fingerprint_all(results)
        for _fp in _fp_all:
            for _fingerprint in _fp.fingerprints:
                if not _fingerprint.service_key:
                    continue
                _fp_banner = f"{_fingerprint.app_name} {_fingerprint.version}".strip()
                # Auto-fetch CVE pour l'app détectée
                try:
                    _fp_kw = [_fingerprint.app_name, _fingerprint.service_key]
                    auto_fetch_service(
                        _fingerprint.service_key, _fp_kw,
                        min_cvss=5.0, silent=True,
                        session_cache=_autofetch_cache,
                        new_cves_out=_new_cves_session,
                        after_year=getattr(args, 'after_year', None),
                    )
                except Exception:
                    pass
                # CVE matching pour cette app
                _fp_cves = get_cves_for_service(
                    _fingerprint.service_key, _fp_banner,
                    use_api_fallback=not args.no_api,
                )
                _fp_cves = filter_cves(
                    _fp_cves, args.min_cvss, severity_filter,
                    after_year=args.after_year,
                )
                # Ajouter aux résultats principaux
                results.append({
                    "service": {
                        "host":         _fp.host,
                        "port":         _fp.port,
                        "protocol":     _fp.protocol,
                        "state":        "open",
                        "service_name": _fingerprint.service_key,
                        "product":      _fingerprint.app_name,
                        "version":      _fingerprint.version,
                        "extrainfo":    f"Web fingerprint ({_fingerprint.confidence})",
                        "banner":       _fp_banner,
                    },
                    "cves": _fp_cves,
                    "_source": "web_fingerprint",
                    "_fp_confidence": _fingerprint.confidence,
                    "_fp_method": _fingerprint.detection_method,
                })
                if _fp_cves:
                    console.print(
                        f"  [green][WFP][/green] [bold]{_fingerprint.app_name}"
                        f"{' ' + _fingerprint.version if _fingerprint.version else ''}[/bold]"
                        f" → [bold red]{len(_fp_cves)} CVE(s)[/bold red]"
                        + (" dont [bold red]" +
                           ", ".join(c.get('id','?') for c in _fp_cves
                                     if float(c.get('cvss',0) or 0) >= 9.0)[:80]
                           + "[/bold red]"
                           if any(float(c.get('cvss',0) or 0) >= 9.0 for c in _fp_cves) else "")
                    )

    # ── Mode interactif ─────────────────────────────────────────────────────
    if args.interactive:
        run_interactive(results, output_dir=args.output_dir,
                    lhost=args.lhost or "",
                    lport=getattr(args, 'lport', 4444) or 4444)
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



    # ── Token Privilege Helper ───────────────────────────────────────────────
    if args.tokens is not None:
        whoami_input = args.tokens if args.tokens not in ("all", None) else ""
        checks = analyze_whoami_priv(whoami_input) if whoami_input else get_token_checks()

        console.print(f"\n[bold yellow]{'='*62}[/bold yellow]")
        console.print(f"[bold yellow]  TOKEN PRIVILEGE HELPER — Windows[/bold yellow]")
        console.print(f"[bold yellow]{'='*62}[/bold yellow]")

        if whoami_input:
            console.print(f"  [dim]Filtré sur les privilèges détectés dans whoami /priv[/dim]")
        else:
            console.print(f"  [dim]{len(checks)} checks — tous les token privileges Windows[/dim]")
        console.print(f"  [dim]Commencer par : whoami /priv  puis  whoami /groups[/dim]")

        cat_colors = {
            "potato":    "red",
            "debug":     "magenta",
            "ownership": "yellow",
            "backup":    "cyan",
            "driver":    "blue",
            "misc":      "green",
        }
        cat_labels = {
            "potato":    "Potato Attacks (SeImpersonate / SeAssignPrimaryToken)",
            "debug":     "SeDebugPrivilege — LSASS dump",
            "ownership": "SeTakeOwnershipPrivilege",
            "backup":    "SeBackupPrivilege / SeRestorePrivilege",
            "driver":    "SeLoadDriverPrivilege — BYOVD",
            "misc":      "Autres techniques (AlwaysInstallElevated, Incognito...)",
        }

        current_cat = ""
        for check in checks:
            if check.category != current_cat:
                current_cat = check.category
                col = cat_colors.get(check.category, "white")
                label = cat_labels.get(check.category, check.category)
                console.print(f"\n[bold {col}]── {label}[/bold {col}]")

            sev_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(
                check.severity, "white"
            )
            diff_color = {"easy": "green", "medium": "yellow", "hard": "red"}.get(
                check.difficulty, "white"
            )
            priv_tag = (f" [dim]← {check.privilege}[/dim]"
                        if check.privilege != "*" else "")
            console.print(
                f"\n  [{sev_color}][{check.severity.upper()}][/{sev_color}] "
                f"[{diff_color}]{check.difficulty}[/{diff_color}]  "
                f"[bold]{check.title}[/bold]{priv_tag}"
            )
            console.print(f"  [dim]{check.description[:130]}[/dim]")

            console.print(f"  [dim]Check :[/dim]")
            for line in check.check_cmd.split("\n")[:3]:
                if line.startswith("#"):
                    console.print(f"  [dim]{line}[/dim]")
                elif line.strip():
                    console.print(f"  [green]{line}[/green]")

            console.print(f"  [dim]Exploit :[/dim]")
            exploit_lines = [l for l in check.exploit_cmd.split("\n")
                             if l.strip() and not l.startswith("#")]
            for line in exploit_lines[:4]:
                console.print(f"  [yellow]{line}[/yellow]")

            for note in check.notes[:1]:
                console.print(f"  [dim]• {note}[/dim]")

        console.print(f"\n[bold yellow]{'='*62}[/bold yellow]")
        console.print(f"[dim]→ --tokens 'SeImpersonatePrivilege  Enabled\n...' pour filtrer[/dim]")
        console.print(f"[dim]→ Télécharger GodPotato : https://github.com/BeichenDream/GodPotato[/dim]\n")

    # ── Cloud Enum ────────────────────────────────────────────────────────────
    if args.cloud:
        cloud = enumerate_cloud(results)

        console.print(f"\n[bold cyan]{'='*62}[/bold cyan]")
        console.print(f"[bold cyan]  CLOUD ENUMERATION[/bold cyan]")
        console.print(f"[bold cyan]{'='*62}[/bold cyan]")

        prov_str = ", ".join(cloud.detected_providers).upper() or "générique"
        console.print(f"  Providers : [yellow]{prov_str}[/yellow]")
        console.print(f"  SSRF context : {'[green]oui — tester metadata services[/green]' if cloud.ssrf_context else '[dim]non détecté[/dim]'}")
        console.print(f"  Checks : [yellow]{len(cloud.checks)}[/yellow]")

        if cloud.bucket_candidates:
            console.print(f"  Candidats buckets : [dim]{', '.join(cloud.bucket_candidates[:6])}...[/dim]")

        prov_colors = {"aws": "yellow", "azure": "blue", "gcp": "red", "generic": "cyan"}
        cat_labels  = {
            "storage": "Stockage (S3 / Blob / GCS)",
            "iam":     "IAM & Credentials",
            "metadata":"Metadata Service (SSRF)",
            "secrets": "Secrets & Tokens",
            "misc":    "Outils multi-cloud",
        }
        current_cat = ""
        for check in cloud.checks:
            if check.category != current_cat:
                current_cat = check.category
                col = prov_colors.get(check.provider, "white")
                console.print(f"\n[bold {col}]── [{check.provider.upper()}] {cat_labels.get(check.category, check.category)}[/bold {col}]")

            sev_col = {"critical": "red", "high": "yellow"}.get(check.severity, "blue")
            console.print(f"\n  [{sev_col}][{check.severity.upper()}][/{sev_col}]  [bold]{check.title}[/bold]")
            console.print(f"  [dim]{check.description[:110]}[/dim]")
            for line in [l for l in check.exploit_cmd.split("\n") if l.strip() and not l.startswith("#")][:4]:
                console.print(f"  [green]{line}[/green]")
            for note in check.notes[:1]:
                console.print(f"  [dim]• {note}[/dim]")

        console.print(f"\n[bold cyan]{'='*62}[/bold cyan]")
        for note in cloud.notes[:6]:
            console.print(f"  [dim]{note}[/dim]")
        console.print("")

    # ── Lateral Movement ─────────────────────────────────────────────────────
    if args.lateral:
        lat = generate_lateral_commands(results)

        console.print(f"\n[bold magenta]{'='*62}[/bold magenta]")
        console.print(f"[bold magenta]  LATERAL MOVEMENT — {lat.domain}[/bold magenta]")
        console.print(f"[bold magenta]{'='*62}[/bold magenta]")
        console.print(f"  DC détecté    : {'[green]oui[/green]' if lat.dc_detected else '[dim]non[/dim]'}")
        console.print(f"  MSSQL détecté : {'[green]oui[/green]' if lat.mssql_detected else '[dim]non[/dim]'}")
        console.print(f"  RDP détecté   : {'[green]oui[/green]' if lat.rdp_detected else '[dim]non[/dim]'}")
        console.print(f"  Techniques    : [yellow]{len(lat.techniques)}[/yellow]")

        cat_labels = {
            "dcom":       ("DCOM",                          "cyan"),
            "wmi":        ("WMI natif",                     "blue"),
            "mssql":      ("MSSQL Linked Servers",          "yellow"),
            "laps":       ("LAPS",                          "green"),
            "delegation": ("Délégation Kerberos",           "red"),
            "coercion":   ("Coercition NTLM",               "bold red"),
            "adcs":       ("AD CS — Certificate Services",  "bold yellow"),
            "shadow":     ("Shadow Credentials",            "magenta"),
            "rdp":        ("RDP Hijacking",                 "blue"),
        }
        current_cat = ""
        for tech in lat.techniques:
            if tech.category != current_cat:
                current_cat = tech.category
                label, col = cat_labels.get(tech.category, (tech.category, "white"))
                console.print(f"\n[bold {col}]── {label}[/bold {col}]")

            sev_col  = {"critical": "red", "high": "yellow"}.get(tech.severity, "blue")
            diff_col = {"easy": "green", "medium": "yellow", "hard": "red"}.get(tech.difficulty, "white")
            console.print(
                f"\n  [{sev_col}][{tech.severity.upper()}][/{sev_col}] "
                f"[{diff_col}]{tech.difficulty}[/{diff_col}]  [bold]{tech.title}[/bold]"
            )
            console.print(f"  [dim]{tech.description[:120]}[/dim]")
            console.print(f"  [dim]Check :[/dim]")
            for line in tech.check_cmd.split("\n")[:3]:
                console.print(f"  [dim]{line}[/dim]" if line.startswith("#") else f"  [green]{line}[/green]")
            console.print(f"  [dim]Exploit :[/dim]")
            for line in [l for l in tech.exploit_cmd.split("\n") if l.strip() and not l.startswith("#")][:4]:
                console.print(f"  [yellow]{line}[/yellow]")
            for note in tech.notes[:1]:
                console.print(f"  [dim]• {note}[/dim]")

        console.print(f"\n[bold magenta]{'='*62}[/bold magenta]")
        for note in lat.notes[:5]:
            console.print(f"  [dim]{note}[/dim]")
        console.print("")

    # ── Web Fingerprinter ─────────────────────────────────────────────────────
    if args.web_fingerprint:

        console.print(f"\n[bold cyan]{'='*62}[/bold cyan]")
        console.print(f"[bold cyan]  WEB FINGERPRINTER — Détection active des applications[/bold cyan]")
        console.print(f"[bold cyan]{'='*62}[/bold cyan]")
        console.print(f"  [dim]Fingerprinting en cours... (requêtes HTTP actives)[/dim]")

        _autofetch_cache: set = set()   # cache session partagé
        _new_cves_session: set = set()   # IDs des CVE nouvelles cette session
        fp_results = fingerprint_all(results)

        if not fp_results:
            console.print("  [dim]Aucun service web accessible.[/dim]")
        else:
            total_apps = sum(len(fp.fingerprints) for fp in fp_results)
            console.print(f"  Services web sondés : [yellow]{len(fp_results)}[/yellow]  "
                          f"Applications détectées : [green]{total_apps}[/green]")

            for fp in fp_results:
                proto_tag = "[cyan]HTTPS[/cyan]" if fp.protocol == "https" else "[blue]HTTP[/blue]"
                console.print(f"\n  {proto_tag} [bold]{fp.host}:{fp.port}[/bold]"
                               + (f"  [dim]({fp.server})[/dim]" if fp.server else "")
                               + (f"  [dim]« {fp.title} »[/dim]" if fp.title else ""))

                if fp.error:
                    console.print(f"  [dim]  Erreur : {fp.error}[/dim]")
                    continue

                if not fp.fingerprints:
                    console.print(f"  [dim]  Aucune application identifiée (service générique)[/dim]")
                    continue

                for fingerprint in fp.fingerprints:
                    conf_col = {"high": "green", "medium": "yellow", "low": "dim"}.get(
                        fingerprint.confidence, "white"
                    )
                    ver_str = f" [dim]{fingerprint.version}[/dim]" if fingerprint.version else ""
                    console.print(
                        f"  [{conf_col}]▶[/{conf_col}] [bold]{fingerprint.app_name}[/bold]{ver_str}"
                        f"  [dim]({fingerprint.confidence} — {fingerprint.detection_method[:60]})[/dim]"
                    )

                    # ── Auto-fetch CVE si absentes de la base ──────────────────
                    _kw = [fingerprint.app_name]
                    if fingerprint.service_key != fingerprint.app_name.lower().replace(' ', '_'):
                        _kw.append(fingerprint.service_key)
                    _fetched = auto_fetch_service(
                        fingerprint.service_key, _kw,
                        min_cvss=5.0, silent=False,
                        session_cache=_autofetch_cache,
                        new_cves_out=_new_cves_session,
                        after_year=getattr(args, 'after_year', None),
                    )

                    # CVE matching sur l'app détectée
                    banner = f"{fingerprint.app_name} {fingerprint.version}".strip()
                    cves = get_cves_for_service(
                        fingerprint.service_key, banner,
                        use_api_fallback=not args.no_api,
                    )

                    if not cves:
                        console.print(f"    [dim]Aucune CVE trouvée dans la base locale.[/dim]")
                        if not fingerprint.version:
                            console.print(f"    [dim]Conseil : version non détectée → résultats moins précis.[/dim]")
                    else:
                        # Trier par CVSS décroissant
                        cves_sorted = sorted(
                            cves,
                            key=lambda c: float(c.get("cvss", 0) or 0),
                            reverse=True,
                        )[:args.top_cves]

                        console.print(
                            f"    [bold red]{len(cves)} CVE(s) trouvée(s)[/bold red]"
                            f" [dim](top {len(cves_sorted)} affichées)[/dim]"
                        )

                        for cve in cves_sorted:
                            cve_id   = cve.get("id", "CVE-????-????")
                            cvss     = cve.get("cvss", 0) or 0
                            sev      = cve.get("severity", "UNKNOWN")
                            desc     = (cve.get("description", "") or "")[:80]
                            kev      = " [bold red]KEV[/bold red]" if cve.get("kev") else ""
                            sev_col  = {"CRITICAL": "red", "HIGH": "yellow",
                                        "MEDIUM": "blue", "LOW": "dim"}.get(sev, "white")

                            console.print(
                                f"    [{sev_col}]{cve_id}[/{sev_col}]  "
                                f"[bold]CVSS {cvss:.1f}[/bold]  {sev}{kev}"
                            )
                            if desc:
                                console.print(f"      [dim]{desc}[/dim]")

        console.print(f"\n[bold cyan]{'='*62}[/bold cyan]")
        console.print(f"[dim]→ --enum-web pour énumérer les répertoires/fichiers[/dim]")
        console.print(f"[dim]→ --web-payloads --lhost IP pour générer les payloads d'exploitation[/dim]\n")

    # ── Wordlist Builder ──────────────────────────────────────────────────────
    if args.wordlist is not None:
        _wl_out = (args.wordlist
                   if args.wordlist not in ("auto", None)
                   else "")
        _wl_result = build_wordlists(
            results,
            output_file=_wl_out,
            custom_words=getattr(args, "custom_words", []) or [],
        )

        console.print(f"\n[bold green]{'='*62}[/bold green]")
        console.print(f"[bold green]  WORDLIST BUILDER[/bold green]")
        console.print(f"[bold green]{'='*62}[/bold green]")

        s = _wl_result.stats
        console.print(f"  Cible   : [cyan]{_wl_result.target}[/cyan]")
        if _wl_result.domain:
            console.print(f"  Domaine : [cyan]{_wl_result.domain}[/cyan]")
        if _wl_result.company:
            console.print(f"  Société : [cyan]{_wl_result.company}[/cyan]")
        console.print(f"\n  [bold]Statistiques[/bold]")
        console.print(f"  Mots de base   : [yellow]{s['base_words']}[/yellow]")
        console.print(f"  Total (mutés)  : [green]{s['total_words']}[/green]")
        console.print(f"  Avec symbole   : {s['words_with_sym']}  |  Avec chiffre : {s['words_with_num']}")
        console.print(f"  Longueur       : min={s['min_len']} / moy={s['avg_len']} / max={s['max_len']}")
        console.print(f"  Mots ≥8 chars  : {s['words_gte8']}")

        # Aperçu
        console.print(f"\n  [bold]Mots de base extraits[/bold]")
        for w in _wl_result.base_words[:20]:
            console.print(f"  [dim]{w}[/dim]")
        if len(_wl_result.base_words) > 20:
            console.print(f"  [dim]  ... {len(_wl_result.base_words)-20} autres[/dim]")

        console.print(f"\n  [bold]Aperçu wordlist finale (25 premiers mots)[/bold]")
        for w in _wl_result.all_words[:25]:
            console.print(f"  [green]{w}[/green]")
        if len(_wl_result.all_words) > 25:
            console.print(f"  [dim]  ... {len(_wl_result.all_words)-25} autres[/dim]")

        if _wl_out:
            console.print(f"\n  [bold green]✓ Wordlist écrite → {_wl_out}[/bold green]  "
                          f"[dim]({s['total_words']} lignes)[/dim]")
        else:
            console.print(f"\n  [dim]→ Ajouter un chemin pour exporter : --wordlist /tmp/cible.txt[/dim]")

        # CeWL
        console.print(f"\n[bold yellow]── CeWL — Spider web pour enrichir la wordlist[/bold yellow]")
        for line in _wl_result.cewl_cmds[:12]:
            if line.startswith("#"):
                console.print(f"  [dim]{line}[/dim]")
            elif line.strip():
                console.print(f"  [green]{line}[/green]")
            else:
                console.print("")

        # Usernames
        console.print(f"\n[bold yellow]── Génération d'usernames[/bold yellow]")
        for line in _wl_result.username_cmds[:12]:
            if line.startswith("#"):
                console.print(f"  [dim]{line}[/dim]")
            elif line.strip():
                console.print(f"  [green]{line}[/green]")
            else:
                console.print("")

        # Règles hashcat
        console.print(f"\n[bold yellow]── Règles hashcat[/bold yellow]")
        for line in _wl_result.hashcat_rules[:8]:
            if line.startswith("#"):
                console.print(f"  [dim]{line}[/dim]")
            elif line.strip():
                console.print(f"  [green]{line}[/green]")
            else:
                console.print("")

        for note in _wl_result.notes:
            console.print(f"\n  [dim]{note}[/dim]")

        console.print(f"[bold green]{'='*62}[/bold green]\n")

    # ── Container Escape ─────────────────────────────────────────────────────
    if args.container is not None:
        quick_mode = (args.container == "quick")
        checks = get_quick_container_checks() if quick_mode else get_container_escape_checklist()

        console.print(f"\n[bold cyan]{'='*62}[/bold cyan]")
        console.print(f"[bold cyan]  CONTAINER ESCAPE{'— Quick' if quick_mode else ''}[/bold cyan]")
        console.print(f"[bold cyan]{'='*62}[/bold cyan]")
        console.print(f"  [dim]{len(checks)} vérifications • Exécuter depuis un shell dans le conteneur[/dim]")

        # Analyse du scan pour services conteneurs exposés
        _lhost_ct = args.lhost or "LHOST"
        ext_checks = analyze_container_host(results, lhost=_lhost_ct)
        if ext_checks:
            console.print(f"\n[bold red]── Services conteneurs exposés ({len(ext_checks)} détecté(s)) ──[/bold red]")
            for ec in ext_checks:
                sev_color = "red" if ec.severity == "critical" else "yellow"
                console.print(f"\n  [{sev_color}][{ec.severity.upper()}][/{sev_color}] [bold]{ec.title}[/bold]")
                console.print(f"  [dim]{ec.description}[/dim]")
                for line in ec.command.split("\n")[:6]:
                    if line.startswith("#"):
                        console.print(f"  [dim]{line}[/dim]")
                    elif line.strip():
                        console.print(f"  [green]{line}[/green]")
                    else:
                        console.print("")
                for note in ec.notes:
                    console.print(f"  [dim]• {note}[/dim]")

        # Checklist interne
        cat_colors = {
            "detect":     "dim",
            "capability": "red",
            "socket":     "bold red",
            "mount":      "yellow",
            "escape":     "magenta",
            "kubernetes": "cyan",
            "cve":        "bold yellow",
        }
        current_cat = ""
        for check in checks:
            if check.category != current_cat:
                current_cat = check.category
                cat_label = {
                    "detect":     "Détection — suis-je dans un conteneur ?",
                    "capability": "Capabilities dangereuses",
                    "socket":     "Docker Socket",
                    "mount":      "Montages sensibles",
                    "kubernetes": "Kubernetes",
                    "cve":        "CVEs connues",
                }.get(check.category, check.category)
                col = cat_colors.get(check.category, "white")
                console.print(f"\n[bold {col}]── {cat_label}[/bold {col}]")

            sev_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(check.severity, "white")
            diff_color = {"easy": "green", "medium": "yellow", "hard": "red"}.get(check.difficulty, "white")
            console.print(
                f"\n  [{sev_color}][{check.severity.upper()}][/{sev_color}] "
                f"[{diff_color}]{check.difficulty}[/{diff_color}]  "
                f"[bold]{check.title}[/bold]"
            )
            console.print(f"  [dim]{check.description[:120]}[/dim]")
            console.print(f"  [dim]Check :[/dim]")
            for line in check.check_cmd.split("\n")[:3]:
                if line.startswith("#"):
                    console.print(f"  [dim]{line}[/dim]")
                elif line.strip():
                    console.print(f"  [green]{line}[/green]")
            console.print(f"  [dim]Exploit :[/dim]")
            exploit_lines = [l for l in check.exploit_cmd.split("\n")
                             if l.strip() and not l.startswith("#")]
            for line in exploit_lines[:3]:
                console.print(f"  [yellow]{line}[/yellow]")
            for note in check.notes[:1]:
                console.print(f"  [dim]• {note}[/dim]")

        console.print(f"\n[bold cyan]{'='*62}[/bold cyan]")
        if not quick_mode:
            console.print(f"[dim]→ --container quick pour les vérifications rapides uniquement[/dim]")
        console.print(f"[dim]→ deepce.sh automatise la détection : "
                      f"curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh | sh[/dim]\n")

    # ── Web Payload Generator ─────────────────────────────────────────────────
    if args.web_payloads is not None:
        from modules.nmap_parser import NmapService as _NmapService
        # Construire la liste des services
        svc_objects = []
        for result in results:
            svc = result.get("service", {})
            svc_objects.append(_NmapService(
                host=svc.get("host", ""), port=svc.get("port", 0),
                protocol=svc.get("protocol", "tcp"), state="open",
                service_name=svc.get("service_name", ""), product=svc.get("product", ""),
                version=svc.get("version", ""), extrainfo=svc.get("extrainfo", ""),
                banner=svc.get("banner", ""),
            ))

        _lhost_wp = args.lhost or "LHOST"
        _lport_wp = getattr(args, "lport", 4444) or 4444
        wp_results = analyze_web_payloads(svc_objects, lhost=_lhost_wp, lport=_lport_wp)

        if not wp_results:
            console.print("\n[dim]Aucun service HTTP/HTTPS détecté. "
                          "Vérifier que le scan couvre les ports web (80, 443, 8080...).[/dim]")
        else:
            for wp in wp_results:
                console.print(f"\n[bold green]{'='*62}[/bold green]")
                console.print(
                    f"[bold green]  WEB PAYLOADS — "
                    f"{wp.protocol.upper()}://{wp.host}:{wp.port}[/bold green]"
                )
                console.print(f"[bold green]{'='*62}[/bold green]")
                if wp.detected_tech:
                    console.print(
                        f"  Stack : [cyan]{', '.join(wp.detected_tech)}[/cyan]  "
                        f"OS : [cyan]{wp.os_hint}[/cyan]"
                    )
                for note in wp.notes:
                    console.print(f"  [dim]{note}[/dim]")

                # ── LFI ───────────────────────────────────────────────────────
                console.print(f"\n[bold yellow]── LFI / Path Traversal ({len(wp.lfi_payloads)} payloads)[/bold yellow]")
                for p in wp.lfi_payloads[:8]:
                    console.print(f"  [green]{p.payload}[/green]")
                    if p.description:
                        console.print(f"  [dim]  → {p.description}[/dim]")
                console.print(f"  [dim]  ({len(wp.lfi_payloads)-8} autres payloads disponibles)[/dim]")

                # ── SSTI ──────────────────────────────────────────────────────
                console.print(f"\n[bold yellow]── SSTI — Moteurs détectés ({len(wp.ssti_engines)})[/bold yellow]")
                for engine in wp.ssti_engines:
                    console.print(f"\n  [cyan][{engine.name}][/cyan]  "
                                  f"[dim]tech: {', '.join(engine.tech)}[/dim]")
                    console.print(f"  [dim]Détection :[/dim] [green]{engine.detect}[/green]")
                    for line in engine.rce_linux.split("\n")[:4]:
                        if line.startswith("#"):
                            console.print(f"  [dim]{line}[/dim]")
                        elif line.strip():
                            console.print(f"  [yellow]{line}[/yellow]")
                    if engine.notes:
                        console.print(f"  [dim]Note : {engine.notes[:100]}[/dim]")

                # ── SQLi ──────────────────────────────────────────────────────
                console.print(f"\n[bold yellow]── SQLi — DBMS ({len(wp.sqli_entries)})[/bold yellow]")
                for sqli in wp.sqli_entries:
                    console.print(f"\n  [cyan][{sqli.dbms}][/cyan]")
                    console.print(f"  [dim]Error-based :[/dim]")
                    for line in sqli.error_based.split("\n")[:2]:
                        if line.strip():
                            console.print(f"  [green]{line.strip()}[/green]")
                    console.print(f"  [dim]Blind time   :[/dim]")
                    for line in sqli.blind_time.split("\n")[:2]:
                        if line.strip() and not line.startswith("#"):
                            console.print(f"  [green]{line.strip()}[/green]")
                    if sqli.rce_cmd:
                        console.print(f"  [dim]RCE (si privs) :[/dim]")
                        for line in sqli.rce_cmd.split("\n")[:2]:
                            if line.strip() and not line.startswith("#"):
                                console.print(f"  [red]{line.strip()}[/red]")

                # ── SSRF ──────────────────────────────────────────────────────
                console.print(f"\n[bold yellow]── SSRF Bypasses ({len(wp.ssrf_payloads)} payloads)[/bold yellow]")
                for p in wp.ssrf_payloads[:6]:
                    console.print(f"  [green]{p.payload}[/green]  [dim]{p.description}[/dim]")

                # ── XXE ───────────────────────────────────────────────────────
                console.print(f"\n[bold yellow]── XXE ({len(wp.xxe_payloads)} templates)[/bold yellow]")
                for p in wp.xxe_payloads[:2]:
                    console.print(f"\n  [cyan]{p.name}[/cyan]")
                    for line in p.payload.split("\n")[:4]:
                        console.print(f"  [green]{line}[/green]")

                # ── sqlmap ────────────────────────────────────────────────────
                console.print(f"\n[bold yellow]── sqlmap[/bold yellow]")
                for line in wp.sqlmap_cmds[:8]:
                    if line.startswith("#"):
                        console.print(f"  [dim]{line}[/dim]")
                    elif line.strip():
                        console.print(f"  [green]{line}[/green]")
                    else:
                        console.print("")

                console.print(f"[bold green]{'='*62}[/bold green]\n")

    # ── Pivot Helper ──────────────────────────────────────────────────────────
    if args.pivot is not None:
        _pivot_lhost = (args.pivot if args.pivot != "auto" else None) or args.lhost or "LHOST"
        _pivot_lport = getattr(args, "lport", 8080) or 8080

        pivot_result = generate_pivot_commands(
            results=results,
            lhost=_pivot_lhost,
            lport=_pivot_lport,
        )

        console.print(f"\n[bold cyan]{'='*62}[/bold cyan]")
        console.print(f"[bold cyan]  PIVOT HELPER — {pivot_result.target}[/bold cyan]")
        console.print(f"[bold cyan]{'='*62}[/bold cyan]")
        console.print(f"  LHOST : [bold]{pivot_result.lhost}[/bold]")
        console.print(f"  SSH   : {'[green]ouvert[/green]' if pivot_result.ssh_available else '[dim]non détecté[/dim]'}")
        if pivot_result.internal_nets:
            console.print(f"  Réseaux internes : [yellow]{', '.join(pivot_result.internal_nets)}[/yellow]")

        # Quick start
        console.print(f"\n[bold]Quick start :[/bold]")
        for line in pivot_result.quick_start.split("\n"):
            if line.startswith("#"):
                console.print(f"  [dim]{line}[/dim]")
            elif line.strip():
                console.print(f"  [green]{line}[/green]")

        # Guides
        for guide in pivot_result.guides:
            tool_colors = {
                "ligolo": "magenta", "chisel": "cyan",
                "ssh": "blue", "socat": "yellow", "sshuttle": "green",
            }
            col = tool_colors.get(guide.tool, "white")
            console.print(f"\n[bold {col}]── {guide.title}[/bold {col}]")
            console.print(f"  [dim]{guide.description}[/dim]")

            if guide.attacker:
                console.print(f"  [dim]Côté attaquant :[/dim]")
                for line in guide.attacker[:6]:
                    if line.startswith("#"):
                        console.print(f"  [dim]{line}[/dim]")
                    elif line.strip():
                        console.print(f"  [green]{line}[/green]")
                    else:
                        console.print("")

            if guide.target:
                console.print(f"  [dim]Côté cible :[/dim]")
                for line in guide.target[:5]:
                    if line.startswith("#"):
                        console.print(f"  [dim]{line}[/dim]")
                    elif line.strip():
                        console.print(f"  [yellow]{line}[/yellow]")
                    else:
                        console.print("")

            for note in guide.notes[:2]:
                console.print(f"  [dim]• {note}[/dim]")

        for note in pivot_result.notes:
            console.print(f"\n  [dim]{note}[/dim]")

        console.print(f"[bold cyan]{'='*62}[/bold cyan]\n")

    # ── Cipher Decoder ────────────────────────────────────────────────────────
    if args.cipher:
        cipher_result = analyze_cipher(args.cipher)
        console.print(f"\n[bold magenta]● Cipher Decoder[/bold magenta]")
        console.print(f"  Input : [dim]{args.cipher[:80]}{'...' if len(args.cipher)>80 else ''}[/dim]")
        console.print(f"  {cipher_result.summary}")

        if cipher_result.best_guess:
            bg = cipher_result.best_guess
            conf_color = {"high": "green", "medium": "yellow", "low": "red"}.get(
                bg.confidence, "white"
            )
            console.print(
                f"\n  [bold]Meilleure hypothèse :[/bold] [{conf_color}]{bg.cipher_type}[/{conf_color}] "
                f"(confiance : {bg.confidence})"
            )
            if bg.decoded and bg.decoded != "[non décodable directement — voir commande]":
                preview = bg.decoded[:200].replace("\n", " ↵ ")
                console.print(f"  [green]Décodé : {preview}[/green]")
            console.print(f"\n  [dim]Commande :[/dim]")
            for line in bg.decode_cmd.split("\n")[:5]:
                if line.startswith("#"):
                    console.print(f"  [dim]{line}[/dim]")
                elif line.strip():
                    console.print(f"  [green]{line}[/green]")
            if bg.notes:
                console.print(f"\n  [dim]{bg.notes[:200]}[/dim]")
            if bg.cyberchef_url:
                console.print(f"\n  [dim]CyberChef : {bg.cyberchef_url}[/dim]")

        if len(cipher_result.detections) > 1:
            other = [d for d in cipher_result.detections if d != cipher_result.best_guess]
            console.print(f"\n  [dim]Autres détections : {', '.join(d.cipher_type for d in other)}[/dim]")

    # ── Brute Force Helper ────────────────────────────────────────────────────
    if args.brute:
        brute_results = generate_brute_commands(results, target=target)
        if not brute_results:
            console.print("\n[dim]Aucun service bruteforçable détecté "
                          "(SSH, FTP, HTTP, SMB, RDP, MySQL, etc.).[/dim]")
        else:
            console.print(f"\n[bold red]● Brute Force Helper[/bold red]")
            for br in brute_results:
                console.print(f"\n  [cyan]Host : {br.host}[/cyan]  "
                               f"({len(br.commands)} commande(s))")
                for cmd in br.commands:
                    tool_colors = {
                        "hydra": "green", "medusa": "cyan",
                        "crackmapexec": "yellow", "ncrack": "blue",
                    }
                    col = tool_colors.get(cmd.tool, "white")
                    console.print(f"\n  [{col}][{cmd.tool.upper()}][/{col}] {cmd.title}")
                    console.print(f"  [green]{cmd.command.split(chr(10))[0]}[/green]")
                    # Afficher la commande complète si multi-ligne
                    lines = cmd.command.split("\n")
                    for line in lines[1:]:
                        if line.strip() and not line.startswith("#"):
                            console.print(f"  [green]{line}[/green]")
                        elif line.startswith("#"):
                            console.print(f"  [dim]{line}[/dim]")
                    for note in cmd.notes[:2]:
                        console.print(f"  [dim]• {note}[/dim]")

                for note in br.notes[:2]:
                    console.print(f"\n  [dim]{note}[/dim]")

    # ── SMB Helper ────────────────────────────────────────────────────────────
    if args.smb:
        smb_result = generate_smb_commands(results)
        if smb_result is None:
            console.print("\n[dim]Aucun service SMB détecté (ports 445/139).[/dim]")
        else:
            ctx = smb_result.context
            console.print(f"\n[bold blue]{'='*62}[/bold blue]")
            console.print(f"[bold blue]  SMB HELPER — {ctx.host}:{ctx.port}[/bold blue]")
            console.print(f"[bold blue]{'='*62}[/bold blue]")
            console.print(f"  Domaine  : [cyan]{ctx.domain}[/cyan]")
            console.print(f"  Signing  : {'[red]DÉSACTIVÉ — relay possible[/red]' if not ctx.signing else '[green]activé[/green]'}")
            if ctx.dc:
                console.print(f"  Rôle     : [yellow]Contrôleur de domaine (Kerberos/LDAP détectés)[/yellow]")
            for note in smb_result.notes:
                if "⚠" in note:
                    console.print(f"  [bold red]{note}[/bold red]")
                else:
                    console.print(f"  [dim]{note}[/dim]")

            cat_sections = [
                ("Null session", smb_result.null_session,    "blue"),
                ("Énumération auth", smb_result.enumeration, "cyan"),
                ("Impacket",    smb_result.impacket,         "yellow"),
                ("Relay NTLM",  smb_result.relay,            "red"),
                ("Pass-the-Hash", smb_result.pass_the_hash,  "magenta"),
                ("Kerberos",    smb_result.kerberos,         "green"),
            ]

            for section_title, cmds, col in cat_sections:
                if not cmds:
                    continue
                console.print(f"\n[bold {col}]── {section_title} ({len(cmds)} commande(s))[/bold {col}]")
                for cmd in cmds:
                    auth_tag = " [dim][auth requis][/dim]" if cmd.requires_auth else ""
                    console.print(f"\n  [bold]{cmd.title}[/bold]{auth_tag}")
                    console.print(f"  [dim]{cmd.description[:100]}[/dim]")
                    for line in cmd.command.split("\n")[:6]:
                        if line.startswith("#"):
                            console.print(f"  [dim]{line}[/dim]")
                        elif line.strip():
                            console.print(f"  [green]{line}[/green]")
                        else:
                            console.print("")
                    for note in cmd.notes[:2]:
                        console.print(f"  [dim]• {note}[/dim]")

            console.print(f"[bold blue]{'='*62}[/bold blue]\n")

    # ── Subdomain Enumeration ─────────────────────────────────────────────────
    if args.subdomain:
        do_passive = not args.sub_active    # passif par défaut sauf --sub-active
        do_active  = not args.sub_passive   # actif par défaut sauf --sub-passive
        wordlist_src = args.sub_wordlist or None

        # ── Résolution du domaine cible ──────────────────────────────────────
        if args.subdomain == "auto":
            # Extraire les noms d'hôtes depuis les résultats du scan
            # NmapService.host contient "hostname or host_ip" (voir nmap_parser.py)
            import re
            _ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
            _seen_domains: dict[str, int] = {}
            for svc in results:
                h = svc.host.lower().strip()
                if _ip_re.match(h):
                    continue  # IP pure, on ignore
                # Extraire le domaine de base : les deux derniers labels (foo.bar.htb → bar.htb)
                parts = h.split(".")
                base = ".".join(parts[-2:]) if len(parts) >= 2 else h
                _seen_domains[base] = _seen_domains.get(base, 0) + 1

            if not _seen_domains:
                console.print(
                    "\n  [yellow]⚠  Mode auto : aucun nom d'hôte trouvé dans le scan.[/yellow]\n"
                    "  [dim]Spécifie le domaine explicitement : --subdomain target.htb[/dim]\n"
                )
            elif len(_seen_domains) == 1:
                domain = next(iter(_seen_domains))
                console.print(f"\n  [dim]Auto-détection : domaine trouvé → [bold]{domain}[/bold][/dim]")
            else:
                # Plusieurs domaines : prendre le plus fréquent
                domain = max(_seen_domains, key=_seen_domains.get)
                others = [d for d in _seen_domains if d != domain]
                console.print(
                    f"\n  [dim]Auto-détection : {len(_seen_domains)} domaines trouvés, "
                    f"utilisation de [bold]{domain}[/bold] "
                    f"(ignorés : {', '.join(others)})[/dim]\n"
                    f"  [dim]Pour un autre domaine : --subdomain <DOMAIN>[/dim]"
                )
        else:
            domain = args.subdomain.strip().lower()

        # Sortir proprement si aucun domaine résolu en mode auto
        if args.subdomain == "auto" and not _seen_domains:
            pass  # Message déjà affiché ci-dessus
        else:
            console.print(f"\n[bold cyan]{'='*62}[/bold cyan]")
            console.print(f"[bold cyan]  SUBDOMAIN ENUMERATION — {domain}[/bold cyan]")
            console.print(f"[bold cyan]{'='*62}[/bold cyan]")

            modes = []
            if do_passive:
                modes.append("[cyan]passif[/cyan] (crt.sh · HackerTarget · RapidDNS)")
            if do_active:
                modes.append("[yellow]actif[/yellow] (bruteforce DNS)")
            console.print(f"  Modes : {' + '.join(modes)}")
            if do_active and wordlist_src:
                console.print(f"  Wordlist : [dim]{wordlist_src}[/dim]")
            elif do_active:
                console.print(f"  Wordlist : [dim]embarquée (~250 mots)[/dim]")
            console.print()

            sub_result = enumerate_subdomains(
                domain        = domain,
                passive       = do_passive,
                active        = do_active,
                wordlist_path = wordlist_src,
                threads       = args.sub_threads,
                verbose       = args.verbose,
            )

            display_subdomain_results(sub_result, show_commands=True, max_cmds=3)

            if args.export_html and sub_result.subdomains:
                console.print(
                    f"\n  [dim]→ Section HTML prête "
                    f"({len(sub_result.subdomains)} sous-domaines)[/dim]"
                )

            console.print(f"[bold cyan]{'='*62}[/bold cyan]\n")

if __name__ == "__main__":
    main()
