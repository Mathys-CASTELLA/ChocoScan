#!/usr/bin/env python3
"""
ChocoScan - Mise à jour automatique de la base CVE locale.
Interroge l'API NVD pour enrichir cve_db.json et cve_recent.json.

Usage:
    python update_db.py                        # Met à jour tous les services
    python update_db.py --service openssh      # Met à jour un service spécifique
    python update_db.py --min-cvss 7.0         # Seulement les CVEs High/Critical
    python update_db.py --recent-only          # Met à jour seulement cve_recent.json (CVE < 2 ans)
    python update_db.py --dry-run              # Affiche ce qui serait ajouté sans modifier
"""

import json
import time
import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

try:
    import requests
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich import box
    from rich.rule import Rule
except ImportError:
    print("[!] Dépendances manquantes. Installez-les : pip install requests rich")
    sys.exit(1)

console = Console()

DATA_DIR       = Path(__file__).parent / "data"
CVE_DB_PATH    = DATA_DIR / "cve_db.json"
RECENT_DB_PATH = DATA_DIR / "cve_recent.json"

NVD_BASE_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RECENT_CUTOFF_YEARS = 2  # CVE des 2 dernières années dans cve_recent.json

# Mapping service -> termes de recherche NVD
SERVICE_SEARCH_TERMS = {
    "openssh":       ["OpenSSH"],
    "apache":        ["Apache HTTP Server"],
    "nginx":         ["nginx"],
    "mysql":         ["MySQL"],
    "postgresql":    ["PostgreSQL"],
    "php":           ["PHP"],
    "tomcat":        ["Apache Tomcat"],
    "spring":        ["Spring Framework", "Spring Boot"],
    "jenkins":       ["Jenkins"],
    "redis":         ["Redis"],
    "mongodb":       ["MongoDB"],
    "elasticsearch": ["Elasticsearch"],
    "wordpress":     ["WordPress"],
    "drupal":        ["Drupal"],
    "joomla":        ["Joomla"],
    "gitlab":        ["GitLab"],
    "confluence":    ["Confluence"],
    "jira":          ["Jira"],
    "log4j":         ["Log4j", "log4shell"],
    "struts":        ["Apache Struts"],
    "smb":           ["SMB", "Server Message Block"],
    "rdp":           ["Remote Desktop"],
    "samba":         ["Samba"],
    "fortinet":      ["FortiOS", "FortiGate", "Fortinet"],
    "paloalto":      ["PAN-OS", "Palo Alto"],
    "citrix":        ["Citrix NetScaler", "Citrix ADC"],
    "ivanti":        ["Ivanti Connect Secure", "Pulse Secure"],
    "vmware":        ["VMware vCenter", "VMware ESXi"],
    "exchange":      ["Microsoft Exchange Server"],
    "iis":           ["Microsoft IIS", "Internet Information Services"],
    "activemq":      ["Apache ActiveMQ"],
    "weblogic":      ["Oracle WebLogic"],
    "teamcity":      ["JetBrains TeamCity"],
    "grafana":       ["Grafana"],
    "kubernetes":    ["Kubernetes"],
    "docker":        ["Docker Engine"],
    "apache":        ["Apache httpd"],
    "ssl":           ["OpenSSL"],
    "winrm":         ["WinRM", "Windows Remote Management"],
    "phpmyadmin":    ["phpMyAdmin"],
    "webmin":        ["Webmin"],
    "splunk":        ["Splunk"],
    "sonarqube":     ["SonarQube"],
    "moodle":        ["Moodle"],
    "nagios":        ["Nagios"],
    "zabbix":        ["Zabbix"],
    "cacti":         ["Cacti"],
    "roundcube":     ["Roundcube"],
}


def load_db(path: Path) -> dict:
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            console.print(f"[yellow][!] Impossible de charger {path.name} : {e}[/yellow]")
    return {}


def save_db(path: Path, db: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)


def is_recent(cve_id: str) -> bool:
    """Retourne True si la CVE date de moins de RECENT_CUTOFF_YEARS ans."""
    import re
    match = re.match(r"CVE-(\d{4})-", cve_id.upper())
    if not match:
        return False
    year = int(match.group(1))
    return year >= datetime.now().year - RECENT_CUTOFF_YEARS


def fetch_nvd(keyword: str, min_cvss: float = 0.0, max_results: int = 20) -> list:
    """
    Interroge l'API NVD et retourne une liste de CVEs formatées.
    Inclut un sleep pour respecter le rate limit (5 req/s sans clé API).
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    # Filtre sévérité NVD si CVSS demandé
    if min_cvss >= 9.0:
        params["cvssV3Severity"] = "CRITICAL"
    elif min_cvss >= 7.0:
        params["cvssV3Severity"] = "HIGH"
    elif min_cvss >= 4.0:
        params["cvssV3Severity"] = "MEDIUM"

    try:
        resp = requests.get(NVD_BASE_URL, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        console.print(f"  [yellow]⚠ Timeout pour '{keyword}'[/yellow]")
        return []
    except Exception as e:
        console.print(f"  [yellow]⚠ Erreur NVD pour '{keyword}' : {e}[/yellow]")
        return []
    finally:
        time.sleep(0.7)  # Rate limit NVD

    results = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id", "")

        if not cve_id:
            continue

        # Description anglais
        descriptions = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
        if not desc:
            continue

        # Score CVSS (v3.1 > v3.0 > v2)
        score    = None
        severity = "UNKNOWN"
        metrics  = cve_data.get("metrics", {})

        for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
            if metric_key in metrics and metrics[metric_key]:
                cvss_data = metrics[metric_key][0].get("cvssData", {})
                score     = cvss_data.get("baseScore")
                severity  = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                break

        if score is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            score     = cvss_data.get("baseScore")
            severity  = "UNKNOWN"  # CVSSv2 n'a pas de severity label standardisé

        if score is None:
            continue

        # Filtre CVSS minimum
        try:
            if float(score) < min_cvss:
                continue
        except (ValueError, TypeError):
            continue

        # Références
        refs = [r["url"] for r in cve_data.get("references", [])[:3] if "url" in r]
        if not refs:
            refs = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]

        results.append({
            "id":          cve_id,
            "description": desc[:300] + ("..." if len(desc) > 300 else ""),
            "cvss":        float(score),
            "severity":    severity,
            "affected_versions": [],  # NVD ne fournit pas de format simple, à compléter manuellement
            "references":  refs,
        })

    return results


def update_service(service_key: str, keywords: list, main_db: dict, recent_db: dict,
                   min_cvss: float, dry_run: bool) -> tuple[int, int]:
    """
    Met à jour un service dans les deux DBs.
    Retourne (nb_ajoutés_main, nb_ajoutés_recent).
    """
    existing_main   = {c["id"] for c in main_db.get(service_key, [])}
    existing_recent = {c["id"] for c in recent_db.get(service_key, [])}
    added_main   = 0
    added_recent = 0

    for keyword in keywords:
        cves = fetch_nvd(keyword, min_cvss=min_cvss)

        for cve in cves:
            cve_id = cve["id"]

            # Ajout dans la DB principale
            if cve_id not in existing_main:
                if not dry_run:
                    if service_key not in main_db:
                        main_db[service_key] = []
                    main_db[service_key].append(cve)
                existing_main.add(cve_id)
                added_main += 1

            # Ajout dans la DB récente si la CVE est récente
            if is_recent(cve_id) and cve_id not in existing_recent:
                if not dry_run:
                    if service_key not in recent_db:
                        recent_db[service_key] = []
                    recent_db[service_key].append(cve)
                existing_recent.add(cve_id)
                added_recent += 1

    return added_main, added_recent


def main():
    parser = argparse.ArgumentParser(
        description="ChocoScan — Mise à jour de la base CVE via l'API NVD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python update_db.py                          # Met à jour tous les services
  python update_db.py --service openssh nginx  # Services spécifiques
  python update_db.py --min-cvss 7.0           # CVEs HIGH et CRITICAL seulement
  python update_db.py --recent-only            # Seulement cve_recent.json
  python update_db.py --dry-run                # Simulation sans modification
        """
    )
    parser.add_argument("--service", nargs="+", metavar="SERVICE",
                        help=f"Services à mettre à jour (parmi : {', '.join(sorted(SERVICE_SEARCH_TERMS.keys()))})")
    parser.add_argument("--min-cvss", type=float, default=5.0,
                        help="Score CVSS minimum à importer (défaut: 5.0)")
    parser.add_argument("--recent-only", action="store_true",
                        help="Met à jour seulement cve_recent.json (CVEs < 2 ans)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simule la mise à jour sans modifier les fichiers")

    args = parser.parse_args()

    console.print(f"\n[bold cyan]ChocoScan — Mise à jour CVE[/bold cyan]")
    console.print(Rule(style="blue"))

    if args.dry_run:
        console.print("[bold yellow]Mode DRY-RUN activé : aucune modification ne sera effectuée.[/bold yellow]")

    # Sélection des services à mettre à jour
    if args.service:
        unknown = [s for s in args.service if s not in SERVICE_SEARCH_TERMS]
        if unknown:
            console.print(f"[red][!] Services inconnus : {', '.join(unknown)}[/red]")
            console.print(f"[dim]Services disponibles : {', '.join(sorted(SERVICE_SEARCH_TERMS.keys()))}[/dim]")
            sys.exit(1)
        services_to_update = {s: SERVICE_SEARCH_TERMS[s] for s in args.service}
    else:
        services_to_update = SERVICE_SEARCH_TERMS

    console.print(f"[*] Services à mettre à jour : [bold]{len(services_to_update)}[/bold]")
    console.print(f"[*] Score CVSS minimum : [bold]{args.min_cvss}[/bold]")
    console.print(f"[*] Cutoff CVE récentes : [bold]{RECENT_CUTOFF_YEARS} ans[/bold]\n")

    # Chargement des DBs
    main_db   = {} if args.recent_only else load_db(CVE_DB_PATH)
    recent_db = load_db(RECENT_DB_PATH)

    total_main   = 0
    total_recent = 0
    stats_table  = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Mise à jour...", total=len(services_to_update))

        for service_key, keywords in services_to_update.items():
            progress.update(task, description=f"[cyan]{service_key}[/cyan]")

            added_m, added_r = update_service(
                service_key, keywords, main_db, recent_db,
                args.min_cvss, args.dry_run
            )

            total_main   += added_m
            total_recent += added_r
            if added_m > 0 or added_r > 0:
                stats_table.append((service_key, added_m, added_r))

            progress.advance(task)

    # Sauvegarde
    if not args.dry_run:
        if not args.recent_only:
            save_db(CVE_DB_PATH, main_db)
        save_db(RECENT_DB_PATH, recent_db)

    # Résumé
    console.print(Rule(style="dim"))
    console.print(f"\n[bold green]✓ Mise à jour terminée[/bold green]")

    if stats_table:
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        table.add_column("Service")
        table.add_column("+ cve_db", justify="right")
        table.add_column("+ cve_recent", justify="right")
        for row in stats_table:
            table.add_row(row[0], str(row[1]), str(row[2]))
        console.print(table)

    console.print(f"\n  CVEs ajoutées dans cve_db.json     : [bold green]{total_main}[/bold green]")
    console.print(f"  CVEs ajoutées dans cve_recent.json : [bold green]{total_recent}[/bold green]")

    if args.dry_run:
        console.print("\n[yellow]DRY-RUN : aucun fichier modifié.[/yellow]")

    # Stats globales
    if not args.dry_run:
        total_db     = sum(len(v) for v in main_db.values())
        total_recent = sum(len(v) for v in recent_db.values())
        console.print(f"\n  Total cve_db.json     : [bold]{total_db}[/bold] CVEs / {len(main_db)} services")
        console.print(f"  Total cve_recent.json : [bold]{total_recent}[/bold] CVEs / {len(recent_db)} services")

    console.print()


if __name__ == "__main__":
    main()
