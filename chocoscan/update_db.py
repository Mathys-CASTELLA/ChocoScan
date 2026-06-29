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

    # ── Privilege Escalation Linux (très fréquents HTB) ──────────────────────
    "sudo":          ["sudo", "sudoedit"],
    "polkit":        ["polkit", "PolicyKit", "pkexec"],
    "linux_kernel":  ["Linux Kernel"],
    "bash":          ["GNU Bash"],                   # ShellShock
    "screen":        ["GNU Screen"],
    "pkexec":        ["polkit", "pkexec"],            # PwnKit

    # ── FTP (omniprésents sur HTB) ────────────────────────────────────────────
    "vsftpd":        ["vsftpd"],                     # CVE-2011-2523 backdoor
    "proftpd":       ["ProFTPD"],
    "pure_ftpd":     ["Pure-FTPd", "PureFTPd"],
    "filezilla":     ["FileZilla Server"],

    # ── Mail ──────────────────────────────────────────────────────────────────
    "exim":          ["Exim"],
    "postfix":       ["Postfix"],
    "dovecot":       ["Dovecot"],
    "sendmail":      ["Sendmail"],
    "zimbra":        ["Zimbra"],

    # ── OpenSSL / TLS (Heartbleed, etc.) ─────────────────────────────────────
    "openssl":       ["OpenSSL"],
    "libssl":        ["OpenSSL"],

    # ── Web apps manquantes ───────────────────────────────────────────────────
    "craft_cms":     ["craftcms", "Craft CMS", "craft cms"],
    "nextcloud":     ["Nextcloud"],
    "laravel":       ["Laravel"],
    "django":        ["Django"],
    "flask":         ["Werkzeug", "Flask"],
    "rails":         ["Ruby on Rails"],
    "symfony":       ["Symfony"],
    "opencart":      ["OpenCart"],
    "prestashop":    ["PrestaShop"],
    "typo3":         ["TYPO3"],
    "concrete5":     ["Concrete CMS", "concrete5"],
    "ghost":         ["Ghost CMS"],
    "pimcore":       ["Pimcore"],
    "liferay":       ["Liferay"],
    "coldfusion":    ["Adobe ColdFusion"],
    "sharepoint":    ["Microsoft SharePoint"],
    "xwiki":         ["XWiki"],
    "bookstack":     ["BookStack"],
    "openemr":       ["OpenEMR"],

    # ── Frameworks / runtimes ─────────────────────────────────────────────────
    "nodejs":        ["Node.js"],
    "java":          ["Java SE", "OpenJDK"],          # désérialisations
    "python":        ["CPython"],
    "ruby":          ["Ruby"],
    "imagemagick":   ["ImageMagick"],                # ImageTragick
    "ghostscript":   ["Ghostscript"],
    "ffmpeg":        ["FFmpeg"],
    "libpng":        ["libpng"],
    "libjpeg":       ["libjpeg"],
    "poppler":       ["Poppler"],                    # pdf rendering

    # ── Réseau / services système ─────────────────────────────────────────────
    "cups":          ["CUPS"],                       # print service, souvent oublié
    "nfs":           ["NFS", "rpcbind"],
    "rsync":         ["rsync"],
    "bind":          ["ISC BIND"],                   # DNS
    "dnsmasq":       ["dnsmasq"],
    "ldap":          ["OpenLDAP"],
    "kerberos":      ["MIT Kerberos"],
    "snmp":          ["Net-SNMP"],
    "vnc":           ["TigerVNC", "TightVNC", "RealVNC", "LibVNCServer"],
    "telnet":        ["telnet"],
    "lighttpd":      ["lighttpd"],
    "squid":         ["Squid"],
    "haproxy":       ["HAProxy"],

    # ── Virtualisation / containers ───────────────────────────────────────────
    "xen":           ["Xen"],
    "qemu":          ["QEMU"],
    "lxc":           ["LXC"],
    "containerd":    ["containerd"],
    "runc":          ["runc"],

    # ── Databases ─────────────────────────────────────────────────────────────
    "mssql":         ["Microsoft SQL Server"],
    "oracle_db":     ["Oracle Database"],
    "sqlite":        ["SQLite"],
    "memcached":     ["Memcached"],
    "cassandra":     ["Apache Cassandra"],
    "couchdb":       ["Apache CouchDB"],

    # ── Outils DevOps ─────────────────────────────────────────────────────────
    "ansible":       ["Ansible"],
    "terraform":     ["Terraform"],
    "git":           ["Git"],
    "gitea":         ["Gitea"],
    "harbor":        ["Harbor"],
    "artifactory":   ["JFrog Artifactory"],
    "nexus":         ["Sonatype Nexus"],

    # ── Équipements réseau ────────────────────────────────────────────────────
    "cisco_ios":     ["Cisco IOS"],
    "cisco_asa":     ["Cisco ASA"],
    "f5_bigip":      ["F5 BIG-IP"],
    "barracuda":     ["Barracuda"],
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


def fetch_nvd(keyword: str, min_cvss: float = 0.0,
              max_results: int = 2000, after_year: int | None = None) -> list:
    """
    Interroge l'API NVD avec pagination complète.
    Récupère TOUTES les CVEs (pas seulement les 20 premières).
    max_results : limite par page (max NVD = 2000).
    """
    results   = []
    start_idx = 0
    fetched   = 0

    while True:
        params = {
            "keywordSearch":  keyword,
            "resultsPerPage": min(max_results, 2000),
            "startIndex":     start_idx,
        }
        # Filtre date : ne récupérer que les CVE publiées après after_year
        if after_year:
            params["pubStartDate"] = f"{after_year}-01-01T00:00:00.000"
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
            break
        except Exception as e:
            console.print(f"  [yellow]⚠ Erreur NVD pour '{keyword}' : {e}[/yellow]")
            break
        finally:
            time.sleep(0.7)  # Rate limit NVD

        total_results = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
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
                severity  = "UNKNOWN"

            if score is None:
                continue

            try:
                if float(score) < min_cvss:
                    continue
            except (ValueError, TypeError):
                continue

            refs = [r["url"] for r in cve_data.get("references", [])[:3] if "url" in r]
            if not refs:
                refs = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]

            results.append({
                "id":                cve_id,
                "description":       desc[:300] + ("..." if len(desc) > 300 else ""),
                "cvss":              float(score),
                "severity":          severity,
                "affected_versions": [],
                "references":        refs,
            })

        fetched   += len(vulnerabilities)
        start_idx += len(vulnerabilities)

        if fetched >= total_results or not vulnerabilities:
            break

    return results

def update_service(service_key: str, keywords: list, main_db: dict, recent_db: dict,
                   min_cvss: float, dry_run: bool,
                   after_year: int | None = None) -> tuple[int, int]:
    """
    Met à jour un service dans les deux DBs.
    Retourne (nb_ajoutés_main, nb_ajoutés_recent).
    """
    existing_main   = {c["id"] for c in main_db.get(service_key, [])}
    existing_recent = {c["id"] for c in recent_db.get(service_key, [])}
    added_main   = 0
    added_recent = 0

    for keyword in keywords:
        cves = fetch_nvd(keyword, min_cvss=min_cvss, after_year=after_year)

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



def auto_fetch_if_missing(service_key: str, keywords: list[str],
                           min_cvss: float = 5.0,
                           silent: bool = False) -> int:
    """Alias de auto_fetch_service pour compatibilité ascendante."""
    return auto_fetch_service(service_key, keywords,
                              min_cvss=min_cvss, silent=silent)


def auto_fetch_service(service_key: str, keywords: list[str],
                       min_cvss: float = 5.0,
                       silent: bool = False,
                       session_cache: set | None = None,
                       new_cves_out: set | None = None,
                       after_year: int | None = None) -> int:
    """
    Télécharge les CVE NVD pour un service et enrichit la base locale.
    Ajoute TOUJOURS les nouvelles CVE, même si la base n'est pas vide
    (contrairement à auto_fetch_if_missing qui skippait si déjà présent).

    Un cache de session (session_cache) évite de requêter NVD deux fois
    pour le même service dans un même scan.

    Args:
        service_key    : clé de service (ex: "craft_cms", "openssh")
        keywords       : mots-clés NVD (ex: ["Craft CMS", "craftcms"])
        min_cvss       : score CVSS minimum à importer
        silent         : si True, aucun affichage console
        session_cache  : set partagé entre appels pour dédupliquer dans
                         la même session (modifié en place)

    Returns:
        Nombre de nouvelles CVE ajoutées dans cve_db.json
    """
    # Cache de session : ne pas requêter NVD deux fois pour le même service
    if session_cache is not None:
        if service_key in session_cache:
            return 0
        session_cache.add(service_key)

    main_db   = load_db(CVE_DB_PATH)
    recent_db = load_db(RECENT_DB_PATH)

    already = len(main_db.get(service_key, []))

    if not silent:
        status = f"({already} CVE existantes)" if already else "(absent de la base)"
        console.print(
            f"  [dim]Auto-fetch [bold]{keywords[0]}[/bold] {status}...[/dim]"
        )

    # Capturer les IDs existants AVANT le fetch pour savoir ce qui est nouveau
    _ids_before = {c["id"] for c in main_db.get(service_key, [])}

    added_main, added_recent = update_service(
        service_key, keywords, main_db, recent_db,
        min_cvss=min_cvss, dry_run=False, after_year=after_year,
    )

    # Alimenter new_cves_out avec les IDs réellement nouveaux
    if new_cves_out is not None and added_main > 0:
        _ids_after = {c["id"] for c in main_db.get(service_key, [])}
        new_cves_out.update(_ids_after - _ids_before)

    if added_main > 0 or added_recent > 0:
        save_db(CVE_DB_PATH,    main_db)
        save_db(RECENT_DB_PATH, recent_db)
        if not silent:
            console.print(
                f"  [green]✓ +{added_main} CVE pour "
                f"[bold]{keywords[0]}[/bold] "
                f"(total : {already + added_main})[/green]"
            )
    elif not silent and already > 0:
        console.print(
            f"  [dim]✓ {keywords[0]} déjà à jour ({already} CVE)[/dim]"
        )

    return added_main


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
                        help="Clés de service à mettre à jour. "
                             "Accepte n'importe quel nom : s'il n'est pas dans "
                             "SERVICE_SEARCH_TERMS, le nom est utilisé directement comme "
                             "mot-clé NVD. Ex: --service sudo craft_cms")
    parser.add_argument("--keyword", nargs="+", metavar="TEXT",
                        help="Recherche textuelle libre sur NVD (indépendant de SERVICE_SEARCH_TERMS). "
                             "Ex: --keyword 'Craft CMS' 'sudo Baron Samedit'")
    parser.add_argument("--from-scan", metavar="XML_FILE_OR_IP",
                        help="Lit un fichier XML Nmap OU scanne directement une IP/hostname "
                             "et télécharge les CVE pour chaque service détecté. "
                             "Ex: --from-scan 10.129.33.138        (scan automatique) "
                             "    --from-scan output/scan.xml      (fichier existant)")
    parser.add_argument("--min-cvss", type=float, default=5.0,
                        help="Score CVSS minimum à importer (défaut: 5.0)")
    parser.add_argument("--max-results", type=int, default=2000, metavar="N",
                        help="Nombre max de CVE à récupérer par service (défaut: 2000, max NVD: 2000)")
    parser.add_argument("--recent-only", action="store_true",
                        help="Met à jour seulement cve_recent.json (CVEs < 2 ans)")
    parser.add_argument("--after-year", type=int, default=None, metavar="YEAR",
                        help="Ne télécharger que les CVE publiées depuis cette année. "
                             "Ex: --after-year 2024 (gain de temps et d'espace).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simule la mise à jour sans modifier les fichiers")

    args = parser.parse_args()

    console.print(f"\n[bold cyan]ChocoScan — Mise à jour CVE[/bold cyan]")
    console.print(Rule(style="blue"))

    if args.dry_run:
        console.print("[bold yellow]Mode DRY-RUN activé : aucune modification ne sera effectuée.[/bold yellow]")

    # ── --from-scan : IP/hostname → scan auto, ou fichier XML existant ──────────
    if args.from_scan:
        import xml.etree.ElementTree as _ET
        import subprocess as _sub
        import shutil as _shutil

        _from_scan_path = args.from_scan

        # ── Détection IP/hostname vs fichier ──────────────────────────────────
        _IP_RE   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        _HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\.\-]*[A-Za-z0-9]$")
        _is_target = (
            not _from_scan_path.endswith((".xml", ".json", ".nessus"))
            and "/" not in _from_scan_path
            and "\\" not in _from_scan_path
            and (_IP_RE.match(_from_scan_path) or _HOST_RE.match(_from_scan_path))
        )

        if _is_target:
            _target  = _from_scan_path
            _xml_out = f"/tmp/chocoscan_autoscan_{_target.replace('.', '_')}.xml"
            _nmap    = _shutil.which("nmap")

            if not _nmap:
                console.print("[red][!] nmap introuvable.[/red]")
                sys.exit(1)

            _cmd = [_nmap, "-sV", "-sC", "--open", "-T4", "-oX", _xml_out, _target]
            console.print(f"\n[bold cyan][*] Cible : {_target}[/bold cyan]")
            console.print(f"[*] Scan : [dim]{' '.join(_cmd)}[/dim]")

            try:
                _proc = _sub.run(_cmd, capture_output=True, text=True, timeout=300)
                if _proc.returncode != 0:
                    console.print(f"[red][!] nmap erreur (code {_proc.returncode})[/red]")
                    sys.exit(1)
                console.print(f"[green][+] Scan OK → {_xml_out}[/green]")
                _from_scan_path = _xml_out
            except _sub.TimeoutExpired:
                console.print("[red][!] Timeout (5min) — relancer manuellement.[/red]")
                sys.exit(1)
            except Exception as _se:
                console.print(f"[red][!] {_se}[/red]")
                sys.exit(1)

        try:
            _tree = _ET.parse(_from_scan_path)
            _root = _tree.getroot()
            _scan_services: dict[str, list[str]] = {}
            for _port in _root.findall(".//port"):
                _svc = _port.find("service")
                if _svc is None:
                    continue
                _name    = _svc.attrib.get("name", "")
                _product = _svc.attrib.get("product", "")
                _version = _svc.attrib.get("version", "")
                for _term in filter(None, [_product, _name]):
                    _key = re.sub(r"[^a-z0-9_]", "_", _term.lower().strip())
                    if _key and _key not in _scan_services:
                        _scan_services[_key] = [_term]
            console.print(f"  [cyan]from-scan[/cyan] : {len(_scan_services)} services détectés dans {_from_scan_path}")
            # Ajouter uniquement les services non encore dans la base
            _main_db_check = load_db(CVE_DB_PATH)
            _new_services = {k: v for k, v in _scan_services.items()
                             if k not in _main_db_check or not _main_db_check[k]}
            console.print(f"  [yellow]{len(_new_services)} services sans CVE dans la base → à télécharger[/yellow]")
        except Exception as _e:
            console.print(f"[red][!] Erreur lecture {_from_scan_path} : {_e}[/red]")
            sys.exit(1)
    else:
        _new_services = {}

    # ── --keyword : recherche textuelle libre ────────────────────────────────
    keyword_services: dict[str, list[str]] = {}
    if args.keyword:
        for kw in args.keyword:
            _key = re.sub(r"[^a-z0-9_]", "_", kw.lower().strip())
            keyword_services[_key] = [kw]
            console.print(f"  [cyan]keyword[/cyan] : '{kw}' → clé '{_key}'")

    # ── --service : accepte n'importe quel nom ────────────────────────────────
    if args.service:
        custom_services: dict[str, list[str]] = {}
        for s in args.service:
            if s in SERVICE_SEARCH_TERMS:
                custom_services[s] = SERVICE_SEARCH_TERMS[s]
            else:
                # Nom libre → utiliser directement comme mot-clé NVD
                _key = re.sub(r"[^a-z0-9_]", "_", s.lower().strip())
                custom_services[_key] = [s]
                console.print(f"  [dim]Service libre : '{s}' → mot-clé NVD '{s}'[/dim]")
        services_to_update = custom_services
    elif keyword_services or _new_services:
        services_to_update = {**keyword_services, **_new_services}
    else:
        services_to_update = SERVICE_SEARCH_TERMS

    # Fusionner les keyword et from-scan avec les services sélectionnés
    if keyword_services and args.service:
        services_to_update.update(keyword_services)
    if _new_services and args.service:
        services_to_update.update(_new_services)

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
                args.min_cvss, args.dry_run,
                after_year=getattr(args, 'after_year', None),
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
