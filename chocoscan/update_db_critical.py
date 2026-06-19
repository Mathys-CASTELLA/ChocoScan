#!/usr/bin/env python3
"""
ChocoScan — Mise à jour exhaustive des CVEs CRITICAL (score 9.0 → 10.0).

Interroge l'API NVD pour récupérer TOUTES les CVEs avec un score CVSS ≥ 9.0,
puis injecte dans cve_db.json uniquement celles qui concernent les services
déjà présents dans la base (matching par CPE et mots-clés de description).

Usage :
    python update_db_critical.py                        # Sans clé API (lent, ~30 min)
    python update_db_critical.py --api-key VOTRE_CLE   # Avec clé NVD (rapide, ~3 min)
    python update_db_critical.py --min-cvss 9.5        # Seuil CVSS personnalisé
    python update_db_critical.py --dry-run             # Aperçu sans modifier la base
    python update_db_critical.py --stats               # Statistiques après import
    python update_db_critical.py --year 2024           # Seulement une année

Clé API NVD gratuite : https://nvd.nist.gov/developers/request-an-api-key
(multiplie la vitesse par 10, fortement recommandée)
"""

import json
import time
import argparse
import re
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] 'requests' manquant — pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeRemainingColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

NVD_API_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATA_DIR        = Path(__file__).parent / "data"
CVE_DB_PATH     = DATA_DIR / "cve_db.json"

# Rate limits NVD : 5 req/30s sans clé, 50 req/30s avec clé
DELAY_NO_KEY    = 6.5    # secondes entre requêtes sans clé API
DELAY_WITH_KEY  = 0.7    # secondes entre requêtes avec clé API
RESULTS_PER_PAGE = 2000  # maximum autorisé par l'API NVD


# ─────────────────────────────────────────────────────────────────────────────
# Table de correspondance service → mots-clés CPE + description
# ─────────────────────────────────────────────────────────────────────────────
# Format : service_db -> ([cpe_keywords], [desc_keywords])
# cpe_keywords : cherchés dans le champ "criteria" des CPE (ex: cpe:2.3:a:apache:http_server)
# desc_keywords : cherchés dans la description textuelle de la CVE

SERVICE_KEYWORDS: dict[str, tuple[list[str], list[str]]] = {
    "apache":       (["apache:http_server", "apache:apache2"], ["apache http server", "apache httpd", "mod_rewrite", "mod_proxy", "mod_lua"]),
    "nginx":        (["nginx:nginx"], ["nginx", "openresty"]),
    "iis":          (["microsoft:internet_information_services", "microsoft:iis"], ["iis", "internet information services", "microsoft iis"]),
    "tomcat":       (["apache:tomcat"], ["apache tomcat", "tomcat"]),
    "php":          (["php:php"], ["php", "php-fpm"]),
    "openssh":      (["openbsd:openssh"], ["openssh", "openssh server", "sshd"]),
    "ssl":          (["openssl:openssl"], ["openssl", "tls", "ssl certificate"]),
    "smb":          (["microsoft:windows", "microsoft:smb"], ["smb", "server message block", "netlogon", "cifs"]),
    "samba":        (["samba:samba"], ["samba"]),
    "rdp":          (["microsoft:remote_desktop"], ["remote desktop", "rdp", "terminal services", "mstsc"]),
    "mysql":        (["mysql:mysql", "oracle:mysql"], ["mysql"]),
    "postgresql":   (["postgresql:postgresql"], ["postgresql", "postgres"]),
    "redis":        (["redis:redis"], ["redis"]),
    "mongodb":      (["mongodb:mongodb"], ["mongodb"]),
    "elasticsearch":(["elastic:elasticsearch"], ["elasticsearch", "elastic stack"]),
    "wordpress":    (["wordpress:wordpress"], ["wordpress", "wp-admin", "wp-login"]),
    "drupal":       (["drupal:drupal"], ["drupal"]),
    "joomla":       (["joomla:joomla"], ["joomla"]),
    "moodle":       (["moodle:moodle"], ["moodle"]),
    "jenkins":      (["jenkins:jenkins"], ["jenkins"]),
    "gitlab":       (["gitlab:gitlab"], ["gitlab"]),
    "confluence":   (["atlassian:confluence"], ["confluence"]),
    "jira":         (["atlassian:jira"], ["jira"]),
    "bamboo":       (["atlassian:bamboo"], ["atlassian bamboo"]),
    "spring":       (["pivotal_software:spring", "vmware:spring"], ["spring framework", "spring boot", "spring mvc", "spring security", "springshell", "spring4shell"]),
    "log4j":        (["apache:log4j"], ["log4j", "log4shell", "jndi"]),
    "struts":       (["apache:struts"], ["apache struts", "struts2", "ognl"]),
    "weblogic":     (["oracle:weblogic_server"], ["weblogic", "oracle weblogic"]),
    "jboss":        (["redhat:jboss", "jboss:jboss_application_server"], ["jboss", "wildfly", "jboss application"]),
    "coldfusion":   (["adobe:coldfusion"], ["coldfusion"]),
    "vmware":       (["vmware:vcenter_server", "vmware:esxi", "vmware:vsphere"], ["vmware", "vcenter", "esxi", "vsphere"]),
    "fortinet":     (["fortinet:fortios", "fortinet:fortigate", "fortinet:fortiproxy"], ["fortios", "fortigate", "fortinet", "fortiproxy", "fortivpn"]),
    "paloalto":     (["palo_alto_networks:pan-os"], ["pan-os", "palo alto", "panos"]),
    "citrix":       (["citrix:netscaler", "citrix:application_delivery_controller"], ["citrix", "netscaler", "citrix adc"]),
    "ivanti":       (["ivanti:connect_secure", "pulse_secure:pulse_connect_secure"], ["ivanti", "pulse connect secure", "pulse secure"]),
    "exchange":     (["microsoft:exchange_server"], ["microsoft exchange", "exchange server"]),
    "sharepoint":   (["microsoft:sharepoint_server"], ["sharepoint"]),
    "windows":      (["microsoft:windows_10", "microsoft:windows_11", "microsoft:windows_server"], ["windows kernel", "win32k", "windows tcp", "windows ole", "windows rpc", "hyper-v", "windows ntlm"]),
    "junos":        (["juniper:junos"], ["junos", "juniper"]),
    "f5":           (["f5:big-ip"], ["big-ip", "f5 big-ip", "icontrol"]),
    "veeam":        (["veeam:backup_&_replication"], ["veeam backup", "veeam"]),
    "asa":          (["cisco:adaptive_security_appliance", "cisco:asa"], ["cisco asa", "adaptive security appliance", "cisco ftd"]),
    "zabbix":       (["zabbix:zabbix"], ["zabbix"]),
    "grafana":      (["grafana:grafana"], ["grafana"]),
    "splunk":       (["splunk:splunk_enterprise"], ["splunk"]),
    "kibana":       (["elastic:kibana"], ["kibana"]),
    "docker":       (["docker:docker", "docker:engine"], ["docker", "containerd", "runc"]),
    "kubernetes":   (["kubernetes:kubernetes"], ["kubernetes", "kubectl", "kubelet", "k8s"]),
    "cacti":        (["the_cacti_group:cacti"], ["cacti"]),
    "nagios":       (["nagios:nagios_xi", "nagios:nagios"], ["nagios xi", "nagios"]),
    "glpi":         (["glpi-project:glpi"], ["glpi"]),
    "roundcube":    (["roundcube:webmail"], ["roundcube", "roundcube webmail"]),
    "zimbra":       (["synacor:zimbra_collaboration_suite"], ["zimbra"]),
    "openfire":     (["igniterealtime:openfire"], ["openfire"]),
    "sonarqube":    (["sonarsource:sonarqube"], ["sonarqube", "sonar"]),
    "minio":        (["minio:minio"], ["minio"]),
    "vault":        (["hashicorp:vault"], ["hashicorp vault"]),
    "consul":       (["hashicorp:consul"], ["hashicorp consul"]),
    "ofbiz":        (["apache:ofbiz", "apache:open_for_business"], ["ofbiz", "apache ofbiz"]),
    "magento":      (["magento:magento", "adobe:commerce"], ["magento", "adobe commerce"]),
    "prestashop":   (["prestashop:prestashop"], ["prestashop"]),
    "laravel":      (["laravel:laravel"], ["laravel", "ignition"]),
    "django":       (["djangoproject:django"], ["django"]),
    "nodejs":       (["nodejs:node.js"], ["node.js", "nodejs"]),
    "couchdb":      (["apache:couchdb"], ["couchdb", "apache couchdb"]),
    "rabbitmq":     (["pivotal_software:rabbitmq", "vmware:rabbitmq"], ["rabbitmq"]),
    "activemq":     (["apache:activemq"], ["activemq", "apache activemq"]),
    "h2_database":  (["h2database:h2"], ["h2 database", "h2 console"]),
    "thinkphp":     (["thinkphp:thinkphp"], ["thinkphp"]),
    "webmin":       (["webmin:webmin"], ["webmin"]),
    "phpmyadmin":   (["phpmyadmin:phpmyadmin"], ["phpmyadmin"]),
    "nostromo":     (["nazgul:nostromo"], ["nostromo", "nhttpd"]),
    "wso2":         (["wso2:identity_server", "wso2:api_manager"], ["wso2"]),
    "sudo":         (["sudo_project:sudo"], ["sudo", "sudoedit", "baron samedit"]),
    "polkit":       (["polkit_project:polkit"], ["polkit", "pkexec", "pwnkit"]),
    "dirtycow":     ([], ["dirty cow", "dirtycow", "dirty pipe", "dirtypipe"]),
    "erlang_ssh":   (["erlang:otp"], ["erlang", "otp ssh"]),
    "shellshock":   (["gnu:bash"], ["shellshock", "bash env", "cve-2014-6271"]),
}


# ─────────────────────────────────────────────────────────────────────────────
# Utilitaires
# ─────────────────────────────────────────────────────────────────────────────

def log(msg: str, style: str = ""):
    if console:
        console.print(f"[{style}]{msg}[/{style}]" if style else msg)
    else:
        print(msg)


def extract_score(cve_data: dict) -> tuple[float, str]:
    """Extrait le score CVSS et la sévérité depuis les métriques NVD."""
    metrics = cve_data.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore", 0.0)
            sev   = data.get("baseSeverity", "UNKNOWN")
            if not sev and score >= 9.0:
                sev = "CRITICAL"
            elif not sev and score >= 7.0:
                sev = "HIGH"
            elif not sev and score >= 4.0:
                sev = "MEDIUM"
            elif not sev:
                sev = "LOW"
            return float(score), sev.upper()

    return 0.0, "UNKNOWN"


def extract_description(cve_data: dict, lang: str = "en") -> str:
    """Extrait la description dans la langue demandée."""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang", "") == lang:
            return desc.get("value", "").strip()
    # Fallback sur la première description disponible
    descs = cve_data.get("descriptions", [])
    return descs[0].get("value", "") if descs else ""


def extract_cpe_list(cve_data: dict) -> list[str]:
    """Extrait tous les CPE (criteria) de la CVE."""
    cpes = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                crit = match.get("criteria", "")
                if crit:
                    cpes.append(crit.lower())
            # Nested nodes
            for child in node.get("children", []):
                for match in child.get("cpeMatch", []):
                    crit = match.get("criteria", "")
                    if crit:
                        cpes.append(crit.lower())
    return cpes


def extract_references(cve_data: dict) -> list[str]:
    """Extrait les URLs de référence NVD."""
    refs = []
    for ref in cve_data.get("references", []):
        url = ref.get("url", "")
        if url:
            refs.append(url)
    return refs[:5]  # max 5 refs


def extract_affected_versions(cve_data: dict) -> list[str]:
    """Tente d'extraire des versions affectées depuis les CPE."""
    versions = set()
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                ver_start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                ver_end   = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                crit      = match.get("criteria", "")

                # Extraire la version depuis le CPE (partie après le 5e ':')
                parts = crit.split(":")
                if len(parts) > 5 and parts[5] not in ("*", "-", ""):
                    versions.add(parts[5])

                if ver_start and ver_end:
                    versions.add(f">= {ver_start}, <= {ver_end}")
                elif ver_end:
                    versions.add(f"< {ver_end}")
                elif ver_start:
                    versions.add(f">= {ver_start}")

    return list(versions)[:5] if versions else ["Check NVD for affected versions"]


def match_service(cve_id: str, description: str, cpe_list: list[str]) -> list[str]:
    """
    Détermine à quel(s) service(s) de la base appartient cette CVE.
    Retourne une liste de clés de service (peut être vide si aucun match).
    """
    matched = []
    desc_lower = description.lower()
    cpes_str   = " ".join(cpe_list)

    for service, (cpe_keywords, desc_keywords) in SERVICE_KEYWORDS.items():
        # Match CPE
        cpe_match = any(kw in cpes_str for kw in cpe_keywords)
        # Match description
        desc_match = any(kw in desc_lower for kw in desc_keywords)

        if cpe_match or desc_match:
            matched.append(service)

    return matched


# ─────────────────────────────────────────────────────────────────────────────
# Fetch NVD
# ─────────────────────────────────────────────────────────────────────────────

def fetch_nvd_page(
    session: requests.Session,
    start_index: int,
    min_cvss: float,
    year: int | None,
    api_key: str | None,
    delay: float,
) -> tuple[int, list[dict]]:
    """
    Récupère une page de CVEs depuis l'API NVD.
    Retourne (total_results, liste_de_cve_data).
    """
    params: dict = {
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex":     start_index,
    }

    if year:
        params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
        params["pubEndDate"]   = f"{year}-12-31T23:59:59.999"

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(3):
        try:
            resp = session.get(
                NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=30,
            )
            if resp.status_code == 403:
                log("  [!] Rate limit atteint — attente 35 secondes...", "yellow")
                time.sleep(35)
                continue
            if resp.status_code == 404:
                return 0, []
            resp.raise_for_status()
            data = resp.json()
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            return total, vulns
        except (requests.RequestException, json.JSONDecodeError) as e:
            log(f"  [!] Tentative {attempt+1}/3 échouée : {e}", "yellow")
            time.sleep(delay * 2)

    return 0, []


# ─────────────────────────────────────────────────────────────────────────────
# Traitement d'une CVE
# ─────────────────────────────────────────────────────────────────────────────

def process_cve(vuln: dict, min_cvss: float) -> list[tuple[str, dict]]:
    """
    Traite une CVE NVD et retourne une liste de (service, cve_entry).
    Une CVE peut correspondre à plusieurs services.
    """
    cve_data = vuln.get("cve", {})
    cve_id   = cve_data.get("id", "")

    if not cve_id:
        return []

    score, severity = extract_score(cve_data)

    # Filtrer par score minimum
    if score < min_cvss:
        return []

    description_en = extract_description(cve_data, "en")
    cpe_list       = extract_cpe_list(cve_data)
    services       = match_service(cve_id, description_en, cpe_list)

    if not services:
        return []

    # Construire l'entrée CVE
    refs = extract_references(cve_data)
    # S'assurer qu'il y a toujours le lien NVD
    nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    if nvd_link not in refs:
        refs.insert(0, nvd_link)

    affected = extract_affected_versions(cve_data)

    entry = {
        "id":              cve_id,
        "description":     description_en[:500] if description_en else f"See NVD for details: {nvd_link}",
        "description_fr":  description_en[:500] if description_en else f"Voir NVD pour les détails : {nvd_link}",
        "cvss":            score,
        "severity":        severity,
        "affected_versions": affected,
        "exploit_available": False,
        "references":      refs,
    }

    return [(svc, entry) for svc in services]


# ─────────────────────────────────────────────────────────────────────────────
# Mise à jour principale
# ─────────────────────────────────────────────────────────────────────────────

def update_critical(
    db: dict,
    api_key: str | None,
    min_cvss: float,
    year: int | None,
    dry_run: bool,
) -> tuple[dict, dict]:
    """
    Récupère toutes les CVEs CRITICAL depuis NVD et les injecte dans la base.
    Retourne (db_mise_à_jour, stats).
    """
    delay   = DELAY_WITH_KEY if api_key else DELAY_NO_KEY
    session = requests.Session()
    session.headers.update({"User-Agent": "ChocoScan/2.0 CVE-CRITICAL-updater"})

    stats = defaultdict(int)
    new_by_service: dict[str, list[dict]] = defaultdict(list)

    # Index des CVEs existantes pour déduplication rapide
    existing_ids: set[str] = set()
    for cves in db.values():
        for c in cves:
            existing_ids.add(c.get("id", ""))

    log("")
    log(Rule("[bold yellow]ChocoScan — Import CVEs CRITICAL depuis NVD[/bold yellow]"))
    log(f"  Score minimum : [cyan]{min_cvss}[/cyan]")
    log(f"  Année filtrée : [cyan]{year or 'toutes'}[/cyan]")
    log(f"  Clé API NVD   : [cyan]{'Oui ✓' if api_key else 'Non (mode lent)'}[/cyan]")
    log(f"  Dry-run       : [cyan]{'Oui — aucune modification' if dry_run else 'Non'}[/cyan]")
    log(f"  Délai requêtes : [cyan]{delay}s[/cyan]")
    log("")

    # ── 1. Première requête pour connaître le total ──────────────────────────
    log("Connexion à l'API NVD...", "cyan")
    total, first_page = fetch_nvd_page(session, 0, min_cvss, year, api_key, delay)

    if total == 0:
        log("[!] Aucun résultat ou erreur API.", "red")
        return db, stats

    pages = (total + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE
    log(f"Total CVEs CRITICAL sur NVD : [bold cyan]{total:,}[/bold cyan] — {pages} pages à récupérer")
    log("")

    # ── 2. Traiter la première page ──────────────────────────────────────────
    for vuln in first_page:
        for svc, entry in process_cve(vuln, min_cvss):
            cid = entry["id"]
            if cid not in existing_ids:
                new_by_service[svc].append(entry)
                existing_ids.add(cid)
                stats["new"] += 1
            else:
                stats["duplicate"] += 1
        stats["processed"] += 1

    time.sleep(delay)

    # ── 3. Pages suivantes ───────────────────────────────────────────────────
    if pages > 1:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                "[cyan]Récupération des CVEs CRITICAL...",
                total=pages - 1
            )

            for page_idx in range(1, pages):
                start = page_idx * RESULTS_PER_PAGE
                progress.update(
                    task,
                    description=f"[cyan]Page {page_idx+1}/{pages} "
                                f"(+{stats['new']} nouvelles CVEs)[/cyan]"
                )

                _, vulns = fetch_nvd_page(
                    session, start, min_cvss, year, api_key, delay
                )

                for vuln in vulns:
                    for svc, entry in process_cve(vuln, min_cvss):
                        cid = entry["id"]
                        if cid not in existing_ids:
                            new_by_service[svc].append(entry)
                            existing_ids.add(cid)
                            stats["new"] += 1
                        else:
                            stats["duplicate"] += 1
                    stats["processed"] += 1

                progress.advance(task)
                time.sleep(delay)

    stats["services_updated"] = len(new_by_service)

    # ── 4. Injection dans la base ─────────────────────────────────────────────
    if not dry_run:
        for svc, entries in new_by_service.items():
            if svc not in db:
                db[svc] = []
            db[svc].extend(entries)

    return db, dict(stats), new_by_service


# ─────────────────────────────────────────────────────────────────────────────
# Affichage des stats
# ─────────────────────────────────────────────────────────────────────────────

def show_stats(db: dict):
    """Affiche les statistiques actuelles de la base."""
    total = sum(len(v) for v in db.values())
    critical = sum(
        1 for cves in db.values()
        for c in cves
        if c.get("severity") == "CRITICAL" or c.get("cvss", 0) >= 9.0
    )
    log(Panel.fit(
        f"[bold]Services :[/bold]  {len(db)}\n"
        f"[bold]CVEs totales :[/bold]  {total}\n"
        f"[bold]CVEs CRITICAL (≥9.0) :[/bold]  [red]{critical}[/red]",
        title="[bold yellow]📊 État de la base[/bold yellow]",
        border_style="yellow"
    ))

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    table.add_column("Service", style="bold")
    table.add_column("Total", justify="center")
    table.add_column("CRITICAL", justify="center", style="red")

    for svc, cves in sorted(db.items(), key=lambda x: len(x[1]), reverse=True)[:25]:
        crit = sum(1 for c in cves if c.get("severity") == "CRITICAL" or c.get("cvss", 0) >= 9.0)
        table.add_row(svc, str(len(cves)), str(crit) if crit else "-")

    log(table)


def show_run_summary(stats: dict, new_by_service: dict, dry_run: bool):
    """Affiche le résumé de l'exécution."""
    log("")
    log(Rule("[bold green]Résumé[/bold green]"))

    summary = Table(box=box.SIMPLE, show_header=False)
    summary.add_column("", style="bold")
    summary.add_column("", style="cyan", justify="right")
    summary.add_row("CVEs analysées",         f"{stats.get('processed', 0):,}")
    summary.add_row("Nouvelles CVEs trouvées", f"{stats.get('new', 0):,}")
    summary.add_row("Doublons ignorés",        f"{stats.get('duplicate', 0):,}")
    summary.add_row("Services enrichis",       f"{stats.get('services_updated', 0)}")
    log(summary)

    if new_by_service:
        log("")
        log("[bold]Nouvelles CVEs par service :[/bold]")
        detail = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        detail.add_column("Service", style="bold yellow")
        detail.add_column("Nouvelles CVEs", justify="center", style="green")
        detail.add_column("Exemples", style="dim")

        for svc, entries in sorted(new_by_service.items(), key=lambda x: len(x[1]), reverse=True):
            examples = ", ".join(e["id"] for e in entries[:3])
            if len(entries) > 3:
                examples += f"... (+{len(entries)-3})"
            detail.add_row(svc, str(len(entries)), examples)

        log(detail)

    if dry_run:
        log("")
        log("[bold red]DRY-RUN : aucune modification enregistrée.[/bold red]")
    else:
        log("")
        log(f"[bold green]✓ Base mise à jour avec {stats.get('new', 0):,} nouvelles CVEs CRITICAL.[/bold green]")


# ─────────────────────────────────────────────────────────────────────────────
# Point d'entrée
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ChocoScan — Import exhaustif des CVEs CRITICAL (≥9.0) depuis NVD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  # Import complet sans clé API (~30 min)
  python update_db_critical.py

  # Import rapide avec clé API NVD (~3 min)
  python update_db_critical.py --api-key VOTRE-CLE-ICI

  # Seulement les CVEs avec score ≥ 9.5
  python update_db_critical.py --min-cvss 9.5 --api-key VOTRE-CLE

  # Seulement l'année 2024
  python update_db_critical.py --year 2024 --api-key VOTRE-CLE

  # Aperçu sans modifier la base
  python update_db_critical.py --dry-run --api-key VOTRE-CLE

  # Statistiques actuelles
  python update_db_critical.py --stats

Clé API NVD gratuite (recommandée) :
  https://nvd.nist.gov/developers/request-an-api-key
        """
    )

    parser.add_argument(
        "--api-key", metavar="CLE",
        help="Clé API NVD (gratuite sur nvd.nist.gov) — accélère x10"
    )
    parser.add_argument(
        "--min-cvss", type=float, default=9.0, metavar="SCORE",
        help="Score CVSS minimum (défaut: 9.0)"
    )
    parser.add_argument(
        "--year", type=int, default=None, metavar="AAAA",
        help="Filtrer sur une année de publication (ex: 2024)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Affiche ce qui serait ajouté sans modifier la base"
    )
    parser.add_argument(
        "--stats", action="store_true",
        help="Afficher les statistiques actuelles et quitter"
    )

    args = parser.parse_args()

    # Charger la base
    if not CVE_DB_PATH.exists():
        log(f"[red]✗ Base CVE introuvable : {CVE_DB_PATH}[/red]")
        sys.exit(1)

    with open(CVE_DB_PATH, encoding="utf-8") as f:
        db = json.load(f)

    total_before = sum(len(v) for v in db.values())
    log(f"\n[bold]ChocoScan[/bold] — Base : [cyan]{total_before:,}[/cyan] CVEs sur [cyan]{len(db)}[/cyan] services\n")

    # Mode stats uniquement
    if args.stats:
        show_stats(db)
        return

    # Validation
    if args.min_cvss < 9.0:
        log("[yellow]⚠ Ce script est conçu pour les CVEs CRITICAL (≥9.0). "
            "Pour les scores inférieurs, utilisez update_db.py[/yellow]")

    # Lancement
    db_updated, stats, new_by_service = update_critical(
        db=db,
        api_key=args.api_key,
        min_cvss=args.min_cvss,
        year=args.year,
        dry_run=args.dry_run,
    )

    # Affichage résumé
    show_run_summary(stats, new_by_service, args.dry_run)

    # Sauvegarde
    if not args.dry_run and stats.get("new", 0) > 0:
        with open(CVE_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(db_updated, f, indent=2, ensure_ascii=False)
        total_after = sum(len(v) for v in db_updated.values())
        log(f"[dim]Sauvegardé → {CVE_DB_PATH} ({total_before:,} → {total_after:,} CVEs)[/dim]")


if __name__ == "__main__":
    main()
