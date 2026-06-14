"""
Module de matching CVE.
Recherche dans la base locale puis fallback sur l'API NVD,
avec cache persistant pour limiter les requêtes réseau.
"""

import json
import re
import time
import hashlib
import requests
from pathlib import Path
from datetime import datetime, timedelta
from modules.version_checker import is_version_affected


# Chemins
CVE_DB_PATH     = Path(__file__).parent.parent / "data" / "cve_db.json"
CVE_RECENT_PATH = Path(__file__).parent.parent / "data" / "cve_recent.json"
NVD_CACHE_PATH  = Path(__file__).parent.parent / "data" / "nvd_cache.json"

# TTL du cache NVD (24 heures)
NVD_CACHE_TTL_HOURS = 24

# Mapping service nmap -> clé dans la CVE DB
SERVICE_ALIASES = {
    "ssh": "openssh",
    "openssh": "openssh",
    "http": "apache",
    "https": "apache",
    "apache": "apache",
    "apache httpd": "apache",
    "nginx": "nginx",
    "ftp": "vsftpd",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "mysql": "mysql",
    "mariadb": "mysql",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "microsoft-ds": "smb",
    "smb": "smb",
    "netbios-ssn": "smb",
    "ms-wbt-server": "rdp",
    "rdp": "rdp",
    "iis": "iis",
    "microsoft iis": "iis",
    "http-proxy": "iis",
    "php": "php",
    "ssl": "ssl",
    "openssl": "ssl",
    "telnet": "telnet",
    "smtp": "smtp",
    "tomcat": "tomcat",
    "apache tomcat": "tomcat",
    "samba": "samba",
    "smbd": "samba",
    "vnc": "vnc",
    "redis": "redis",
    "mongodb": "mongodb",
    "elasticsearch": "elasticsearch",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "jenkins": "jenkins",
    "docker": "docker",
    "docker registry": "docker",
    "domain": "dns",
    "dns": "dns",
    "rsync": "rsync",
    "memcache": "memcached",
    "memcached": "memcached",
    "exim": "smtp",
    "exim smtpd": "smtp",
    "postfix": "smtp",
    "gitlab": "gitlab",
    "confluence": "confluence",
    "spring": "spring",
    "spring boot": "spring",
    "fortinet": "fortinet",
    "fortios": "fortinet",
    "fortigate": "fortinet",
    "vmware": "vmware",
    "vcenter": "vmware",
    "esxi": "vmware",
    "citrix": "citrix",
    "netscaler": "citrix",
    "microsoft windows rpc": "rpc",
    "msrpc": "rpc",
    "ms-rpc": "rpc",
    "snmp": "snmp",
    "snmpd": "snmp",
    "ldap": "ldap",
    "openldap": "ldap",
    "kerberos": "kerberos",
    "kerberos-sec": "kerberos",
    "ftp-data": "ftp",
    "rabbitmq": "rabbitmq",
    "amqp": "rabbitmq_amqp",
    "erlang": "erlang_ssh",
    "grafana": "grafana",
    "zabbix": "zabbix",
    "zabbix-agent": "zabbix",
    "openvpn": "openvpn",
    "git": "git",
    "git-daemon": "git",
    "kibana": "kibana",
    "couchdb": "couchdb",
    "squid": "squid",
    "squid-http": "squid",
    "haproxy": "haproxy",
    "minio": "minio",
    "zimbra": "zimbra",
    "exchange": "exchange",
    "microsoft exchange": "exchange",
    "sharepoint": "sharepoint",
    "veeam": "veeam",
    "ivanti": "ivanti",
    "pulse secure": "ivanti",
    "palo alto": "paloalto",
    "pan-os": "paloalto",
    "f5": "f5",
    "big-ip": "f5",
    "junos": "junos",
    "moodle": "moodle",
    "phpmyadmin": "phpmyadmin",
    "webmin": "webmin",
    "splunkd": "splunk",
    "splunk": "splunk",
    "sonarqube": "sonarqube",
    "activemq": "activemq",
    "openwire": "activemq",
    "node.js": "node",
    "node": "node",
    "django": "django",
    "laravel": "laravel",
    "windows rdp": "windows",
    "ms-wbt": "windows",
    "winrm": "winrm",
    "wsman": "winrm",
    "gitea": "gitea",
    "gogs": "gogs",
    "nfs": "nfs",
    "nfsd": "nfs",
    "rpcbind": "rpc",
    "h2 database": "h2_database",
    "h2": "h2_database",
    "openfire": "openfire",
    "supervisor": "supervisor",
    "supervisord": "supervisor",
    "wso2": "wso2",
    "nostromo": "nostromo",
    "nhttpd": "nostromo",
    "icecast": "icecast",
    "jboss": "jboss",
    "wildfly": "jboss",
    "weblogic": "weblogic",
    "struts": "struts",
    "log4j": "log4j",
    "xz": "openssh",
    "liblzma": "openssh",
    "ofbiz": "ofbiz",
    "apache ofbiz": "ofbiz",
    "coldfusion": "coldfusion",
    "adobe coldfusion": "coldfusion",
    "glpi": "glpi",
    "octopus": "octopus",
    "octopus deploy": "octopus",
    "cacti": "cacti",
    "roundcube": "roundcube",
    "nagios": "nagios",
    "nagios xi": "nagios",
    "cisco asa": "asa",
    "asa": "asa",
    "sharefile": "sharefile",
    "bamboo": "bamboo",
    "jira": "jira",
    "thinkphp": "thinkphp",
    "umbraco": "umbraco",
    "ghost": "ghost_cms",
    "prestashop": "prestashop",
    "magento": "magento",
    "rocket.chat": "rocketchat",
    "rocketchat": "rocketchat",
    "rstudio": "rstudio",
    "jupyter": "jupyter",
    "jupyterhub": "jupyter",
    "concrete5": "concrete5",
    "concrete cms": "concrete5",
    "typo3": "typo3",
    "owncloud": "owncloud",
    "harbor": "harbor",
    "consul": "consul",
    "vault": "vault",
    "hashicorp vault": "vault",
    "etcd": "etcd",
    "kubernetes": "kubernetes",
    "kube-apiserver": "kubernetes",
    "portainer": "portainer",
    "synapse": "matrix_synapse",
    "matrix": "matrix_synapse",
    "teamcity": "teamcity",
    "selenium": "selenium",
    "selenium grid": "selenium",
    "adminer": "adminer",
    "freepbx": "freepbx",
    "asterisk": "freepbx",
    "sip": "freepbx",
    "webdav": "webdav",
    "http webdav": "webdav",
}

LOCAL_PRIVESC_SERVICES = [
    "shellshock", "dirtycow", "polkit", "sudo", "screen", "pkexec", "openssl_3"
]


# ─── Cache NVD ────────────────────────────────────────────────────────────────

def _load_nvd_cache() -> dict:
    if NVD_CACHE_PATH.exists():
        try:
            with open(NVD_CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_nvd_cache(cache: dict):
    try:
        with open(NVD_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
    except Exception:
        pass


def _cache_key(service: str, version: str) -> str:
    raw = f"{service.lower().strip()}|{version.lower().strip()}"
    return hashlib.md5(raw.encode()).hexdigest()


def _cache_is_valid(entry: dict) -> bool:
    try:
        ts = datetime.fromisoformat(entry.get("timestamp", ""))
        return datetime.now() - ts < timedelta(hours=NVD_CACHE_TTL_HOURS)
    except Exception:
        return False


# ─── Chargement des bases ─────────────────────────────────────────────────────

def load_local_db() -> dict:
    """Charge la base CVE locale principale."""
    with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_recent_db() -> dict:
    """Charge la base CVE récentes (cve_recent.json) si disponible."""
    if CVE_RECENT_PATH.exists():
        try:
            with open(CVE_RECENT_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


# ─── Extraction service / version ─────────────────────────────────────────────

def extract_service_key(service_name: str, banner: str = "") -> str | None:
    """Détermine la clé de la CVE DB depuis le nom du service et sa bannière."""
    combined = f"{service_name} {banner}".lower().strip()
    for alias, key in SERVICE_ALIASES.items():
        if alias in combined:
            return key
    return None


def extract_version_from_banner(banner: str) -> str:
    """Extrait la version depuis une bannière nmap."""
    patterns = [
        r'(\d+\.\d+[\.\d]*(?:[p\-]\d+)?)',
    ]
    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1)
    return ""


# ─── Recherche locale ─────────────────────────────────────────────────────────

def search_local_db(service_key: str, version: str) -> list:
    """
    Recherche des CVE dans les bases locales pour un service/version.
    Priorité : cve_recent.json (CVEs récentes) > cve_db.json (base principale)
    Les doublons (même CVE ID) sont dédupliqués, recent_db prioritaire.
    """
    main_db   = load_local_db()
    recent_db = load_recent_db()

    seen_ids = set()
    results  = []

    # 1. CVE récentes en priorité
    for cve in recent_db.get(service_key, []):
        if not version or is_version_affected(version, cve.get("affected_versions", [])):
            cve_id = cve.get("id", "")
            if cve_id not in seen_ids:
                seen_ids.add(cve_id)
                results.append({**cve, "source": "Local DB (récent)"})

    # 2. Base principale
    for cve in main_db.get(service_key, []):
        if not version or is_version_affected(version, cve.get("affected_versions", [])):
            cve_id = cve.get("id", "")
            if cve_id not in seen_ids:
                seen_ids.add(cve_id)
                results.append({**cve, "source": "Local DB"})

    return results


# ─── Traduction ───────────────────────────────────────────────────────────────

def translate_to_french(text: str) -> str:
    """Traduit un texte EN -> FR via l'API gratuite MyMemory."""
    if not text:
        return ""
    try:
        url = "https://api.mymemory.translated.net/get"
        params = {"q": text[:490], "langpair": "en|fr"}
        resp = requests.get(url, params=params, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        translated = data.get("responseData", {}).get("translatedText", "")
        if translated and "MYMEMORY WARNING" not in translated.upper():
            return translated
    except Exception:
        pass
    return ""


# ─── API NVD avec cache ───────────────────────────────────────────────────────

def search_nvd_api(service: str, version: str, max_results: int = 5) -> list:
    """
    Interroge l'API NVD comme fallback, avec cache persistant 24h.
    Retourne une liste de CVE simplifiées.
    """
    cache = _load_nvd_cache()
    key   = _cache_key(service, version)

    # Retour depuis le cache si valide
    if key in cache and _cache_is_valid(cache[key]):
        return cache[key]["data"]

    query  = f"{service} {version}".strip()
    url    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": max_results}

    try:
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        data    = resp.json()
        results = []

        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "N/A")

            descriptions = cve_data.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available")

            score    = "N/A"
            severity = "UNKNOWN"
            metrics  = cve_data.get("metrics", {})

            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                score     = cvss_data.get("baseScore", "N/A")
                severity  = cvss_data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                score     = cvss_data.get("baseScore", "N/A")
                severity  = "N/A (CVSSv2)"

            desc_short = desc[:200] + "..." if len(desc) > 200 else desc
            results.append({
                "id":             cve_id,
                "description":    desc_short,
                "description_fr": translate_to_french(desc_short),
                "cvss":           score,
                "severity":       severity,
                "source":         "NVD API",
            })

        # Mise en cache
        cache[key] = {"timestamp": datetime.now().isoformat(), "data": results}
        _save_nvd_cache(cache)

        time.sleep(0.6)  # Rate limiting NVD : 5 req/s sans clé API
        return results

    except requests.exceptions.Timeout:
        return [{"id": "API_ERROR", "description": "NVD API timeout", "cvss": "N/A", "severity": "N/A"}]
    except Exception as e:
        return [{"id": "API_ERROR", "description": f"NVD API error: {str(e)}", "cvss": "N/A", "severity": "N/A"}]


# ─── Point d'entrée principal ─────────────────────────────────────────────────

def get_cves_for_service(service_name: str, banner: str, use_api_fallback: bool = True) -> list:
    """
    Point d'entrée principal.
    1. Essaie la base locale (recent + main)
    2. Fallback API NVD avec cache si rien trouvé
    """
    version     = extract_version_from_banner(banner)
    service_key = extract_service_key(service_name, banner)

    local_results = []
    if service_key:
        local_results = search_local_db(service_key, version)

    if local_results:
        return local_results

    # Fallback API NVD (avec cache)
    if use_api_fallback and (service_name or banner):
        return search_nvd_api(service_name if service_name else "", version)

    return []
