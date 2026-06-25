"""
ChocoScan — Credentials par défaut & suggestions Hydra.

Pour chaque service détecté, ce module fournit :
  - La liste des credentials par défaut connus
  - La commande Hydra optimisée pour le brute-force (wordlists Kali)
  - Des commandes de test rapide (1 tentative sans brute-force)

Sources : docs officielles, CVE advisories, SecLists, expérience CTF.
Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations
from dataclasses import dataclass, field

# ── Modèle ────────────────────────────────────────────────────────────────────

@dataclass
class DefaultCred:
    username: str
    password: str
    note: str = ""  # contexte (ex: "Tomcat Manager", "Pi par défaut")


@dataclass
class CredResult:
    service:     str
    port:        int
    target:      str
    creds:       list[DefaultCred]
    hydra_cmd:   str
    quick_test:  str  # commande de test rapide (sans brute-force)
    protocol:    str  # protocole hydra (ftp, ssh, mysql...)


# ── Base de credentials par défaut ───────────────────────────────────────────
#
# Clé = service_key normalisé (cf. SERVICE_ALIASES dans cve_matcher.py)
# Valeur = liste de DefaultCred, triée par fréquence de rencontre en CTF

DEFAULT_CREDS: dict[str, list[DefaultCred]] = {

    "ftp": [
        DefaultCred("anonymous", "anonymous", "Accès anonyme FTP classique"),
        DefaultCred("anonymous", "",          "Accès anonyme sans mot de passe"),
        DefaultCred("ftp",       "ftp"),
        DefaultCred("admin",     "admin"),
        DefaultCred("admin",     "ftp"),
        DefaultCred("root",      "root"),
        DefaultCred("user",      "user"),
        DefaultCred("guest",     "guest"),
    ],

    "openssh": [
        DefaultCred("root",    "root"),
        DefaultCred("root",    "toor"),
        DefaultCred("admin",   "admin"),
        DefaultCred("admin",   "password"),
        DefaultCred("admin",   "123456"),
        DefaultCred("ubuntu",  "ubuntu",    "Image Ubuntu cloud"),
        DefaultCred("pi",      "raspberry", "Raspberry Pi par défaut"),
        DefaultCred("vagrant", "vagrant",   "Box Vagrant"),
        DefaultCred("user",    "user"),
        DefaultCred("test",    "test"),
        DefaultCred("guest",   "guest"),
    ],

    "mysql": [
        DefaultCred("root",  "",        "Pas de mot de passe — très fréquent"),
        DefaultCred("root",  "root"),
        DefaultCred("root",  "mysql"),
        DefaultCred("root",  "toor"),
        DefaultCred("root",  "password"),
        DefaultCred("admin", "admin"),
        DefaultCred("mysql", "mysql"),
    ],

    "postgresql": [
        DefaultCred("postgres", "",         "Pas de mot de passe — défaut Debian/Ubuntu"),
        DefaultCred("postgres", "postgres"),
        DefaultCred("admin",    "admin"),
        DefaultCred("postgres", "password"),
    ],

    "redis": [
        DefaultCred("",      "",        "Redis sans auth — très fréquent"),
        DefaultCred("redis", ""),
        DefaultCred("redis", "redis"),
        DefaultCred("",      "redis"),
        DefaultCred("",      "password"),
    ],

    "mongodb": [
        DefaultCred("admin", "",        "MongoDB sans auth — fréquent"),
        DefaultCred("admin", "admin"),
        DefaultCred("root",  "root"),
        DefaultCred("mongo", "mongo"),
    ],

    "tomcat": [
        DefaultCred("admin",  "admin",     "Manager par défaut"),
        DefaultCred("tomcat", "tomcat",    "Compte par défaut"),
        DefaultCred("admin",  "s3cr3t",    "Configuration fréquente"),
        DefaultCred("admin",  "tomcat"),
        DefaultCred("both",   "tomcat"),
        DefaultCred("role",   "changethis"),
        DefaultCred("root",   "root"),
        DefaultCred("admin",  "password"),
    ],

    "jenkins": [
        DefaultCred("admin",   "admin",    "Setup initial Jenkins"),
        DefaultCred("admin",   "password"),
        DefaultCred("jenkins", "jenkins"),
        DefaultCred("admin",   "jenkins"),
        DefaultCred("root",    "root"),
    ],

    "smb": [
        DefaultCred("guest",         "",         "Accès anonyme SMB"),
        DefaultCred("administrator", "",         "Compte admin sans mot de passe"),
        DefaultCred("administrator", "password"),
        DefaultCred("administrator", "Password123!"),
        DefaultCred("admin",         "admin"),
        DefaultCred("",              "",         "NULL session"),
    ],

    "rdp": [
        DefaultCred("administrator", "password"),
        DefaultCred("administrator", "Password123!"),
        DefaultCred("admin",         "admin"),
        DefaultCred("administrator", ""),
    ],

    "vnc": [
        DefaultCred("",     "",         "VNC sans mot de passe"),
        DefaultCred("",     "password"),
        DefaultCred("",     "123456"),
        DefaultCred("",     "admin"),
        DefaultCred("root", "root"),
    ],

    "telnet": [
        DefaultCred("admin", "admin"),
        DefaultCred("root",  "root"),
        DefaultCred("admin", ""),
        DefaultCred("guest", "guest"),
        DefaultCred("user",  "user"),
    ],

    "iis": [
        DefaultCred("administrator", "password"),
        DefaultCred("admin",         "admin"),
        DefaultCred("iusr",          ""),
    ],

    "apache": [
        DefaultCred("admin", "admin",    "Interface d'administration"),
        DefaultCred("admin", "password"),
        DefaultCred("root",  "root"),
    ],

    "nginx": [
        DefaultCred("admin", "admin"),
        DefaultCred("admin", "password"),
    ],

    "elasticsearch": [
        DefaultCred("elastic",  "",        "Elasticsearch sans auth (défaut avant 8.0)"),
        DefaultCred("elastic",  "elastic"),
        DefaultCred("elastic",  "changeme", "Défaut post-7.0"),
        DefaultCred("",         "",         "Accès anonyme (versions < 7.0)"),
    ],

    "grafana": [
        DefaultCred("admin", "admin",    "Défaut Grafana — à changer au premier login"),
        DefaultCred("admin", "password"),
        DefaultCred("admin", "grafana"),
    ],

    "zabbix": [
        DefaultCred("Admin",  "zabbix",   "Compte admin par défaut"),
        DefaultCred("admin",  "zabbix"),
        DefaultCred("Admin",  "admin"),
    ],

    "gitlab": [
        DefaultCred("root",  "5iveL!fe", "Défaut avant GitLab 12.0"),
        DefaultCred("root",  "password"),
        DefaultCred("admin", "admin"),
    ],

    "confluence": [
        DefaultCred("admin",     "admin"),
        DefaultCred("admin",     "confluence"),
        DefaultCred("sysadmin",  "sysadmin"),
    ],

    "webmin": [
        DefaultCred("root", "root"),
        DefaultCred("admin", "admin"),
        DefaultCred("admin", "password"),
    ],

    "phpmyadmin": [
        DefaultCred("root",  "",       "Sans mot de passe — très fréquent"),
        DefaultCred("root",  "root"),
        DefaultCred("admin", "admin"),
        DefaultCred("pma",   ""),
    ],

    "wordpress": [
        DefaultCred("admin",  "admin"),
        DefaultCred("admin",  "password"),
        DefaultCred("admin",  "123456"),
        DefaultCred("editor", "editor"),
    ],

    "snmp": [
        DefaultCred("public",  "",    "Community string read-only par défaut"),
        DefaultCred("private", "",    "Community string read-write par défaut"),
        DefaultCred("manager", "",    "Community string alternative"),
    ],
}

# Alias de service vers les clés de la base
SERVICE_ALIASES: dict[str, str] = {
    "ssh":           "openssh",
    "http":          "apache",
    "http-alt":      "apache",
    "https":         "apache",
    "www":           "apache",
    "3306":          "mysql",
    "5432":          "postgresql",
    "6379":          "redis",
    "27017":         "mongodb",
    "8080":          "tomcat",
    "8443":          "tomcat",
    "8090":          "confluence",
    "3000":          "grafana",
    "161":           "snmp",
    "microsoft-ds":  "smb",
    "netbios-ssn":   "smb",
    "ms-wbt-server": "rdp",
}

# Protocoles Hydra par service
HYDRA_PROTOCOLS: dict[str, str] = {
    "openssh":      "ssh",
    "ftp":          "ftp",
    "mysql":        "mysql",
    "postgresql":   "postgres",
    "redis":        "redis-basic",
    "mongodb":      "mongodb",
    "tomcat":       "http-post-form",
    "smb":          "smb",
    "rdp":          "rdp",
    "vnc":          "vnc",
    "telnet":       "telnet",
    "iis":          "http-get",
    "apache":       "http-get",
    "elasticsearch":"http-get",
    "grafana":      "http-post-form",
    "wordpress":    "http-post-form",
    "webmin":       "https-post-form",
    "gitlab":       "http-post-form",
}

# Wordlists Kali disponibles sur /usr/share/seclists
WORDLISTS = {
    "users":     "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "passwords": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "rockyou":   "/usr/share/wordlists/rockyou.txt",
    "defaults":  "/usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv",
}


# ── Fonctions principales ─────────────────────────────────────────────────────

def _resolve_service(service_name: str, port: int) -> str | None:
    """Résout un nom de service vers une clé de DEFAULT_CREDS."""
    svc = service_name.lower().strip()

    # Match direct
    if svc in DEFAULT_CREDS:
        return svc

    # Alias
    if svc in SERVICE_ALIASES:
        return SERVICE_ALIASES[svc]

    # Alias par port
    port_str = str(port)
    if port_str in SERVICE_ALIASES:
        return SERVICE_ALIASES[port_str]

    # Ports bien connus
    PORT_MAP = {
        21: "ftp", 22: "openssh", 23: "telnet", 80: "apache",
        443: "apache", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 5985: "smb", 6379: "redis", 8080: "tomcat",
        8443: "tomcat", 8090: "confluence", 9200: "elasticsearch",
        27017: "mongodb", 139: "smb", 445: "smb", 161: "snmp",
        3000: "grafana", 10000: "webmin",
    }
    if port in PORT_MAP:
        return PORT_MAP[port]

    return None


def _build_hydra_command(service_key: str, target: str, port: int,
                          creds: list[DefaultCred]) -> str:
    """Génère la commande Hydra optimisée pour le service."""
    proto = HYDRA_PROTOCOLS.get(service_key, service_key)

    # Construit une mini-liste des logins et passwords connus
    users    = list(dict.fromkeys(c.username for c in creds if c.username))
    passwords = list(dict.fromkeys(c.password for c in creds))

    users_str    = ",".join(users[:5]) if users else "admin"
    pass_str     = ",".join(f'"{p}"' for p in passwords[:5]) if passwords else '""'

    port_arg = f" -s {port}" if port not in (21, 22, 23, 80, 443, 3306, 3389, 5432, 5900, 6379, 27017, 139, 445) else ""

    # Commandes spécialisées par service
    if service_key == "tomcat":
        return (f"hydra -L <(echo -e '{chr(10).join(users[:4])}') "
                f"-P <(echo -e '{chr(10).join(passwords[:4])}') "
                f"{target}{port_arg} http-get /manager/html")

    if service_key == "wordpress":
        return (f"hydra -l admin "
                f"-P {WORDLISTS['rockyou']} "
                f"{target}{port_arg} http-post-form "
                f"'/wp-login.php:log=^USER^&pwd=^PASS^:Invalid username'")

    if service_key == "grafana":
        return (f"hydra -l admin "
                f"-P {WORDLISTS['passwords']} "
                f"{target}{port_arg} http-post-form "
                f"'/login:user=^USER^&password=^PASS^:Invalid'")

    if service_key in ("smb", "rdp"):
        return (f"hydra -L {WORDLISTS['users']} "
                f"-P {WORDLISTS['passwords']} "
                f"{proto}://{target}{port_arg}")

    if service_key == "snmp":
        return (f"onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt "
                f"{target}")

    # Commande générique
    return (f"hydra -L {WORDLISTS['users']} "
            f"-P {WORDLISTS['passwords']} "
            f"{proto}://{target}{port_arg}")


def _build_quick_test(service_key: str, target: str, port: int,
                       creds: list[DefaultCred]) -> str:
    """Commande de test rapide pour les premiers creds sans brute-force."""
    if not creds:
        return ""

    c = creds[0]  # Premier credential (le plus probable)

    cmds = {
        "ftp":        f"ftp {target}  # login: {c.username} / pass: {c.password or '(vide)'}",
        "openssh":    f"ssh {c.username}@{target} -p {port}",
        "mysql":      f"mysql -h {target} -u {c.username} {'-p' + c.password if c.password else '--password='} 2>/dev/null",
        "postgresql": f"psql -h {target} -U {c.username} -c '\\l' 2>/dev/null",
        "redis":      f"redis-cli -h {target} -p {port} ping",
        "mongodb":    f"mongosh {target}:{port} --eval 'db.adminCommand({{listDatabases: 1}})'",
        "smb":        f"smbclient -L //{target} -U '{c.username}%{c.password}' -N",
        "rdp":        f"xfreerdp /v:{target} /u:{c.username} /p:'{c.password}' /cert-ignore 2>/dev/null",
        "vnc":        f"vncviewer {target}:{port}",
        "snmp":       f"snmpwalk -v2c -c public {target}",
        "elasticsearch": f"curl -s http://{target}:{port}/_cat/indices",
        "tomcat":     f"curl -u '{c.username}:{c.password}' http://{target}:{port}/manager/html",
        "grafana":    f"curl -s -u '{c.username}:{c.password}' http://{target}:{port}/api/org",
        "webmin":     f"curl -k -s -u '{c.username}:{c.password}' https://{target}:{port}/",
    }

    return cmds.get(service_key, f"# Test manuel: {c.username}:{c.password or '(vide)'}")


def get_default_creds(service_name: str, port: int,
                       target: str = "TARGET") -> CredResult | None:
    """
    Retourne les credentials par défaut et commandes associées
    pour un service donné.
    Retourne None si le service n'est pas dans la base.
    """
    service_key = _resolve_service(service_name, port)
    if not service_key or service_key not in DEFAULT_CREDS:
        return None

    creds = DEFAULT_CREDS[service_key]

    return CredResult(
        service=service_key,
        port=port,
        target=target,
        creds=creds,
        hydra_cmd=_build_hydra_command(service_key, target, port, creds),
        quick_test=_build_quick_test(service_key, target, port, creds),
        protocol=HYDRA_PROTOCOLS.get(service_key, service_key),
    )


def enrich_results_with_creds(results: list[dict],
                                target: str = "TARGET") -> list[dict]:
    """
    Enrichit les résultats du pipeline avec les credentials par défaut.
    Ajoute la clé 'default_creds' sur chaque service.
    """
    for result in results:
        svc = result.get("service", {})
        service_name = svc.get("service_name", "")
        port = svc.get("port", 0)
        cred_result = get_default_creds(service_name, port, target)
        if cred_result:
            result["default_creds"] = {
                "creds": [{"username": c.username, "password": c.password, "note": c.note}
                           for c in cred_result.creds],
                "hydra_cmd":  cred_result.hydra_cmd,
                "quick_test": cred_result.quick_test,
            }
    return results
