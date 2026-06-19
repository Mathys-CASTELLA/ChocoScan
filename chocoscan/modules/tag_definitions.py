"""
ChocoScan — Taxonomie des tags CVE
====================================

Catalogue officiel des tags disponibles, avec pour chacun :
  - description lisible
  - icône terminal + couleur curses
  - couleur HTML pour le rapport
  - bonus de score contextuel (ajout au ctx_score final)
  - services et mots-clés pour le tagging automatique

Tags de contexte technique   : #web, #windows, #linux, #network, #database, #devops, #iot
Tags de menace               : #apt, #ransomware, #supply-chain, #initial-access, #lateral
Tags d'exploitation          : #ctf-frequent, #exploit-public, #no-auth, #rce-chain
Tags de surface d'attaque    : #cloud, #active-directory, #container
"""

from __future__ import annotations
from dataclasses import dataclass, field


# ─── Structure d'un tag ───────────────────────────────────────────────────────

@dataclass
class TagDef:
    name: str                    # identifiant sans # (ex: "apt")
    label: str                   # libellé affiché (ex: "APT")
    description: str             # description courte
    icon: str                    # icône terminal (1-2 chars)
    color_curses: int            # indice de paire curses (défini dans interactive.py)
    color_html: str              # couleur CSS hex
    score_bonus: float           # bonus ajouté au ctx_score (0.0 → 1.5)
    auto_services: list[str]     # services qui reçoivent ce tag automatiquement
    auto_keywords: list[str]     # mots-clés dans description → tag automatique
    group: str                   # groupe d'affichage : "threat" | "tech" | "exploit" | "surface"


# ─── Catalogue complet ────────────────────────────────────────────────────────

TAGS: dict[str, TagDef] = {

    # ══ MENACE — impact réel observé dans la nature ════════════════════════════

    "apt": TagDef(
        name          = "apt",
        label         = "APT",
        description   = "Exploitée par des groupes APT étatiques (espionnage, sabotage)",
        icon          = "⬡",
        color_curses  = 3,   # RED → défini dynamiquement dans interactive
        color_html    = "#ef4444",
        score_bonus   = 1.5,
        auto_services = [],
        auto_keywords = [
            "apt", "nation-state", "state-sponsored", "advanced persistent",
            "lazarus", "cobalt strike", "fancy bear", "cozy bear", "apt28", "apt29",
            "equation group", "shadow brokers", "volt typhoon", "salt typhoon",
            "mandiant", "crowdstrike", "fin7", "fin8", "darkside", "revil",
            "hafnium", "nobelium", "midnight blizzard",
        ],
        group = "threat",
    ),

    "ransomware": TagDef(
        name          = "ransomware",
        label         = "Ransomware",
        description   = "Vecteur d'entrée ou pivot utilisé dans des campagnes ransomware",
        icon          = "⬢",
        color_curses  = 3,   # RED
        color_html    = "#f97316",
        score_bonus   = 1.3,
        auto_services = [],
        auto_keywords = [
            "ransomware", "wannacry", "notpetya", "ryuk", "lockbit", "blackcat",
            "alphv", "clop", "cl0p", "hive", "black basta", "akira",
            "revil", "sodinokibi", "darkside", "conti", "maze",
            "eternalblue", "ms17-010",  # EternalBlue = ransomware primaire
        ],
        group = "threat",
    ),

    "supply-chain": TagDef(
        name          = "supply-chain",
        label         = "Supply-Chain",
        description   = "Attaque via la chaîne d'approvisionnement logicielle",
        icon          = "⬟",
        color_curses  = 4,   # YELLOW
        color_html    = "#a78bfa",
        score_bonus   = 1.1,
        auto_services = ["maven", "npm", "pypi"],
        auto_keywords = [
            "supply chain", "supply-chain", "build system", "package manager",
            "solarwinds", "codecov", "xz utils", "xz-utils", "liblzma",
            "3cxdesktopapp", "mooverang", "dependency", "upstream",
            "malicious.*package", "typosquat",
        ],
        group = "threat",
    ),

    "initial-access": TagDef(
        name          = "initial-access",
        label         = "Initial Access",
        description   = "Permet un accès initial sans authentification préalable",
        icon          = "▶",
        color_curses  = 3,   # RED
        color_html    = "#fb923c",
        score_bonus   = 0.9,
        auto_services = [],
        auto_keywords = [
            "unauthenticated", "without authentication", "no authentication",
            "pre-auth", "pre-authentication", "anonymous", "remote code execution",
            "unauthenticated rce", "initial access", "non authentifié",
        ],
        group = "threat",
    ),

    "lateral": TagDef(
        name          = "lateral",
        label         = "Lateral Movement",
        description   = "Permet le déplacement latéral dans un réseau compromis",
        icon          = "→",
        color_curses  = 4,   # YELLOW
        color_html    = "#fbbf24",
        score_bonus   = 0.8,
        auto_services = ["smb", "rdp", "kerberos", "ldap", "winrm", "rpc"],
        auto_keywords = [
            "lateral movement", "pass-the-hash", "pass-the-ticket",
            "kerberoasting", "dcsync", "golden ticket", "silver ticket",
            "mimikatz", "impacket", "responder", "ntlm relay",
            "pivot", "movement.*network", "network.*movement",
        ],
        group = "threat",
    ),

    # ══ CONTEXTE TECHNIQUE ════════════════════════════════════════════════════

    "web": TagDef(
        name          = "web",
        label         = "Web",
        description   = "Application ou serveur web (HTTP/HTTPS)",
        icon          = "🌐",
        color_curses  = 6,   # CYAN
        color_html    = "#38bdf8",
        score_bonus   = 0.0,
        auto_services = [
            "apache", "nginx", "iis", "tomcat", "php", "wordpress", "drupal",
            "joomla", "weblogic", "nostromo", "coldfusion", "struts", "spring",
            "django", "laravel", "roundcube", "confluence", "jira", "jenkins",
            "gitlab", "grafana", "kibana", "phpmyadmin", "webmin", "adminer",
            "sonarqube", "owncloud", "harbor", "moodle", "prestashop", "magento",
            "typo3", "concrete5", "ghost_cms", "rstudio", "jupyter", "glpi",
            "cacti", "nagios", "zabbix", "octopus", "bamboo", "teamcity",
            "sharepoint", "exchange", "zimbra",
        ],
        auto_keywords = [
            "http", "web", "application", "url", "uri", "request", "response",
            "sql injection", "xss", "csrf", "ssrf", "path traversal",
            "directory traversal", "file inclusion", "lfi", "rfi", "ssti",
            "deserialization", "ognl", "template injection",
        ],
        group = "tech",
    ),

    "windows": TagDef(
        name          = "windows",
        label         = "Windows",
        description   = "Systèmes Windows / Active Directory",
        icon          = "⊞",
        color_curses  = 6,   # CYAN
        color_html    = "#60a5fa",
        score_bonus   = 0.0,
        auto_services = [
            "smb", "rdp", "iis", "rpc", "winrm", "kerberos", "ldap",
            "exchange", "sharepoint", "windows", "mssql", "wmi",
        ],
        auto_keywords = [
            "windows", "microsoft", "ntfs", "ntlm", "active directory",
            "domain controller", "smb", "netbios", "rdp", "remote desktop",
            "wmi", "powershell", "com object", "ole", "dcom",
        ],
        group = "tech",
    ),

    "linux": TagDef(
        name          = "linux",
        label         = "Linux",
        description   = "Systèmes Linux / Unix (kernel, sudo, services système)",
        icon          = "🐧",
        color_curses  = 5,   # GREEN
        color_html    = "#4ade80",
        score_bonus   = 0.0,
        auto_services = [
            "sudo", "polkit", "kernel", "openssh", "nfs", "cups",
            "rsyslog", "x11", "distcc", "vsftpd", "proftpd",
        ],
        auto_keywords = [
            "linux", "unix", "kernel", "sudo", "setuid", "suid",
            "privilege escalation", "local root", "cgroup", "namespace",
            "procfs", "sysfs", "glibc", "libc",
        ],
        group = "tech",
    ),

    "network": TagDef(
        name          = "network",
        label         = "Network",
        description   = "Infrastructure réseau (VPN, firewall, DNS, SNMP)",
        icon          = "⬡",
        color_curses  = 6,   # CYAN
        color_html    = "#818cf8",
        score_bonus   = 0.0,
        auto_services = [
            "dns", "snmp", "telnet", "ftp", "vsftpd", "proftpd", "ssl",
            "openvpn", "fortinet", "paloalto", "asa", "f5", "junos",
            "ivanti", "citrix", "haproxy", "traefik", "squid",
        ],
        auto_keywords = [
            "vpn", "firewall", "router", "switch", "network device",
            "firmware", "snmp", "dns", "dhcp", "bgp", "ospf",
        ],
        group = "tech",
    ),

    "database": TagDef(
        name          = "database",
        label         = "Database",
        description   = "Serveur de base de données",
        icon          = "⬡",
        color_curses  = 4,   # YELLOW
        color_html    = "#fde047",
        score_bonus   = 0.0,
        auto_services = [
            "mysql", "postgresql", "redis", "mongodb", "elasticsearch",
            "couchdb", "memcached", "cassandra", "influxdb", "neo4j",
            "h2_database", "clickhouse", "mssql", "oracle",
        ],
        auto_keywords = [
            "database", "sql", "nosql", "query", "injection",
            "credentials", "authentication bypass.*database",
        ],
        group = "tech",
    ),

    "devops": TagDef(
        name          = "devops",
        label         = "DevOps / CI-CD",
        description   = "Pipeline CI/CD, registres, orchestration (Jenkins, GitLab, K8s)",
        icon          = "⚙",
        color_curses  = 6,   # CYAN
        color_html    = "#34d399",
        score_bonus   = 0.2,
        auto_services = [
            "docker", "kubernetes", "jenkins", "gitlab", "teamcity", "gitea",
            "gogs", "consul", "vault", "etcd", "portainer", "minio",
            "sonarqube", "activemq", "rabbitmq", "kafka", "prometheus",
            "grafana", "airflow", "bamboo", "octopus",
        ],
        auto_keywords = [
            "ci/cd", "pipeline", "build server", "container", "docker",
            "kubernetes", "registry", "artifact", "deploy",
        ],
        group = "tech",
    ),

    "iot": TagDef(
        name          = "iot",
        label         = "IoT / SCADA",
        description   = "Équipements IoT, systèmes industriels (ICS/SCADA)",
        icon          = "⬡",
        color_curses  = 4,   # YELLOW
        color_html    = "#fb7185",
        score_bonus   = 0.3,
        auto_services = ["mqtt", "coap", "modbus", "dnp3", "s7comm"],
        auto_keywords = [
            "iot", "industrial", "scada", "ics", "plc", "hmi",
            "embedded", "firmware", "ot ", "operational technology",
            "mqtt", "modbus", "profinet",
        ],
        group = "tech",
    ),

    # ══ SURFACE D'ATTAQUE ═════════════════════════════════════════════════════

    "active-directory": TagDef(
        name          = "active-directory",
        label         = "Active Directory",
        description   = "Cible ou pivot dans un environnement Active Directory",
        icon          = "AD",
        color_curses  = 4,   # YELLOW
        color_html    = "#fb923c",
        score_bonus   = 0.5,
        auto_services = ["kerberos", "ldap", "smb", "rpc", "winrm"],
        auto_keywords = [
            "active directory", "domain controller", "kerberos", "kerberoasting",
            "dcsync", "ntlm", "ldap", "forest", "domain trust",
            "bloodhound", "sharphound", "adcs", "certipy",
        ],
        group = "surface",
    ),

    "cloud": TagDef(
        name          = "cloud",
        label         = "Cloud",
        description   = "Infrastructure cloud (AWS, Azure, GCP) ou services SaaS",
        icon          = "☁",
        color_curses  = 6,   # CYAN
        color_html    = "#7dd3fc",
        score_bonus   = 0.2,
        auto_services = ["minio", "kubernetes", "etcd", "consul"],
        auto_keywords = [
            "aws", "azure", "gcp", "s3 bucket", "cloud", "saas",
            "imds", "metadata service", "instance metadata",
            "iam role", "sts", "assume role",
        ],
        group = "surface",
    ),

    "container": TagDef(
        name          = "container",
        label         = "Container Escape",
        description   = "Évasion de conteneur ou compromission de l'hôte via container",
        icon          = "⬡",
        color_curses  = 3,   # RED
        color_html    = "#f43f5e",
        score_bonus   = 0.8,
        auto_services = ["docker", "kubernetes", "runc", "containerd"],
        auto_keywords = [
            "container escape", "container breakout", "cgroup escape",
            "docker escape", "runc", "privileged container",
            "host namespace", "évasion de conteneur",
        ],
        group = "surface",
    ),

    # ══ EXPLOITATION ══════════════════════════════════════════════════════════

    "ctf-frequent": TagDef(
        name          = "ctf-frequent",
        label         = "CTF Fréquent",
        description   = "Régulièrement rencontrée sur HackTheBox / TryHackMe / CTF",
        icon          = "🏴",
        color_curses  = 5,   # GREEN
        color_html    = "#86efac",
        score_bonus   = 0.3,
        auto_services = [],
        auto_keywords = [],  # géré par ctf_machines dans update_db_ctf
        group = "exploit",
    ),

    "exploit-public": TagDef(
        name          = "exploit-public",
        label         = "Exploit Public",
        description   = "PoC ou exploit public disponible (ExploitDB, Metasploit, GitHub)",
        icon          = "★",
        color_curses  = 4,   # YELLOW
        color_html    = "#fbbf24",
        score_bonus   = 0.2,
        auto_services = [],
        auto_keywords = [],  # géré par exploit_available + exploit_db + metasploit
        group = "exploit",
    ),

    "no-auth": TagDef(
        name          = "no-auth",
        label         = "No Auth",
        description   = "Exploitable sans authentification préalable",
        icon          = "🔓",
        color_curses  = 3,   # RED
        color_html    = "#22d3ee",
        score_bonus   = 0.4,
        auto_services = [],
        auto_keywords = [
            "unauthenticated", "without authentication", "no authentication required",
            "no auth", "pre-auth", "pre-authentication", "before authentication",
            "anonymous", "sans authentification", "non authentifié",
            "pré-authentification",
        ],
        group = "exploit",
    ),

    "rce-chain": TagDef(
        name          = "rce-chain",
        label         = "RCE Chain",
        description   = "RCE obtenu par chaînage de vulnérabilités",
        icon          = "⛓",
        color_curses  = 3,   # RED
        color_html    = "#ef4444",
        score_bonus   = 0.6,
        auto_services = [],
        auto_keywords = [
            "chain", "combine", "bypass.*fix", "bypass.*patch",
            "second.*stage", "two.*stage", "file upload.*rce",
            "ssrf.*rce", "xxe.*rce", "deserialization.*rce",
            "ghostcat",  # Ghostcat = file-read → RCE via upload
        ],
        group = "exploit",
    ),
}


# ─── Accès rapide ─────────────────────────────────────────────────────────────

ALL_TAG_NAMES: set[str] = set(TAGS.keys())

def get(tag_name: str) -> TagDef | None:
    """Retourne la définition d'un tag par son nom (sans #)."""
    return TAGS.get(tag_name.lstrip("#"))

def bonus(tags: list[str]) -> float:
    """Calcule le bonus de score total pour une liste de tags."""
    return sum(TAGS[t.lstrip("#")].score_bonus
               for t in tags
               if t.lstrip("#") in TAGS)

def html_badges(tags: list[str]) -> str:
    """Génère les badges HTML pour une liste de tags."""
    badges = []
    for t in tags:
        name = t.lstrip("#")
        td = TAGS.get(name)
        if not td:
            continue
        badges.append(
            f'<span class="cve-tag" style="'
            f'border-color:{td.color_html}33;'
            f'color:{td.color_html};'
            f'background:{td.color_html}18">'
            f'{td.icon} #{name}'
            f'</span>'
        )
    return " ".join(badges)


# ─── CSS pour les badges HTML ─────────────────────────────────────────────────

TAG_CSS = """
  /* ── Tags CVE ────────────────────────────────────── */
  .cve-tags {
    display: flex; flex-wrap: wrap; gap: .25rem; margin-top: .3rem;
  }
  .cve-tag {
    font-size: .62rem; font-weight: 700;
    padding: .1rem .35rem; border-radius: 4px;
    border: 1px solid; white-space: nowrap;
    font-family: 'Courier New', monospace;
    letter-spacing: .02em;
  }
  /* Filtre tag dans le rapport */
  .tag-filter-bar {
    display: flex; flex-wrap: wrap; gap: .3rem;
    margin: .5rem 0 1rem; padding: .5rem;
    background: #0e1225; border-radius: 6px;
    border: 1px solid #1c2240;
  }
  .tag-filter-btn {
    cursor: pointer; font-size: .7rem; font-weight: 700;
    padding: .2rem .5rem; border-radius: 4px;
    border: 1px solid; transition: opacity .15s;
  }
  .tag-filter-btn.active { opacity: 1; }
  .tag-filter-btn.inactive { opacity: .35; }
"""
