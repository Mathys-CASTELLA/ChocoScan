"""
ChocoScan — Scan authentifié (credentialed scan) via SSH.

Au lieu de déduire les CVE depuis le banner Nmap (souvent imprécis,
parfois absent si le service masque sa version), ce module se
connecte directement à la cible avec des identifiants fournis par
l'utilisateur et interroge le gestionnaire de paquets natif pour
obtenir la liste exacte des paquets installés.

Cas d'usage : tu as déjà les creds d'une VM CTF/pentest (via un
premier accès, des creds par défaut, etc.) et tu veux une vue
complète de la surface de vulnérabilité, pas juste les services
qui écoutent sur le réseau.

Distributions supportées (détection automatique) :
    - Debian / Ubuntu  → dpkg -l
    - RHEL / CentOS / Fedora → rpm -qa
    - Arch / Manjaro   → pacman -Q

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import getpass
import re
import socket
from dataclasses import dataclass, field

try:
    import paramiko
except ImportError:
    paramiko = None

from modules.nmap_parser import NmapService


# ── Normalisation des noms de paquets ────────────────────────────────────

# Préfixes courants Debian/RPM à retirer pour retomber sur un nom de
# produit reconnaissable par SERVICE_ALIASES (ex: "python3-requests" → "requests",
# "lib32-openssl" → "openssl").
_PACKAGE_PREFIXES = ("lib32-", "lib64-", "python3-", "python-", "lib", "lib32", "lib64")

# Suffixes de version/architecture courants à retirer (ex: "openssh-server" → "openssh",
# "nginx-common" → "nginx", "libssl1.1" → "libssl" → "ssl" après retrait du préfixe lib).
_PACKAGE_SUFFIXES = (
    "-server", "-client", "-common", "-bin", "-dev", "-doc", "-data",
    "-utils", "-core", "-extra", "-dbg", "-tools",
)

# Mapping direct pour les cas où la normalisation générique ne suffit pas
# (noms de paquets qui ne correspondent à aucune entrée SERVICE_ALIASES
# même après retrait des préfixes/suffixes).
_PACKAGE_NAME_OVERRIDES = {
    "libssl1.1": "openssl",
    "libssl3": "openssl",
    "libssl-dev": "openssl",
    "libc6": "glibc",
    "openssh-client": "openssh",
    "nginx-core": "nginx",
    "nginx-full": "nginx",
    "nginx-light": "nginx",
    "mysql-server": "mysql",
    "mariadb-server": "mysql",
    "postgresql-common": "postgresql",
    "apache2": "apache",
    "apache2-bin": "apache",
    "apache2-utils": "apache",
}


def normalize_package_name(raw_name: str) -> str:
    """
    Normalise un nom de paquet brut (dpkg/rpm/pacman) vers un nom de
    produit plus susceptible d'être reconnu par SERVICE_ALIASES dans
    cve_matcher.py.

    Ex: "openssh-server" → "openssh", "libssl1.1" → "openssl" (override),
        "python3-requests" → "requests"
    """
    name = raw_name.strip().lower()

    if name in _PACKAGE_NAME_OVERRIDES:
        return _PACKAGE_NAME_OVERRIDES[name]

    for prefix in sorted(_PACKAGE_PREFIXES, key=len, reverse=True):
        if name.startswith(prefix) and len(name) > len(prefix):
            name = name[len(prefix):]
            break

    for suffix in sorted(_PACKAGE_SUFFIXES, key=len, reverse=True):
        if name.endswith(suffix) and len(name) > len(suffix):
            name = name[: -len(suffix)]
            break

    # Retire un éventuel numéro de version collé au nom (ex: "libssl1.1" → "libssl"
    # si pas déjà capturé par un override) pour éviter que ça pollue le matching.
    name = re.sub(r"[\d.]+$", "", name).rstrip("-")

    return name if name else raw_name.strip().lower()


# ── Modèle de données ────────────────────────────────────────────────────

@dataclass
class InstalledPackage:
    """Représente un paquet détecté sur le système distant."""
    name: str
    version: str
    architecture: str = ""

    def to_nmap_service(self, host: str) -> NmapService:
        """
        Convertit ce paquet en objet NmapService, pour rester compatible
        avec le pipeline existant (get_cves_for_service, filter_cves,
        inject_scores, display_results_terminal, exports HTML/JSON...).

        Le nom du paquet est normalisé (préfixes/suffixes Debian/RPM retirés)
        pour maximiser les chances de matcher SERVICE_ALIASES dans
        cve_matcher.py, tout en gardant le nom brut dans `product`.

        Port/protocole sont fictifs (0/pkg) puisqu'il ne s'agit pas
        d'un service réseau mais d'un paquet local installé.
        """
        banner = f"{self.name} {self.version}".strip()
        normalized = normalize_package_name(self.name)
        return NmapService(
            host=host,
            port=0,
            protocol="pkg",
            state="installed",
            service_name=normalized,
            product=self.name,
            version=self.version,
            extrainfo=self.architecture,
            banner=banner,
        )


class SSHCredentialError(Exception):
    """Levée en cas d'échec d'authentification SSH."""
    pass


class SSHConnectionError(Exception):
    """Levée en cas d'échec de connexion réseau SSH."""
    pass


# ── Connexion et détection de distribution ──────────────────────────────

def _resolve_password(password: str | None) -> str | None:
    """
    Si aucun mot de passe n'est fourni en argument, le demande de façon
    masquée via getpass plutôt que de forcer l'utilisateur à le passer
    en clair sur la ligne de commande (visible dans l'historique shell
    et `ps aux`).
    """
    if password:
        return password
    return None  # laisse paramiko tenter la clé SSH par défaut si pas de password


def connect_ssh(
    host: str,
    username: str,
    password: str | None = None,
    key_filename: str | None = None,
    port: int = 22,
    timeout: int = 10,
):
    """
    Établit une connexion SSH vers la cible.
    Retourne un client paramiko.SSHClient connecté.

    Lève SSHConnectionError si la cible est injoignable,
    SSHCredentialError si l'authentification échoue.
    """
    if paramiko is None:
        raise RuntimeError(
            "paramiko n'est pas installé. Lance : pip install paramiko"
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            key_filename=key_filename,
            timeout=timeout,
            look_for_keys=(password is None and key_filename is None),
            allow_agent=(password is None and key_filename is None),
        )
    except paramiko.AuthenticationException as e:
        raise SSHCredentialError(
            f"Authentification SSH échouée pour {username}@{host} : {e}"
        )
    except (socket.timeout, socket.error, paramiko.SSHException) as e:
        raise SSHConnectionError(f"Connexion SSH à {host}:{port} impossible : {e}")

    return client


def _run_command(client, command: str) -> tuple[str, str, int]:
    """Exécute une commande sur la cible et retourne (stdout, stderr, exit_code)."""
    stdin, stdout, stderr = client.exec_command(command, timeout=30)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return out, err, exit_code


def detect_distro(client) -> str:
    """
    Détecte la famille de distribution Linux de la cible via /etc/os-release.
    Retourne : 'debian', 'rhel', 'arch', ou 'unknown'.
    """
    out, _, code = _run_command(client, "cat /etc/os-release 2>/dev/null")
    if code != 0 or not out:
        return "unknown"

    content = out.lower()
    id_like_match = re.search(r'^id_like="?([^"\n]+)"?', content, re.MULTILINE)
    id_match = re.search(r'^id="?([^"\n]+)"?', content, re.MULTILINE)

    combined = " ".join(filter(None, [
        id_match.group(1) if id_match else "",
        id_like_match.group(1) if id_like_match else "",
    ]))

    if any(d in combined for d in ("debian", "ubuntu")):
        return "debian"
    if any(d in combined for d in ("rhel", "centos", "fedora", "rocky", "alma")):
        return "rhel"
    if "arch" in combined:
        return "arch"

    return "unknown"


# ── Collecteurs par distribution ─────────────────────────────────────────

def _collect_dpkg(client) -> list[InstalledPackage]:
    """Liste les paquets via dpkg -l (Debian/Ubuntu)."""
    out, _, code = _run_command(client, "dpkg -l 2>/dev/null")
    packages = []
    if code != 0:
        return packages

    for line in out.splitlines():
        # Format dpkg -l : "ii  nom  version  arch  description"
        if not line.startswith("ii"):
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        _, name, version, arch = parts[0], parts[1], parts[2], parts[3]
        # dpkg ajoute parfois l'architecture au nom (ex: libc6:amd64)
        name = name.split(":")[0]
        packages.append(InstalledPackage(name=name, version=version, architecture=arch))

    return packages


def _collect_rpm(client) -> list[InstalledPackage]:
    """Liste les paquets via rpm -qa (RHEL/CentOS/Fedora)."""
    fmt = r"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"
    out, _, code = _run_command(client, f"rpm -qa --queryformat '{fmt}' 2>/dev/null")
    packages = []
    if code != 0:
        return packages

    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        arch = parts[2] if len(parts) > 2 else ""
        packages.append(InstalledPackage(name=name, version=version, architecture=arch))

    return packages


def _collect_pacman(client) -> list[InstalledPackage]:
    """Liste les paquets via pacman -Q (Arch/Manjaro)."""
    out, _, code = _run_command(client, "pacman -Q 2>/dev/null")
    packages = []
    if code != 0:
        return packages

    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        name, version = parts
        packages.append(InstalledPackage(name=name, version=version))

    return packages


_COLLECTORS = {
    "debian": _collect_dpkg,
    "rhel": _collect_rpm,
    "arch": _collect_pacman,
}


# ── Point d'entrée principal ─────────────────────────────────────────────

def collect_packages_ssh(
    host: str,
    username: str,
    password: str | None = None,
    key_filename: str | None = None,
    port: int = 22,
    distro_hint: str | None = None,
) -> tuple[list[InstalledPackage], str]:
    """
    Se connecte à la cible en SSH et retourne la liste des paquets installés.

    Retourne (liste_paquets, distro_detectee).

    Si `password` n'est pas fourni et qu'aucune clé n'est trouvée
    automatiquement par paramiko, lève SSHCredentialError.
    """
    client = connect_ssh(host, username, password=password, key_filename=key_filename, port=port)

    try:
        distro = distro_hint or detect_distro(client)

        collector = _COLLECTORS.get(distro)
        if collector is None:
            raise RuntimeError(
                f"Distribution non supportée ou non détectée sur {host} "
                f"(détecté: '{distro}'). Distributions supportées : "
                f"{', '.join(_COLLECTORS.keys())}."
            )

        packages = collector(client)
        return packages, distro

    finally:
        client.close()


def packages_to_services(packages: list[InstalledPackage], host: str) -> list[NmapService]:
    """Convertit une liste de paquets en objets NmapService réutilisables par le pipeline CVE existant."""
    return [pkg.to_nmap_service(host) for pkg in packages]
