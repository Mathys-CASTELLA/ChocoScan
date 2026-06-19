"""
Module de parsing des résultats Nmap.
Supporte les formats XML (-oX) et texte normal.
"""

import xml.etree.ElementTree as ET
import re
import subprocess
import os
import shutil
import shlex
import platform
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NmapService:
    """Représente un service découvert par nmap."""
    host: str
    port: int
    protocol: str
    state: str
    service_name: str
    product: str
    version: str
    extrainfo: str
    banner: str  # product + version + extrainfo combinés

    def __str__(self):
        return f"{self.host}:{self.port}/{self.protocol} [{self.state}] {self.banner}"


def parse_nmap_xml(xml_file: str) -> list[NmapService]:
    """Parse un fichier XML nmap (-oX)."""
    services = []

    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host in root.findall("host"):
        # IP de l'hôte
        address_elem = host.find("address[@addrtype='ipv4']")
        if address_elem is None:
            address_elem = host.find("address[@addrtype='ipv6']")
        host_ip = address_elem.attrib.get("addr", "unknown") if address_elem is not None else "unknown"

        # Hostname si disponible
        hostname_elem = host.find("hostnames/hostname")
        hostname = hostname_elem.attrib.get("name", "") if hostname_elem is not None else ""

        # Ports
        for port_elem in host.findall("ports/port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.attrib.get("state") != "open":
                continue

            port_id = int(port_elem.attrib.get("portid", 0))
            protocol = port_elem.attrib.get("protocol", "tcp")

            service_elem = port_elem.find("service")
            if service_elem is not None:
                service_name = service_elem.attrib.get("name", "unknown")
                product = service_elem.attrib.get("product", "")
                version = service_elem.attrib.get("version", "")
                extrainfo = service_elem.attrib.get("extrainfo", "")
            else:
                service_name = "unknown"
                product = version = extrainfo = ""

            banner = " ".join(filter(None, [product, version, extrainfo])).strip()

            services.append(NmapService(
                host=hostname or host_ip,
                port=port_id,
                protocol=protocol,
                state="open",
                service_name=service_name,
                product=product,
                version=version,
                extrainfo=extrainfo,
                banner=banner,
            ))

    return services


def parse_nmap_text(text_output: str) -> list[NmapService]:
    """
    Parse la sortie texte standard nmap (pour les cas sans XML).
    Moins précis que le XML mais utile comme fallback.
    """
    services = []
    current_host = "unknown"

    for line in text_output.splitlines():
        line = line.strip()

        # Détecte l'hôte
        host_match = re.match(r'Nmap scan report for (.+)', line)
        if host_match:
            current_host = host_match.group(1).strip()
            # Extrait l'IP si format "hostname (ip)"
            ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', current_host)
            if ip_match:
                current_host = ip_match.group(1)
            continue

        # Détecte les ports ouverts
        # Format: 22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
        port_match = re.match(
            r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)',
            line
        )
        if port_match:
            port = int(port_match.group(1))
            protocol = port_match.group(2)
            state = port_match.group(3)
            service_name = port_match.group(4)
            banner = port_match.group(5).strip()

            if state == "open":
                services.append(NmapService(
                    host=current_host,
                    port=port,
                    protocol=protocol,
                    state=state,
                    service_name=service_name,
                    product=banner.split()[0] if banner else "",
                    version=" ".join(banner.split()[1:]) if len(banner.split()) > 1 else "",
                    extrainfo="",
                    banner=banner,
                ))

    return services


def find_nmap_binary() -> Optional[str]:
    """
    Localise le binaire nmap sur le système.

    Cherche dans le PATH standard, puis dans les emplacements courants
    qui ne sont pas toujours dans le PATH (Homebrew sur macOS, etc).

    Returns:
        Chemin absolu vers nmap, ou None si introuvable.
    """
    found = shutil.which("nmap")
    if found:
        return found

    # Emplacements connus pour ne pas toujours être dans le PATH
    common_paths = [
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/homebrew/bin/nmap",       # macOS Apple Silicon (Homebrew)
        "/usr/local/opt/nmap/bin/nmap", # macOS Intel (Homebrew)
        "/opt/local/bin/nmap",          # MacPorts
        "C:\\Program Files (x86)\\Nmap\\nmap.exe",
        "C:\\Program Files\\Nmap\\nmap.exe",
    ]
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None


def _install_hint() -> str:
    """Retourne la commande d'installation adaptée à l'OS courant."""
    system = platform.system()
    if system == "Darwin":
        return "brew install nmap"
    elif system == "Linux":
        # Détecter la distro si possible
        if os.path.isfile("/etc/debian_version"):
            return "sudo apt install nmap"
        elif os.path.isfile("/etc/redhat-release"):
            return "sudo dnf install nmap   (ou: sudo yum install nmap)"
        elif os.path.isfile("/etc/arch-release"):
            return "sudo pacman -S nmap"
        else:
            return "sudo apt install nmap   (ou le gestionnaire de paquets de votre distro)"
    elif system == "Windows":
        return "Téléchargez l'installeur sur https://nmap.org/download.html"
    else:
        return "Consultez https://nmap.org/download.html"


def _needs_privileges(extra_args: str) -> bool:
    """
    Détermine si les arguments nmap demandent des privilèges root/admin.

    Les scans SYN (-sS), UDP (-sU), OS detection (-O) et certains scripts
    nécessitent des sockets raw, donc root sur Unix ou admin sur Windows.
    """
    privileged_flags = ("-sS", "-sU", "-sO", "-sA", "-sW", "-sM", "-O", "--traceroute")
    tokens = extra_args.split()
    return any(flag in tokens for flag in privileged_flags)


def _has_raw_socket_capability() -> bool:
    """Vérifie si le process actuel peut probablement ouvrir des raw sockets."""
    system = platform.system()
    if system == "Windows":
        return True  # Nmap gère différemment sous Windows (Npcap)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    # Vérifier la capability Linux cap_net_raw sur le binaire nmap (setcap)
    nmap_path = find_nmap_binary()
    if nmap_path and system == "Linux":
        try:
            result = subprocess.run(
                ["getcap", nmap_path],
                capture_output=True, text=True, timeout=5,
            )
            if "cap_net_raw" in result.stdout:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    return False


def run_nmap_scan(
    target: str,
    output_xml: str,
    extra_args: str = "",
    timeout: int = 300,
) -> Optional[list[NmapService]]:
    """
    Lance un scan nmap directement depuis le script.

    Gère :
      - détection du binaire nmap (PATH + emplacements connus)
      - parsing correct des arguments (guillemets, espaces) via shlex
      - détection des besoins de privilèges (-sS, -sU, -O…)
      - messages d'erreur clairs et actionnables selon la cause d'échec

    Args:
        target:     cible du scan (IP, plage CIDR, hostname)
        output_xml: chemin du fichier XML de sortie
        extra_args: arguments nmap additionnels (ex: "-p 1-1000 --script vuln")
        timeout:    timeout en secondes (défaut 300)

    Returns:
        Liste de NmapService si succès, None si échec (message déjà affiché).
    """
    # ── 1. Vérifier que nmap est installé ───────────────────────────────────
    nmap_bin = find_nmap_binary()
    if nmap_bin is None:
        print("[!] nmap introuvable sur ce système.")
        print(f"    Installation : {_install_hint()}")
        print("    Vous pouvez aussi fournir un scan existant avec -x scan.xml")
        return None

    # ── 2. Parser les arguments correctement (gère guillemets et espaces) ──
    try:
        extra_tokens = shlex.split(extra_args) if extra_args else []
    except ValueError as e:
        print(f"[!] --nmap-args mal formé (guillemets non fermés ?) : {e}")
        print(f"    Reçu : {extra_args!r}")
        return None

    cmd_tokens = [nmap_bin, "-sV", "-sC", "--open", *extra_tokens, "-oX", output_xml, target]

    # ── 3. Avertir si privilèges potentiellement insuffisants ──────────────
    if _needs_privileges(extra_args) and not _has_raw_socket_capability():
        print("[!] Attention : les options utilisées (-sS/-sU/-O…) nécessitent")
        print("    généralement les privilèges root pour les raw sockets.")
        print("    Si le scan échoue, relancez avec : sudo python chocoscan.py --scan ...")
        print(f"    Ou donnez la capability à nmap : sudo setcap cap_net_raw+ep {nmap_bin}")
        print()

    print(f"[*] Lancement du scan : {' '.join(cmd_tokens)}")

    # ── 4. Exécuter avec gestion fine des erreurs ───────────────────────────
    try:
        result = subprocess.run(
            cmd_tokens,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[!] Scan nmap interrompu après {timeout}s (timeout).")
        print("    Pour un scan plus rapide : --nmap-args \"-T4 --top-ports 1000\"")
        print(f"    Pour augmenter le timeout, modifiez le code ou réduisez la portée du scan.")
        return None
    except FileNotFoundError:
        # Filet de sécurité — ne devrait plus arriver grâce à find_nmap_binary()
        print(f"[!] Impossible d'exécuter '{nmap_bin}'.")
        print(f"    Installation : {_install_hint()}")
        return None
    except PermissionError:
        print(f"[!] Permission refusée pour exécuter '{nmap_bin}'.")
        print(f"    Vérifiez les droits d'exécution : chmod +x {nmap_bin}")
        return None

    # ── 5. Analyser le résultat ──────────────────────────────────────────────
    if result.returncode == 0 and os.path.exists(output_xml):
        return parse_nmap_xml(output_xml)

    # Échec — diagnostiquer la cause la plus probable
    stderr = (result.stderr or "").strip()
    stderr_lower = stderr.lower()

    if "requires root privileges" in stderr_lower or "permission denied" in stderr_lower:
        print("[!] nmap nécessite des privilèges root pour ce type de scan.")
        print(f"    Relancez avec : sudo python chocoscan.py --scan {target} --nmap-args \"{extra_args}\"")
        print(f"    Ou donnez la capability : sudo setcap cap_net_raw+ep {nmap_bin}")
    elif "failed to resolve" in stderr_lower or "could not resolve" in stderr_lower:
        print(f"[!] Impossible de résoudre la cible : '{target}'")
        print("    Vérifiez l'orthographe de l'IP/hostname ou votre connectivité réseau.")
    elif "no targets were specified" in stderr_lower:
        print("[!] Aucune cible valide spécifiée.")
        print(f"    Cible reçue : '{target}'")
    elif not stderr:
        print(f"[!] nmap a échoué (code {result.returncode}) sans message d'erreur.")
        print(f"    Sortie standard : {result.stdout[:300] if result.stdout else '(vide)'}")
    else:
        print(f"[!] Erreur nmap (code {result.returncode}) :")
        # Afficher les dernières lignes pertinentes de stderr
        for line in stderr.splitlines()[-5:]:
            print(f"      {line}")

    return None
