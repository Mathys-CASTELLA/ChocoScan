"""
Module de parsing des résultats Nmap.
Supporte les formats XML (-oX) et texte normal.
"""

import xml.etree.ElementTree as ET
import re
import subprocess
import os
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


def run_nmap_scan(target: str, output_xml: str, extra_args: str = "") -> Optional[list[NmapService]]:
    """
    Lance un scan nmap directement depuis le script.
    Requiert nmap installé sur le système.
    """
    cmd = f"nmap -sV -sC --open {extra_args} -oX {output_xml} {target}"
    print(f"[*] Lancement du scan : {cmd}")

    try:
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0 and os.path.exists(output_xml):
            return parse_nmap_xml(output_xml)
        else:
            print(f"[!] Erreur nmap : {result.stderr}")
            return None
    except subprocess.TimeoutExpired:
        print("[!] Scan nmap timeout (300s)")
        return None
    except FileNotFoundError:
        print("[!] nmap non trouvé. Installez-le avec : sudo apt install nmap")
        return None
