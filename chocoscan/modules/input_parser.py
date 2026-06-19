"""
ChocoScan — Parseur multi-format d'entrée.

Formats supportés :
  - Nmap XML    (-oX)          → parse_nmap_xml()       [existant]
  - Nmap texte  (-oN)          → parse_nmap_text()      [existant]
  - Masscan XML (-oX)          → parse_masscan_xml()
  - Masscan JSON (-oJ)         → parse_masscan_json()
  - Masscan texte (défaut)     → parse_masscan_text()
  - RustScan JSON              → parse_rustscan_json()
  - RustScan texte             → parse_rustscan_text()
  - Nessus CSV (.csv)          → parse_nessus_csv()
  - Nessus XML (.nessus)       → parse_nessus_xml()
  - JSON générique ChocoScan   → parse_chocoscan_json()
  - Texte tabulaire générique  → parse_generic_text()

Détection automatique du format via --input-format auto (défaut).

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations
import re
import json
import csv
import xml.etree.ElementTree as ET
from pathlib import Path

from modules.nmap_parser import NmapService, parse_nmap_xml, parse_nmap_text


# ─────────────────────────────────────────────────────────────────────────────
# Détection automatique du format
# ─────────────────────────────────────────────────────────────────────────────

def detect_format(filepath: str) -> str:
    """
    Détecte automatiquement le format d'un fichier de scan.
    Retourne une chaîne parmi :
      'nmap_xml', 'nmap_text', 'masscan_xml', 'masscan_json', 'masscan_text',
      'rustscan_json', 'rustscan_text', 'nessus_csv', 'nessus_xml',
      'chocoscan_json', 'generic_text', 'unknown'
    """
    p = Path(filepath)
    ext = p.suffix.lower()

    # Lire les premiers octets / lignes pour la détection de contenu
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(2048)
    except OSError:
        return "unknown"

    # ── Nessus .nessus (XML propriétaire) ─────────────────────────────────────
    if ext == ".nessus" or "NessusClientData_v2" in head:
        return "nessus_xml"

    # ── Nessus CSV ────────────────────────────────────────────────────────────
    if ext == ".csv" and any(
        kw in head for kw in ["Plugin ID", "Risk", "CVE", "Solution", "Synopsis"]
    ):
        return "nessus_csv"

    # ── JSON ──────────────────────────────────────────────────────────────────
    if ext == ".json" or head.lstrip().startswith("{") or head.lstrip().startswith("["):
        try:
            data = json.loads(head + "...") if not head.strip().endswith(("}", "]")) else json.loads(head)
        except json.JSONDecodeError:
            # Parser partiellement
            pass
        # Masscan JSON : array avec "proto" ET "ttl" dans les ports
        if '"ip"' in head and '"proto"' in head and '"ttl"' in head:
            return "masscan_json"
        # RustScan : array d'objets avec "ip" et "ports"
        if '"ports"' in head and ('"ip"' in head or '"addresses"' in head):
            return "rustscan_json"
        # ChocoScan JSON : {"metadata": ..., "results": ...}
        if '"metadata"' in head and '"results"' in head:
            return "chocoscan_json"
        return "unknown"

    # ── XML ───────────────────────────────────────────────────────────────────
    if ext == ".xml" or head.lstrip().startswith("<?xml") or head.lstrip().startswith("<"):
        if "<nmaprun" in head:
            return "nmap_xml"
        if "<masscan" in head or "masscan" in head.lower():
            return "masscan_xml"
        if "<NessusClientData" in head:
            return "nessus_xml"
        if "<nmaprun" in head or "Nmap" in head:
            return "nmap_xml"
        return "nmap_xml"  # Fallback XML → Nmap

    # ── Texte ─────────────────────────────────────────────────────────────────
    if "Nmap scan report" in head or "Starting Nmap" in head:
        return "nmap_text"
    # Masscan texte : "Discovered open port 80/tcp on 10.10.10.1"
    if "Discovered open port" in head:
        return "masscan_text"
    # RustScan texte : "Open 10.10.10.1:80"
    if re.search(r"Open \d+\.\d+\.\d+\.\d+:\d+", head):
        return "rustscan_text"
    # Gnmap (-oG) : "Host: 10.10.10.1 () Ports: 22/open/tcp"
    if "Host:" in head and "Ports:" in head:
        return "nmap_text"

    return "generic_text"


# ─────────────────────────────────────────────────────────────────────────────
# Parseurs
# ─────────────────────────────────────────────────────────────────────────────

# ── Masscan XML ───────────────────────────────────────────────────────────────

def parse_masscan_xml(filepath: str) -> list[NmapService]:
    """
    Parse un fichier XML Masscan (-oX).
    Format : <host><address addr="..."/><ports><port protocol="tcp" portid="80">
             <state state="open"/><service name="http"/></port></ports></host>
    """
    services = []
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError:
        return []

    for host in root.findall("host"):
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        host_ip = addr_elem.attrib.get("addr", "unknown")

        for port_elem in host.findall("ports/port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.attrib.get("state") != "open":
                continue

            port_id   = int(port_elem.attrib.get("portid", 0))
            protocol  = port_elem.attrib.get("protocol", "tcp")
            svc_elem  = port_elem.find("service")
            svc_name  = svc_elem.attrib.get("name", "unknown") if svc_elem is not None else "unknown"
            banner    = svc_elem.attrib.get("banner", "") if svc_elem is not None else ""

            services.append(NmapService(
                host=host_ip, port=port_id, protocol=protocol,
                state="open", service_name=svc_name,
                product=svc_name, version="", extrainfo="", banner=banner,
            ))

    return services


# ── Masscan JSON ──────────────────────────────────────────────────────────────

def parse_masscan_json(filepath: str) -> list[NmapService]:
    """
    Parse un fichier JSON Masscan (-oJ).
    Format :
      [{"ip":"10.10.10.1","timestamp":"...","ports":[
        {"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":64}
      ]}]
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            raw = f.read().strip()
        # Masscan ajoute parfois une virgule trailing ou une ligne finale
        raw = re.sub(r",\s*\]$", "]", raw)
        raw = re.sub(r",\s*$", "", raw)
        if not raw.endswith("]"):
            raw += "]"
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError):
        return []

    services = []
    for entry in data:
        host_ip = entry.get("ip", "unknown")
        for p in entry.get("ports", []):
            port_id  = int(p.get("port", 0))
            proto    = p.get("proto", "tcp")
            status   = p.get("status", "")
            if status != "open":
                continue
            services.append(NmapService(
                host=host_ip, port=port_id, protocol=proto,
                state="open", service_name="unknown",
                product="", version="", extrainfo="", banner="",
            ))

    return services


# ── Masscan texte ─────────────────────────────────────────────────────────────

def parse_masscan_text(filepath: str) -> list[NmapService]:
    """
    Parse la sortie texte Masscan (défaut).
    Format : Discovered open port 80/tcp on 10.10.10.1
    """
    services = []
    pattern = re.compile(
        r"Discovered open port\s+(\d+)/(tcp|udp)\s+on\s+([\d\.]+)"
    )
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    port     = int(m.group(1))
                    proto    = m.group(2)
                    host_ip  = m.group(3)
                    services.append(NmapService(
                        host=host_ip, port=port, protocol=proto,
                        state="open", service_name="unknown",
                        product="", version="", extrainfo="", banner="",
                    ))
    except OSError:
        pass
    return services


# ── RustScan JSON ─────────────────────────────────────────────────────────────

def parse_rustscan_json(filepath: str) -> list[NmapService]:
    """
    Parse la sortie JSON de RustScan (--accessible --scripts none -a TARGET -- -oJ).
    Format (selon version) :
      [{"ip":"10.10.10.1","ports":[80,443,22]}]
      ou
      [{"addresses":{"ipv4":"10.10.10.1"},"ports":[{"port":80,"protocol":"tcp"}]}]
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        data = [data]

    services = []
    for entry in data:
        # Format simple : {"ip": "...", "ports": [80, 443]}
        host_ip = entry.get("ip") or ""
        if not host_ip:
            addrs = entry.get("addresses", {})
            host_ip = addrs.get("ipv4") or addrs.get("ipv6") or "unknown"

        ports_raw = entry.get("ports", [])
        for p in ports_raw:
            if isinstance(p, int):
                port_id, proto = p, "tcp"
            elif isinstance(p, dict):
                port_id = int(p.get("port", 0))
                proto   = p.get("protocol", "tcp")
            else:
                continue
            if port_id == 0:
                continue
            services.append(NmapService(
                host=host_ip, port=port_id, protocol=proto,
                state="open", service_name="unknown",
                product="", version="", extrainfo="", banner="",
            ))

    return services


# ── RustScan texte ────────────────────────────────────────────────────────────

def parse_rustscan_text(filepath: str) -> list[NmapService]:
    """
    Parse la sortie texte RustScan.
    Format : Open 10.10.10.1:80
    ou (avec couleurs ANSI supprimées) : Open IP:PORT
    """
    services = []
    # Pattern "Open IP:PORT" ou "Open IP:PORT/tcp"
    p1 = re.compile(r"Open\s+([\d\.]+):(\d+)(?:/(tcp|udp))?")
    # Pattern port list : "10.10.10.1 -> [22, 80, 443]"
    p2 = re.compile(r"([\d\.]+)\s*->\s*\[([0-9,\s]+)\]")

    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")

    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return []

    content = ansi_escape.sub("", content)

    for m in p1.finditer(content):
        host_ip = m.group(1)
        port    = int(m.group(2))
        proto   = m.group(3) or "tcp"
        services.append(NmapService(
            host=host_ip, port=port, protocol=proto,
            state="open", service_name="unknown",
            product="", version="", extrainfo="", banner="",
        ))

    if not services:
        for m in p2.finditer(content):
            host_ip = m.group(1)
            ports   = [int(p.strip()) for p in m.group(2).split(",") if p.strip().isdigit()]
            for port in ports:
                services.append(NmapService(
                    host=host_ip, port=port, protocol="tcp",
                    state="open", service_name="unknown",
                    product="", version="", extrainfo="", banner="",
                ))

    return services


# ── Nessus CSV ────────────────────────────────────────────────────────────────

# Mapping Nessus plugin ID / service name → service_name ChocoScan
NESSUS_SVC_MAP = {
    "www": "http", "http": "http", "https": "https",
    "ssh": "openssh", "ftp": "vsftpd", "smtp": "smtp",
    "mysql": "mysql", "ms-sql": "mysql", "postgresql": "postgresql",
    "smb": "smb", "microsoft-ds": "smb", "ldap": "ldap",
    "kerberos": "kerberos", "rdp": "rdp",
    "vnc": "vnc", "redis": "redis", "mongodb": "mongodb",
    "elasticsearch": "elasticsearch",
}


def parse_nessus_csv(filepath: str) -> list[NmapService]:
    """
    Parse un export CSV de Nessus.
    Colonnes attendues : Plugin ID, CVE, CVSS v3.0 Base Score, Risk, Host,
                         Protocol, Port, Name, Synopsis, Description, Solution,
                         Plugin Output
    """
    services_map: dict[tuple[str,int,str], NmapService] = {}

    try:
        with open(filepath, encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                host  = row.get("Host", "").strip()
                proto = row.get("Protocol", "tcp").lower().strip()
                try:
                    port = int(row.get("Port", "0").strip())
                except ValueError:
                    continue
                if not host or port == 0:
                    continue

                plugin_name = row.get("Name", "").strip()
                svc_raw     = row.get("Service", "").lower().strip()
                svc_name    = NESSUS_SVC_MAP.get(svc_raw, svc_raw or "unknown")

                # Inférer le service depuis le port si inconnu
                if svc_name == "unknown":
                    svc_name = _port_to_service(port)

                key = (host, port, proto)
                if key not in services_map:
                    services_map[key] = NmapService(
                        host=host, port=port, protocol=proto,
                        state="open", service_name=svc_name,
                        product=plugin_name, version="", extrainfo="",
                        banner=plugin_name,
                    )
    except (OSError, csv.Error):
        pass

    return list(services_map.values())


# ── Nessus XML (.nessus) ──────────────────────────────────────────────────────

def parse_nessus_xml(filepath: str) -> list[NmapService]:
    """
    Parse un fichier .nessus (XML NessusClientData_v2).
    Extrait les ports ouverts avec service et version depuis les ReportItem.
    """
    services_map: dict[tuple[str,int,str], NmapService] = {}

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError:
        return []

    for report_host in root.findall(".//ReportHost"):
        host_ip = report_host.attrib.get("name", "unknown")

        # Récupérer l'IP depuis les tags HostProperties si dispo
        for tag in report_host.findall("HostProperties/tag"):
            if tag.attrib.get("name") == "host-ip":
                host_ip = tag.text or host_ip
                break

        for item in report_host.findall("ReportItem"):
            try:
                port = int(item.attrib.get("port", "0"))
            except ValueError:
                continue
            if port == 0:
                continue

            proto    = item.attrib.get("protocol", "tcp").lower()
            svc_raw  = item.attrib.get("svc_name", "").lower()
            svc_name = NESSUS_SVC_MAP.get(svc_raw, svc_raw or _port_to_service(port))
            plugin   = item.attrib.get("pluginName", "")

            # Version depuis plugin_output ou description
            version = ""
            ver_elem = item.find("plugin_output")
            if ver_elem is not None and ver_elem.text:
                ver_m = re.search(r"version[:\s]+([0-9][0-9a-z\.\-_]+)", ver_elem.text, re.I)
                if ver_m:
                    version = ver_m.group(1)

            key = (host_ip, port, proto)
            if key not in services_map:
                banner = " ".join(filter(None, [svc_name, version]))
                services_map[key] = NmapService(
                    host=host_ip, port=port, protocol=proto,
                    state="open", service_name=svc_name,
                    product=svc_name, version=version, extrainfo="",
                    banner=banner,
                )

    return list(services_map.values())


# ── JSON générique ChocoScan (réimport d'un export JSON) ─────────────────────

def parse_chocoscan_json(filepath: str) -> list[NmapService]:
    """
    Réimporte un rapport JSON ChocoScan précédent (--export-json).
    Permet de relancer une analyse avec des filtres différents.
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    services = []
    for result in data.get("results", []):
        svc = result.get("service", {})
        services.append(NmapService(
            host=svc.get("host", "unknown"),
            port=int(svc.get("port", 0)),
            protocol=svc.get("protocol", "tcp"),
            state="open",
            service_name=svc.get("service_name", "unknown"),
            product=svc.get("product", ""),
            version=svc.get("version", ""),
            extrainfo="",
            banner=svc.get("banner", ""),
        ))
    return services


# ── Texte générique (fallback) ────────────────────────────────────────────────

def parse_generic_text(filepath: str) -> list[NmapService]:
    """
    Tente de parser un fichier texte générique contenant des
    adresses IP et ports sous diverses formes.
    Formats reconnus :
      - IP:PORT
      - IP PORT
      - PORT/tcp
      - host PORT/protocol service
    """
    services = []
    seen = set()

    patterns = [
        # ip:port ou ip:port/proto
        re.compile(r"([\d\.]+):(\d+)(?:/(tcp|udp))?"),
        # port/proto open service version
        re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)"),
    ]

    current_host = "unknown"

    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_clean = line.strip()

                # Détecter un hôte
                host_m = re.match(r"(?:Host:|Nmap scan report for)\s*([\d\.a-zA-Z\-\.]+)", line_clean)
                if host_m:
                    current_host = host_m.group(1)
                    continue

                # Pattern IP:PORT
                m0 = patterns[0].search(line_clean)
                if m0:
                    host_ip = m0.group(1)
                    port    = int(m0.group(2))
                    proto   = m0.group(3) or "tcp"
                    key     = (host_ip, port, proto)
                    if key not in seen:
                        seen.add(key)
                        services.append(NmapService(
                            host=host_ip, port=port, protocol=proto,
                            state="open", service_name=_port_to_service(port),
                            product="", version="", extrainfo="", banner="",
                        ))
                    continue

                # Pattern PORT/proto open service
                m1 = patterns[1].match(line_clean)
                if m1:
                    port     = int(m1.group(1))
                    proto    = m1.group(2)
                    svc_name = m1.group(3)
                    banner   = m1.group(4).strip()
                    key      = (current_host, port, proto)
                    if key not in seen:
                        seen.add(key)
                        services.append(NmapService(
                            host=current_host, port=port, protocol=proto,
                            state="open", service_name=svc_name,
                            product=banner.split()[0] if banner else "",
                            version=" ".join(banner.split()[1:]) if len(banner.split()) > 1 else "",
                            extrainfo="", banner=banner,
                        ))
    except OSError:
        pass

    return services


# ─────────────────────────────────────────────────────────────────────────────
# Enrichissement post-parse (inférence service depuis port)
# ─────────────────────────────────────────────────────────────────────────────

# Ports classiques → nom de service ChocoScan
PORT_SERVICE_MAP: dict[int, str] = {
    21: "vsftpd",   22: "openssh",  23: "telnet",   25: "smtp",
    53: "dns",      80: "apache",   88: "kerberos",  110: "smtp",
    111: "rpc",     119: "smtp",    135: "rpc",      139: "smb",
    143: "smtp",    389: "ldap",    443: "ssl",      445: "smb",
    464: "kerberos",465: "smtp",    587: "smtp",     631: "cups",
    636: "ldap",    993: "smtp",    995: "smtp",
    1433: "mysql",  1521: "weblogic",1723: "openvpn",
    2049: "nfs",    2181: "kafka",  2375: "docker",  2376: "docker",
    3268: "ldap",   3269: "ldap",   3306: "mysql",   3389: "rdp",
    3690: "git",    4444: "metasploit",
    4848: "jboss",  5432: "postgresql", 5601: "kibana",
    5672: "rabbitmq", 5900: "vnc",  5985: "winrm",   5986: "winrm",
    6379: "redis",  6443: "kubernetes", 7474: "neo4j",
    8080: "tomcat", 8443: "spring", 8888: "jupyter", 8983: "solr",
    9000: "sonarqube", 9090: "prometheus", 9200: "elasticsearch",
    9418: "git",    10000: "webmin",10250: "kubernetes",
    10443: "kubernetes", 11211: "memcached",
    15672: "rabbitmq", 27017: "mongodb", 27018: "mongodb",
    5044: "elasticsearch", 9300: "elasticsearch",
}


def _port_to_service(port: int) -> str:
    return PORT_SERVICE_MAP.get(port, "unknown")


def enrich_services(services: list[NmapService]) -> list[NmapService]:
    """
    Post-traitement : comble les service_name="unknown" via le port.
    Utilisé après les parseurs qui ne récupèrent pas le service (Masscan, RustScan).
    """
    for svc in services:
        if svc.service_name in ("unknown", "", None):
            svc.service_name = _port_to_service(svc.port)
        if not svc.banner and svc.service_name != "unknown":
            svc.banner = svc.service_name
    return services


# ─────────────────────────────────────────────────────────────────────────────
# Point d'entrée principal
# ─────────────────────────────────────────────────────────────────────────────

FORMAT_LABELS = {
    "nmap_xml":       "Nmap XML (-oX)",
    "nmap_text":      "Nmap texte (-oN / -oG)",
    "masscan_xml":    "Masscan XML (-oX)",
    "masscan_json":   "Masscan JSON (-oJ)",
    "masscan_text":   "Masscan texte",
    "rustscan_json":  "RustScan JSON",
    "rustscan_text":  "RustScan texte",
    "nessus_csv":     "Nessus CSV",
    "nessus_xml":     "Nessus .nessus",
    "chocoscan_json": "ChocoScan JSON (réimport)",
    "generic_text":   "Texte générique",
    "unknown":        "Format inconnu",
}

PARSERS = {
    "nmap_xml":       lambda f: parse_nmap_xml(f),
    "nmap_text":      lambda f: parse_nmap_text(open(f, encoding="utf-8", errors="ignore").read()),
    "masscan_xml":    parse_masscan_xml,
    "masscan_json":   parse_masscan_json,
    "masscan_text":   parse_masscan_text,
    "rustscan_json":  parse_rustscan_json,
    "rustscan_text":  parse_rustscan_text,
    "nessus_csv":     parse_nessus_csv,
    "nessus_xml":     parse_nessus_xml,
    "chocoscan_json": parse_chocoscan_json,
    "generic_text":   parse_generic_text,
}


def parse_input_file(
    filepath: str,
    fmt: str = "auto",
) -> tuple[list[NmapService], str]:
    """
    Parse un fichier de scan dans n'importe quel format supporté.

    Args:
        filepath : chemin vers le fichier
        fmt      : format forcé, ou 'auto' pour détection automatique

    Returns:
        (list[NmapService], format_détecté)
    """
    if fmt == "auto":
        fmt = detect_format(filepath)

    parser = PARSERS.get(fmt)
    if parser is None:
        return [], fmt

    services = parser(filepath)

    # Enrichissement pour les formats sans info de service
    if fmt in ("masscan_xml", "masscan_json", "masscan_text",
               "rustscan_json", "rustscan_text"):
        services = enrich_services(services)

    return services, fmt
