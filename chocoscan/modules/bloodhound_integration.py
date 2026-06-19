"""
ChocoScan — Intégration BloodHound CE.

Lit les fichiers JSON produits par SharpHound CE ou BloodHound.py
(ZIP ou répertoire) et croise les données AD avec les CVEs ChocoScan :

  - Comptes Kerberoastables (hasspn=true) → CVEs Kerberos
  - Comptes AS-REP Roastables (dontreqpreauth=true) → CVEs Kerberos
  - Machines avec délégation non contrainte → CVEs SMB/Kerberos/Windows
  - OS obsolètes (XP, 2003, 2008, Vista, 7) → CVEs Windows critiques
  - Machines avec LAPS absent → exposition credentials
  - Administrateurs de domaine → cibles prioritaires
  - Domaines de confiance (trusts) → vecteurs inter-domaines
  - Croisement machines BloodHound × services Nmap scannés

Usage :
    python chocoscan.py -x scan.xml --bloodhound /chemin/vers/bloodhound.zip
    python chocoscan.py -x scan.xml --bloodhound /chemin/vers/dossier_json/

Formats supportés :
    - ZIP SharpHound CE  (YYYYMMDDHHMMSS_BloodHound.zip)
    - ZIP BloodHound.py  (bloodhound_*.zip)
    - Répertoire contenant les fichiers JSON individuels
    - Fichier JSON unique (computers.json, users.json, etc.)

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations
import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None


# ─────────────────────────────────────────────────────────────────────────────
# OS obsolètes (vulnérables à de nombreuses CVEs critiques)
# ─────────────────────────────────────────────────────────────────────────────

LEGACY_OS_PATTERNS = [
    (r"windows\s*(xp|me)",              "Windows XP/ME",      "EoL 2014"),
    (r"windows\s*vista",                "Windows Vista",      "EoL 2017"),
    (r"windows\s*7",                    "Windows 7",          "EoL 2020"),
    (r"windows\s*8\.0",                 "Windows 8",          "EoL 2016"),
    (r"server\s*2000",                  "Windows 2000 Server","EoL 2010"),
    (r"server\s*2003",                  "Windows Server 2003","EoL 2015"),
    (r"server\s*2008(\s|r2|$)",         "Windows Server 2008","EoL 2020"),
    (r"server\s*2012(\s|r2|$)",         "Windows Server 2012","EoL 2023"),
]


def is_legacy_os(os_str: str) -> tuple[bool, str, str]:
    """Retourne (est_obsolète, nom_os, date_eol)."""
    if not os_str:
        return False, "", ""
    s = os_str.lower()
    for pattern, name, eol in LEGACY_OS_PATTERNS:
        if re.search(pattern, s):
            return True, name, eol
    return False, "", ""


# ─────────────────────────────────────────────────────────────────────────────
# Structures de données
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BHUser:
    """Utilisateur extrait des fichiers BloodHound."""
    name:            str
    domain:          str
    enabled:         bool
    admin_count:     bool
    has_spn:         bool        # Kerberoastable
    dont_req_preauth:bool        # AS-REP Roastable
    pwd_last_set:    int         # timestamp UNIX
    last_logon:      int
    description:     str
    sensitive:       bool
    sid:             str

    @property
    def display_name(self) -> str:
        return self.name.split("@")[0] if "@" in self.name else self.name

    @property
    def is_kerberoastable(self) -> bool:
        return self.has_spn and self.enabled and not self.name.upper().startswith("KRBTGT")

    @property
    def is_asrep_roastable(self) -> bool:
        return self.dont_req_preauth and self.enabled


@dataclass
class BHComputer:
    """Machine extraite des fichiers BloodHound."""
    name:                  str
    domain:                str
    os:                    str
    enabled:               bool
    is_dc:                 bool
    unconstrained_deleg:   bool
    has_laps:              bool
    allowed_to_delegate:   list[str]
    sid:                   str


@dataclass
class BHTrust:
    """Relation de confiance entre domaines."""
    source:     str
    target:     str
    trust_type: str
    transitive: bool


@dataclass
class BHData:
    """Données complètes extraites d'un ZIP/répertoire BloodHound."""
    domain:       str
    users:        list[BHUser]        = field(default_factory=list)
    computers:    list[BHComputer]    = field(default_factory=list)
    trusts:       list[BHTrust]       = field(default_factory=list)
    da_members:   list[str]           = field(default_factory=list)

    # Résultats croisés avec CVEs
    findings:     list[dict]          = field(default_factory=list)

    @property
    def kerberoastable_users(self) -> list[BHUser]:
        return [u for u in self.users if u.is_kerberoastable]

    @property
    def asrep_roastable_users(self) -> list[BHUser]:
        return [u for u in self.users if u.is_asrep_roastable]

    @property
    def unconstrained_computers(self) -> list[BHComputer]:
        return [c for c in self.computers if c.unconstrained_deleg and not c.is_dc]

    @property
    def legacy_computers(self) -> list[tuple[BHComputer, str, str]]:
        result = []
        for c in self.computers:
            legacy, name, eol = is_legacy_os(c.os)
            if legacy:
                result.append((c, name, eol))
        return result

    @property
    def no_laps_computers(self) -> list[BHComputer]:
        return [c for c in self.computers if not c.is_dc and not c.has_laps]


# ─────────────────────────────────────────────────────────────────────────────
# Parseurs BloodHound JSON
# ─────────────────────────────────────────────────────────────────────────────

def _parse_users_json(data: dict) -> list[BHUser]:
    users = []
    entries = data.get("data") or data.get("users") or []

    for entry in entries:
        props = entry.get("Properties", entry.get("properties", {}))
        name  = props.get("name", "") or entry.get("Name", "")
        if not name:
            continue

        users.append(BHUser(
            name             = name.upper(),
            domain           = props.get("domain", "").upper(),
            enabled          = bool(props.get("enabled", True)),
            admin_count      = bool(props.get("admincount", False)),
            has_spn          = bool(props.get("hasspn", False)),
            dont_req_preauth = bool(props.get("dontreqpreauth", False)),
            pwd_last_set     = int(props.get("pwdlastset", 0) or 0),
            last_logon       = int(props.get("lastlogon", 0) or 0),
            description      = str(props.get("description", "") or ""),
            sensitive        = bool(props.get("sensitive", False)),
            sid              = props.get("objectid", props.get("ObjectIdentifier", "")),
        ))

    return users


def _parse_computers_json(data: dict) -> list[BHComputer]:
    computers = []
    entries = data.get("data") or data.get("computers") or []

    for entry in entries:
        props = entry.get("Properties", entry.get("properties", {}))
        name  = props.get("name", "") or entry.get("Name", "")
        if not name:
            continue

        # Délégation contrainte
        allowed = []
        for key in ("AllowedToDelegate", "allowedtodelegate"):
            raw = entry.get(key) or props.get(key)
            if isinstance(raw, list):
                allowed = [str(x) for x in raw]
                break

        computers.append(BHComputer(
            name                = name.upper(),
            domain              = props.get("domain", "").upper(),
            os                  = str(props.get("operatingsystem", "") or ""),
            enabled             = bool(props.get("enabled", True)),
            is_dc               = bool(props.get("isdc", props.get("is_dc", False))),
            unconstrained_deleg = bool(props.get("unconstraineddelegation", False)),
            has_laps            = bool(props.get("haslaps", False)),
            allowed_to_delegate = allowed,
            sid                 = props.get("objectid", props.get("ObjectIdentifier", "")),
        ))

    return computers


def _parse_groups_json(data: dict) -> list[str]:
    """Extrait les membres du groupe Domain Admins."""
    da_members = []
    entries = data.get("data") or data.get("groups") or []

    for entry in entries:
        props = entry.get("Properties", entry.get("properties", {}))
        name  = str(props.get("name", "") or entry.get("Name", "")).upper()

        if "DOMAIN ADMINS" in name or name.endswith("-512"):
            members = entry.get("Members", entry.get("members", []))
            for m in members:
                mname = m.get("ObjectIdentifier", m.get("MemberId", ""))
                if mname:
                    da_members.append(mname)

    return da_members


def _parse_domains_json(data: dict) -> tuple[str, list[BHTrust]]:
    """Extrait le nom du domaine et les trusts."""
    trusts = []
    domain = ""
    entries = data.get("data") or data.get("domains") or []

    for entry in entries:
        props = entry.get("Properties", entry.get("properties", {}))
        d = str(props.get("name", "") or entry.get("Name", "")).upper()
        if d and not domain:
            domain = d

        for trust in entry.get("Trusts", entry.get("trusts", [])):
            trusts.append(BHTrust(
                source     = d,
                target     = str(trust.get("TargetDomainName", "")).upper(),
                trust_type = str(trust.get("TrustType", "Unknown")),
                transitive = bool(trust.get("IsTransitive", False)),
            ))

    return domain, trusts


def _load_json_bytes(data: bytes) -> dict:
    try:
        return json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Point d'entrée : chargement
# ─────────────────────────────────────────────────────────────────────────────

def load_bloodhound(path: str) -> Optional[BHData]:
    """
    Charge et parse les données BloodHound depuis :
      - Un fichier ZIP SharpHound/BloodHound.py
      - Un répertoire contenant les fichiers JSON
      - Un fichier JSON unique

    Retourne un BHData ou None si aucune donnée valide.
    """
    p = Path(path)
    if not p.exists():
        return None

    raw: dict[str, dict] = {}   # nom_court → contenu JSON

    # ── ZIP ───────────────────────────────────────────────────────────────────
    if p.suffix.lower() == ".zip" or zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for name in zf.namelist():
                    stem = Path(name).stem.lower()
                    # Ignorer les fichiers non JSON et les manifest
                    if not name.endswith(".json"):
                        continue
                    # Garder uniquement les fichiers connus BloodHound
                    for key in ("users", "computers", "groups", "domains",
                                "ous", "gpos", "containers", "sessions"):
                        if key in stem:
                            raw[key] = _load_json_bytes(zf.read(name))
                            break
        except (zipfile.BadZipFile, OSError):
            return None

    # ── Répertoire ────────────────────────────────────────────────────────────
    elif p.is_dir():
        for json_file in p.glob("*.json"):
            stem = json_file.stem.lower()
            for key in ("users", "computers", "groups", "domains",
                        "ous", "gpos", "containers", "sessions"):
                if key in stem:
                    try:
                        with open(json_file, encoding="utf-8") as f:
                            raw[key] = json.load(f)
                    except (json.JSONDecodeError, OSError):
                        pass
                    break

    # ── Fichier JSON unique ───────────────────────────────────────────────────
    elif p.suffix.lower() == ".json":
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            stem = p.stem.lower()
            for key in ("users", "computers", "groups", "domains"):
                if key in stem:
                    raw[key] = data
                    break
        except (json.JSONDecodeError, OSError):
            return None

    if not raw:
        return None

    # ── Parsing ───────────────────────────────────────────────────────────────
    users     = _parse_users_json(raw.get("users", {}))
    computers = _parse_computers_json(raw.get("computers", {}))
    da_members= _parse_groups_json(raw.get("groups", {}))
    domain, trusts = _parse_domains_json(raw.get("domains", {}))

    if not domain and users:
        # Inférer le domaine depuis le premier utilisateur
        first = users[0].domain or (users[0].name.split("@")[-1] if "@" in users[0].name else "")
        domain = first.upper()

    bh = BHData(
        domain    = domain,
        users     = users,
        computers = computers,
        trusts    = trusts,
        da_members= da_members,
    )

    return bh if (users or computers) else None


# ─────────────────────────────────────────────────────────────────────────────
# Croisement avec les CVEs ChocoScan
# ─────────────────────────────────────────────────────────────────────────────

# CVEs directement liées aux misconfigurations AD détectées
MISCONFIG_CVES: dict[str, list[str]] = {
    "kerberoasting": [
        "CVE-2022-33679",  # Windows Kerberos elevation
        "CVE-2020-17049",  # Bronze Bit — Kerberos delegation bypass
    ],
    "asrep_roasting": [
        "CVE-2021-42278",  # NoPac — sAMAccountName spoofing
        "CVE-2021-42287",  # NoPac — Privilege Attribute Certificate
    ],
    "unconstrained_delegation": [
        "CVE-2021-36942",  # PetitPotam — forced auth to unconstrained
        "CVE-2020-1472",   # Zerologon — path via unconstrained DC
    ],
    "legacy_os": [
        "CVE-2017-0144",   # EternalBlue
        "CVE-2017-0145",   # EternalRomance
        "CVE-2019-0708",   # BlueKeep (Windows 7/2008)
        "CVE-2020-0796",   # SMBGhost
    ],
    "no_laps": [
        "CVE-2023-28252",  # Windows CLFS LPE (get local admin → dump)
        "CVE-2021-3156",   # sudo baron samedit (si Linux hybride)
    ],
}


def cross_with_cves(bh: BHData, cve_db: dict) -> BHData:
    """
    Croise les misconfigurations BloodHound avec les CVEs de la base.
    Injecte les findings dans bh.findings.
    """
    findings = []

    def get_cves_by_ids(ids: list[str]) -> list[dict]:
        found = []
        for cves in cve_db.values():
            for c in cves:
                if c.get("id") in ids:
                    found.append(c)
        return found

    def get_top_cves_for_service(svc: str, n: int = 4) -> list[dict]:
        cves = cve_db.get(svc, [])
        return sorted(cves, key=lambda c: float(str(c.get("cvss", 0)).replace("N/A", "0") or 0), reverse=True)[:n]

    # ── Kerberoasting ─────────────────────────────────────────────────────────
    if bh.kerberoastable_users:
        related = get_top_cves_for_service("kerberos", 4)
        related += get_cves_by_ids(MISCONFIG_CVES["kerberoasting"])
        findings.append({
            "type":        "KERBEROASTING",
            "severity":    "HIGH",
            "title":       f"Kerberoasting — {len(bh.kerberoastable_users)} compte(s) avec SPN",
            "description": (
                "Des comptes de service ont un SPN configuré avec l'authentification "
                "Kerberos active. Un attaquant authentifié peut demander un ticket TGS "
                "et cracker le hash offline sans déclencher d'alerte."
            ),
            "affected":    [u.display_name for u in bh.kerberoastable_users[:10]],
            "commands": [
                f"GetUserSPNs.py {bh.domain}/user:'pass' -dc-ip DC_IP -request",
                f"hashcat -m 13100 spn_hashes.txt /usr/share/wordlists/rockyou.txt",
                "python -m impacket.GetUserSPNs",
            ],
            "cves":        related,
            "tools":       ["GetUserSPNs.py (Impacket)", "Rubeus /kerberoast", "hashcat"],
        })

    # ── AS-REP Roasting ───────────────────────────────────────────────────────
    if bh.asrep_roastable_users:
        related = get_top_cves_for_service("kerberos", 3)
        related += get_cves_by_ids(MISCONFIG_CVES["asrep_roasting"])
        findings.append({
            "type":        "ASREP_ROASTING",
            "severity":    "HIGH",
            "title":       f"AS-REP Roasting — {len(bh.asrep_roastable_users)} compte(s) sans pré-auth",
            "description": (
                "Des comptes ont la pré-authentification Kerberos désactivée "
                "(DontRequirePreAuth). Un attaquant peut obtenir un AS-REP chiffré "
                "SANS être authentifié et le cracker offline."
            ),
            "affected":    [u.display_name for u in bh.asrep_roastable_users[:10]],
            "commands": [
                f"GetNPUsers.py {bh.domain}/ -dc-ip DC_IP -no-pass -usersfile users.txt",
                f"GetNPUsers.py {bh.domain}/ -dc-ip DC_IP -no-pass -format hashcat",
                "hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt",
            ],
            "cves":        related,
            "tools":       ["GetNPUsers.py (Impacket)", "Rubeus /asreproast", "hashcat"],
        })

    # ── Délégation non contrainte ─────────────────────────────────────────────
    if bh.unconstrained_computers:
        related = get_top_cves_for_service("kerberos", 2)
        related += get_top_cves_for_service("smb", 2)
        related += get_cves_by_ids(MISCONFIG_CVES["unconstrained_delegation"])
        findings.append({
            "type":        "UNCONSTRAINED_DELEGATION",
            "severity":    "CRITICAL",
            "title":       f"Délégation Kerberos non contrainte — {len(bh.unconstrained_computers)} machine(s)",
            "description": (
                "Des machines non-DC ont la délégation non contrainte activée. "
                "Si un administrateur du domaine (ou le compte machine du DC) "
                "s'authentifie sur l'une de ces machines, l'attaquant peut extraire "
                "son ticket TGT et usurper son identité (PetitPotam + Unconstrained)."
            ),
            "affected":    [c.name for c in bh.unconstrained_computers[:8]],
            "commands": [
                "Rubeus monitor /interval:5 /nowrap",
                "PetitPotam.py <machine_attaquant> <machine_deleg>",
                "secretsdump.py -k -no-pass DC_FQDN",
            ],
            "cves":        related,
            "tools":       ["Rubeus", "PetitPotam", "Impacket secretsdump"],
        })

    # ── OS obsolètes ─────────────────────────────────────────────────────────
    legacy = bh.legacy_computers
    if legacy:
        related = get_cves_by_ids(MISCONFIG_CVES["legacy_os"])
        related += get_top_cves_for_service("smb", 2)
        related += get_top_cves_for_service("rdp", 2)
        findings.append({
            "type":        "LEGACY_OS",
            "severity":    "CRITICAL",
            "title":       f"OS obsolètes — {len(legacy)} machine(s) hors support",
            "description": (
                "Des machines tournent sous des OS Microsoft hors support (EoL). "
                "Ces systèmes ne reçoivent plus de patches de sécurité et sont "
                "vulnérables à des CVEs critiques connues (EternalBlue, BlueKeep, SMBGhost)."
            ),
            "affected":    [f"{c.name} ({name} — EoL {eol})" for c, name, eol in legacy[:8]],
            "commands": [
                "nmap -p 445 --script smb-vuln-ms17-010 <target>",
                "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; ...'",
            ],
            "cves":        related,
            "tools":       ["Metasploit (ms17_010_eternalblue)", "nmap scripts"],
        })

    # ── Absence de LAPS ───────────────────────────────────────────────────────
    no_laps = bh.no_laps_computers
    if no_laps:
        findings.append({
            "type":        "NO_LAPS",
            "severity":    "MEDIUM",
            "title":       f"LAPS absent — {len(no_laps)} machine(s) sans rotation de mot de passe admin local",
            "description": (
                "Des machines n'ont pas LAPS (Local Administrator Password Solution) "
                "configuré. Le mot de passe de l'admin local est identique sur plusieurs "
                "machines — compromettre une machine donne accès à toutes les autres "
                "via Pass-the-Hash."
            ),
            "affected":    [c.name for c in no_laps[:8]],
            "commands": [
                "crackmapexec smb <subnet> -u administrator -H <hash> --local-auth",
                "secretsdump.py ./administrator@<ip>",
            ],
            "cves":        [],
            "tools":       ["CrackMapExec", "Impacket secretsdump", "Mimikatz"],
        })

    # ── Domain Admins ────────────────────────────────────────────────────────
    if bh.da_members:
        findings.append({
            "type":        "DOMAIN_ADMINS",
            "severity":    "INFO",
            "title":       f"Domain Admins — {len(bh.da_members)} membre(s) identifié(s)",
            "description": "Membres du groupe Domain Admins — cibles prioritaires pour le DCSync.",
            "affected":    bh.da_members[:10],
            "commands": [
                "secretsdump.py DOMAIN/admin:'pass'@DC_IP",
                "bloodyAD -H DC_IP -d DOMAIN -u admin -p 'pass' get object 'Domain Admins'",
            ],
            "cves":        [],
            "tools":       ["Impacket secretsdump (DCSync)", "mimikatz lsadump::dcsync"],
        })

    # ── Domaines de confiance ─────────────────────────────────────────────────
    if bh.trusts:
        findings.append({
            "type":        "DOMAIN_TRUSTS",
            "severity":    "MEDIUM",
            "title":       f"Trusts inter-domaines — {len(bh.trusts)} relation(s)",
            "description": (
                "Des relations de confiance existent entre domaines. "
                "Un attaquant compromettant un domaine fils peut pivoter "
                "vers le domaine parent via SID History ou tickets inter-realm."
            ),
            "affected":    [f"{t.source} → {t.target} ({t.trust_type})" for t in bh.trusts[:6]],
            "commands": [
                "mimikatz.exe 'kerberos::golden /domain:child /sid:CHILD_SID /sids:PARENT_SID-519 /krbtgt:HASH /user:admin'",
                "raiseChild.py CHILD_DOMAIN/admin:'pass'",
            ],
            "cves":        [],
            "tools":       ["mimikatz Golden Ticket", "Impacket raiseChild"],
        })

    bh.findings = findings
    return bh


# ─────────────────────────────────────────────────────────────────────────────
# Croisement avec les services Nmap scannés
# ─────────────────────────────────────────────────────────────────────────────

def cross_with_scan(bh: BHData, services: list) -> dict:
    """
    Croise les machines BloodHound avec les services Nmap scannés.
    Retourne un dict {hostname: [NmapService]} pour les machines identifiées.
    """
    matched: dict[str, list] = {}
    bh_hostnames = {c.name.split(".")[0].upper() for c in bh.computers}
    bh_fqdns     = {c.name.upper() for c in bh.computers}

    for svc in services:
        host_upper = svc.host.upper()
        # Correspondance par hostname ou FQDN
        if host_upper in bh_fqdns or host_upper in bh_hostnames:
            matched.setdefault(svc.host, []).append(svc)

    return matched


# ─────────────────────────────────────────────────────────────────────────────
# Affichage terminal
# ─────────────────────────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": "bold red", "HIGH": "bold yellow",
    "MEDIUM": "yellow",     "INFO": "dim cyan",
}


def display_bloodhound_terminal(bh: BHData):
    """Affiche l'analyse BloodHound dans le terminal."""
    if not console:
        return

    console.print()
    console.print(Rule("[bold red]🩸 Analyse BloodHound CE[/bold red]"))
    console.print(f"\n  Domaine : [bold cyan]{bh.domain}[/bold cyan]")
    console.print(f"  Utilisateurs : [bold]{len(bh.users)}[/bold]  "
                  f"Machines : [bold]{len(bh.computers)}[/bold]  "
                  f"Trusts : [bold]{len(bh.trusts)}[/bold]")

    # Résumé des misconfigs
    issues = [
        (len(bh.kerberoastable_users),   "Kerberoastable",        "bold yellow"),
        (len(bh.asrep_roastable_users),  "AS-REP Roastable",      "bold yellow"),
        (len(bh.unconstrained_computers),"Délégation non contrainte", "bold red"),
        (len(bh.legacy_computers),       "OS obsolètes",          "bold red"),
        (len(bh.no_laps_computers),      "Sans LAPS",             "yellow"),
        (len(bh.da_members),             "Domain Admins",         "bold magenta"),
    ]
    console.print()
    for count, label, color in issues:
        if count:
            bar = "█" * min(count, 20)
            console.print(f"  [{color}]{count:3d}[/{color}]  {label:30s} [{color}]{bar}[/{color}]")

    # Findings
    console.print()
    for f in bh.findings:
        sev   = f["severity"]
        color = SEV_COLORS.get(sev, "white")
        console.print(f"\n  [{color}]▶ [{sev}] {f['title']}[/{color}]")
        console.print(f"    [dim]{f['description'][:120]}[/dim]")

        # Afficher les 4 premiers affectés
        affected = f.get("affected", [])[:4]
        if affected:
            console.print(f"    [dim]Affectés : {', '.join(str(a) for a in affected)}"
                          f"{'...' if len(f.get('affected',[]))>4 else ''}[/dim]")

        # CVEs liées
        cves = f.get("cves", [])[:3]
        for c in cves:
            cvss  = c.get("cvss", "?")
            cid   = c.get("id", "")
            desc  = (c.get("description_fr") or c.get("description") or "")[:70]
            exp   = " [green]⚡PoC[/green]" if c.get("exploit_available") else ""
            console.print(f"      [cyan]{cid}[/cyan] CVSS {cvss} — {desc}{exp}")

        # Commande suggérée
        cmds = f.get("commands", [])[:1]
        for cmd in cmds:
            console.print(f"    [green]$ {cmd}[/green]")


# ─────────────────────────────────────────────────────────────────────────────
# Export HTML
# ─────────────────────────────────────────────────────────────────────────────

def bloodhound_to_html_section(bh: BHData) -> str:
    """Génère la section HTML BloodHound pour le rapport ChocoScan."""

    sev_color = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","INFO":"#38bdf8"}

    # Stats header
    stats_html = f"""
    <div class="bh-stats">
      <div class="bh-stat"><div class="bh-stat-lbl">Domaine</div><div class="bh-stat-val" style="color:#60a0f0">{bh.domain}</div></div>
      <div class="bh-stat"><div class="bh-stat-lbl">Utilisateurs</div><div class="bh-stat-val">{len(bh.users)}</div></div>
      <div class="bh-stat"><div class="bh-stat-lbl">Machines</div><div class="bh-stat-val">{len(bh.computers)}</div></div>
      <div class="bh-stat bh-stat-warn"><div class="bh-stat-lbl">Kerberoastable</div><div class="bh-stat-val" style="color:#f97316">{len(bh.kerberoastable_users)}</div></div>
      <div class="bh-stat bh-stat-warn"><div class="bh-stat-lbl">AS-REP Roastable</div><div class="bh-stat-val" style="color:#f97316">{len(bh.asrep_roastable_users)}</div></div>
      <div class="bh-stat bh-stat-crit"><div class="bh-stat-lbl">Déléquation non contrainte</div><div class="bh-stat-val" style="color:#ef4444">{len(bh.unconstrained_computers)}</div></div>
      <div class="bh-stat bh-stat-crit"><div class="bh-stat-lbl">OS hors support</div><div class="bh-stat-val" style="color:#ef4444">{len(bh.legacy_computers)}</div></div>
      <div class="bh-stat"><div class="bh-stat-lbl">Sans LAPS</div><div class="bh-stat-val" style="color:#eab308">{len(bh.no_laps_computers)}</div></div>
    </div>"""

    # Findings
    findings_html = ""
    for f in bh.findings:
        sev    = f["severity"]
        color  = sev_color.get(sev, "#6b7280")
        affected_str = ", ".join(str(a) for a in f.get("affected", [])[:6])
        if len(f.get("affected", [])) > 6:
            affected_str += f"… (+{len(f['affected'])-6})"

        # CVEs
        cves_html = ""
        for c in f.get("cves", [])[:4]:
            cid   = c.get("id", "")
            cvss  = c.get("cvss", "?")
            desc  = (c.get("description_fr") or c.get("description") or "")[:120]
            exp   = '<span class="bh-exp">⚡</span>' if c.get("exploit_available") else ""
            link  = f'<a href="https://nvd.nist.gov/vuln/detail/{cid}" target="_blank" class="bh-cve-link">{cid}</a>'
            cves_html += f"""
            <div class="bh-cve-row">{link} <span class="bh-cvss">CVSS {cvss}</span>{exp}<span class="bh-cve-desc">{desc}</span></div>"""

        # Commandes
        cmds_html = ""
        for cmd in f.get("commands", [])[:3]:
            cmds_html += f'<div class="bh-cmd"><code>{cmd}</code></div>'

        # Outils
        tools_html = " ".join(
            f'<span class="bh-tool">{t}</span>' for t in f.get("tools", [])
        )

        findings_html += f"""
        <div class="bh-finding" style="border-left:3px solid {color}">
          <div class="bh-finding-head">
            <span class="bh-sev" style="color:{color}">[{sev}]</span>
            <span class="bh-finding-title">{f["title"]}</span>
          </div>
          <p class="bh-finding-desc">{f["description"]}</p>
          {"<div class='bh-affected'>🎯 " + affected_str + "</div>" if affected_str else ""}
          {"<div class='bh-cves'><div class='bh-sub-title'>CVEs associées</div>" + cves_html + "</div>" if cves_html else ""}
          {"<div class='bh-cmds'><div class='bh-sub-title'>Commandes suggérées</div>" + cmds_html + "</div>" if cmds_html else ""}
          {"<div class='bh-tools'>Outils : " + tools_html + "</div>" if tools_html else ""}
        </div>"""

    # Trusts
    trusts_html = ""
    if bh.trusts:
        rows = "".join(
            f"<tr><td>{t.source}</td><td>→</td><td>{t.target}</td>"
            f"<td>{t.trust_type}</td><td>{'✓' if t.transitive else '✗'}</td></tr>"
            for t in bh.trusts[:10]
        )
        trusts_html = f"""
        <div class="bh-sub-title">Domaines de confiance</div>
        <table class="bh-trust-table">
          <thead><tr><th>Source</th><th></th><th>Cible</th><th>Type</th><th>Transitif</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    return f"""
<div class="section bh-section" id="bh-section">
  <h2 class="section-h2">🩸 Analyse BloodHound CE
    <span class="section-count">{len(bh.findings)} finding(s)</span>
  </h2>
  {stats_html}
  <div class="bh-findings">{findings_html}</div>
  {trusts_html}

  <style>
    .bh-section {{ margin: 1.5rem 0; }}
    .bh-stats {{ display:flex; flex-wrap:wrap; gap:.6rem; margin-bottom:1.25rem; }}
    .bh-stat {{ background:#0d1829; border:1px solid #1c3060; border-radius:6px; padding:.6rem .9rem; min-width:110px; }}
    .bh-stat-lbl {{ font-size:.65rem; text-transform:uppercase; letter-spacing:.06em; color:#4a6488; margin-bottom:.2rem; }}
    .bh-stat-val {{ font-size:1.4rem; font-weight:800; font-family:monospace; color:#dce8f8; }}
    .bh-stat-warn {{ border-color:#f9731644; }}
    .bh-stat-crit {{ border-color:#ef444444; }}

    .bh-findings {{ display:flex; flex-direction:column; gap:.75rem; }}
    .bh-finding {{ background:#111428; border:1px solid #1c2240; border-radius:8px; padding:1rem 1.25rem; }}
    .bh-finding-head {{ display:flex; align-items:center; gap:.5rem; margin-bottom:.4rem; flex-wrap:wrap; }}
    .bh-sev {{ font-size:.75rem; font-weight:800; }}
    .bh-finding-title {{ font-size:.9rem; font-weight:700; color:#dce8f8; }}
    .bh-finding-desc {{ font-size:.8rem; color:#4a6488; line-height:1.5; margin-bottom:.5rem; }}
    .bh-affected {{ font-size:.75rem; color:#8aaad0; background:#161b30; border-radius:4px; padding:.3rem .6rem; margin-bottom:.5rem; }}
    .bh-sub-title {{ font-size:.65rem; text-transform:uppercase; letter-spacing:.07em; color:#4a6488; margin:.5rem 0 .3rem; }}
    .bh-cves {{ margin-bottom:.5rem; }}
    .bh-cve-row {{ font-size:.78rem; color:#4a6488; padding:.2rem 0; display:flex; gap:.5rem; align-items:baseline; flex-wrap:wrap; }}
    .bh-cve-link {{ font-family:monospace; color:#60a0f0; font-size:.78rem; border-bottom:1px dashed rgba(96,160,240,.3); }}
    .bh-cve-link:hover {{ color:#a0d0f0; }}
    .bh-cvss {{ font-size:.72rem; color:#4a6488; }}
    .bh-exp {{ color:#38bdf8; font-size:.75rem; }}
    .bh-cve-desc {{ font-size:.72rem; color:#4a6488; }}
    .bh-cmds {{ margin-bottom:.5rem; }}
    .bh-cmd {{ background:#0a0d1a; border:1px solid #1c2240; border-radius:4px; padding:.35rem .7rem; margin:.2rem 0; }}
    .bh-cmd code {{ font-family:monospace; font-size:.78rem; color:#4ade80; }}
    .bh-tools {{ font-size:.72rem; color:#4a6488; }}
    .bh-tool {{ display:inline-block; background:#1e243a; color:#60a0f0; padding:.05rem .35rem; border-radius:3px; font-family:monospace; font-size:.72rem; margin:.1rem .1rem .1rem 0; }}

    .bh-trust-table {{ width:100%; border-collapse:collapse; font-size:.8rem; margin-top:.3rem; }}
    .bh-trust-table th {{ background:#0d0f1f; color:#4a6488; font-size:.68rem; text-transform:uppercase; letter-spacing:.06em; padding:.4rem .7rem; text-align:left; border-bottom:1px solid #1c2240; }}
    .bh-trust-table td {{ padding:.4rem .7rem; border-bottom:1px solid #1c2240; color:#8aaad0; font-family:monospace; font-size:.75rem; }}
    .bh-trust-table tr:last-child td {{ border-bottom:none; }}
  </style>
</div>"""
