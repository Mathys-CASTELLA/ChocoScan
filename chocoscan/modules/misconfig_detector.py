"""
ChocoScan — Détection de misconfigurations réseau.

Détecte les configurations dangereuses indépendamment des CVE :
un service peut être sur une version non vulnérable mais mal configuré.

Exemples : Redis sans auth, FTP anonyme, MongoDB ouvert, NFS sans restriction,
           SNMP avec community string par défaut, Rsync sans auth, etc.

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Misconfig:
    service:     str
    port:        int
    host:        str
    title:       str
    severity:    str          # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    impact:      str
    remediation: str
    check_cmd:   str          # Commande pour confirmer manuellement
    tags:        list[str]


# ── Règles de détection ───────────────────────────────────────────────────────
# Chaque règle est une fonction (service_name, port, banner) -> Misconfig | None

def _check_ftp(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port != 21 and "ftp" not in svc_name.lower():
        return results

    banner_low = banner.lower()
    if any(kw in banner_low for kw in ("anonymous", "no password", "login ok", "guest")):
        results.append(Misconfig(
            service="FTP", port=port, host=host,
            title="FTP — Accès anonyme activé",
            severity="HIGH",
            description="Le serveur FTP accepte les connexions anonymes sans mot de passe. "
                        "Un attaquant peut lister et télécharger les fichiers accessibles.",
            impact="Lecture (et parfois écriture) de fichiers sans authentification.",
            remediation="Désactiver l'accès anonyme dans vsftpd.conf/proftpd.conf "
                        "(anonymous_enable=NO).",
            check_cmd=f"ftp {host}  # login: anonymous / pass: anonymous",
            tags=["anonymous", "ftp", "no-auth"],
        ))
    return results


def _check_redis(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port not in (6379, 6380) and "redis" not in svc_name.lower():
        return results

    results.append(Misconfig(
        service="Redis", port=port, host=host,
        title="Redis — Probablement sans authentification",
        severity="CRITICAL",
        description="Redis expose son port réseau. Les versions par défaut n'ont pas "
                    "de mot de passe configuré, permettant un accès total à la base de données "
                    "et souvent une exécution de commandes via CONFIG SET dir/dbfilename.",
        impact="Lecture/écriture de toutes les données, RCE potentielle via écriture de cron/SSH keys.",
        remediation="Configurer requirepass dans redis.conf, lier à 127.0.0.1, "
                    "utiliser un firewall.",
        check_cmd=f"redis-cli -h {host} -p {port} ping  # Réponse 'PONG' = accès ouvert",
        tags=["no-auth", "redis", "rce-potential", "data-exposure"],
    ))
    return results


def _check_mongodb(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port not in (27017, 27018, 27019) and "mongo" not in svc_name.lower():
        return results

    results.append(Misconfig(
        service="MongoDB", port=port, host=host,
        title="MongoDB — Probablement sans authentification",
        severity="CRITICAL",
        description="MongoDB expose son port réseau. Sans authentification activée "
                    "(--auth), n'importe qui peut lire et modifier toutes les bases de données.",
        impact="Accès complet à toutes les données sans identifiants.",
        remediation="Activer l'authentification (--auth), lier à 127.0.0.1, "
                    "utiliser un firewall.",
        check_cmd=f"mongosh {host}:{port} --eval 'db.adminCommand({{listDatabases:1}})' 2>/dev/null",
        tags=["no-auth", "mongodb", "data-exposure"],
    ))
    return results


def _check_elasticsearch(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port not in (9200, 9300) and "elastic" not in svc_name.lower():
        return results

    results.append(Misconfig(
        service="Elasticsearch", port=port, host=host,
        title="Elasticsearch — Potentiellement sans authentification",
        severity="HIGH",
        description="Elasticsearch < 8.0 n'a pas d'authentification par défaut. "
                    "Toutes les données indexées sont accessibles sans identifiants.",
        impact="Lecture de toutes les données indexées, suppression possible des indices.",
        remediation="Activer X-Pack Security, configurer TLS et authentification.",
        check_cmd=f"curl -s http://{host}:{port}/_cat/indices",
        tags=["no-auth", "elasticsearch", "data-exposure"],
    ))
    return results


def _check_nfs(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port not in (2049, 111) and "nfs" not in svc_name.lower():
        return results

    results.append(Misconfig(
        service="NFS", port=port, host=host,
        title="NFS — Partage réseau exposé",
        severity="HIGH",
        description="Un serveur NFS est exposé sur le réseau. Si les exports ne "
                    "sont pas correctement restreints, un attaquant peut monter "
                    "les partages et accéder aux fichiers.",
        impact="Lecture/écriture de fichiers selon la configuration des exports, "
               "potentiel vol de clés SSH ou écrasement de fichiers.",
        remediation="Restreindre les exports à des IPs spécifiques dans /etc/exports, "
                    "utiliser 'no_root_squash' uniquement si nécessaire.",
        check_cmd=f"showmount -e {host}  # Liste les exports NFS disponibles",
        tags=["nfs", "file-access", "potential-privesc"],
    ))
    return results


def _check_snmp(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port != 161 and "snmp" not in svc_name.lower():
        return results

    results.append(Misconfig(
        service="SNMP", port=port, host=host,
        title="SNMP — Community string par défaut probable",
        severity="MEDIUM",
        description="SNMP est souvent configuré avec les community strings par défaut "
                    "'public' (lecture) et 'private' (écriture), permettant l'énumération "
                    "d'informations système détaillées.",
        impact="Énumération des processus, interfaces réseau, utilisateurs, "
               "informations système. Écriture possible avec community string 'private'.",
        remediation="Changer les community strings, utiliser SNMPv3 avec authentification.",
        check_cmd=f"snmpwalk -v2c -c public {host} 1.3.6.1.2.1.1",
        tags=["snmp", "info-disclosure", "enumeration"],
    ))
    return results


def _check_rsync(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port != 873 and "rsync" not in svc_name.lower():
        return results

    results.append(Misconfig(
        service="Rsync", port=port, host=host,
        title="Rsync — Partage potentiellement sans authentification",
        severity="HIGH",
        description="Rsync expose ses modules réseau. Sans authentification, "
                    "un attaquant peut lister et télécharger tous les fichiers partagés.",
        impact="Accès en lecture (et parfois écriture) aux fichiers partagés, "
               "potentiel vol de données sensibles ou de clés SSH.",
        remediation="Configurer secrets file dans rsyncd.conf, restreindre les hosts autorisés.",
        check_cmd=f"rsync --list-only rsync://{host}/",
        tags=["rsync", "file-access", "no-auth"],
    ))
    return results


def _check_smb(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port not in (139, 445) and "smb" not in svc_name.lower() and "netbios" not in svc_name.lower():
        return results

    results.append(Misconfig(
        service="SMB", port=port, host=host,
        title="SMB — Null session et partages anonymes potentiels",
        severity="MEDIUM",
        description="SMB peut permettre des sessions nulles (sans authentification) "
                    "permettant l'énumération des utilisateurs, partages et informations système.",
        impact="Énumération des utilisateurs, groupes, partages accessibles, "
               "politique de mots de passe.",
        remediation="Désactiver les sessions nulles, activer SMB Signing, "
                    "restreindre l'accès aux partages.",
        check_cmd=f"smbclient -L //{host} -N && enum4linux -a {host}",
        tags=["smb", "null-session", "enumeration"],
    ))
    return results


def _check_vnc(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port not in (5900, 5901, 5902) and "vnc" not in svc_name.lower():
        return results

    results.append(Misconfig(
        service="VNC", port=port, host=host,
        title="VNC — Accès bureau à distance exposé",
        severity="HIGH",
        description="Un serveur VNC est exposé sur le réseau. VNC peut être "
                    "configuré sans mot de passe ou avec un mot de passe faible.",
        impact="Accès graphique complet au bureau de la machine distante.",
        remediation="Configurer un mot de passe fort, utiliser un tunnel SSH, "
                    "restreindre les IPs autorisées.",
        check_cmd=f"nmap -sV --script vnc-info,vnc-brute -p {port} {host}",
        tags=["vnc", "remote-access", "potential-no-auth"],
    ))
    return results


def _check_webmin(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port not in (10000, 10001) and "webmin" not in svc_name.lower():
        return results

    results.append(Misconfig(
        service="Webmin", port=port, host=host,
        title="Webmin — Interface d'administration exposée",
        severity="HIGH",
        description="Webmin expose une interface d'administration système complète "
                    "sur le réseau. Une authentification faible ou des CVE connues "
                    "(ex: CVE-2019-15107) peuvent permettre une compromission totale.",
        impact="Administration système complète si authentification compromise.",
        remediation="Restreindre l'accès par IP, activer 2FA, garder Webmin à jour.",
        check_cmd=f"curl -k -s https://{host}:{port}/  # Vérifier si accessible",
        tags=["webmin", "admin-interface", "high-value"],
    ))
    return results


def _check_docker_api(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port not in (2375, 2376) and "docker" not in svc_name.lower():
        return results

    results.append(Misconfig(
        service="Docker API", port=port, host=host,
        title="Docker API — Socket TCP exposé sans TLS",
        severity="CRITICAL",
        description="L'API Docker est exposée sur le réseau sans TLS. "
                    "Un accès à l'API Docker permet de créer des conteneurs "
                    "avec montage du système de fichiers hôte, équivalent à un accès root.",
        impact="Compromission complète de l'hôte via création de conteneurs privilégiés.",
        remediation="Ne pas exposer Docker API sur TCP, utiliser TLS si nécessaire, "
                    "utiliser uniquement le socket Unix local.",
        check_cmd=f"curl -s http://{host}:{port}/version",
        tags=["docker", "container-escape", "rce-potential", "critical"],
    ))
    return results


def _check_kubernetes(svc_name: str, port: int, host: str, banner: str) -> list[Misconfig]:
    results = []
    if port not in (6443, 8080, 8443, 10250) and "kubernetes" not in svc_name.lower() and "k8s" not in svc_name.lower():
        return results

    if port == 10250:
        results.append(Misconfig(
            service="Kubernetes Kubelet", port=port, host=host,
            title="Kubernetes Kubelet API — Exposée sans authentification",
            severity="CRITICAL",
            description="La Kubelet API (port 10250) est accessible. Si l'authentification "
                        "n'est pas configurée, un attaquant peut exécuter des commandes "
                        "dans n'importe quel pod du noeud.",
            impact="Exécution de commandes dans tous les pods, accès aux secrets K8s.",
            remediation="Activer l'authentification Kubelet, restreindre l'accès réseau.",
            check_cmd=f"curl -sk https://{host}:{port}/pods | python3 -m json.tool | head -50",
            tags=["kubernetes", "kubelet", "rce-potential", "critical"],
        ))
    return results


# ── Moteur principal ──────────────────────────────────────────────────────────

_CHECKS = [
    _check_ftp, _check_redis, _check_mongodb, _check_elasticsearch,
    _check_nfs, _check_snmp, _check_rsync, _check_smb, _check_vnc,
    _check_webmin, _check_docker_api, _check_kubernetes,
]


def detect_misconfigs(services: list) -> list[Misconfig]:
    """
    Analyse une liste de NmapService et retourne les misconfigurations détectées.
    Ne fait pas d'appel réseau — basé uniquement sur le nom de service,
    le port et le banner fournis par Nmap.
    """
    findings: list[Misconfig] = []
    for svc in services:
        svc_name = getattr(svc, "service_name", "") or ""
        port     = getattr(svc, "port", 0) or 0
        host     = getattr(svc, "host", "TARGET") or "TARGET"
        banner   = getattr(svc, "banner", "") or ""
        for check in _CHECKS:
            findings.extend(check(svc_name, port, host, banner))

    # Déduplique par (host, port, title)
    seen = set()
    unique = []
    for f in findings:
        key = (f.host, f.port, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return sorted(unique, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x.severity, 4))
