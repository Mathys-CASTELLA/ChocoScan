"""
ChocoScan — Vhost & Subdomain Discovery.

Pour chaque service HTTP/HTTPS détecté dans le scan, génère les
commandes ffuf/gobuster optimisées pour :
  - La découverte de virtual hosts (Host header fuzzing)
  - La découverte de sous-domaines
  - La découverte de répertoires/fichiers

Très fréquent sur HTB : presque toutes les boxes Medium+ ont
un vhost caché (dev., admin., api., internal., ...).

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class VhostTarget:
    host:     str
    port:     int
    protocol: str    # http | https
    banner:   str
    domain:   str    # domaine de base détecté ou deviné


@dataclass
class VhostCommands:
    target:   VhostTarget
    commands: list[dict]   # [{"title": ..., "cmd": ..., "desc": ...}]


# ── Wordlists recommandées ────────────────────────────────────────────────────

WORDLISTS = {
    "vhosts_small":   "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "vhosts_medium":  "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "vhosts_large":   "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    "dirs_small":     "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "dirs_medium":    "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "dirs_large":     "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "files":          "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
    "api":            "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "params":         "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "htb_custom":     "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",
}


# ── Détection du domaine ──────────────────────────────────────────────────────

def _guess_domain(host: str, banner: str, port: int) -> str:
    """Tente de deviner le domaine de base depuis le banner ou l'IP."""
    import re

    # Cherche un domaine dans le banner Nmap
    domain_match = re.search(
        r"([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})", banner
    )
    if domain_match:
        return domain_match.group(1).lower()

    # Pattern HTB classique : IP de la box → <machinename>.htb
    if re.match(r"10\.10\.\d+\.\d+", host):
        return "TARGET.htb"

    # VPN HTB
    if re.match(r"10\.10\.11\.\d+", host):
        return "TARGET.htb"

    return f"{host}.local"


def _detect_http_services(results: list[dict]) -> list[VhostTarget]:
    """Extrait tous les services HTTP/HTTPS du scan."""
    targets = []
    for result in results:
        svc  = result.get("service", {})
        port = svc.get("port", 0)
        svc_name = svc.get("service_name", "").lower()
        banner   = svc.get("banner", "").lower()
        host     = svc.get("host", "")

        is_http = (
            port in (80, 8080, 8000, 8008, 8888, 3000, 4000, 5000) or
            "http" in svc_name or "www" in svc_name
        )
        is_https = (
            port in (443, 8443, 9443) or "https" in svc_name
        )

        if not (is_http or is_https):
            continue

        proto  = "https" if is_https else "http"
        domain = _guess_domain(host, banner, port)

        targets.append(VhostTarget(
            host=host, port=port, protocol=proto,
            banner=banner, domain=domain,
        ))

    return targets


# ── Génération des commandes ──────────────────────────────────────────────────

def _build_commands(t: VhostTarget) -> list[dict]:
    """Génère les commandes ffuf/gobuster pour un service HTTP."""
    base_url = f"{t.protocol}://{t.host}"
    if t.port not in (80, 443):
        base_url += f":{t.port}"

    domain = t.domain
    cmds = []

    # ── 1. Vhost fuzzing — ffuf ───────────────────────────────────────────────
    cmds.append({
        "title": "Vhost Discovery — ffuf (recommandé)",
        "desc": (
            "Découverte de virtual hosts via le header Host. "
            "Filtrer avec -fw (mots), -fl (lignes) ou -fs (taille) selon les faux positifs."
        ),
        "cmd": (
            f"# Étape 1 : noter la taille/nombre de mots de la réponse par défaut\n"
            f"curl -s {base_url}/ | wc -w\n\n"
            f"# Étape 2 : fuzzer les vhosts (adapter -fw avec la valeur ci-dessus)\n"
            f"ffuf -w {WORDLISTS['vhosts_small']} "
            f"-u {base_url}/ "
            f"-H 'Host: FUZZ.{domain}' "
            f"-fw 42 "
            f"-mc 200,301,302,403 "
            f"-t 50 -v 2>/dev/null\n\n"
            f"# Avec résolution DNS auto (si le domaine est dans /etc/hosts) :\n"
            f"ffuf -w {WORDLISTS['vhosts_medium']} "
            f"-u {t.protocol}://FUZZ.{domain}/ "
            f"-fw 42 -t 50 -v 2>/dev/null"
        ),
    })

    # ── 2. Vhost fuzzing — gobuster ───────────────────────────────────────────
    cmds.append({
        "title": "Vhost Discovery — gobuster",
        "desc": "Alternative gobuster pour les vhosts.",
        "cmd": (
            f"gobuster vhost "
            f"-u {base_url} "
            f"-w {WORDLISTS['vhosts_small']} "
            f"--append-domain "
            f"-t 50 "
            f"--exclude-length 0 "
            f"2>/dev/null\n\n"
            f"# Ou avec un domaine HTB :\n"
            f"gobuster vhost "
            f"-u http://{domain} "
            f"-w {WORDLISTS['vhosts_small']} "
            f"--append-domain "
            f"-r -t 50 2>/dev/null"
        ),
    })

    # ── 3. Subdomain enumeration ───────────────────────────────────────────────
    cmds.append({
        "title": "Subdomain Enumeration — ffuf",
        "desc": "Énumération de sous-domaines (nécessite le domaine dans /etc/hosts ou DNS).",
        "cmd": (
            f"# Ajouter le domaine dans /etc/hosts si pas fait :\n"
            f"echo '{t.host} {domain}' | sudo tee -a /etc/hosts\n\n"
            f"ffuf -w {WORDLISTS['vhosts_medium']} "
            f"-u {t.protocol}://FUZZ.{domain}/ "
            f"-fw 42 -mc 200,301,302,403 "
            f"-t 50 2>/dev/null"
        ),
    })

    # ── 4. Directory / File fuzzing ────────────────────────────────────────────
    cmds.append({
        "title": "Directory & File Fuzzing — ffuf",
        "desc": "Découverte de répertoires et fichiers sensibles.",
        "cmd": (
            f"# Répertoires\n"
            f"ffuf -w {WORDLISTS['dirs_medium']} "
            f"-u {base_url}/FUZZ "
            f"-mc 200,204,301,302,307,401,403 "
            f"-t 50 -v 2>/dev/null\n\n"
            f"# Fichiers avec extensions courantes\n"
            f"ffuf -w {WORDLISTS['dirs_small']} "
            f"-u {base_url}/FUZZ "
            f"-e .php,.txt,.bak,.html,.js,.json,.xml,.conf,.log,.zip,.tar.gz "
            f"-mc 200,204 "
            f"-t 50 2>/dev/null"
        ),
    })

    # ── 5. API endpoint discovery ─────────────────────────────────────────────
    cmds.append({
        "title": "API Endpoint Discovery",
        "desc": "Découverte d'endpoints API (si un service REST/GraphQL est suspecté).",
        "cmd": (
            f"# Endpoints API standards\n"
            f"ffuf -w {WORDLISTS['api']} "
            f"-u {base_url}/FUZZ "
            f"-mc 200,201,204,400,401,403,405 "
            f"-t 50 2>/dev/null\n\n"
            f"# Paramètres GET\n"
            f"ffuf -w {WORDLISTS['params']} "
            f"-u '{base_url}/index.php?FUZZ=test' "
            f"-mc 200 -fw 42 "
            f"-t 50 2>/dev/null"
        ),
    })

    # ── 6. Commande /etc/hosts ─────────────────────────────────────────────────
    cmds.append({
        "title": "Ajouter à /etc/hosts (si domaine HTB)",
        "desc": "Indispensable avant de tester les vhosts sur HTB.",
        "cmd": (
            f"echo '{t.host} {domain}' | sudo tee -a /etc/hosts\n"
            f"# Pour les vhosts trouvés (remplacer VHOST) :\n"
            f"echo '{t.host} VHOST.{domain}' | sudo tee -a /etc/hosts"
        ),
    })

    return cmds


# ── Point d'entrée ────────────────────────────────────────────────────────────

def analyze_vhosts(results: list[dict],
                    custom_domain: str = "") -> list[VhostCommands]:
    """
    Analyse les résultats du scan et génère les commandes
    de vhost/subdomain discovery pour chaque service HTTP détecté.
    """
    targets = _detect_http_services(results)
    if not targets:
        return []

    # Si domaine custom fourni, l'applique à tous les targets
    if custom_domain:
        for t in targets:
            t.domain = custom_domain

    return [
        VhostCommands(target=t, commands=_build_commands(t))
        for t in targets
    ]
