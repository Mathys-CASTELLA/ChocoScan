"""
ChocoScan — Gestion du fichier de configuration
=================================================

Lit ~/.chocoscan.conf (format TOML) et applique les valeurs comme
defaults argparse — les arguments CLI ont toujours la priorité.

Fichier de config exemple : ~/.chocoscan.conf
─────────────────────────────────────────────
  # Options par défaut de ChocoScan
  # Toutes les valeurs ici sont surchargées par les arguments CLI.

  min_cvss     = 7.0
  top_cves     = 10
  exploits     = true
  export_html  = false
  output_dir   = "~/chocoscan_reports"
  severity     = "CRITICAL,HIGH"
  no_api       = false
  after_year   = 2020

  [scan]
  nmap_args    = "-T4 --open"

  [web]
  enum_web     = false
  enum_threads = 20
  enum_delay   = 0.05
─────────────────────────────────────────────

Priorité de résolution (la plus haute gagne) :
  1. Argument CLI explicite        (--min-cvss 9.0)
  2. Variable d'environnement      (CHOCOSCAN_MIN_CVSS=9.0)
  3. Fichier ~/.chocoscan.conf
  4. Défaut argparse

Règles de nommage :
  - Clé TOML : underscore  (min_cvss, top_cves, export_html)
  - Arg CLI  : tiret        (--min-cvss, --top-cves, --export-html)
  - Variable env : CHOCOSCAN_ + MAJUSCULES + underscore
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from typing import Any



# ─── Activation des modules depuis la config ──────────────────────────────────
#
# Certains modules utilisent nargs="?" (valeur optionnelle) plutôt que
# store_true. Quand la config dit module = true, il faut passer la bonne
# valeur d'activation à set_defaults() plutôt que True.
#
#   store_true  → True
#   nargs="?"   → constante d'activation (ex: "auto", "all")
#
MODULE_ACTIVATION_MAP: dict[str, Any] = {
    # Web
    "web_fingerprint": True,      # store_true
    "web_payloads":   "auto",   # nargs="?"
    "vhost":          "auto",   # nargs="?"
    "revshell":       "auto",   # nargs="?"
    # Réseau
    "pivot":          "auto",   # nargs="?"
    "upgrade_shell":  True,     # store_true
    # Credentials
    "brute":          True,     # store_true
    "default_creds":  True,     # store_true
    "hashcrack":      "auto",   # nargs="?"
    "wordlist":       "auto",   # nargs="?"
    # SMB & AD
    "smb":            True,     # store_true
    "ad_enum":        True,     # store_true
    "lateral":        True,     # store_true
    # Privesc
    "privesc":        True,     # store_true
    "gtfobins":       True,     # store_true
    "misconfig":      True,     # store_true
    "tokens":         "all",    # nargs="?"  → "all" = checklist complète
    # Container & Cloud
    "container":      "all",    # nargs="?"  → "all" = checklist complète
    "cloud":          True,     # store_true
    # Divers
    "msf":            True,     # store_true
    "kill_chain":     True,     # store_true
    "loot":           True,     # store_true
    "web_fingerprint": True,    # store_true
    # Reconnaissance
    "subdomain":      "auto",   # nargs="?" → "auto" = détection depuis le scan
}


# ─── Chemins de recherche du fichier de config ───────────────────────────────

CONFIG_SEARCH_PATHS: list[Path] = [
    Path.home() / ".chocoscan.conf",
    Path.home() / ".config" / "chocoscan" / "config.toml",
    Path(".chocoscan.conf"),          # répertoire courant (utile en CTF)
]

# Variable d'environnement pour forcer un chemin de config
CONFIG_ENV_VAR = "CHOCOSCAN_CONFIG"


# ─── Clés configurables et leurs métadonnées ─────────────────────────────────
# Format : clé_toml → (type Python, valeur_défaut_argparse, section_toml)
# La section_toml None = section racine [global]

CONFIGURABLE_KEYS: dict[str, tuple[type, Any, str | None]] = {
    # Filtrage
    "min_cvss":      (float, 0.0,     None),
    "severity":      (str,   "",      None),
    "after_year":    (int,   None,    None),
    "top_cves":      (int,   5,       None),
    # Comportement
    "no_api":        (bool,  False,   None),
    "exploits":      (bool,  False,   None),
    "no_scoring":    (bool,  False,   None),
    "no_ad":         (bool,  False,   None),
    "no_chains":     (bool,  False,   None),
    "interactive":   (bool,  False,   None),
    # Export
    "export_html":   (bool,  False,   None),
    "export_json":   (bool,  False,   None),
    "output_dir":    (str,   "output", None),
    "input_format":  (str,   "auto",  None),
    # Scan nmap
    "nmap_args":     (str,   "",      "scan"),
    # Reconnaissance (subdomain enum)
    "subdomain":     (str,   "",      None),       # "" = désactivé, "auto" = détecter depuis scan
    "sub_wordlist":  (str,   "",      "subdomain"),
    "sub_threads":   (int,   30,      "subdomain"),
    "sub_passive":   (bool,  False,   "subdomain"),
    "sub_active":    (bool,  False,   "subdomain"),
    # Énumération web
    "enum_web":      (bool,  False,   "web"),
    "enum_threads":  (int,   10,      "web"),
    "enum_delay":    (float, 0.05,    "web"),

    # ── Réseau / attaquant ────────────────────────────────────────────────────
    "lhost":          (str,   "",      None),
    "lport":          (int,   4444,    None),

    # ── Connexion SSH ─────────────────────────────────────────────────────────
    "ssh_user":       (str,   "",      "ssh"),
    "ssh_key":        (str,   "",      "ssh"),
    "ssh_port":       (int,   22,      "ssh"),

    # ── Modules offensifs (bool, false = désactivé par défaut) ───────────────
    # Web
    "web_payloads":   (bool,  False,   "modules"),
    "vhost":          (bool,  False,   "modules"),
    "revshell":       (bool,  False,   "modules"),
    # Réseau
    "pivot":          (bool,  False,   "modules"),
    "upgrade_shell":  (bool,  False,   "modules"),
    # Credentials & brute force
    "brute":          (bool,  False,   "modules"),
    "default_creds":  (bool,  False,   "modules"),
    "hashcrack":      (bool,  False,   "modules"),
    "wordlist":       (bool,  False,   "modules"),
    # SMB & Active Directory
    "smb":            (bool,  False,   "modules"),
    "ad_enum":        (bool,  False,   "modules"),
    "lateral":        (bool,  False,   "modules"),
    # Privilege escalation
    "privesc":        (bool,  False,   "modules"),
    "gtfobins":       (bool,  False,   "modules"),
    "misconfig":      (bool,  False,   "modules"),
    "tokens":         (bool,  False,   "modules"),
    # Container & Cloud
    "container":      (bool,  False,   "modules"),
    "cloud":          (bool,  False,   "modules"),
    # Divers
    "msf":            (bool,  False,   "modules"),
    "kill_chain":     (bool,  False,   "modules"),
    "loot":           (bool,  False,   "modules"),
    "web_fingerprint": (bool,  False,   "modules"),  # Détection active CMS/frameworks
}


# ─── Lecture du fichier de config ─────────────────────────────────────────────

def find_config_file() -> Path | None:
    """
    Trouve le fichier de config selon l'ordre de priorité :
    1. $CHOCOSCAN_CONFIG (variable d'environnement)
    2. CONFIG_SEARCH_PATHS (dans l'ordre)
    """
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        p = Path(env_path).expanduser()
        if p.exists():
            return p
        # Variable définie mais fichier absent → avertir
        _warn(f"$CHOCOSCAN_CONFIG={env_path} introuvable, ignoré.")

    for p in CONFIG_SEARCH_PATHS:
        if p.expanduser().exists():
            return p.expanduser()

    return None


def _warn(msg: str):
    """Affiche un avertissement discret sur stderr."""
    try:
        from rich.console import Console
        Console(stderr=True).print(f"[yellow dim][config] {msg}[/yellow dim]")
    except ImportError:
        print(f"[config] {msg}", file=sys.stderr)


def _info(msg: str):
    """Affiche un message d'info config si rich disponible."""
    try:
        from rich.console import Console
        Console(stderr=True).print(f"[dim][config] {msg}[/dim]")
    except ImportError:
        pass  # silencieux sans rich


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    """
    Charge et valide le fichier de config.

    Retourne un dict plat clé_toml → valeur, prêt pour set_defaults().
    Retourne {} si aucun fichier trouvé.
    """
    path = config_path or find_config_file()
    if path is None:
        return {}

    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        _warn(f"Erreur de syntaxe dans {path} : {e}")
        return {}
    except OSError as e:
        _warn(f"Impossible de lire {path} : {e}")
        return {}

    return _flatten_and_validate(raw, path)


def _flatten_and_validate(raw: dict, path: Path) -> dict[str, Any]:
    """
    Aplatie la structure TOML (sections → clé_racine) et valide les types.
    """
    flat: dict[str, Any] = {}
    unknown: list[str] = []

    # Clés de la section racine
    for key, value in raw.items():
        if isinstance(value, dict):
            # Section TOML ([scan], [web], etc.)
            for subkey, subval in value.items():
                full_key = subkey  # les sous-clés sont des clés directes
                _process_key(full_key, subval, flat, unknown)
        else:
            _process_key(key, value, flat, unknown)

    if unknown:
        _warn(f"{path.name} : clés inconnues ignorées : {', '.join(unknown)}")

    return flat


def _process_key(key: str, value: Any, flat: dict, unknown: list):
    """Valide et insère une clé dans le dict plat."""
    if key not in CONFIGURABLE_KEYS:
        unknown.append(key)
        return

    expected_type, _, _ = CONFIGURABLE_KEYS[key]

    # Coercition de type avec message clair
    try:
        if expected_type == bool:
            if not isinstance(value, bool):
                raise TypeError(f"attendu bool, reçu {type(value).__name__}")
            flat[key] = value
        elif expected_type == float:
            flat[key] = float(value)
        elif expected_type == int:
            flat[key] = int(value)
        elif expected_type == str:
            v = str(value)
            if key == "output_dir":
                v = str(Path(v).expanduser())
            flat[key] = v
        else:
            flat[key] = value
    except (TypeError, ValueError) as e:
        _warn(f"Clé '{key}' : valeur invalide ({e}), ignorée.")


# ─── Variables d'environnement ────────────────────────────────────────────────

def load_env_overrides() -> dict[str, Any]:
    """
    Lit les variables d'environnement CHOCOSCAN_* et retourne un dict
    de valeurs à appliquer (priorité au-dessus du fichier de config).

    Exemples :
      CHOCOSCAN_MIN_CVSS=9.0
      CHOCOSCAN_EXPLOITS=true
      CHOCOSCAN_OUTPUT_DIR=/tmp/reports
    """
    overrides: dict[str, Any] = {}
    prefix = "CHOCOSCAN_"

    for env_key, env_val in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        config_key = env_key[len(prefix):].lower()
        if config_key not in CONFIGURABLE_KEYS:
            continue

        expected_type, _, _ = CONFIGURABLE_KEYS[config_key]
        try:
            if expected_type == bool:
                overrides[config_key] = env_val.strip().lower() in ("1", "true", "yes", "on")
            elif expected_type == float:
                overrides[config_key] = float(env_val)
            elif expected_type == int:
                overrides[config_key] = int(env_val)
            else:
                overrides[config_key] = env_val
        except (ValueError, TypeError):
            _warn(f"${env_key} : valeur invalide '{env_val}', ignorée.")

    return overrides


# ─── Application sur le parser argparse ───────────────────────────────────────

def apply_to_parser(parser, config_path: Path | None = None, verbose: bool = True) -> Path | None:
    """
    Charge la config et l'applique sur le parser via set_defaults().

    Les valeurs CLI ont toujours la priorité (c'est le comportement
    naturel de set_defaults : elles ne font que remplacer les défauts,
    pas les valeurs explicitement passées par l'utilisateur).

    Returns:
        Le Path du fichier de config chargé, ou None.
    """
    path = config_path or find_config_file()

    # 1. Config fichier
    file_cfg = load_config(path)

    # 2. Variables d'environnement (priorité sur fichier)
    env_cfg = load_env_overrides()

    # Fusion : env écrase fichier
    merged = {**file_cfg, **env_cfg}

    if not merged:
        return path  # rien à appliquer

    # Convertir les clés underscore en clés argparse (tirets)
    # argparse stocke les attrs avec underscore (--min-cvss → args.min_cvss)
    # set_defaults prend les noms d'attributs (avec underscore)
    # Donc on peut passer directement.

    # ── Modules : convertir bool True → valeur d'activation argparse ──────
    # Les modules nargs="?" ont besoin de "auto"/"all" et non True.
    # Les modules désactivés (False) sont retirés pour laisser le défaut argparse.
    module_keys = set(MODULE_ACTIVATION_MAP.keys())
    for key in list(merged.keys()):
        if key not in module_keys:
            continue
        if merged[key] is True:
            merged[key] = MODULE_ACTIVATION_MAP[key]
        else:
            # False → ne pas passer à set_defaults (garde le défaut argparse)
            del merged[key]

    parser.set_defaults(**merged)

    if verbose and path:
        _info(f"Config chargée : {path}")

    return path


# ─── CLI : chocoscan config ────────────────────────────────────────────────────

def cmd_config_show(config_path: Path | None = None):
    """Affiche la config active (fichier + env) avec leur source."""
    path = config_path or find_config_file()
    file_cfg = load_config(path)
    env_cfg  = load_env_overrides()

    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box as rbox

        c = Console()
        t = Table(
            title=f"Config active — {path or 'aucun fichier trouvé'}",
            box=rbox.ROUNDED,
            show_header=True,
        )
        t.add_column("Clé",        style="cyan",   min_width=18)
        t.add_column("Valeur",     style="bold",   min_width=12)
        t.add_column("Source",     style="dim",    min_width=14)
        t.add_column("Défaut CLI", style="dim",    min_width=12)

        for key, (typ, default, _) in sorted(CONFIGURABLE_KEYS.items()):
            if key in env_cfg:
                val    = env_cfg[key]
                source = f"$CHOCOSCAN_{key.upper()}"
            elif key in file_cfg:
                val    = file_cfg[key]
                source = path.name if path else "fichier"
            else:
                val    = default
                source = "défaut"

            val_str = str(val) if val is not None else "—"
            def_str = str(default) if default is not None else "—"

            # Mettre en valeur les clés non-défaut
            row_style = "" if source == "défaut" else "bold"
            t.add_row(key, val_str, source, def_str)

        c.print(t)
        if not path:
            c.print(f"\n[dim]Aucun fichier de config trouvé. "
                    f"Créez [bold]~/.chocoscan.conf[/bold] pour personnaliser vos défauts.[/dim]")
    except ImportError:
        # Fallback sans rich
        print(f"\nConfig active — {path or 'aucun fichier'}")
        print(f"{'Clé':<20} {'Valeur':<15} Source")
        print("-" * 55)
        for key, (typ, default, _) in sorted(CONFIGURABLE_KEYS.items()):
            if key in env_cfg:
                val, src = env_cfg[key], "env"
            elif key in file_cfg:
                val, src = file_cfg[key], "fichier"
            else:
                val, src = default, "défaut"
            print(f"  {key:<18} {str(val):<15} {src}")


def cmd_config_init(target: Path | None = None):
    """Crée un fichier ~/.chocoscan.conf avec toutes les options commentées."""
    dest = target or Path.home() / ".chocoscan.conf"

    if dest.exists():
        try:
            from rich.console import Console
            Console().print(f"[yellow][!] {dest} existe déjà. Utilisez --force pour écraser.[/yellow]")
        except ImportError:
            print(f"[!] {dest} existe déjà.")
        return

    content = _generate_default_config()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")

    try:
        from rich.console import Console
        Console().print(f"[green][+] Config créée : {dest}[/green]")
        Console().print(f"[dim]Éditez le fichier pour personnaliser vos préférences.[/dim]")
    except ImportError:
        print(f"[+] Config créée : {dest}")


def cmd_config_init_force(target: Path | None = None):
    """Crée ou écrase ~/.chocoscan.conf."""
    dest = target or Path.home() / ".chocoscan.conf"
    content = _generate_default_config()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    try:
        from rich.console import Console
        Console().print(f"[green][+] Config (ré)initialisée : {dest}[/green]")
    except ImportError:
        print(f"[+] Config (ré)initialisée : {dest}")


def _generate_default_config() -> str:
    """Génère le contenu du fichier de config par défaut."""
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d")

    return f"""# ChocoScan — Fichier de configuration personnelle
# Généré le {now}
# Emplacement : ~/.chocoscan.conf
#
# Toutes les valeurs ici sont des DÉFAUTS — elles sont surchargées
# par les arguments CLI (ex: --min-cvss 9.0 écrase min_cvss ci-dessous).
#
# Variables d'environnement : CHOCOSCAN_<CLÉ_MAJUSCULE>
#   ex: export CHOCOSCAN_MIN_CVSS=9.0
#
# Syntaxe TOML : https://toml.io/en/

# ─── Filtrage ────────────────────────────────────────────────────────────────

# Score CVSS minimum pour afficher une CVE (0.0 = toutes)
min_cvss = 0.0

# Sévérités à afficher — laisser vide pour toutes
# Valeurs : CRITICAL, HIGH, MEDIUM, LOW  (séparées par virgules)
severity = ""

# Afficher uniquement les CVEs publiées depuis cette année (null = toutes)
# after_year = 2022

# Nombre max de CVEs affichées par port dans le terminal (0 = toutes)
# Le rapport HTML affiche toujours toutes les CVEs.
top_cves = 5

# ─── Comportement ────────────────────────────────────────────────────────────

# Désactiver le fallback vers l'API NVD (plus rapide, résultats locaux seuls)
no_api = false

# Clé API NVD — accélère le fallback de 5 à 50 requêtes/30s.
# Gratuite, à demander sur : https://nvd.nist.gov/developers/request-an-api-key
# (Cette clé n'apparaît pas dans `chocoscan config show` pour rester discrète.)
# nvd_api_key = "votre-clé-ici"

# Rechercher des exploits PoC GitHub pour chaque CVE
exploits = false

# Désactiver le scoring contextuel (utilise uniquement le CVSS brut)
no_scoring = false

# Désactiver la détection Active Directory
no_ad = false

# Désactiver l'analyse des CVEs chaînables
no_chains = false

# Lancer le mode interactif après chaque scan
interactive = false

# ─── Export ──────────────────────────────────────────────────────────────────

# Générer un rapport HTML automatiquement
export_html = false

# Générer un rapport JSON automatiquement
export_json = false

# Dossier de sortie pour les rapports (~ est supporté)
output_dir = "output"

# Format d'entrée (auto = détection automatique)
# Valeurs : auto, nmap_xml, nmap_text, masscan_json, rustscan_json, nessus_csv, ...
input_format = "auto"

# ─── Réseau / attaquant ──────────────────────────────────────────────────────
# Utilisé automatiquement par --revshell, --web-payloads, --pivot, etc.

# Ton IP VPN (tun0 sur HTB) — plus besoin de taper --lhost à chaque fois
lhost = ""

# Port d'écoute pour les reverse shells (défaut : 4444)
lport = 4444

# ─── Scan Nmap ───────────────────────────────────────────────────────────────
# Arguments passés à nmap lors d'un scan --scan <TARGET>.
# La valeur ci-dessous remplace le défaut de ChocoScan.
# Les arguments CLI --nmap-args ont toujours la priorité.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RÉFÉRENCE RAPIDE NMAP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# ── TYPES DE SCAN ────────────────────────────────────────────────────────────
#
#  -sS   SYN scan (stealth, défaut root)   — envoie SYN, attend SYN-ACK sans
#                                            compléter le handshake. Rapide et
#                                            peu loggé. Nécessite root.
#        Ex: nmap -sS -p 80,443 10.10.10.1
#
#  -sT   TCP Connect (défaut sans root)    — handshake complet, plus lent,
#                                            loggé dans les applications.
#        Ex: nmap -sT -p 22,80 10.10.10.1
#
#  -sU   UDP scan                          — lent, souvent oublié en CTF.
#                                            SNMP (161), DNS (53), TFTP (69),
#                                            NTP (123). Combiner avec -sS.
#        Ex: nmap -sU -sS --top-ports 20 10.10.10.1
#
#  -sV   Version detection                 — banner grabbing + fingerprinting.
#                                            --version-intensity 0-9 (5 = défaut)
#        Ex: nmap -sV --version-intensity 7 10.10.10.1
#
#  -sC   Scripts par défaut (safe)         — équivalent à --script=default.
#                                            http-title, ssl-cert,
#                                            smb-security-mode, ssh-hostkey…
#        Ex: nmap -sC 10.10.10.1
#
#  -A    All-in-one                        — équivalent -sV -sC -O --traceroute.
#                                            Bruyant mais complet.
#        Ex: nmap -A -T4 10.10.10.1
#
#  -sn   Ping scan (host discovery only)   — vérifie si les hôtes répondent,
#                                            sans scanner de ports.
#        Ex: nmap -sn 192.168.1.0/24
#
#  -O    OS detection                      — fingerprinting OS (TTL, TCP window).
#                                            Nécessite root.
#        Ex: nmap -O 10.10.10.1
#
#  -Pn   Skip host discovery               — indispensable si ICMP est bloqué
#                                            ou si la cible répond "down".
#        Ex: nmap -Pn -sV 10.10.10.1
#
#  -n    Pas de résolution DNS             — accélère le scan (pas de PTR lookup).
#
# ── SÉLECTION DES PORTS ──────────────────────────────────────────────────────
#
#  -p 22,80,443          Ports spécifiques
#  -p 1-1024             Plage
#  -p 80,443,8000-8100   Mixte
#  -p-                   Tous les ports (1-65535) — lent mais exhaustif
#  --top-ports 100       Top N ports les plus communs
#  --top-ports 1000      Bon compromis vitesse/couverture (défaut ChocoScan)
#  -F                    Fast mode — top 100 ports uniquement
#
# ── TIMING (-T0 à -T5) ───────────────────────────────────────────────────────
#
#  -T0  Paranoid    — 5 min entre chaque sonde. Bypass IDS. Très lent.
#  -T1  Sneaky      — 15 s entre sondes. Discret mais utilisable.
#  -T2  Polite      — 400 ms. Réduit la charge réseau.
#  -T3  Normal      — défaut nmap.
#  -T4  Aggressive  — délais réduits, parallélisme augmenté. Recommandé HTB.
#  -T5  Insane      — timeout minimal. Peut rater des ports sur réseau lent.
#
#  Note HTB : -T4 est le bon défaut. -T5 peut louper des ports ouverts
#             sur les boxes lentes (Windows, services custom).
#
# ── PERFORMANCE FINE ─────────────────────────────────────────────────────────
#
#  --min-rate N          Minimum N paquets/seconde (ex: --min-rate 5000)
#  --max-rate N          Maximum N paquets/seconde
#  --min-parallelism N   Minimum N sondes en parallèle
#  --max-retries N       Retransmissions (défaut 10 → mettre 2-3 pour aller vite)
#  --host-timeout Xm     Abandonner un hôte après X minutes (ex: 5m)
#  --scan-delay Xms      Pause entre sondes (contourne rate limiting)
#
#  Exemple full speed réseau fiable :
#    nmap -p- --min-rate 10000 -T4 --open 10.10.10.1
#
# ── SCRIPTS NSE ──────────────────────────────────────────────────────────────
#
#  --script=default          Safe et utiles (= -sC)
#  --script=vuln             Vérifications vulnérabilités connues (bruyant)
#  --script=auth             Tentatives d'authentification (guest, anonymous)
#  --script=discovery        Enumération réseau approfondie
#  --script=safe             Tous les scripts "safe"
#  --script=brute            Bruteforce léger par protocole
#
#  Scripts ciblés fréquents en CTF :
#    --script=http-title,http-auth-finder
#    --script=smb-vuln-ms17-010          # EternalBlue
#    --script=smb-enum-shares,smb-enum-users
#    --script=ldap-rootdse               # Active Directory
#    --script=ftp-anon                   # FTP anonymous login
#    --script=ssh-auth-methods           # Méthodes SSH supportées
#    --script=ssl-heartbleed             # CVE-2014-0160
#    --script=dns-zone-transfer          # AXFR
#    --script=mysql-empty-password
#
#  Avec arguments :
#    --script=http-brute --script-args http-brute.path=/login
#
# ── ÉVASION ──────────────────────────────────────────────────────────────────
#
#  -f                    Fragmentation IP (paquets de 8 octets)
#  --mtu N               MTU custom (multiple de 8, ex: --mtu 16)
#  -D RND:10             10 IPs leurres dans les paquets
#  -D decoy1,decoy2,ME   Leurres spécifiques + ta propre IP
#  -S <IP>               Spoof de l'IP source (root requis)
#  --spoof-mac 0         Adresse MAC aléatoire
#  --data-length N       Padding des paquets (+ discret)
#  -g 53                 Port source = 53 (bypass certains firewalls)
#
# ── OUTPUT ───────────────────────────────────────────────────────────────────
#
#  -oN fichier.txt   Format texte lisible
#  -oX fichier.xml   XML — requis pour ChocoScan (-x)
#  -oG fichier.gnmap Format grepable
#  -oA prefixe       Les 3 formats à la fois (.nmap, .xml, .gnmap)
#  -v / -vv          Verbosité (ports ouverts en temps réel)
#  --reason          Pourquoi un port est open/closed/filtered
#  --open            N'afficher que les ports ouverts (très recommandé)
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROFILS PRÉDÉFINIS — décommenter celui qui convient
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# HTB/CTF — rapide, 1000 ports courants, versions + scripts
#   nmap_args = "-sV -sC -T4 --open"
#
# HTB — tous les ports (à faire en premier, puis retour ciblé)
#   nmap_args = "-p- --min-rate 10000 -T4 --open"
#
# HTB — UDP (services cachés : SNMP, TFTP, DNS)
#   nmap_args = "-sU --top-ports 20 -T4"
#
# Réseau interne / pentest pro (discret, log XML)
#   nmap_args = "-sS -sV --top-ports 1000 -T3 --open -oA output/scan"
#
# Vulnérabilités (scripts vuln, bruyant)
#   nmap_args = "-sV -sC --script=vuln -T4 --open"
#
# Furtif (pas de ping, fragmentation, port source DNS)
#   nmap_args = "-sS -Pn -f -g 53 -T2 --open"
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[scan]
# Valeur active — décommenter un profil ci-dessus ou écrire le tien.
# Défaut ChocoScan si laissé vide : -sV -sC --top-ports 1000 --open -T4
nmap_args = ""

# ─── Énumération web ─────────────────────────────────────────────────────────

[web]
# Activer l'énumération web par défaut
enum_web = false

# Nombre de threads pour l'énumération web
enum_threads = 10

# Délai entre les requêtes (secondes)
enum_delay = 0.05

# ─── Énumération de sous-domaines ────────────────────────────────────────────
# Paramètres utilisés par --subdomain <DOMAIN>.
# L'activation du module se fait toujours via CLI.
# Ces clés définissent uniquement les options par défaut.

[subdomain]
# ── Wordlist pour le bruteforce DNS ──────────────────────────────────────────
#
# Vide = wordlist embarquée (~250 mots courants, suffisante pour un premier
#        passage CTF / réseau interne).
#
# SecLists — choisir selon le contexte :
#   Petite  (5 000 mots)   : rapide, bon pour un premier passage
# sub_wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
#
#   Moyenne (20 000 mots)  : bon compromis vitesse/couverture (recommandé)
# sub_wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
#
#   Grande  (110 000 mots) : exhaustif (Bug Bounty, domaines publics)
# sub_wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
#
#   Jhaddix (HTB/CTF)      : orientée boxes et environnements typiques CTF
# sub_wordlist = "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"
#
#   Custom                 : noms du contexte (box, entreprise, produits...)
# sub_wordlist = "~/wordlists/custom.txt"
sub_wordlist = ""

# ── Threads pour le bruteforce DNS ───────────────────────────────────────────
# HTB VPN  : 50-100 threads sont OK.
# Réseau local : 100+ possibles.
# Réduire si tu observes des timeouts ou des faux négatifs.
sub_threads = 30

# ── Mode de fonctionnement ───────────────────────────────────────────────────
# Par défaut (les deux à false) : passif + bruteforce actif.
#
# sub_passive = true  →  recon passive uniquement
#                         (crt.sh, HackerTarget, RapidDNS — zéro bruit réseau)
# sub_active  = true  →  bruteforce DNS uniquement (pas d'appel API externe)
#
# Profil discret (OPSEC) : sub_passive = true
# Profil réseau isolé     : sub_active  = true
sub_passive = false
sub_active  = false

# ─── Connexion SSH ────────────────────────────────────────────────────────────
# Utilisé par --ssh-scan, --loot, et les modules qui s'authentifient en SSH.

[ssh]
# Nom d'utilisateur SSH par défaut
ssh_user = ""

# Chemin vers la clé privée SSH (~ supporté)
# ssh_key = "~/.ssh/id_rsa"

# Port SSH si non standard
ssh_port = 22

# ─── Modules offensifs ────────────────────────────────────────────────────────
# Passer à true pour activer automatiquement à chaque scan.
# Équivalent à passer le flag CLI correspondant.
# Les modules restent toujours disponibles via CLI même si false ici.
#
# Exemple profil CTF :
#   web_payloads = true  →  --web-payloads --lhost LHOST
#   brute        = true  →  --brute
#   smb          = true  →  --smb
#
# Note : les modules comme --web-payloads et --pivot utilisent
# automatiquement lhost/lport définis ci-dessus.

[modules]

# ── Reconnaissance ────────────────────────────────────────────────────────────

# Énumération sous-domaines automatique  (--subdomain)
# true      → mode "auto" : détecte le domaine depuis le scan (hostname nmap)
# "mon.tld" → domaine fixe (utile sur un engagement long : subdomain = "target.htb")
# false     → désactivé (lancer manuellement avec --subdomain <DOMAIN>)
subdomain = false

# Virtual host discovery  (--vhost)
vhost = false

# Reverse shells adaptés aux services détectés  (--revshell)
revshell = false

# ── Réseau ────────────────────────────────────────────────────────────────────

# Guide pivoting : Ligolo-ng, Chisel, SSH local/remote/dynamic, socat  (--pivot)
pivot = false

# Upgrade shell basique → TTY interactif  (--upgrade-shell)
upgrade_shell = false

# ── Credentials & Brute force ─────────────────────────────────────────────────

# Commandes hydra / medusa / CrackMapExec par service détecté  (--brute)
brute = false

# Credentials par défaut — Tomcat, Jenkins, Grafana, routeurs...  (--default-creds)
default_creds = false

# Identification du type de hash + commandes hashcat / john  (--hashcrack)
hashcrack = false

# Wordlist ciblée depuis le contexte du scan (domaine, hostname, produits)  (--wordlist)
wordlist = false

# ── SMB & Active Directory ────────────────────────────────────────────────────

# Énumération SMB complète + impacket (secretsdump, wmiexec, relay, PTH)  (--smb)
smb = false

# Énumération AD : Kerberoasting, AS-REP, LDAP, BloodHound  (--ad-enum)
ad_enum = false

# Mouvement latéral post-compromise : DCOM, LAPS, délégation, AD CS  (--lateral)
lateral = false

# ── Privilege Escalation ──────────────────────────────────────────────────────

# Checklist privesc Linux + Windows  (--privesc)
privesc = false

# GTFOBins — binaires SUID / sudo / capabilities exploitables  (--gtfobins)
gtfobins = false

# Détection de misconfigurations système  (--misconfig)
misconfig = false

# Token privileges Windows : SeImpersonate → Potato, SeDebug → LSASS dump  (--tokens)
tokens = false

# ── Container & Cloud ─────────────────────────────────────────────────────────

# Container escape Docker / LXC / Kubernetes  (--container)
container = false

# Énumération misconfigurations AWS / Azure / GCP  (--cloud)
cloud = false

# ── Divers ────────────────────────────────────────────────────────────────────

# Modules Metasploit associés aux CVE détectées  (--msf)
msf = false

# Kill chain MITRE ATT&CK  (--kill-chain)
kill_chain = false

# Collecte de fichiers sensibles via SSH (credentials, clés, historiques)  (--loot)
loot = false

# Fingerprinting actif des apps web (Craft CMS, Laravel, Drupal...)  (--web-fingerprint)
# Résout le problème nginx → Craft CMS non détecté par Nmap
web_fingerprint = false
"""
