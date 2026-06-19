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
    # Énumération web
    "enum_web":      (bool,  False,   "web"),
    "enum_threads":  (int,   10,      "web"),
    "enum_delay":    (float, 0.05,    "web"),
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

# ─── Scan Nmap ───────────────────────────────────────────────────────────────

[scan]
# Arguments supplémentaires passés à nmap avec --scan
# Exemple : nmap_args = "-T4 --open -p 1-65535"
nmap_args = ""

# ─── Énumération web ─────────────────────────────────────────────────────────

[web]
# Activer l'énumération web par défaut
enum_web = false

# Nombre de threads pour l'énumération web
enum_threads = 10

# Délai entre les requêtes (secondes)
enum_delay = 0.05
"""
