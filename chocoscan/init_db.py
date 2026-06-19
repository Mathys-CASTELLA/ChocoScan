#!/usr/bin/env python3
"""
ChocoScan — Initialisation de la base CVE
===========================================

Vérifie l'état de data/cve_db.json au premier lancement et propose
une stratégie d'initialisation adaptée :

  1. data/cve_db.json existe déjà (≥ 50 services)  → rien à faire
  2. Absent ou minimal → propose de copier data/cve_db.seed.json
     (524 CVEs critiques/CTF/APT, ~370 Ko, versionnée dans le repo)
  3. Optionnellement, lance update_db_critical.py pour compléter
     avec l'API NVD (nécessite une connexion réseau)

Ce script résout un problème de versioning git : la base complète
(cve_db.json, ~1 500 CVEs, ~900 Ko) change à chaque mise à jour et
n'a pas sa place dans l'historique git. Seule la seed (524 CVEs
essentielles) est versionnée ; la base complète se régénère
localement et reste dans .gitignore.

Usage :
    python init_db.py                 # interactif
    python init_db.py --yes           # non-interactif, accepte la seed
    python init_db.py --full          # seed + tentative API NVD
    python init_db.py --force         # écrase la DB existante
    python init_db.py --check         # vérifie l'état sans rien modifier
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None


DATA_DIR     = Path(__file__).parent / "data"
CVE_DB_PATH  = DATA_DIR / "cve_db.json"
SEED_DB_PATH = DATA_DIR / "cve_db.seed.json"

# Seuil sous lequel on considère la DB comme "minimale" / à compléter
MIN_HEALTHY_SERVICES = 50


def _print(msg: str, style: str = ""):
    if RICH:
        console.print(msg, style=style or None)
    else:
        # Dégrade proprement les balises rich si la lib est absente
        import re
        clean = re.sub(r"\[/?[a-z_ ]*\]", "", msg)
        print(clean)


def db_stats(path: Path) -> tuple[int, int] | None:
    """Retourne (nb_services, nb_cves) ou None si le fichier est absent/invalide."""
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            db = json.load(f)
        n_services = len(db)
        n_cves     = sum(len(v) for v in db.values())
        return (n_services, n_cves)
    except (json.JSONDecodeError, OSError):
        return None


def check_status() -> str:
    """
    Détermine l'état de la base CVE.

    Returns:
        "healthy"  : DB complète présente et saine
        "minimal"  : DB présente mais en dessous du seuil
        "missing"  : DB absente ou corrompue
    """
    stats = db_stats(CVE_DB_PATH)
    if stats is None:
        return "missing"
    n_services, _ = stats
    if n_services < MIN_HEALTHY_SERVICES:
        return "minimal"
    return "healthy"


def print_status_table():
    """Affiche un état des lieux des deux fichiers DB."""
    main_stats = db_stats(CVE_DB_PATH)
    seed_stats = db_stats(SEED_DB_PATH)

    if RICH:
        t = Table(title="État de la base CVE", box=box.ROUNDED)
        t.add_column("Fichier", style="cyan")
        t.add_column("Services", justify="right")
        t.add_column("CVEs", justify="right")
        t.add_column("État")

        if main_stats:
            n_svc, n_cve = main_stats
            state = "[green]✓ Saine[/green]" if n_svc >= MIN_HEALTHY_SERVICES else "[yellow]⚠ Minimale[/yellow]"
            t.add_row("cve_db.json", str(n_svc), str(n_cve), state)
        else:
            t.add_row("cve_db.json", "—", "—", "[red]✗ Absente[/red]")

        if seed_stats:
            n_svc, n_cve = seed_stats
            t.add_row("cve_db.seed.json", str(n_svc), str(n_cve), "[dim]source (versionnée)[/dim]")
        else:
            t.add_row("cve_db.seed.json", "—", "—", "[red]✗ Absente du repo ![/red]")

        console.print(t)
    else:
        print("\nÉtat de la base CVE")
        print("-" * 50)
        if main_stats:
            print(f"  cve_db.json      : {main_stats[0]} services, {main_stats[1]} CVEs")
        else:
            print("  cve_db.json      : absente")
        if seed_stats:
            print(f"  cve_db.seed.json : {seed_stats[0]} services, {seed_stats[1]} CVEs (source)")
        else:
            print("  cve_db.seed.json : absente du repo !")
        print()


def init_from_seed(force: bool = False) -> bool:
    """Copie la seed DB vers cve_db.json. Retourne True si effectué."""
    if not SEED_DB_PATH.exists():
        _print(f"[red][!] Fichier source introuvable : {SEED_DB_PATH}[/red]")
        _print("    Le repo semble incomplet — re-clonez ChocoScan ou ouvrez une issue.")
        return False

    if CVE_DB_PATH.exists() and not force:
        stats = db_stats(CVE_DB_PATH)
        if stats and stats[0] >= MIN_HEALTHY_SERVICES:
            _print(f"[yellow][!] data/cve_db.json existe déjà ({stats[0]} services). "
                   f"Utilisez --force pour écraser.[/yellow]")
            return False

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SEED_DB_PATH, CVE_DB_PATH)

    stats = db_stats(CVE_DB_PATH)
    _print(f"[green][+] Base initialisée depuis la seed : "
           f"{stats[0]} services, {stats[1]} CVEs[/green]")
    return True


def offer_full_update():
    """Propose de lancer update_db_critical.py pour compléter la base."""
    update_script = Path(__file__).parent / "update_db_critical.py"
    if not update_script.exists():
        return

    _print("\n[dim]Pour une couverture complète (1 500+ CVEs, 145 services), lancez :[/dim]")
    _print("  [bold cyan]python update_db_critical.py[/bold cyan]")
    _print("[dim]Une clé API NVD accélère grandement le processus — voir `python chocoscan.py config init`[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="ChocoScan — Initialisation de la base CVE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python init_db.py              # mode interactif (recommandé au premier clone)
  python init_db.py --check      # vérifie l'état sans rien modifier
  python init_db.py --yes        # initialise depuis la seed sans confirmation
  python init_db.py --force      # écrase une DB existante
        """,
    )
    parser.add_argument("--check", action="store_true",
                         help="Affiche l'état de la base sans rien modifier")
    parser.add_argument("--yes", "-y", action="store_true",
                         help="Initialise depuis la seed sans confirmation interactive")
    parser.add_argument("--force", action="store_true",
                         help="Écrase data/cve_db.json même s'il existe déjà")
    parser.add_argument("--full", action="store_true",
                         help="Affiche aussi la suggestion de mise à jour complète via l'API NVD")
    args = parser.parse_args()

    if RICH:
        console.print(Panel.fit(
            "[bold cyan]ChocoScan[/bold cyan] — [yellow]Initialisation de la base CVE[/yellow]"
        ))
    else:
        print("\n=== ChocoScan — Initialisation de la base CVE ===\n")

    print_status_table()

    status = check_status()

    if args.check:
        sys.exit(0 if status == "healthy" else 1)

    # --force écrase inconditionnellement, peu importe l'état actuel
    if args.force:
        if not args.yes:
            try:
                reply = input("\n[!] --force va écraser data/cve_db.json existant. Confirmer ? [o/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                _print("\n[dim]Annulé.[/dim]")
                return
            if reply not in ("o", "oui", "y", "yes"):
                _print("[dim]Annulé.[/dim]")
                return
        ok = init_from_seed(force=True)
        if ok and args.full:
            offer_full_update()
        return

    if status == "healthy":
        _print("\n[green]✓ La base CVE est déjà initialisée et saine.[/green]")
        if args.full:
            offer_full_update()
        return

    # ── DB absente ou minimale → proposer la seed ──────────────────────────
    if status == "minimal":
        _print(f"\n[yellow]La base actuelle est en dessous du seuil recommandé "
               f"({MIN_HEALTHY_SERVICES} services).[/yellow]")
    else:
        _print("\n[yellow]Aucune base CVE locale détectée.[/yellow]")

    if not args.yes:
        try:
            reply = input("\nInitialiser depuis la seed versionnée (524 CVEs essentielles) ? [O/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            _print("\n[dim]Annulé.[/dim]")
            return
        if reply not in ("", "o", "oui", "y", "yes"):
            _print("[dim]Initialisation annulée.[/dim]")
            return

    ok = init_from_seed(force=args.force)
    if ok:
        offer_full_update()


if __name__ == "__main__":
    main()
