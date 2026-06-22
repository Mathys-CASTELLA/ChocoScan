#!/usr/bin/env python3
"""
ChocoScan — Enrichissement CPE de la base CVE
================================================

Ajoute un champ "cpe" sur chaque entrée de cve_db.json et cve_recent.json,
de façon additive : la structure existante n'est pas modifiée, seul un
nouveau champ est injecté sur chaque CVE.

Le CPE est résolu au niveau service_key (un seul appel par clé, pas par
CVE individuelle) via modules.cpe_resolver :
    1. Table statique PRODUCT_CPE_MAP (instantané)
    2. Fallback API NVD CPE Dictionary avec cache disque

Le champ affected_versions (texte) reste la source de vérité pour le
matching de version — le CPE sert uniquement à fiabiliser les requêtes
API NVD (cpeName au lieu de keywordSearch), pas à remplacer la logique
de version_checker.py.

Usage :
    python update_db_cpe.py                  # Enrichir toute la DB
    python update_db_cpe.py --dry-run         # Aperçu sans modifier
    python update_db_cpe.py --service openssh # Un seul service
    python update_db_cpe.py --stats           # Statistiques de couverture
    python update_db_cpe.py --no-api          # Statique uniquement (rapide, pas de réseau)
"""

import json
import sys
import argparse
from pathlib import Path
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH = True
except ImportError:
    RICH = False

sys.path.insert(0, str(Path(__file__).parent))
from modules.cpe_resolver import resolve_cpe, resolve_cpe_static, PRODUCT_CPE_MAP

console = Console() if RICH else None

DATA_DIR          = Path(__file__).parent / "data"
CVE_DB_PATH        = DATA_DIR / "cve_db.json"
CVE_RECENT_PATH     = DATA_DIR / "cve_recent.json"


def _print(msg: str):
    if RICH:
        console.print(msg)
    else:
        print(msg)


def load_db(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_db(path: Path, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def enrich_database(
    db_path: Path,
    only_service: str | None = None,
    dry_run: bool = False,
    use_api: bool = True,
) -> dict:
    """
    Parcourt une base CVE et ajoute le champ "cpe" sur chaque entrée.
    Retourne des statistiques : {service_key: (méthode, nb_cves)}
    """
    if not db_path.exists():
        _print(f"[yellow][!] Fichier introuvable : {db_path}[/yellow]" if RICH else f"[!] Fichier introuvable : {db_path}")
        return {}

    data = load_db(db_path)
    stats = {}

    service_keys = [only_service] if only_service else list(data.keys())

    progress_ctx = (
        Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console)
        if RICH else None
    )

    def _process_key(key: str):
        if key not in data:
            return
        cves = data[key]
        if not cves:
            return

        # Résolution une seule fois par service_key (pas par CVE)
        static_cpe = resolve_cpe_static(key)
        if static_cpe:
            method = "statique"
            base_cpe = static_cpe
        elif use_api:
            base_cpe = resolve_cpe(key, product_name=key, use_api_fallback=True)
            method = "api" if base_cpe else "non résolu"
        else:
            base_cpe = None
            method = "non résolu (--no-api)"

        if base_cpe:
            # On stocke un CPE "template" sans version figée (la version
            # exacte dépendra de chaque CVE/cible au moment du scan) :
            # on remplace le composant version par "*" pour que le champ
            # serve de base à la construction du CPE précis à la volée.
            parts = base_cpe.split(":")
            if len(parts) >= 6:
                parts[5] = "*"
                template_cpe = ":".join(parts)
            else:
                template_cpe = base_cpe

            if not dry_run:
                for cve in cves:
                    cve["cpe"] = template_cpe

        stats[key] = (method, len(cves))

    if progress_ctx:
        with progress_ctx as progress:
            task = progress.add_task("Résolution CPE...", total=len(service_keys))
            for key in service_keys:
                progress.update(task, description=f"Résolution CPE : {key}...")
                _process_key(key)
                progress.advance(task)
    else:
        for key in service_keys:
            _process_key(key)

    if not dry_run:
        save_db(db_path, data)

    return stats


def display_stats(all_stats: dict[str, dict]):
    """Affiche un récapitulatif de couverture par fichier de base."""
    total_static = total_api = total_unresolved = 0

    for db_name, stats in all_stats.items():
        if not stats:
            continue

        if RICH:
            table = Table(title=f"Couverture CPE — {db_name}", show_header=True, header_style="bold cyan")
            table.add_column("Service", style="bold")
            table.add_column("Méthode")
            table.add_column("Nb CVE", justify="right")

            for key, (method, count) in sorted(stats.items()):
                color = {"statique": "green", "api": "yellow", "non résolu": "red"}.get(
                    method.split(" ")[0] if " " in method else method, "white"
                )
                table.add_row(key, f"[{color}]{method}[/{color}]", str(count))
                if method == "statique":
                    total_static += 1
                elif method == "api":
                    total_api += 1
                else:
                    total_unresolved += 1

            console.print(table)
        else:
            print(f"\n=== {db_name} ===")
            for key, (method, count) in sorted(stats.items()):
                print(f"  {key:25s} {method:20s} {count} CVE(s)")

    total = total_static + total_api + total_unresolved
    if total:
        summary = (
            f"\nTotal : {total} service(s) — "
            f"{total_static} statique, {total_api} via API, {total_unresolved} non résolu(s)"
        )
        _print(f"[bold]{summary}[/bold]" if RICH else summary)


def main():
    parser = argparse.ArgumentParser(description="Enrichissement CPE de la base CVE ChocoScan")
    parser.add_argument("--dry-run", action="store_true", help="Aperçu sans modifier les fichiers")
    parser.add_argument("--service", type=str, default=None, help="Limiter à un seul service_key")
    parser.add_argument("--stats", action="store_true", help="Afficher uniquement les statistiques de couverture")
    parser.add_argument("--no-api", action="store_true", help="Résolution statique uniquement, pas d'appel réseau")
    args = parser.parse_args()

    use_api = not args.no_api

    if args.dry_run:
        _print("[cyan][*] Mode dry-run : aucune modification ne sera écrite[/cyan]" if RICH else "[*] Mode dry-run")

    all_stats = {}

    for label, path in (("cve_db.json", CVE_DB_PATH), ("cve_recent.json", CVE_RECENT_PATH)):
        _print(f"\n[bold]Traitement de {label}...[/bold]" if RICH else f"\nTraitement de {label}...")
        stats = enrich_database(path, only_service=args.service, dry_run=args.dry_run, use_api=use_api)
        all_stats[label] = stats

    display_stats(all_stats)

    if not args.dry_run:
        _print("\n[green][+] Bases mises à jour avec le champ CPE.[/green]" if RICH else "\n[+] Bases mises à jour.")


if __name__ == "__main__":
    main()
