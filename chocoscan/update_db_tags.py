#!/usr/bin/env python3
"""
ChocoScan — Tagger automatique de la base CVE
==============================================

Applique les tags de la taxonomie à toutes les CVEs de cve_db.json
en utilisant des règles combinées :
  1. Mapping service → tags (ex: "smb" → #windows, #network)
  2. Mots-clés dans description EN/FR → tags (ex: "ransomware" → #ransomware)
  3. Champs structurés → tags (exploit_available → #exploit-public,
                                ctf_machines → #ctf-frequent,
                                metasploit → #exploit-public)
  4. Règles manuelles par CVE-ID pour les cas connus non détectables par keywords

Usage :
    python update_db_tags.py                  # Tagger toute la DB
    python update_db_tags.py --dry-run        # Aperçu sans modifier
    python update_db_tags.py --service openssh # Un seul service
    python update_db_tags.py --stats          # Statistiques après tagging
    python update_db_tags.py --list-tags      # Lister la taxonomie complète
    python update_db_tags.py --reset          # Supprimer tous les tags existants
"""

import json
import sys
import argparse
import re
from pathlib import Path
from collections import defaultdict
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

sys.path.insert(0, str(Path(__file__).parent))
from modules.tag_definitions import TAGS, ALL_TAG_NAMES, TagDef

console = Console() if RICH else None

DATA_DIR    = Path(__file__).parent / "data"
CVE_DB_PATH = DATA_DIR / "cve_db.json"


# ─── Règles manuelles par CVE-ID ──────────────────────────────────────────────
# Pour les CVEs dont les tags ne peuvent pas être inférés par keywords

MANUAL_TAGS: dict[str, list[str]] = {
    # EternalBlue — WannaCry + NotPetya
    "CVE-2017-0144": ["#apt", "#ransomware", "#windows", "#lateral"],
    "CVE-2017-0145": ["#apt", "#ransomware", "#windows", "#lateral"],
    # MS08-067 — MSF classique, utilisé en APT
    "CVE-2008-4250": ["#windows", "#ctf-frequent"],
    # SMBGhost
    "CVE-2020-0796": ["#windows"],
    # ZeroLogon
    "CVE-2020-1472": ["#apt", "#windows", "#active-directory", "#lateral"],
    # Log4Shell — massif APT + ransomware
    "CVE-2021-44228": ["#apt", "#ransomware", "#initial-access"],
    "CVE-2021-45046": ["#initial-access"],
    # ProxyLogon / Exchange
    "CVE-2021-26855": ["#apt", "#initial-access", "#windows"],
    # PrintNightmare
    "CVE-2021-34527": ["#apt", "#windows", "#lateral"],
    # Spring4Shell
    "CVE-2022-22965": ["#apt", "#initial-access", "#web"],
    # Confluence OGNL
    "CVE-2022-26134": ["#apt", "#initial-access", "#web"],
    "CVE-2023-22527": ["#initial-access", "#web"],
    # GitLab ExifTool RCE
    "CVE-2021-22205": ["#initial-access", "#devops"],
    # GitLab account takeover
    "CVE-2023-7028":  ["#initial-access", "#devops"],
    # Ghostcat — file read → RCE chain
    "CVE-2020-1938":  ["#rce-chain", "#web"],
    # vsftpd backdoor
    "CVE-2011-2523":  ["#ctf-frequent"],
    # Samba usermap
    "CVE-2007-2447":  ["#ctf-frequent"],
    # SambaCry
    "CVE-2017-7494":  ["#apt", "#ransomware"],
    # Shellshock
    "CVE-2014-6271":  ["#apt", "#initial-access"],
    # Apache path traversal
    "CVE-2021-41773": ["#ctf-frequent", "#initial-access"],
    "CVE-2021-42013": ["#ctf-frequent", "#initial-access", "#rce-chain"],
    # Nostromo
    "CVE-2019-16278": ["#ctf-frequent"],
    # Webmin backdoor
    "CVE-2019-15107": ["#ctf-frequent"],
    # Beep
    "CVE-2006-3392":  ["#ctf-frequent"],
    # Log4j
    "CVE-2021-44228": ["#apt", "#ransomware", "#initial-access", "#ctf-frequent"],
    # Drupalgeddon
    "CVE-2018-7600":  ["#ctf-frequent", "#initial-access"],
    "CVE-2018-7602":  ["#ctf-frequent"],
    # Jenkins deserialization
    "CVE-2016-0792":  ["#initial-access", "#devops"],
    "CVE-2024-23897": ["#initial-access", "#devops"],
    # ActiveMQ RCE — exploité massivement en 2023
    "CVE-2023-46604": ["#apt", "#ransomware", "#initial-access", "#ctf-frequent"],
    # BlueKeep
    "CVE-2019-0708":  ["#apt", "#windows", "#initial-access"],
    # PwnKit
    "CVE-2021-4034":  ["#linux", "#ctf-frequent"],
    # Dirty COW
    "CVE-2016-5195":  ["#linux", "#ctf-frequent", "#apt"],
    # Dirty Pipe
    "CVE-2022-0847":  ["#linux", "#ctf-frequent"],
    # Baron Samedit
    "CVE-2021-3156":  ["#linux", "#ctf-frequent"],
    # runc container escape
    "CVE-2019-5736":  ["#container"],
    # Fortinet auth bypass
    "CVE-2022-40684": ["#apt", "#initial-access", "#network"],
    # Ivanti
    "CVE-2024-21887": ["#apt", "#initial-access", "#network"],
    "CVE-2019-11510": ["#apt", "#initial-access", "#network"],
    # Cacti command injection
    "CVE-2022-46169": ["#ctf-frequent", "#initial-access"],
    # Grafana directory traversal
    "CVE-2021-43798": ["#ctf-frequent", "#devops"],
    # XZ backdoor — supply-chain
    "CVE-2024-3094":  ["#supply-chain", "#apt", "#initial-access"],
    # CUPS
    "CVE-2024-47176": ["#linux", "#initial-access"],
    # Confluence 2023
    "CVE-2023-22527": ["#apt", "#ransomware", "#initial-access", "#web"],
    "CVE-2023-22515": ["#apt", "#initial-access", "#web"],
    # PaperCut
    "CVE-2023-27350": ["#apt", "#ransomware", "#initial-access"],
    # CitrixBleed
    "CVE-2023-4966":  ["#apt", "#initial-access", "#network"],
    # WinRAR
    "CVE-2023-38831": ["#apt", "#initial-access"],
    # MOVEit
    "CVE-2023-34362": ["#apt", "#ransomware", "#supply-chain"],
    # PHP CGI
    "CVE-2012-1823":  ["#ctf-frequent", "#web"],
    "CVE-2024-4577":  ["#initial-access", "#web"],
    # regreSSHion
    "CVE-2024-6387":  ["#initial-access", "#linux"],
    # Spring Cloud
    "CVE-2022-22963": ["#initial-access", "#web"],
}


# ─── Moteur de tagging automatique ────────────────────────────────────────────

def _normalize(text: str) -> str:
    return (text or "").lower()


def compute_tags_for_cve(cve: dict, service_key: str) -> list[str]:
    """
    Calcule l'ensemble des tags pour une CVE donnée.

    Ordre de priorité :
    1. Tags manuels (MANUAL_TAGS) — les plus fiables
    2. Tags structurés (exploit_available, ctf_machines, metasploit)
    3. Tags par service (mapping service → tags)
    4. Tags par mots-clés dans description
    """
    cve_id = cve.get("id", "")
    tags: set[str] = set()

    # ── 1. Tags manuels ──────────────────────────────────────────────────────
    for manual_id, manual_tags in MANUAL_TAGS.items():
        if manual_id.upper() == cve_id.upper():
            tags.update(t.lstrip("#") for t in manual_tags)

    # ── 2. Tags structurés ───────────────────────────────────────────────────
    if cve.get("exploit_available") or cve.get("exploit_db") or cve.get("metasploit"):
        tags.add("exploit-public")

    if cve.get("ctf_machines"):
        tags.add("ctf-frequent")

    if cve.get("metasploit"):
        tags.add("exploit-public")

    # ── 3. Tags par service ──────────────────────────────────────────────────
    svc = service_key.lower()
    for tag_name, td in TAGS.items():
        if svc in [s.lower() for s in td.auto_services]:
            tags.add(tag_name)

    # ── 4. Tags par mots-clés dans description ───────────────────────────────
    desc = _normalize(cve.get("description", "") + " " + cve.get("description_fr", ""))

    for tag_name, td in TAGS.items():
        for keyword in td.auto_keywords:
            try:
                if re.search(keyword, desc, re.IGNORECASE):
                    tags.add(tag_name)
                    break
            except re.error:
                if keyword.lower() in desc:
                    tags.add(tag_name)
                    break

    # ── Nettoyage : garder uniquement les tags valides ───────────────────────
    return sorted(t for t in tags if t in ALL_TAG_NAMES)


def apply_tags_to_db(
    db: dict,
    target_service: str | None = None,
    reset: bool = False,
) -> dict[str, dict]:
    """
    Applique les tags à toute la DB (ou un service spécifique).

    Returns:
        stats : {service: {"tagged": n, "total": n, "new_tags": n}}
    """
    stats = defaultdict(lambda: {"tagged": 0, "total": 0, "new_tags": 0})

    services = (
        {target_service: db[target_service]}
        if target_service and target_service in db
        else db
    )

    for svc, cves in services.items():
        for cve in cves:
            stats[svc]["total"] += 1

            if reset:
                old_tags = cve.get("tags", [])
                cve["tags"] = []
                stats[svc]["new_tags"] -= len(old_tags)
                continue

            existing = set(cve.get("tags", []))
            computed = set(compute_tags_for_cve(cve, svc))
            new_tags = computed - existing
            merged   = sorted(existing | computed)

            if merged:
                cve["tags"] = merged
                stats[svc]["tagged"] += 1
                stats[svc]["new_tags"] += len(new_tags)

    return stats


# ─── Affichage des stats ──────────────────────────────────────────────────────

def print_stats(stats: dict, db: dict):
    total_cves   = sum(s["total"]    for s in stats.values())
    total_tagged = sum(s["tagged"]   for s in stats.values())
    total_new    = sum(s["new_tags"] for s in stats.values())

    # Distribution des tags sur toute la DB
    tag_counts: dict[str, int] = defaultdict(int)
    for cves in db.values():
        for cve in cves:
            for t in cve.get("tags", []):
                tag_counts[t] += 1

    if RICH:
        console.print()

        # Résumé global
        summary = Table(box=box.SIMPLE, show_header=False)
        summary.add_row("CVEs analysées", f"[bold]{total_cves}[/bold]")
        summary.add_row("CVEs taguées",   f"[bold green]{total_tagged}[/bold green]")
        summary.add_row("Nouveaux tags",  f"[bold cyan]{total_new}[/bold cyan]")
        console.print(Panel(summary, title="Résumé", border_style="cyan"))

        # Distribution par tag
        dist = Table(title="Distribution des tags", box=box.ROUNDED)
        dist.add_column("Tag",          style="cyan",  min_width=20)
        dist.add_column("Groupe",       style="dim",   min_width=10)
        dist.add_column("CVEs",         justify="right", style="bold green", min_width=6)
        dist.add_column("Bonus score",  justify="right", style="yellow",     min_width=10)
        dist.add_column("Description",  style="dim")

        for tag_name in sorted(tag_counts, key=lambda t: -tag_counts[t]):
            td = TAGS.get(tag_name)
            if not td:
                continue
            bonus_str = f"+{td.score_bonus:.1f}" if td.score_bonus > 0 else "—"
            dist.add_row(
                f"#{tag_name}",
                td.group,
                str(tag_counts[tag_name]),
                bonus_str,
                td.description[:60],
            )
        console.print(dist)

    else:
        print(f"\n  CVEs analysées : {total_cves}")
        print(f"  CVEs taguées   : {total_tagged}")
        print(f"  Nouveaux tags  : {total_new}")
        print(f"\n  {'Tag':<25} {'CVEs':>6}  {'Bonus':>6}  Description")
        print("  " + "-" * 70)
        for tag_name in sorted(tag_counts, key=lambda t: -tag_counts[t]):
            td = TAGS.get(tag_name)
            if not td:
                continue
            bonus_str = f"+{td.score_bonus:.1f}" if td.score_bonus > 0 else "  —"
            print(f"  #{tag_name:<24} {tag_counts[tag_name]:>6}  {bonus_str:>6}  {td.description[:45]}")
        print()


def list_taxonomy():
    """Affiche la taxonomie complète des tags."""
    groups = defaultdict(list)
    for name, td in TAGS.items():
        groups[td.group].append((name, td))

    group_labels = {
        "threat":  "Menace (impact threat intel)",
        "tech":    "Contexte technique",
        "surface": "Surface d'attaque",
        "exploit": "Exploitation",
    }

    if RICH:
        for group, label in group_labels.items():
            t = Table(title=label, box=box.SIMPLE, show_header=True)
            t.add_column("Tag",         style="cyan bold", min_width=22)
            t.add_column("Label",       min_width=18)
            t.add_column("Bonus",       justify="right", style="yellow", min_width=7)
            t.add_column("Icône",       justify="center", min_width=5)
            t.add_column("Description", style="dim")
            for name, td in sorted(groups[group], key=lambda x: -x[1].score_bonus):
                bonus_str = f"[bold]+{td.score_bonus:.1f}[/bold]" if td.score_bonus > 0 else "[dim]—[/dim]"
                t.add_row(f"#{name}", td.label, bonus_str, td.icon, td.description)
            console.print(t)
            console.print()
    else:
        for group, label in group_labels.items():
            print(f"\n  ── {label} ──")
            for name, td in sorted(groups[group], key=lambda x: -x[1].score_bonus):
                bonus_str = f"+{td.score_bonus:.1f}" if td.score_bonus > 0 else "  —"
                print(f"    #{name:<22} {bonus_str:>5}  {td.description[:55]}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ChocoScan — Tagger automatique de la base CVE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python update_db_tags.py
  python update_db_tags.py --dry-run
  python update_db_tags.py --service smb
  python update_db_tags.py --list-tags
  python update_db_tags.py --reset && python update_db_tags.py
        """,
    )
    parser.add_argument("--dry-run",      action="store_true", help="Aperçu sans modifier la DB")
    parser.add_argument("--service",      type=str, default=None, help="Tagger un seul service")
    parser.add_argument("--stats",        action="store_true", help="Afficher les stats après tagging")
    parser.add_argument("--list-tags",    action="store_true", help="Lister la taxonomie et quitter")
    parser.add_argument("--reset",        action="store_true", help="Supprimer tous les tags existants")
    args = parser.parse_args()

    if args.list_tags:
        list_taxonomy()
        return

    if RICH:
        console.print(Panel.fit(
            "[bold cyan]ChocoScan[/bold cyan] — [yellow]Tagger la base CVE[/yellow]",
            subtitle=f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M')}[/dim]"
        ))
    else:
        print("\n=== ChocoScan — Tagger la base CVE ===\n")

    # Charger la DB
    with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
        db = json.load(f)

    if args.service and args.service not in db:
        available = ", ".join(sorted(db.keys())[:20]) + "…"
        print(f"[!] Service inconnu : '{args.service}'\n    Exemples : {available}")
        sys.exit(1)

    # Appliquer les tags (sur une copie pour le dry-run)
    db_work = {k: [dict(c) for c in v] for k, v in db.items()}
    stats   = apply_tags_to_db(db_work, target_service=args.service, reset=args.reset)

    if args.dry_run:
        if RICH:
            console.print("\n[bold yellow]Mode dry-run — aucune modification[/bold yellow]\n")
        else:
            print("\n[DRY-RUN] Aucune modification.\n")
        print_stats(stats, db_work)
        # Afficher un aperçu de quelques CVEs taguées
        if RICH:
            console.print("\n[bold]Aperçu (5 premières CVEs taguées) :[/bold]")
            for svc, cves in list(db_work.items())[:10]:
                for cve in cves:
                    if cve.get("tags"):
                        tags_str = "  ".join(f"[cyan]#{t}[/cyan]" for t in cve["tags"])
                        console.print(f"  [magenta]{cve['id']}[/magenta]  {tags_str}")
        return

    # Sauvegarder
    if args.reset:
        if RICH:
            console.print("[yellow]Reset des tags...[/yellow]")
        else:
            print("Reset des tags...")

    with open(CVE_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db_work, f, ensure_ascii=False, indent=2)

    action = "Reset" if args.reset else "Tagging"
    if RICH:
        console.print(f"[green]✓[/green] {action} terminé — [bold]data/cve_db.json[/bold] mis à jour\n")
    else:
        print(f"[+] {action} terminé — data/cve_db.json mis à jour\n")

    if args.stats or not args.reset:
        print_stats(stats, db_work)


if __name__ == "__main__":
    main()
