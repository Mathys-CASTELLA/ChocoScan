"""
ChocoScan — Gestion de la whitelist .chocoscanignore.

Permet d'exclure des CVE ID déjà traitées / faux positifs connus
sur une cible donnée, sans avoir à les refiltrer manuellement à
chaque scan (utile en CTF/pentest où on relance ChocoScan souvent
sur la même VM).

Format du fichier (une entrée par ligne) :

    # commentaire
    CVE-2021-41617              # commentaire de fin de ligne autorisé
    CVE-2023-38408

Recherche du fichier par ordre de priorité :
    1. Chemin explicite (--ignore-file)
    2. .chocoscanignore dans le répertoire courant
    3. ~/.chocoscanignore (whitelist globale utilisateur)

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import re
from pathlib import Path

DEFAULT_LOCAL_NAME = ".chocoscanignore"
DEFAULT_GLOBAL_PATH = Path.home() / ".chocoscanignore"

_CVE_LINE_RE = re.compile(r"^\s*(CVE-\d{4}-\d{4,})\s*(?:#.*)?$", re.IGNORECASE)


def find_ignore_file(explicit_path: str | None = None) -> Path | None:
    """
    Résout le chemin du fichier ignore à utiliser.
    Retourne None si aucun fichier n'est trouvé.
    """
    if explicit_path:
        p = Path(explicit_path)
        return p if p.exists() else None

    local = Path.cwd() / DEFAULT_LOCAL_NAME
    if local.exists():
        return local

    if DEFAULT_GLOBAL_PATH.exists():
        return DEFAULT_GLOBAL_PATH

    return None


def load_ignore_list(explicit_path: str | None = None) -> set[str]:
    """
    Charge la liste des CVE ID à ignorer depuis le fichier résolu.
    Retourne un set vide si aucun fichier trouvé ou en cas d'erreur.

    Les lignes invalides (qui ne ressemblent pas à un ID CVE) sont
    silencieusement ignorées, pour rester tolérant sur le format.
    """
    path = find_ignore_file(explicit_path)
    if path is None:
        return set()

    ignored: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = _CVE_LINE_RE.match(line)
                if m:
                    ignored.add(m.group(1).upper())
    except OSError:
        return set()

    return ignored


def filter_ignored(cves: list[dict], ignored: set[str]) -> tuple[list[dict], int]:
    """
    Retire les CVE dont l'ID est présent dans `ignored`.
    Retourne (liste_filtrée, nombre_ignoré).
    """
    if not ignored:
        return cves, 0

    kept = []
    skipped = 0
    for c in cves:
        cve_id = str(c.get("id", "")).upper()
        if cve_id in ignored:
            skipped += 1
            continue
        kept.append(c)

    return kept, skipped


def add_to_ignore_file(cve_id: str, comment: str = "", explicit_path: str | None = None) -> Path:
    """
    Ajoute une CVE ID au fichier ignore (le crée si besoin).
    Utilisé par le mode interactif (touche 'i' pour ignorer une CVE).

    Si aucun fichier n'existe encore, crée .chocoscanignore dans le
    répertoire courant par défaut.
    """
    path = find_ignore_file(explicit_path)
    if path is None:
        path = Path(explicit_path) if explicit_path else Path.cwd() / DEFAULT_LOCAL_NAME

    cve_id = cve_id.upper().strip()
    existing = load_ignore_list(str(path))
    if cve_id in existing:
        return path

    line = f"{cve_id}"
    if comment:
        line += f"    # {comment}"
    line += "\n"

    is_new = not path.exists()
    with open(path, "a", encoding="utf-8") as f:
        if is_new:
            f.write("# .chocoscanignore — CVE ID à exclure des résultats ChocoScan\n")
            f.write("# Une CVE par ligne, '#' pour les commentaires\n\n")
        f.write(line)

    return path
