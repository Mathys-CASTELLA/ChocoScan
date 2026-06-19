"""
ChocoScan — Moteur de comparaison de versions robuste.

Remplace l'ancien version_checker.py avec :
  - Extraction de version depuis les bannières Nmap réelles
  - Gestion des cas limites : epochs Debian, suffixes OS, MariaDB, pN, ~beta...
  - Retour d'un MatchResult avec confidence score (évite les faux positifs)
  - Logique AND/OR correcte pour les contraintes multiples
  - Version inconnue → UNCERTAIN (jamais True par défaut)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from packaging import version as pkg_version
from packaging.version import Version, InvalidVersion


# ─── Types publics ────────────────────────────────────────────────────────────

class Confidence(Enum):
    """Niveau de certitude du matching version/CVE."""
    CERTAIN    = "certain"     # version exacte extraite et comparée → résultat fiable
    LIKELY     = "likely"      # version partielle (ex: "8.x") → probablement affecté
    UNCERTAIN  = "uncertain"   # version non détectée → on ne sait pas
    NOT_AFFECTED = "not_affected"  # version extraite, hors plage


@dataclass
class MatchResult:
    """Résultat complet d'un test d'affectation CVE."""
    affected: bool             # True si probablement affecté
    confidence: Confidence
    extracted_version: Optional[str]  # version brute extraite du banner
    normalized_version: Optional[str] # version normalisée utilisée pour la comparaison
    reason: str                # explication lisible

    def __bool__(self) -> bool:
        return self.affected


# ─── Préfixes de versions parasites connus ───────────────────────────────────
# MariaDB expose "5.5.5-X.Y.Z-MariaDB" pour la compat MySQL.
# Le vrai numéro est après le premier tiret si "MariaDB" est présent.
_MARIADB_PREFIX = re.compile(r'^5\.5\.5-(\d+\.\d+[\.\d]*.*?-MariaDB)', re.I)

# Préfixes textuels que Nmap préfixe parfois dans le champ version
_TEXT_PREFIXES = re.compile(
    r'^(?:openssh_?|apache/?|nginx/?|vsftpd/?|php/?|redis[/ ]'
    r'|mysql/?|postgresql/?|openssl/?|v(?=\d))',
    re.I
)

# Suffixes à supprimer (OS, distro, build metadata)
_NOISE_SUFFIXES = re.compile(
    r'\s*[\(\[].*?[\)\]]'           # (Ubuntu), (Win64), [Debian]
    r'|\s+(?:ubuntu|debian|centos|rhel|fedora|alpine|el\d+|deb\d+)'
    r'(?:[\s\-]\S*)*'
    r'|\s+\d+ubuntu\S*'             # 0ubuntu0.20.04.1
    r'|\+dfsg.*$'                   # +dfsg-1
    r'|\s+openssl/\S+',             # OpenSSL/1.1.1c dans les banners Apache
    re.I
)

# Epoch Debian/RPM : "1:7.4p1" → garder "7.4p1"
_EPOCH_PREFIX = re.compile(r'^\d+:')

# Tilde Debian pre-release : "5.0~beta1" → "5.0b1" (packaging comprend)
_TILDE_PRERELEASE = re.compile(r'~(\w+)')

# Pattern de version numérique principal
_VERSION_RE = re.compile(
    r'(\d+\.\d+(?:\.\d+)*'    # X.Y ou X.Y.Z...
    r'(?:[p\-]\d+)?'           # optionnel : p1 ou -3
    r')',
)

# Versions textuelles sans chiffres → clairement non parseable
_NO_DIGITS = re.compile(r'^\D+$')


# ─── Extraction de version depuis un banner Nmap ─────────────────────────────

def extract_version(version_field: str, banner: str = "") -> Optional[str]:
    """
    Extrait la version logique depuis les champs Nmap (version + banner).

    Retourne None si aucune version numérique n'est détectable.
    La version retournée est la chaîne brute nettoyée, pas encore normalisée.
    """
    # Priorité 1 : champ version direct de Nmap
    raw = version_field.strip() if version_field else ""

    # Si le champ version est vide, tenter le banner complet
    if not raw:
        raw = banner.strip()

    if not raw:
        return None

    # Supprimer epoch Debian/RPM
    raw = _EPOCH_PREFIX.sub("", raw)

    # Cas MariaDB : "5.5.5-10.3.27-MariaDB" → "10.3.27"
    m = _MARIADB_PREFIX.match(raw)
    if m:
        raw = m.group(1).split("-MariaDB")[0]

    # Supprimer préfixes textuels connus
    raw = _TEXT_PREFIXES.sub("", raw)

    # Supprimer suffixes bruit (OS, distro...)
    raw = _NOISE_SUFFIXES.sub("", raw).strip()

    # Remplacer tilde pre-release par notation PEP440
    raw = _TILDE_PRERELEASE.sub(r"\1", raw)

    # Si plus aucun chiffre → pas de version
    if not raw or _NO_DIGITS.match(raw):
        return None

    # Extraire le premier numéro de version valide
    m = _VERSION_RE.search(raw)
    if not m:
        return None

    return m.group(1)


# ─── Normalisation pour packaging.version ────────────────────────────────────

def _to_version(raw: str) -> Optional[Version]:
    """
    Convertit une version brute extraite en objet packaging.Version.

    Gère : 7.4p1 → 7.4.1,  7.4-1 → 7.4.1,  8.2p1 → 8.2.1
    Retourne None si non parseable.
    """
    if not raw:
        return None

    v = raw.strip()

    # p1 ou -1 en suffixe → .1
    v = re.sub(r'[p\-](\d+)$', r'.\1', v)

    # Supprimer tout ce qui reste après le premier char non numérique/point
    v = re.sub(r'[^\d.].*$', '', v)

    # Dédupliquer les points consécutifs
    v = re.sub(r'\.{2,}', '.', v).strip('.')

    if not v:
        return None

    try:
        return pkg_version.Version(v)
    except InvalidVersion:
        return None


# ─── Parsing des contraintes ─────────────────────────────────────────────────

_OPS = {
    '<=': lambda a, b: a <= b,
    '>=': lambda a, b: a >= b,
    '!=': lambda a, b: a != b,
    '<':  lambda a, b: a < b,
    '>':  lambda a, b: a > b,
    '==': lambda a, b: a == b,
    '=':  lambda a, b: a == b,
}

def _parse_constraint(constraint: str) -> Optional[tuple]:
    """
    Parse une contrainte type '< 9.3p2' ou '= 2.3.4'.
    Retourne (op_func, ref_Version) ou None si non parseable.
    """
    c = constraint.strip()
    if not c or not re.search(r'\d', c):
        return None  # contrainte non numérique (ex: "all versions") → skip

    for op_str in sorted(_OPS, key=len, reverse=True):
        if c.startswith(op_str):
            ref_raw = c[len(op_str):].strip()
            ref_extracted = extract_version(ref_raw) or ref_raw
            ref_ver = _to_version(ref_extracted)
            if ref_ver is None:
                return None
            return (_OPS[op_str], ref_ver, op_str, ref_raw)

    return None


# ─── Détection de la sémantique des contraintes multiples ────────────────────

def _constraints_are_discrete_or(constraints: list[str]) -> bool:
    """
    Détermine si une liste de contraintes représente un OR discret.

    Exemples :
      ["= 7.4", "= 8.0", "= 8.1"]  → OR  (plusieurs versions exactes)
      [">= 2.0", "< 3.0"]           → AND (plage continue)
      ["= 2.4.49", "= 2.4.50"]      → OR
    """
    ops_found = set()
    for c in constraints:
        c = c.strip()
        for op_str in sorted(_OPS, key=len, reverse=True):
            if c.startswith(op_str):
                ops_found.add(op_str)
                break

    # Si toutes les contraintes sont des égalités → OR
    if ops_found <= {'=', '=='}:
        return True

    # Si mix >= et < (ou <= et >) → AND (plage)
    if ('>=' in ops_found or '>' in ops_found) and ('<' in ops_found or '<=' in ops_found):
        return False

    # Par défaut : AND (comportement conservateur)
    return False


# ─── Moteur principal ─────────────────────────────────────────────────────────

def check_version_affected(
    version_field: str,
    banner: str,
    affected_versions: list[str],
) -> MatchResult:
    """
    Vérifie si un service est affecté par une CVE.

    Args:
        version_field : champ `version` du NmapService (ex: "8.2p1")
        banner        : champ `banner` du NmapService (ex: "OpenSSH 8.2p1 Ubuntu")
        affected_versions : liste de contraintes de la CVE DB

    Returns:
        MatchResult avec affected, confidence, version extraite et raison.
    """
    # ── Pas de contraintes → toutes versions affectées (CVE sans version) ──
    if not affected_versions:
        return MatchResult(
            affected=True,
            confidence=Confidence.LIKELY,
            extracted_version=None,
            normalized_version=None,
            reason="Aucune contrainte de version définie — toutes versions potentiellement affectées",
        )

    # ── Extraction de la version depuis le banner Nmap ──
    raw_ver = extract_version(version_field, banner)

    if raw_ver is None:
        return MatchResult(
            affected=False,
            confidence=Confidence.UNCERTAIN,
            extracted_version=None,
            normalized_version=None,
            reason="Version non détectée dans le banner Nmap — impossible de confirmer",
        )

    svc_ver = _to_version(raw_ver)

    if svc_ver is None:
        return MatchResult(
            affected=False,
            confidence=Confidence.UNCERTAIN,
            extracted_version=raw_ver,
            normalized_version=None,
            reason=f"Version extraite '{raw_ver}' non parseable — impossible de confirmer",
        )

    norm_str = str(svc_ver)

    # ── Parse toutes les contraintes ──
    parsed = []
    unparseable = []
    for c in affected_versions:
        result = _parse_constraint(c)
        if result:
            parsed.append((result, c))
        else:
            unparseable.append(c)

    # Si aucune contrainte parseable → UNCERTAIN
    if not parsed:
        return MatchResult(
            affected=False,
            confidence=Confidence.UNCERTAIN,
            extracted_version=raw_ver,
            normalized_version=norm_str,
            reason=f"Contraintes non parseable : {affected_versions}",
        )

    # ── Évaluation selon la sémantique AND / OR ──
    raw_constraints = [c for (_, c) in parsed]
    is_or = _constraints_are_discrete_or(raw_constraints)

    if is_or:
        # OR : au moins une contrainte doit être satisfaite
        match = any(op_func(svc_ver, ref_ver) for (op_func, ref_ver, _, _), _ in parsed)
        logic = "OR"
    else:
        # AND : toutes les contraintes doivent être satisfaites
        match = all(op_func(svc_ver, ref_ver) for (op_func, ref_ver, _, _), _ in parsed)
        logic = "AND"

    constraints_str = f" {logic} ".join(c for _, c in parsed)

    if match:
        return MatchResult(
            affected=True,
            confidence=Confidence.CERTAIN,
            extracted_version=raw_ver,
            normalized_version=norm_str,
            reason=f"v{norm_str} satisfait la contrainte : {constraints_str}",
        )
    else:
        return MatchResult(
            affected=False,
            confidence=Confidence.NOT_AFFECTED,
            extracted_version=raw_ver,
            normalized_version=norm_str,
            reason=f"v{norm_str} ne satisfait pas : {constraints_str}",
        )


# ─── API de compatibilité avec l'ancien version_checker ──────────────────────

def is_version_affected(service_version: str, affected_versions: list) -> bool:
    """
    Rétrocompatibilité avec l'API existante de ChocoScan.

    Comportement modifié vs l'original :
    - Version inconnue/vide → False (était True = source de faux positifs)
    - Contraintes discrètes multiples (= A, = B) → OR logique (était AND)
    """
    result = check_version_affected(service_version, "", affected_versions)
    # UNCERTAIN → False (plus de faux positifs sur version inconnue)
    if result.confidence == Confidence.UNCERTAIN:
        return False
    return result.affected


def parse_version(version_str: str) -> str:
    """Rétrocompatibilité — retourne la version extraite brute."""
    return extract_version(version_str) or ""


def normalize_version(v: str) -> str:
    """Rétrocompatibilité — retourne la version normalisée en str."""
    raw = extract_version(v) or v
    ver = _to_version(raw)
    return str(ver) if ver else v


# ─── Interface pour le cve_matcher ───────────────────────────────────────────

def filter_cves_by_version(
    cves: list[dict],
    version_field: str,
    banner: str,
) -> list[dict]:
    """
    Filtre une liste de CVEs selon la version détectée par Nmap.

    Chaque CVE reçoit un champ supplémentaire '_match' (MatchResult)
    pour que le rapport puisse afficher la confidence.

    Stratégie :
    - CERTAIN / LIKELY   → inclure
    - UNCERTAIN          → inclure AVEC flag (version non confirmée)
    - NOT_AFFECTED       → exclure
    """
    result = []
    for cve in cves:
        affected_versions = cve.get("affected_versions", [])
        match = check_version_affected(version_field, banner, affected_versions)
        cve_copy = dict(cve)
        cve_copy["_match"] = match
        cve_copy["_confidence"] = match.confidence.value
        cve_copy["_match_reason"] = match.reason

        if match.confidence in (Confidence.CERTAIN, Confidence.LIKELY):
            result.append(cve_copy)
        elif match.confidence == Confidence.UNCERTAIN:
            # Inclure mais marquer comme non confirmé
            cve_copy["_unconfirmed"] = True
            result.append(cve_copy)
        # NOT_AFFECTED → on drop silencieusement

    return result
