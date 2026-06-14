"""
Module de comparaison de versions pour le matching CVE.
"""

import re
from packaging import version as pkg_version


def parse_version(version_str: str) -> str:
    """Nettoie et normalise une chaîne de version."""
    version_str = re.sub(r'^[vV]', '', version_str.strip())
    match = re.search(r'[\d]+(?:\.[\d]+)*(?:[p\-][\d]+)?', version_str)
    if match:
        return match.group(0)
    return version_str


def normalize_version(v: str) -> str:
    """Normalise une version pour comparaison (ex: 7.4p1 -> 7.4.1)."""
    v = parse_version(v)
    v = re.sub(r'[p\-]', '.', v)
    return v


def version_matches_constraint(service_version: str, constraint: str) -> bool:
    """
    Vérifie si une version correspond à une contrainte.
    Formats supportés : < X, <= X, > X, >= X, = X
    """
    constraint = constraint.strip()

    # Contraintes spéciales (non-numériques)
    if not re.search(r'\d', constraint):
        return True

    try:
        svc_ver = normalize_version(service_version)
        parsed_svc = pkg_version.parse(svc_ver)

        ops = {
            '<=': lambda a, b: a <= b,
            '>=': lambda a, b: a >= b,
            '<': lambda a, b: a < b,
            '>': lambda a, b: a > b,
            '=': lambda a, b: a == b,
            '==': lambda a, b: a == b,
        }

        for op_str, op_func in sorted(ops.items(), key=lambda x: -len(x[0])):
            if constraint.startswith(op_str):
                ref_str = normalize_version(constraint[len(op_str):].strip())
                ref_ver = pkg_version.parse(ref_str)
                return op_func(parsed_svc, ref_ver)

    except Exception:
        return True

    return False


def is_version_affected(service_version: str, affected_versions: list) -> bool:
    """
    Vérifie si une version est affectée par une CVE.

    Logique :
    - Contrainte unique "= X" → match exact
    - Contrainte unique "<= X" ou "< X" → simple comparaison
    - Plusieurs contraintes → AND logique (plage de versions, ex: >= 1.0 ET < 2.0)
    """
    if not affected_versions:
        return False

    # Contrainte unique : match exact ou simple comparaison
    if len(affected_versions) == 1:
        constraint = affected_versions[0].strip()
        if constraint.startswith('=') and not constraint.startswith('=='):
            ref = normalize_version(constraint[1:].strip())
            svc = normalize_version(service_version)
            try:
                return pkg_version.parse(svc) == pkg_version.parse(ref)
            except Exception:
                return ref in svc
        # Contrainte unique non-exacte : simple vérification
        return version_matches_constraint(service_version, constraint)

    # Plusieurs contraintes : TOUTES doivent être satisfaites (AND logique)
    # Cela gère correctement les plages comme [">= 7.0", "< 8.5"]
    return all(version_matches_constraint(service_version, c) for c in affected_versions)
