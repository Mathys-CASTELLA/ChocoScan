"""
ChocoScan Web — Pont entre FastAPI et le pipeline CLI existant.

Ce module est la seule couche qui connaît les internals de ChocoScan.
Tous les routeurs passent par ici — ils ne manipulent que des schémas Pydantic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# S'assure que les modules ChocoScan sont importables depuis web/
ROOT = Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.input_parser import parse_input_file
from modules.cve_matcher import get_cves_for_service, extract_service_key, filter_cves
from modules.contextual_scorer import inject_scores
from modules.ignore_list import load_ignore_list, filter_ignored
from modules.credentialed_scan import collect_packages_ssh, packages_to_services

from web.models import (
    CVESchema, ServiceResult, ScanStats, ScanFilters
)


def _parse_severity_filter(severity_list: list[str]) -> set[str]:
    return {s.upper() for s in severity_list if s}


def _build_cve_schema(raw: dict) -> CVESchema:
    """Convertit un dict CVE brut du pipeline en schema Pydantic."""
    cvss_raw = raw.get("cvss", "N/A")
    try:
        cvss = float(cvss_raw)
    except (TypeError, ValueError):
        cvss = "N/A"

    return CVESchema(
        id=raw.get("id", ""),
        description=raw.get("description", ""),
        description_fr=raw.get("description_fr", ""),
        cvss=cvss,
        severity=raw.get("severity", "UNKNOWN"),
        affected_versions=raw.get("affected_versions", ""),
        source=raw.get("source", "local"),
        tags=raw.get("tags", []),
        cisa_kev=raw.get("cisa_kev", False),
        exploit_available=raw.get("exploit_available", False),
        contextual_score=raw.get("contextual_score"),
        exploits=raw.get("exploits", []),
        cpe=raw.get("cpe"),
    )


def _run_pipeline(
    services: list,
    filters: ScanFilters,
    ignored_cves: set[str] | None = None,
) -> list[ServiceResult]:
    """
    Applique le pipeline CVE complet sur une liste de NmapService.
    Retourne une liste de ServiceResult prêts à être sérialisés.
    """
    severity_filter = _parse_severity_filter(filters.severity)
    ignored = ignored_cves or set()
    results = []

    for svc in services:
        cves_raw = get_cves_for_service(
            svc.service_name, svc.banner, use_api_fallback=not filters.no_api
        )

        # Filtres CVSS / sévérité / année
        cves_raw = filter_cves(
            cves_raw,
            filters.min_cvss,
            severity_filter,
            after_year=filters.after_year,
        )

        # Whitelist
        if ignored:
            cves_raw, _ = filter_ignored(cves_raw, ignored)

        # Scoring contextuel
        if cves_raw:
            cves_raw = inject_scores(cves_raw)

        results.append(ServiceResult(
            host=svc.host,
            port=svc.port,
            protocol=getattr(svc, "protocol", "tcp"),
            state=getattr(svc, "state", "open"),
            service_name=svc.service_name,
            product=getattr(svc, "product", ""),
            version=getattr(svc, "version", ""),
            banner=svc.banner,
            cves=[_build_cve_schema(c) for c in cves_raw],
        ))

    return results


def compute_stats(results: list[ServiceResult]) -> ScanStats:
    """Calcule les stats résumées à partir des résultats complets."""
    stats = ScanStats(
        services=len(results),
        hosts=len({r.host for r in results}),
    )
    for svc in results:
        for cve in svc.cves:
            stats.total_cves += 1
            sev = str(cve.severity).upper()
            if sev == "CRITICAL":
                stats.critical += 1
            elif sev == "HIGH":
                stats.high += 1
            elif sev == "MEDIUM":
                stats.medium += 1
            elif sev == "LOW":
                stats.low += 1
            if cve.exploit_available:
                stats.with_exploit += 1
            if cve.cisa_kev:
                stats.cisa_kev += 1
    return stats


async def run_file_scan(
    file_path: Path,
    filters: ScanFilters,
    ignored_cves: set[str] | None = None,
) -> list[ServiceResult]:
    """Lance le pipeline sur un fichier de scan uploadé."""
    result = parse_input_file(str(file_path))
    # parse_input_file retourne un tuple (services, format_détecté)
    services = result[0] if isinstance(result, tuple) else result
    return _run_pipeline(services, filters, ignored_cves)


async def run_ssh_scan_pipeline(
    host: str,
    username: str,
    password: str | None,
    key_path: str | None,
    port: int,
    filters: ScanFilters,
    ignored_cves: set[str] | None = None,
) -> tuple[list[ServiceResult], str]:
    """
    Lance un scan authentifié SSH puis passe les paquets dans le pipeline CVE.
    Retourne (résultats, distro_détectée).
    """
    packages, distro = collect_packages_ssh(
        host=host,
        username=username,
        password=password,
        key_filename=key_path,
        port=port,
    )
    services = packages_to_services(packages, host)
    results = _run_pipeline(services, filters, ignored_cves)
    return results, distro


def results_to_json(results: list[ServiceResult]) -> str:
    """Sérialise les résultats en JSON pour la DB."""
    return json.dumps([r.model_dump() for r in results], ensure_ascii=False, default=str)


def results_from_json(raw: str) -> list[ServiceResult]:
    """Désérialise les résultats depuis la DB."""
    return [ServiceResult(**item) for item in json.loads(raw)]
