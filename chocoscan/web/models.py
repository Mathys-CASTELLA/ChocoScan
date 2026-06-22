"""
ChocoScan Web — Schémas Pydantic (I/O de l'API).

Sépare clairement ce que l'API reçoit (Request) et ce qu'elle renvoie (Response),
sans exposer les internals du pipeline.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


# ── CVE (unité de base) ───────────────────────────────────────────────────────

class CVESchema(BaseModel):
    id:              str
    description:     str              = ""
    description_fr:  str              = ""
    cvss:            float | str      = "N/A"
    severity:        str              = "UNKNOWN"
    affected_versions: str | list     = ""
    source:          str              = "local"
    tags:            list[str]        = Field(default_factory=list)
    cisa_kev:        bool             = False
    exploit_available: bool           = False
    contextual_score: float | None    = None
    exploits:        list[dict]       = Field(default_factory=list)
    cpe:             str | None       = None

    model_config = {"extra": "ignore"}


# ── Service (port + CVE associées) ───────────────────────────────────────────

class ServiceResult(BaseModel):
    host:         str
    port:         int
    protocol:     str              = "tcp"
    state:        str              = "open"
    service_name: str              = ""
    product:      str              = ""
    version:      str              = ""
    banner:       str              = ""
    cves:         list[CVESchema]  = Field(default_factory=list)

    model_config = {"extra": "ignore"}


# ── Stats résumées (dashboard) ────────────────────────────────────────────────

class ScanStats(BaseModel):
    total_cves:  int = 0
    critical:    int = 0
    high:        int = 0
    medium:      int = 0
    low:         int = 0
    services:    int = 0
    hosts:       int = 0
    with_exploit: int = 0
    cisa_kev:    int = 0


# ── Scan (persisté en DB) ─────────────────────────────────────────────────────

class ScanSummary(BaseModel):
    """Résumé léger pour l'historique (pas les résultats complets)."""
    id:          int
    created_at:  datetime
    target:      str
    input_type:  str
    status:      str
    stats:       ScanStats | None = None
    error_msg:   str | None       = None

    model_config = {"from_attributes": True}


class ScanDetail(ScanSummary):
    """Scan complet avec résultats."""
    results: list[ServiceResult] = Field(default_factory=list)


# ── Requêtes ──────────────────────────────────────────────────────────────────

class ScanFilters(BaseModel):
    """Filtres applicables à un scan (repris des options CLI)."""
    min_cvss:    float              = 0.0
    severity:    list[str]         = Field(default_factory=list)
    after_year:  int | None        = None
    no_api:      bool              = False
    exploits:    bool              = False


class SSHScanRequest(BaseModel):
    host:        str
    port:        int               = 22
    username:    str
    password:    str | None        = None
    key_path:    str | None        = None
    filters:     ScanFilters       = Field(default_factory=ScanFilters)


# ── Réponses génériques ───────────────────────────────────────────────────────

class APIError(BaseModel):
    detail: str
    code:   str = "error"


class DeleteResponse(BaseModel):
    deleted: bool
    id:      int
