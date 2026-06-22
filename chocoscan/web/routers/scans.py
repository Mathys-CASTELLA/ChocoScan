"""
ChocoScan Web — Routeur /api/scans

POST   /api/scans/upload        Upload d'un fichier de scan
POST   /api/scans/direct        Lance nmap directement sur une IP
GET    /api/scans               Liste l'historique (avec pagination)
GET    /api/scans/{id}          Résultats complets d'un scan
DELETE /api/scans/{id}          Supprime un scan de l'historique
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select, desc, delete
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import ScanRecord, get_session
from web.models import (
    ScanDetail, ScanFilters, ScanStats, ScanSummary,
)
from web.pipeline import (
    compute_stats, results_from_json, results_to_json, run_file_scan
)

router = APIRouter(prefix="/api/scans", tags=["scans"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _record_to_summary(record: ScanRecord) -> ScanSummary:
    stats = None
    if record.stats_json:
        try:
            stats = ScanStats(**json.loads(record.stats_json))
        except Exception:
            pass
    return ScanSummary(
        id=record.id,
        created_at=record.created_at,
        target=record.target,
        input_type=record.input_type,
        status=record.status,
        stats=stats,
        error_msg=record.error_msg,
    )


def _record_to_detail(record: ScanRecord) -> ScanDetail:
    summary = _record_to_summary(record)
    results = []
    if record.results_json:
        try:
            results = results_from_json(record.results_json)
        except Exception:
            pass
    return ScanDetail(**summary.model_dump(), results=results)


# ── Upload fichier ────────────────────────────────────────────────────────────

@router.post("/upload", response_model=ScanDetail, status_code=201)
async def upload_scan(
    file: UploadFile = File(...),
    min_cvss:   float       = Form(0.0),
    severity:   str         = Form(""),
    after_year: int | None  = Form(None),
    no_api:     bool        = Form(False),
    db: AsyncSession        = Depends(get_session),
):
    """
    Reçoit un fichier de scan (Nmap XML/texte, Masscan, RustScan, Nessus...),
    lance le pipeline CVE, sauvegarde et retourne les résultats.
    """
    filters = ScanFilters(
        min_cvss=min_cvss,
        severity=[s.strip() for s in severity.split(",") if s.strip()],
        after_year=after_year,
        no_api=no_api,
    )

    # Sauvegarde temporaire du fichier uploadé
    suffix = Path(file.filename or "scan").suffix or ".xml"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)

    # Enregistrement initial en DB (status = running)
    record = ScanRecord(
        target=file.filename or "uploaded_file",
        input_type="file",
        status="running",
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    try:
        results = await run_file_scan(tmp_path, filters)
        stats = compute_stats(results)

        record.status       = "done"
        record.results_json = results_to_json(results)
        record.stats_json   = json.dumps(stats.model_dump())
    except Exception as e:
        record.status    = "error"
        record.error_msg = str(e)
        await db.commit()
        raise HTTPException(status_code=422, detail=f"Erreur pipeline : {e}")
    finally:
        tmp_path.unlink(missing_ok=True)

    await db.commit()
    await db.refresh(record)
    return _record_to_detail(record)


# ── Scan direct (nmap piloté par ChocoScan) ───────────────────────────────────

@router.post("/direct", response_model=ScanDetail, status_code=201)
async def direct_scan(
    target:     str         = Form(...),
    nmap_args:  str         = Form("-sV -T4 --open"),
    min_cvss:   float       = Form(0.0),
    severity:   str         = Form(""),
    after_year: int | None  = Form(None),
    no_api:     bool        = Form(False),
    db: AsyncSession        = Depends(get_session),
):
    """Lance nmap directement sur la cible puis passe dans le pipeline CVE."""
    filters = ScanFilters(
        min_cvss=min_cvss,
        severity=[s.strip() for s in severity.split(",") if s.strip()],
        after_year=after_year,
        no_api=no_api,
    )

    record = ScanRecord(target=target, input_type="direct", status="running")
    db.add(record)
    await db.commit()
    await db.refresh(record)

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        cmd = ["nmap", "-oX", str(tmp_path)] + nmap_args.split() + [target]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise RuntimeError(f"nmap a échoué : {proc.stderr[:300]}")

        results = await run_file_scan(tmp_path, filters)
        stats   = compute_stats(results)

        record.status       = "done"
        record.results_json = results_to_json(results)
        record.stats_json   = json.dumps(stats.model_dump())
    except Exception as e:
        record.status    = "error"
        record.error_msg = str(e)
        await db.commit()
        raise HTTPException(status_code=422, detail=str(e))
    finally:
        tmp_path.unlink(missing_ok=True)

    await db.commit()
    await db.refresh(record)
    return _record_to_detail(record)


# ── Historique ────────────────────────────────────────────────────────────────

@router.get("", response_model=list[ScanSummary])
async def list_scans(
    limit:  int = 20,
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
):
    """Retourne la liste des scans, du plus récent au plus ancien."""
    result = await db.execute(
        select(ScanRecord)
        .order_by(desc(ScanRecord.created_at))
        .limit(limit)
        .offset(offset)
    )
    records = result.scalars().all()
    return [_record_to_summary(r) for r in records]


# ── Détail ────────────────────────────────────────────────────────────────────

@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_session),
):
    """Retourne les résultats complets d'un scan."""
    record = await db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return _record_to_detail(record)


# ── Suppression ───────────────────────────────────────────────────────────────

@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_session),
):
    """Supprime un scan de l'historique."""
    record = await db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    await db.execute(delete(ScanRecord).where(ScanRecord.id == scan_id))
    await db.commit()
    return {"deleted": True, "id": scan_id}
