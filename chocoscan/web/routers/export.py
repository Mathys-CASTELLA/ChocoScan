"""
ChocoScan Web — Routeur /api/export

GET /api/export/{scan_id}/html    Rapport HTML complet
GET /api/export/{scan_id}/json    Export JSON brut
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import ScanRecord, get_session
from web.pipeline import results_from_json

router = APIRouter(prefix="/api/export", tags=["export"])


@router.get("/{scan_id}/json")
async def export_json(
    scan_id: int,
    db: AsyncSession = Depends(get_session),
):
    """Retourne les résultats bruts du scan en JSON téléchargeable."""
    record = await db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    if not record.results_json:
        raise HTTPException(status_code=404, detail="Pas de résultats pour ce scan")

    data = json.loads(record.results_json)
    filename = f"chocoscan_{record.target.replace('/', '_').replace(':', '_')}_{record.id}.json"

    return JSONResponse(
        content={"scan_id": scan_id, "target": record.target, "results": data},
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/html")
async def export_html(
    scan_id: int,
    db: AsyncSession = Depends(get_session),
):
    """Génère et retourne le rapport HTML complet via report_generator existant."""
    record = await db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    if not record.results_json:
        raise HTTPException(status_code=404, detail="Pas de résultats pour ce scan")

    try:
        from modules.report_generator import generate_html_report
        results = results_from_json(record.results_json)

        # Conversion au format attendu par report_generator
        raw_results = [r.model_dump() for r in results]

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        generate_html_report(
            results=raw_results,
            output_path=str(tmp_path),
            scan_date=record.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            target=record.target,
        )

        filename = f"chocoscan_{record.target.replace('/', '_').replace(':', '_')}_{record.id}.html"
        return FileResponse(
            path=str(tmp_path),
            filename=filename,
            media_type="text/html",
            background=None,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur génération HTML : {e}")
