"""
ChocoScan Web — Routeur /api/ssh

POST /api/ssh/scan    Scan authentifié SSH (liste paquets installés)
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import ScanRecord, get_session
from web.models import ScanDetail, ScanStats, SSHScanRequest
from web.pipeline import (
    compute_stats, results_to_json, run_ssh_scan_pipeline
)

try:
    from modules.credentialed_scan import SSHCredentialError, SSHConnectionError
except ImportError:
    SSHCredentialError = Exception
    SSHConnectionError = Exception

router = APIRouter(prefix="/api/ssh", tags=["ssh"])


def _record_to_detail(record: ScanRecord, results) -> ScanDetail:
    stats = None
    if record.stats_json:
        try:
            stats = ScanStats(**json.loads(record.stats_json))
        except Exception:
            pass
    return ScanDetail(
        id=record.id,
        created_at=record.created_at,
        target=record.target,
        input_type=record.input_type,
        status=record.status,
        stats=stats,
        error_msg=record.error_msg,
        results=results,
    )


@router.post("/scan", response_model=ScanDetail, status_code=201)
async def ssh_scan(
    request: SSHScanRequest,
    db: AsyncSession = Depends(get_session),
):
    """
    Se connecte à la cible en SSH, liste les paquets installés
    (dpkg / rpm / pacman selon la distribution), passe dans le pipeline CVE.
    """
    record = ScanRecord(
        target=f"{request.host}:{request.port}",
        input_type="ssh",
        status="running",
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    try:
        results, distro = await run_ssh_scan_pipeline(
            host=request.host,
            username=request.username,
            password=request.password,
            key_path=request.key_path,
            port=request.port,
            filters=request.filters,
        )
        stats = compute_stats(results)

        record.status       = "done"
        record.results_json = results_to_json(results)
        record.stats_json   = json.dumps({**stats.model_dump(), "distro": distro})

    except SSHCredentialError as e:
        record.status    = "error"
        record.error_msg = f"Authentification échouée : {e}"
        await db.commit()
        raise HTTPException(status_code=401, detail=record.error_msg)

    except SSHConnectionError as e:
        record.status    = "error"
        record.error_msg = f"Connexion impossible : {e}"
        await db.commit()
        raise HTTPException(status_code=503, detail=record.error_msg)

    except RuntimeError as e:
        record.status    = "error"
        record.error_msg = str(e)
        await db.commit()
        raise HTTPException(status_code=422, detail=str(e))

    await db.commit()
    await db.refresh(record)
    return _record_to_detail(record, results)
