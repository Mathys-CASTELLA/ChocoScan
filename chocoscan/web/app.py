"""
ChocoScan Web — Application FastAPI.

Lancement :
    uvicorn web.app:app --reload --port 8000

En production :
    uvicorn web.app:app --host 0.0.0.0 --port 8000 --workers 2

Swagger UI : http://localhost:8000/docs
ReDoc      : http://localhost:8000/redoc
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from web.database import init_db
from web.routers import scans, ssh, export

FRONTEND_DIST = Path(__file__).parent / "frontend" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise la DB au démarrage."""
    await init_db()
    yield


app = FastAPI(
    title="ChocoScan API",
    description=(
        "API REST pour ChocoScan — scanner de vulnérabilités post-Nmap.\n\n"
        "Associe automatiquement les services réseau détectés (Nmap, Masscan, "
        "RustScan, Nessus, ou scan SSH authentifié) aux CVE les affectant, "
        "avec scoring contextuel et historique persistant."
    ),
    version="1.0.0",
    contact={"name": "Kinder-Bueno", "url": "https://github.com/Mathys-CASTELLA"},
    lifespan=lifespan,
)

# ── CORS (permissif en dev, à restreindre en prod) ────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routeurs ──────────────────────────────────────────────────────────────────
app.include_router(scans.router)
app.include_router(ssh.router)
app.include_router(export.router)


# ── Sanity check ──────────────────────────────────────────────────────────────
@app.get("/api/health", tags=["health"])
async def health():
    return {"status": "ok", "service": "ChocoScan API"}


# ── Frontend React (servi en prod depuis le build Vite) ───────────────────────
if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")
