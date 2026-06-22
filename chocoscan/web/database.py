"""
ChocoScan Web — Base de données SQLite async.

Stocke l'historique des scans et leurs résultats.
On stocke les résultats en JSON brut plutôt que de les normaliser :
les structures varient selon le type de scan (réseau vs SSH vs diff)
et on n'a pas besoin de requêter à l'intérieur du JSON côté DB.
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime

from sqlalchemy import String, Text, DateTime, Integer, Enum as SAEnum
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ── Chemin de la DB ───────────────────────────────────────────────────────────

DB_DIR  = Path(__file__).parent.parent / "data"
DB_PATH = DB_DIR / "chocoscan_web.db"

DB_URL = f"sqlite+aiosqlite:///{DB_PATH}"

engine = create_async_engine(DB_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


# ── Modèle SQLAlchemy ────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    """Un scan sauvegardé — résultats complets + métadonnées."""
    __tablename__ = "scans"

    id:          Mapped[int]      = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at:  Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    target:      Mapped[str]      = mapped_column(String(255))
    input_type:  Mapped[str]      = mapped_column(
        SAEnum("file", "direct", "ssh", name="input_type_enum"), default="file"
    )
    status:      Mapped[str]      = mapped_column(
        SAEnum("pending", "running", "done", "error", name="status_enum"), default="pending"
    )
    # Résultats complets sérialisés en JSON
    results_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Stats résumées pour l'historique (évite de désérialiser tout le JSON juste pour le dashboard)
    # ex: {"total_cves": 42, "critical": 5, "high": 12, "services": 8}
    stats_json:   Mapped[str | None] = mapped_column(Text, nullable=True)
    error_msg:    Mapped[str | None] = mapped_column(Text, nullable=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

async def init_db():
    """Crée les tables si elles n'existent pas encore."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session():
    """Dépendance FastAPI — fournit une session DB par requête."""
    async with AsyncSessionLocal() as session:
        yield session
