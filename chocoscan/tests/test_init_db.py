"""
Tests unitaires — init_db.py

Couvre la logique de bootstrap de la base CVE :
  - détection de l'état (healthy / minimal / missing)
  - initialisation depuis la seed sans écraser une DB saine
  - --force écrase inconditionnellement
  - robustesse face à un JSON corrompu
"""

import json
import sys
import importlib
from pathlib import Path

import pytest

# init_db.py est à la racine du projet, pas dans modules/
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import init_db as init_db_module


@pytest.fixture
def isolated_db_paths(tmp_path, monkeypatch):
    """
    Redirige CVE_DB_PATH et SEED_DB_PATH du module vers un répertoire
    temporaire isolé, pour ne jamais toucher aux vraies données du projet.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    main_path = data_dir / "cve_db.json"
    seed_path = data_dir / "cve_db.seed.json"

    monkeypatch.setattr(init_db_module, "DATA_DIR", data_dir)
    monkeypatch.setattr(init_db_module, "CVE_DB_PATH", main_path)
    monkeypatch.setattr(init_db_module, "SEED_DB_PATH", seed_path)

    return main_path, seed_path


def _write_db(path: Path, n_services: int):
    """Écrit une DB factice avec n_services services et 1 CVE chacun."""
    db = {f"service{i}": [{"id": f"CVE-2024-{i:05d}", "cvss": 9.0}] for i in range(n_services)}
    path.write_text(json.dumps(db), encoding="utf-8")


class TestDbStats:

    def test_missing_file_returns_none(self, isolated_db_paths):
        main_path, _ = isolated_db_paths
        assert init_db_module.db_stats(main_path) is None

    def test_valid_db_returns_counts(self, isolated_db_paths):
        main_path, _ = isolated_db_paths
        _write_db(main_path, 10)
        stats = init_db_module.db_stats(main_path)
        assert stats == (10, 10)

    def test_corrupted_json_returns_none(self, isolated_db_paths):
        main_path, _ = isolated_db_paths
        main_path.write_text("{not valid json")
        assert init_db_module.db_stats(main_path) is None


class TestCheckStatus:

    def test_missing_db_is_missing_status(self, isolated_db_paths):
        assert init_db_module.check_status() == "missing"

    def test_below_threshold_is_minimal_status(self, isolated_db_paths):
        main_path, _ = isolated_db_paths
        _write_db(main_path, init_db_module.MIN_HEALTHY_SERVICES - 1)
        assert init_db_module.check_status() == "minimal"

    def test_at_or_above_threshold_is_healthy_status(self, isolated_db_paths):
        main_path, _ = isolated_db_paths
        _write_db(main_path, init_db_module.MIN_HEALTHY_SERVICES)
        assert init_db_module.check_status() == "healthy"

    def test_corrupted_db_is_missing_status(self, isolated_db_paths):
        main_path, _ = isolated_db_paths
        main_path.write_text("not json at all")
        assert init_db_module.check_status() == "missing"


class TestInitFromSeed:

    def test_fails_gracefully_when_seed_absent(self, isolated_db_paths):
        result = init_db_module.init_from_seed()
        assert result is False

    def test_copies_seed_when_main_missing(self, isolated_db_paths):
        main_path, seed_path = isolated_db_paths
        _write_db(seed_path, 20)

        result = init_db_module.init_from_seed()
        assert result is True
        assert main_path.exists()
        assert init_db_module.db_stats(main_path) == (20, 20)

    def test_does_not_overwrite_healthy_db_without_force(self, isolated_db_paths):
        main_path, seed_path = isolated_db_paths
        _write_db(seed_path, 20)
        _write_db(main_path, 100)  # DB saine déjà en place

        result = init_db_module.init_from_seed(force=False)
        assert result is False
        # La DB d'origine (100 services) ne doit pas avoir été écrasée par la seed (20)
        assert init_db_module.db_stats(main_path) == (100, 100)

    def test_force_overwrites_healthy_db(self, isolated_db_paths):
        main_path, seed_path = isolated_db_paths
        _write_db(seed_path, 20)
        _write_db(main_path, 100)

        result = init_db_module.init_from_seed(force=True)
        assert result is True
        assert init_db_module.db_stats(main_path) == (20, 20)

    def test_overwrites_minimal_db_without_force(self, isolated_db_paths):
        # Une DB en dessous du seuil "healthy" doit pouvoir être complétée
        # par la seed même sans --force, car elle n'est pas considérée fiable.
        main_path, seed_path = isolated_db_paths
        _write_db(seed_path, 60)
        _write_db(main_path, 5)  # en dessous de MIN_HEALTHY_SERVICES

        result = init_db_module.init_from_seed(force=False)
        assert result is True
        assert init_db_module.db_stats(main_path) == (60, 60)


class TestSeedFileIntegrity:
    """
    Vérifie que la vraie seed livrée avec le projet (pas une fixture isolée)
    est valide — ce test tape sur le vrai fichier data/cve_db.seed.json.
    """

    def test_real_seed_file_exists(self):
        assert init_db_module.SEED_DB_PATH.exists(), \
            "data/cve_db.seed.json doit être versionné dans le repo"

    def test_real_seed_file_is_valid_json(self):
        stats = init_db_module.db_stats(init_db_module.SEED_DB_PATH)
        assert stats is not None, "la seed réelle doit être un JSON valide"

    def test_real_seed_has_reasonable_coverage(self):
        stats = init_db_module.db_stats(init_db_module.SEED_DB_PATH)
        n_services, n_cves = stats
        assert n_services >= 50, "la seed doit couvrir au moins 50 services"
        assert n_cves >= 200, "la seed doit contenir au moins 200 CVEs"
