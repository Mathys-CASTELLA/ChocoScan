"""
Tests unitaires — modules/cve_matcher.py : get_nvd_api_key()

Couvre la résolution de la clé API NVD :
  - priorité variable d'environnement > fichier de config
  - les deux noms de variable acceptés (CHOCOSCAN_NVD_API_KEY, NVD_API_KEY)
  - absence de clé → None, sans crash
"""

import os
import pytest
from pathlib import Path

from modules.cve_matcher import get_nvd_api_key


@pytest.fixture(autouse=True)
def clean_nvd_env():
    """Nettoie les variables d'environnement liées à la clé NVD entre les tests."""
    saved = {}
    for k in ("CHOCOSCAN_NVD_API_KEY", "NVD_API_KEY"):
        if k in os.environ:
            saved[k] = os.environ.pop(k)
    yield
    for k in ("CHOCOSCAN_NVD_API_KEY", "NVD_API_KEY"):
        os.environ.pop(k, None)
    os.environ.update(saved)


class TestGetNvdApiKey:

    def test_no_key_configured_returns_none(self, monkeypatch):
        # Empêche toute lecture accidentelle d'un ~/.chocoscan.conf réel
        monkeypatch.setattr(
            "modules.cve_matcher.find_config_file", lambda: None
        )
        assert get_nvd_api_key() is None

    def test_chocoscan_prefixed_env_var(self):
        os.environ["CHOCOSCAN_NVD_API_KEY"] = "secret-key-abc"
        assert get_nvd_api_key() == "secret-key-abc"

    def test_unprefixed_nvd_env_var_alias(self):
        os.environ["NVD_API_KEY"] = "alt-secret-key"
        assert get_nvd_api_key() == "alt-secret-key"

    def test_chocoscan_prefix_takes_priority_over_alias(self):
        os.environ["CHOCOSCAN_NVD_API_KEY"] = "priority-key"
        os.environ["NVD_API_KEY"] = "fallback-key"
        assert get_nvd_api_key() == "priority-key"

    def test_empty_env_var_is_ignored(self, monkeypatch):
        monkeypatch.setattr(
            "modules.cve_matcher.find_config_file", lambda: None
        )
        os.environ["CHOCOSCAN_NVD_API_KEY"] = ""
        assert get_nvd_api_key() is None

    def test_reads_key_from_config_file(self, tmp_path, monkeypatch):
        conf = tmp_path / "test.conf"
        conf.write_text('nvd_api_key = "from-config-file"\n')
        monkeypatch.setattr(
            "modules.cve_matcher.find_config_file", lambda: conf
        )
        assert get_nvd_api_key() == "from-config-file"

    def test_env_var_overrides_config_file(self, tmp_path, monkeypatch):
        conf = tmp_path / "test.conf"
        conf.write_text('nvd_api_key = "from-config-file"\n')
        monkeypatch.setattr(
            "modules.cve_matcher.find_config_file", lambda: conf
        )
        os.environ["CHOCOSCAN_NVD_API_KEY"] = "from-env"
        assert get_nvd_api_key() == "from-env"

    def test_malformed_config_file_does_not_crash(self, tmp_path, monkeypatch):
        conf = tmp_path / "broken.conf"
        conf.write_text('nvd_api_key = [not valid toml\n')
        monkeypatch.setattr(
            "modules.cve_matcher.find_config_file", lambda: conf
        )
        # Ne doit pas lever d'exception, juste retourner None
        assert get_nvd_api_key() is None
