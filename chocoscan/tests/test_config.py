"""
Tests unitaires — modules/config.py

Couvre la résolution du fichier ~/.chocoscan.conf :
  - lecture et validation TOML
  - priorité CLI > variables d'environnement > fichier > défaut argparse
  - gestion des erreurs (TOML invalide, fichier absent, clés inconnues)
  - expansion du ~ dans output_dir
"""

import argparse
import os
import tempfile
from pathlib import Path

import pytest

from modules.config import (
    load_config,
    load_env_overrides,
    apply_to_parser,
    find_config_file,
    _generate_default_config,
    CONFIGURABLE_KEYS,
)


@pytest.fixture
def tmp_config_file(tmp_path):
    """Crée un fichier de config TOML temporaire et le supprime après le test."""
    def _make(content: str) -> Path:
        p = tmp_path / "test.conf"
        p.write_text(content)
        return p
    return _make


@pytest.fixture(autouse=True)
def clean_env():
    """S'assure qu'aucune variable CHOCOSCAN_* ne fuit entre les tests."""
    saved = {k: v for k, v in os.environ.items() if k.startswith("CHOCOSCAN_")}
    for k in saved:
        del os.environ[k]
    yield
    for k in list(os.environ):
        if k.startswith("CHOCOSCAN_"):
            del os.environ[k]
    os.environ.update(saved)


# ─── load_config() — lecture et validation TOML ───────────────────────────────

class TestLoadConfig:

    def test_reads_simple_values(self, tmp_config_file):
        p = tmp_config_file('min_cvss = 7.0\ntop_cves = 10\nexploits = true\n')
        cfg = load_config(p)
        assert cfg["min_cvss"] == 7.0
        assert cfg["top_cves"] == 10
        assert cfg["exploits"] is True

    def test_reads_nested_sections(self, tmp_config_file):
        p = tmp_config_file(
            '[scan]\nnmap_args = "-T4 --open"\n\n[web]\nenum_threads = 20\n'
        )
        cfg = load_config(p)
        assert cfg["nmap_args"] == "-T4 --open"
        assert cfg["enum_threads"] == 20

    def test_expands_tilde_in_output_dir(self, tmp_config_file):
        p = tmp_config_file('output_dir = "~/my_reports"\n')
        cfg = load_config(p)
        assert cfg["output_dir"] == str(Path("~/my_reports").expanduser())
        assert "~" not in cfg["output_dir"]

    def test_unknown_key_is_silently_ignored(self, tmp_config_file):
        p = tmp_config_file('min_cvss = 5.0\nchamp_inconnu = "test"\n')
        cfg = load_config(p)
        assert cfg["min_cvss"] == 5.0
        assert "champ_inconnu" not in cfg

    def test_invalid_toml_returns_empty_dict_no_crash(self, tmp_config_file):
        p = tmp_config_file('min_cvss = [invalide\n')
        cfg = load_config(p)
        assert cfg == {}

    def test_missing_file_returns_empty_dict(self):
        cfg = load_config(Path("/tmp/does_not_exist_chocoscan.conf"))
        assert cfg == {}

    def test_type_coercion_int_to_float(self, tmp_config_file):
        p = tmp_config_file("min_cvss = 7\n")  # int dans le TOML, float attendu
        cfg = load_config(p)
        assert cfg["min_cvss"] == 7.0
        assert isinstance(cfg["min_cvss"], float)

    def test_invalid_type_for_bool_is_rejected(self, tmp_config_file):
        # exploits attend un bool ; une string ne doit pas passer silencieusement
        p = tmp_config_file('exploits = "yes"\n')
        cfg = load_config(p)
        assert "exploits" not in cfg


# ─── load_env_overrides() ──────────────────────────────────────────────────────

class TestLoadEnvOverrides:

    def test_reads_chocoscan_prefixed_vars(self):
        os.environ["CHOCOSCAN_MIN_CVSS"] = "9.5"
        os.environ["CHOCOSCAN_NO_API"] = "true"
        os.environ["CHOCOSCAN_TOP_CVES"] = "3"

        env = load_env_overrides()
        assert env["min_cvss"] == 9.5
        assert env["no_api"] is True
        assert env["top_cves"] == 3

    def test_ignores_non_chocoscan_vars(self):
        os.environ["PATH_SOMETHING"] = "irrelevant"
        os.environ["CHOCOSCAN_MIN_CVSS"] = "5.0"
        env = load_env_overrides()
        assert "path_something" not in env
        assert env["min_cvss"] == 5.0

    def test_ignores_unknown_chocoscan_keys(self):
        os.environ["CHOCOSCAN_NOT_A_REAL_KEY"] = "value"
        env = load_env_overrides()
        assert "not_a_real_key" not in env

    def test_bool_parsing_variants(self):
        for truthy in ("1", "true", "True", "yes", "on"):
            os.environ["CHOCOSCAN_EXPLOITS"] = truthy
            assert load_env_overrides()["exploits"] is True, f"'{truthy}' devrait être True"

        for falsy in ("0", "false", "no", "off"):
            os.environ["CHOCOSCAN_EXPLOITS"] = falsy
            assert load_env_overrides()["exploits"] is False, f"'{falsy}' devrait être False"

    def test_invalid_numeric_value_ignored_not_crashed(self):
        os.environ["CHOCOSCAN_MIN_CVSS"] = "not_a_number"
        env = load_env_overrides()
        assert "min_cvss" not in env


# ─── apply_to_parser() — priorité CLI > env > fichier > défaut ────────────────

class TestPriorityResolution:

    def _make_parser(self):
        p = argparse.ArgumentParser()
        p.add_argument("--min-cvss", type=float, default=0.0)
        p.add_argument("--top-cves", type=int, default=5)
        p.add_argument("--exploits", action="store_true")
        p.add_argument("--no-api", action="store_true")
        p.add_argument("--export-html", action="store_true")
        return p

    def test_file_value_used_when_no_cli_no_env(self, tmp_config_file):
        p = tmp_config_file("min_cvss = 7.0\nexploits = true\n")
        parser = self._make_parser()
        apply_to_parser(parser, config_path=p, verbose=False)

        args = parser.parse_args([])
        assert args.min_cvss == 7.0
        assert args.exploits is True

    def test_env_overrides_file(self, tmp_config_file):
        p = tmp_config_file("min_cvss = 7.0\n")
        os.environ["CHOCOSCAN_MIN_CVSS"] = "9.5"

        parser = self._make_parser()
        apply_to_parser(parser, config_path=p, verbose=False)

        args = parser.parse_args([])
        assert args.min_cvss == 9.5, "la variable d'environnement doit gagner sur le fichier"

    def test_cli_always_wins_over_everything(self, tmp_config_file):
        p = tmp_config_file("min_cvss = 7.0\n")
        os.environ["CHOCOSCAN_MIN_CVSS"] = "9.5"

        parser = self._make_parser()
        apply_to_parser(parser, config_path=p, verbose=False)

        args = parser.parse_args(["--min-cvss", "4.0"])
        assert args.min_cvss == 4.0, "l'argument CLI explicite doit toujours gagner"

    def test_default_used_when_nothing_configured(self):
        parser = self._make_parser()
        apply_to_parser(parser, config_path=Path("/tmp/nope.conf"), verbose=False)

        args = parser.parse_args([])
        assert args.min_cvss == 0.0  # défaut argparse inchangé

    def test_partial_cli_keeps_other_file_values(self, tmp_config_file):
        # Un seul arg passé en CLI ne doit pas réinitialiser les autres
        p = tmp_config_file("min_cvss = 7.0\nexploits = true\ntop_cves = 10\n")
        parser = self._make_parser()
        apply_to_parser(parser, config_path=p, verbose=False)

        args = parser.parse_args(["--top-cves", "99"])
        assert args.top_cves == 99       # CLI
        assert args.min_cvss == 7.0      # fichier, non écrasé
        assert args.exploits is True     # fichier, non écrasé


# ─── _generate_default_config() ───────────────────────────────────────────────

class TestGenerateDefaultConfig:

    def test_contains_all_configurable_keys(self):
        content = _generate_default_config()
        # Toutes les clés racine (hors sections) doivent apparaître quelque part
        for key in CONFIGURABLE_KEYS:
            assert key in content, f"clé '{key}' absente du template généré"

    def test_is_valid_toml(self):
        import tomllib
        content = _generate_default_config()
        # Doit parser sans erreur (toutes les lignes actives sont valides)
        parsed = tomllib.loads(content)
        assert isinstance(parsed, dict)

    def test_has_scan_and_web_sections(self):
        content = _generate_default_config()
        assert "[scan]" in content
        assert "[web]" in content
