"""
Tests unitaires — modules/version_checker.py

Couvre le moteur de comparaison de versions :
  - extraction de version depuis les bannières Nmap réelles
  - normalisation (epoch Debian, MariaDB, suffixes OS, p1/-1...)
  - logique AND/OR sur les contraintes multiples
  - niveaux de confiance (CERTAIN / LIKELY / UNCERTAIN / NOT_AFFECTED)
  - non-régression sur le bug historique : version inconnue → ne doit
    JAMAIS retourner affected=True par défaut
"""

import pytest
from modules.version_checker import (
    check_version_affected,
    is_version_affected,
    extract_version,
    filter_cves_by_version,
    Confidence,
)


# ─── extract_version() ────────────────────────────────────────────────────────

class TestExtractVersion:

    def test_simple_version(self):
        assert extract_version("8.2p1") == "8.2p1"

    def test_version_with_os_suffix(self):
        assert extract_version("2.4.41 (Ubuntu)") == "2.4.41"

    def test_version_with_win64_openssl_suffix(self):
        assert extract_version("2.4.41 (Win64) OpenSSL/1.1.1c") == "2.4.41"

    def test_debian_epoch_prefix(self):
        assert extract_version("1:7.4p1-10+deb9u7") == "7.4p1"

    def test_mariadb_compat_prefix(self):
        # MariaDB préfixe avec "5.5.5-" pour compat MySQL — le vrai numéro suit
        assert extract_version("5.5.5-10.3.27-MariaDB") == "10.3.27"

    def test_ubuntu_distro_suffix(self):
        # Note : le suffixe "-0" du build Ubuntu reste accroché car il n'y a
        # pas d'espace avant le tiret (contrairement à "2.4.41 (Ubuntu)").
        # Sans impact fonctionnel : _to_version() normalise quand même
        # correctement en 8.0.27.0, qui compare juste avec les bornes CVE.
        assert extract_version("8.0.27-0ubuntu0.20.04.1") == "8.0.27-0"

    def test_banner_fallback_when_version_field_empty(self):
        assert extract_version("", "OpenSSH 7.2p2 Ubuntu") == "7.2p2"

    def test_product_slash_version_banner(self):
        assert extract_version("", "Apache/2.4.49") == "2.4.49"

    def test_empty_string_returns_none(self):
        assert extract_version("") is None

    def test_text_only_returns_none(self):
        assert extract_version("unknown") is None
        assert extract_version("alpha") is None
        assert extract_version("dev") is None

    def test_tcpwrapped_returns_none(self):
        assert extract_version("", "tcpwrapped") is None


# ─── check_version_affected() — cas critiques de non-régression ─────────────

class TestNoFalsePositiveRegression:
    """
    Ces tests verrouillent le bug historique corrigé : avant le fix,
    une version vide/inconnue retournait affected=True par défaut,
    ce qui polluait les résultats avec des CVEs non confirmées.
    """

    def test_empty_version_is_uncertain_not_affected_true(self):
        result = check_version_affected("", "", ["< 9.3p2"])
        assert result.affected is False
        assert result.confidence == Confidence.UNCERTAIN

    def test_unknown_version_is_uncertain(self):
        result = check_version_affected("unknown", "", ["< 9.3p2"])
        assert result.affected is False
        assert result.confidence == Confidence.UNCERTAIN

    def test_non_numeric_version_is_uncertain(self):
        for v in ("alpha", "dev", "beta"):
            result = check_version_affected(v, "", ["< 1.0"])
            assert result.affected is False, f"'{v}' ne doit pas matcher par défaut"
            assert result.confidence == Confidence.UNCERTAIN

    def test_tcpwrapped_is_uncertain(self):
        result = check_version_affected("", "tcpwrapped", ["< 9.3p2"])
        assert result.affected is False
        assert result.confidence == Confidence.UNCERTAIN

    def test_is_version_affected_compat_api_returns_false_on_unknown(self):
        # L'API de compatibilité doit aussi respecter le fix
        assert is_version_affected("", ["< 9.3p2"]) is False
        assert is_version_affected("unknown", ["< 9.3p2"]) is False


# ─── check_version_affected() — bornes et plages ─────────────────────────────

class TestVersionRanges:

    @pytest.mark.parametrize("version,constraint,expected", [
        ("8.2p1", "< 9.3p2", True),
        ("9.3p2", "< 9.3p2", False),   # borne exclue
        ("9.4",   "< 9.3p2", False),
        ("5.3",   "< 5.3.12", True),   # version courte vs longue
        ("5.3.12", "< 5.3.12", False),
    ])
    def test_single_bound(self, version, constraint, expected):
        result = check_version_affected(version, "", [constraint])
        assert result.affected is expected

    def test_continuous_range_and_logic(self):
        # >= 2.0 ET < 3.0 → plage continue, logique AND
        assert check_version_affected("2.5", "", [">= 2.0", "< 3.0"]).affected is True
        assert check_version_affected("1.9", "", [">= 2.0", "< 3.0"]).affected is False
        assert check_version_affected("3.0", "", [">= 2.0", "< 3.0"]).affected is False

    def test_discrete_versions_or_logic(self):
        # Plusieurs "=" → OR discret, pas AND (bug historique corrigé)
        constraints = ["= 7.4", "= 8.0", "= 8.1"]
        assert check_version_affected("8.0", "", constraints).affected is True
        assert check_version_affected("9.0", "", constraints).affected is False

    def test_exact_match(self):
        assert check_version_affected("2.3.4", "", ["= 2.3.4"]).affected is True
        assert check_version_affected("2.3.5", "", ["= 2.3.4"]).affected is False

    def test_no_constraints_means_all_versions_affected(self):
        result = check_version_affected("1.0", "", [])
        assert result.affected is True
        assert result.confidence == Confidence.LIKELY


# ─── Cas réels issus de bannières Nmap ────────────────────────────────────────

class TestRealWorldBanners:

    def test_samba_debian_suffix(self):
        result = check_version_affected("3.0.20-Debian", "", [">= 3.0.0", "< 3.0.25"])
        assert result.affected is True
        assert result.confidence == Confidence.CERTAIN

    def test_mariadb_full_chain(self):
        result = check_version_affected("5.5.5-10.3.27-MariaDB", "", ["< 10.4.0"])
        assert result.affected is True

        result_out_of_range = check_version_affected("5.5.5-10.3.27-MariaDB", "", [">= 11.0"])
        assert result_out_of_range.affected is False

    def test_apache_win64_openssl_banner(self):
        result = check_version_affected("2.4.41 (Win64) OpenSSL/1.1.1c", "", ["= 2.4.41"])
        assert result.affected is True

    def test_openssh_version_in_banner_only(self):
        result = check_version_affected("", "OpenSSH 7.2p2 Ubuntu", ["< 7.8"])
        assert result.affected is True
        assert result.confidence == Confidence.CERTAIN


# ─── filter_cves_by_version() ────────────────────────────────────────────────

class TestFilterCvesByVersion:

    def test_excludes_not_affected_cves(self):
        cves = [
            {"id": "CVE-AFFECTED",     "affected_versions": ["< 9.3p2"]},
            {"id": "CVE-NOT-AFFECTED", "affected_versions": [">= 99.0"]},
        ]
        result = filter_cves_by_version(cves, "8.2p1", "OpenSSH 8.2p1")
        ids = [c["id"] for c in result]
        assert "CVE-AFFECTED" in ids
        assert "CVE-NOT-AFFECTED" not in ids

    def test_includes_uncertain_with_flag(self):
        cves = [{"id": "CVE-X", "affected_versions": ["< 9.0"]}]
        result = filter_cves_by_version(cves, "", "tcpwrapped")
        assert len(result) == 1
        assert result[0]["_unconfirmed"] is True
        assert result[0]["_confidence"] == "uncertain"

    def test_adds_confidence_metadata(self):
        cves = [{"id": "CVE-X", "affected_versions": ["< 9.3p2"]}]
        result = filter_cves_by_version(cves, "8.2p1", "")
        assert result[0]["_confidence"] == "certain"
        assert "_match_reason" in result[0]
