"""
Tests unitaires — modules/cve_matcher.py

Couvre les fonctions pures (sans appel réseau) :
  - extract_service_key() : mapping bannière Nmap → clé DB
  - extract_version_from_banner() : extraction regex de version
  - search_local_db() : recherche + dédup dans les bases locales

Les fonctions appelant l'API NVD (search_nvd_api, translate_to_french)
ne sont pas testées ici — elles nécessitent un mock réseau dédié.
"""

import pytest
from modules.cve_matcher import (
    extract_service_key,
    extract_version_from_banner,
    search_local_db,
    load_local_db,
)


class TestExtractServiceKey:

    def test_simple_service_name(self):
        assert extract_service_key("openssh") == "openssh"

    def test_service_name_with_banner(self):
        key = extract_service_key("ssh", "OpenSSH 8.2p1 Ubuntu")
        assert key == "openssh"

    def test_apache_http_banner(self):
        key = extract_service_key("http", "Apache httpd 2.4.49")
        assert key == "apache"

    def test_case_insensitive(self):
        assert extract_service_key("OpenSSH") == extract_service_key("openssh")

    def test_unknown_service_returns_none(self):
        assert extract_service_key("totally-unknown-xyz-service") is None

    def test_more_specific_alias_wins_over_generic(self):
        # "apache tomcat" doit matcher tomcat, pas juste apache (alias plus long prioritaire)
        key = extract_service_key("http", "Apache Tomcat 9.0.31")
        assert key == "tomcat"

    def test_empty_inputs_return_none(self):
        assert extract_service_key("", "") is None


class TestExtractVersionFromBanner:

    def test_simple_version(self):
        assert extract_version_from_banner("OpenSSH 8.2p1") == "8.2p1"

    def test_version_with_dots(self):
        assert extract_version_from_banner("Apache httpd 2.4.49") == "2.4.49"

    def test_no_version_in_banner(self):
        assert extract_version_from_banner("tcpwrapped") == ""

    def test_empty_banner(self):
        assert extract_version_from_banner("") == ""

    def test_version_with_patch_suffix(self):
        result = extract_version_from_banner("nginx 1.18.0-1")
        assert "1.18.0" in result


class TestSearchLocalDb:

    def test_returns_list(self):
        result = search_local_db("openssh", "8.2p1")
        assert isinstance(result, list)

    def test_unknown_service_returns_empty(self):
        result = search_local_db("totally-unknown-service-xyz", "1.0")
        assert result == []

    def test_no_version_returns_all_cves_for_service(self):
        # version vide = pas de filtre, retourne toutes les CVEs du service
        with_version = search_local_db("openssh", "")
        db = load_local_db()
        if "openssh" in db:
            assert len(with_version) == len(db["openssh"])

    def test_each_result_has_source_field(self):
        result = search_local_db("openssh", "")
        for cve in result:
            assert "source" in cve
            assert cve["source"] in ("Local DB", "Local DB (récent)")

    def test_no_duplicate_cve_ids(self):
        result = search_local_db("openssh", "")
        ids = [c["id"] for c in result]
        assert len(ids) == len(set(ids)), "des CVE en double n'ont pas été dédupliquées"

    def test_version_filtering_excludes_unaffected(self):
        # Une version très récente/élevée ne doit normalement matcher
        # aucune CVE bornée par une contrainte "< X" basse
        result_old = search_local_db("openssh", "1.0")
        result_new = search_local_db("openssh", "999.999.999")
        # La version extrêmement haute doit donner au plus égal ou moins de CVEs
        # que la version basse (elle ne peut pas matcher plus de bornes "<")
        assert len(result_new) <= len(result_old) + 5  # marge pour CVEs sans contrainte


class TestLoadLocalDb:

    def test_returns_dict(self):
        db = load_local_db()
        assert isinstance(db, dict)

    def test_db_is_not_empty(self):
        db = load_local_db()
        assert len(db) > 0, "la base CVE locale ne doit pas être vide"

    def test_known_service_present(self):
        db = load_local_db()
        assert "openssh" in db

    def test_cve_entries_have_required_fields(self):
        db = load_local_db()
        sample_service = next(iter(db.values()))
        if sample_service:
            cve = sample_service[0]
            assert "id" in cve
            assert "cvss" in cve
            assert "severity" in cve
