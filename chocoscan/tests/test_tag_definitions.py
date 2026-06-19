"""
Tests unitaires — modules/tag_definitions.py

Couvre la taxonomie de tags threat intel :
  - intégrité du catalogue TAGS
  - calcul des bonus de score
  - génération de badges HTML
"""

import pytest
from modules.tag_definitions import TAGS, ALL_TAG_NAMES, get, bonus, html_badges


class TestTagCatalogIntegrity:

    def test_all_tags_have_required_fields(self):
        for name, td in TAGS.items():
            assert td.name == name, f"incohérence nom pour '{name}'"
            assert td.label, f"label manquant pour '{name}'"
            assert td.description, f"description manquante pour '{name}'"
            assert td.icon, f"icône manquante pour '{name}'"
            assert td.color_html.startswith("#"), f"couleur HTML invalide pour '{name}'"
            assert 0.0 <= td.score_bonus <= 1.5, f"bonus hors limites pour '{name}'"
            assert td.group in ("threat", "tech", "surface", "exploit"), \
                f"groupe inconnu '{td.group}' pour '{name}'"

    def test_no_duplicate_tag_names(self):
        names = list(TAGS.keys())
        assert len(names) == len(set(names))

    def test_all_tag_names_matches_catalog_keys(self):
        assert ALL_TAG_NAMES == set(TAGS.keys())

    def test_threat_tags_have_highest_bonuses(self):
        # Les tags de menace (APT, ransomware) doivent peser plus que le contexte technique
        apt_bonus = TAGS["apt"].score_bonus
        web_bonus = TAGS["web"].score_bonus
        assert apt_bonus > web_bonus


class TestGet:

    def test_get_with_hash_prefix(self):
        td = get("#apt")
        assert td is not None
        assert td.name == "apt"

    def test_get_without_hash_prefix(self):
        td = get("apt")
        assert td is not None
        assert td.name == "apt"

    def test_get_unknown_tag_returns_none(self):
        assert get("not-a-real-tag") is None


class TestBonus:

    def test_single_tag_bonus(self):
        assert bonus(["apt"]) == TAGS["apt"].score_bonus

    def test_multiple_tags_sum(self):
        result = bonus(["apt", "ransomware"])
        expected = TAGS["apt"].score_bonus + TAGS["ransomware"].score_bonus
        assert result == pytest.approx(expected)

    def test_empty_list_returns_zero(self):
        assert bonus([]) == 0.0

    def test_unknown_tag_contributes_zero(self):
        assert bonus(["not-a-real-tag"]) == 0.0

    def test_tags_with_hash_prefix_work(self):
        assert bonus(["#apt"]) == bonus(["apt"])

    def test_tech_tags_contribute_zero_or_low_bonus(self):
        # Les tags purement techniques (#web, #windows...) ne doivent pas
        # gonfler artificiellement le score comme les tags de menace
        assert bonus(["web"]) < bonus(["apt"])


class TestHtmlBadges:

    def test_generates_badge_for_known_tag(self):
        html = html_badges(["apt"])
        assert "#apt" in html
        assert "cve-tag" in html

    def test_empty_list_returns_empty_string(self):
        assert html_badges([]) == ""

    def test_unknown_tag_silently_skipped(self):
        html = html_badges(["not-a-real-tag"])
        assert html == ""

    def test_multiple_tags_all_present(self):
        html = html_badges(["apt", "ransomware", "no-auth"])
        assert "#apt" in html
        assert "#ransomware" in html
        assert "#no-auth" in html

    def test_badge_includes_tag_color(self):
        html = html_badges(["apt"])
        assert TAGS["apt"].color_html in html
