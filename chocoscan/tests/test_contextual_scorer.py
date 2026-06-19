"""
Tests unitaires — modules/contextual_scorer.py

Couvre le score composite contextuel :
  - score_cve() retourne des valeurs dans les bornes attendues
  - le bonus de tags fait une vraie différence (#apt, #ransomware...)
  - inject_scores() enrichit correctement une liste de CVEs
  - tri par score décroissant
"""

import pytest
from modules.contextual_scorer import score_cve, score_and_sort, inject_scores, CVEScore


def _make_cve(**overrides):
    """Construit une CVE minimale avec des valeurs par défaut raisonnables."""
    base = {
        "id": "CVE-2024-00000",
        "cvss": 7.0,
        "severity": "HIGH",
        "description": "A generic vulnerability description",
        "description_fr": "Une description générique de vulnérabilité",
        "exploit_available": False,
        "references": [],
        "tags": [],
        "affected_versions": ["< 1.0"],
    }
    base.update(overrides)
    return base


class TestScoreCveBounds:

    def test_score_is_within_0_to_10(self):
        cve = _make_cve(cvss=10.0, exploit_available=True,
                         tags=["apt", "ransomware", "supply-chain"])
        sc = score_cve(cve)
        assert 0.0 <= sc.final_score <= 10.0

    def test_low_cvss_no_exploit_gives_low_score(self):
        cve = _make_cve(cvss=2.0, severity="LOW", exploit_available=False)
        sc = score_cve(cve)
        assert sc.final_score < 5.0

    def test_letter_grade_is_assigned(self):
        cve = _make_cve(cvss=9.8, exploit_available=True)
        sc = score_cve(cve)
        assert sc.letter_grade in ("A+", "A", "B", "C", "D")

    def test_returns_cvescore_dataclass(self):
        sc = score_cve(_make_cve())
        assert isinstance(sc, CVEScore)
        assert sc.cve_id == "CVE-2024-00000"


class TestTagBonusImpact:

    def test_apt_tag_increases_score_over_baseline(self):
        baseline = _make_cve(cvss=8.0, tags=[])
        tagged   = _make_cve(cvss=8.0, tags=["apt"])

        sc_base = score_cve(baseline)
        sc_tag  = score_cve(tagged)

        assert sc_tag.final_score > sc_base.final_score
        assert sc_tag.tag_component > sc_base.tag_component

    def test_combined_threat_tags_outweigh_same_cvss_without_tags(self):
        # Une CVE moins "haute" sur le papier mais avec contexte de menace réel
        # doit pouvoir dépasser une CVE techniquement équivalente sans contexte.
        plain = _make_cve(cvss=9.0, exploit_available=False, tags=[])
        threat = _make_cve(cvss=9.0, exploit_available=True,
                            tags=["apt", "ransomware", "initial-access"])

        sc_plain  = score_cve(plain)
        sc_threat = score_cve(threat)

        assert sc_threat.final_score > sc_plain.final_score

    def test_tag_component_caps_at_1_5(self):
        # Même avec énormément de tags à bonus, le composant est plafonné
        cve = _make_cve(tags=["apt", "ransomware", "supply-chain",
                               "initial-access", "lateral", "container"])
        sc = score_cve(cve)
        assert sc.tag_component <= 1.5

    def test_no_tags_gives_zero_tag_component(self):
        sc = score_cve(_make_cve(tags=[]))
        assert sc.tag_component == 0.0

    def test_unknown_tags_contribute_nothing(self):
        sc = score_cve(_make_cve(tags=["not-a-real-tag"]))
        assert sc.tag_component == 0.0


class TestScoreAndSort:

    def test_sorts_by_score_descending(self):
        cves = [
            _make_cve(id="CVE-LOW",  cvss=3.0, tags=[]),
            _make_cve(id="CVE-HIGH", cvss=9.8, exploit_available=True, tags=["apt"]),
            _make_cve(id="CVE-MID",  cvss=6.0, tags=[]),
        ]
        ranked = score_and_sort(cves)
        scores = [sc.final_score for _, sc in ranked]
        assert scores == sorted(scores, reverse=True)
        assert ranked[0][0]["id"] == "CVE-HIGH"


class TestInjectScores:

    def test_adds_ctx_score_field(self):
        cves = [_make_cve()]
        result = inject_scores(cves)
        assert "ctx_score" in result[0]
        assert isinstance(result[0]["ctx_score"], float)

    def test_adds_ctx_tags_and_bonus_fields(self):
        cves = [_make_cve(tags=["apt", "ransomware"])]
        result = inject_scores(cves)
        assert result[0]["ctx_tags"] == ["apt", "ransomware"]
        assert result[0]["ctx_tag_bonus"] > 0

    def test_preserves_original_cve_fields(self):
        cves = [_make_cve(id="CVE-2024-99999")]
        result = inject_scores(cves)
        assert result[0]["id"] == "CVE-2024-99999"
        assert result[0]["cvss"] == 7.0

    def test_does_not_mutate_input_list_objects_unexpectedly(self):
        # inject_scores ne doit pas planter sur une liste vide
        assert inject_scores([]) == []

    def test_handles_multiple_cves(self):
        cves = [_make_cve(id=f"CVE-{i}") for i in range(5)]
        result = inject_scores(cves)
        assert len(result) == 5
        assert all("ctx_score" in c for c in result)
