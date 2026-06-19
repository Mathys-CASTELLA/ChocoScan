"""
ChocoScan — Système de scoring contextuel des CVEs.

Le score CVSS seul ne suffit pas pour trier les vulnérabilités.
Une CVE CVSS 9.8 sans PoC vaut moins qu'une CVE CVSS 8.1 avec un module
Metasploit public et une exploitation active en 2025.

Score composite ChocoScan (0.0 → 10.0) :
  ┌─────────────────────────────────────┬──────────────┐
  │ Facteur                             │ Poids max    │
  ├─────────────────────────────────────┼──────────────┤
  │ CVSS base score                     │ 6.0 pts      │
  │ Qualité de l'exploit disponible     │ 2.0 pts      │
  │ Fraîcheur (année de publication)    │ 1.0 pts      │
  │ Type d'impact (RCE > LPE > info)    │ 0.7 pts      │
  │ Présence dans CISA KEV              │ 0.5 pts      │
  │ Auth requise (sans > avec)          │ 0.3 pts      │
  └─────────────────────────────────────┴──────────────┘
  Total max : 10.5 pts → normalisé sur 10.0

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from datetime import datetime

try:
    from modules.tag_definitions import TAGS as _TAGS, bonus as _tag_bonus
    _TAGS_AVAILABLE = True
except ImportError:
    _TAGS_AVAILABLE = False
    def _tag_bonus(tags): return 0.0

# ─────────────────────────────────────────────────────────────────────────────
# Liste CISA KEV (Known Exploited Vulnerabilities)
# Subset des CVEs les plus exploitées activement — mise à jour manuelle.
# Source : https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# ─────────────────────────────────────────────────────────────────────────────

CISA_KEV: set[str] = {
    # 2024-2026 (les plus récentes)
    "CVE-2024-3400", "CVE-2024-21762", "CVE-2024-55591", "CVE-2024-38094",
    "CVE-2024-38077", "CVE-2024-40711", "CVE-2024-6387",  "CVE-2024-4577",
    "CVE-2024-27198","CVE-2024-27199", "CVE-2024-23897",  "CVE-2024-1086",
    "CVE-2024-21893","CVE-2024-20767", "CVE-2024-0012",   "CVE-2024-9474",
    "CVE-2025-0282", "CVE-2025-0108",  "CVE-2025-22457",  "CVE-2025-22396",
    "CVE-2025-22397","CVE-2025-32433", "CVE-2025-24813",  "CVE-2025-53770",
    "CVE-2025-5777", "CVE-2025-20281", "CVE-2025-20282",  "CVE-2025-20333",
    "CVE-2025-47949","CVE-2025-53779", "CVE-2025-3248",   "CVE-2025-68645",
    "CVE-2026-21858","CVE-2026-20253", "CVE-2026-50751",  "CVE-2026-0257",
    "CVE-2025-29927","CVE-2025-15467", "CVE-2025-61882",  "CVE-2025-61884",
    # 2023
    "CVE-2023-46604","CVE-2023-22527", "CVE-2023-22518",  "CVE-2023-22515",
    "CVE-2023-34048","CVE-2023-20198", "CVE-2023-3519",   "CVE-2023-4966",
    "CVE-2023-23397","CVE-2023-38408", "CVE-2023-49103",  "CVE-2023-27350",
    "CVE-2023-27351","CVE-2023-42793", "CVE-2023-7028",   "CVE-2023-28432",
    # 2022
    "CVE-2022-22965","CVE-2022-41040", "CVE-2022-41082",  "CVE-2022-1388",
    "CVE-2022-26134","CVE-2022-30190", "CVE-2022-40684",  "CVE-2022-22947",
    "CVE-2022-42475","CVE-2022-0847",  "CVE-2022-24086",  "CVE-2022-23131",
    # 2021
    "CVE-2021-44228","CVE-2021-26855", "CVE-2021-34527",  "CVE-2021-4034",
    "CVE-2021-3156", "CVE-2021-22205", "CVE-2021-26084",  "CVE-2021-40444",
    "CVE-2021-44757","CVE-2021-21985", "CVE-2021-22986",  "CVE-2021-31166",
    # Anciens mais encore exploités
    "CVE-2020-1472", "CVE-2019-0708",  "CVE-2018-13379",  "CVE-2017-0144",
    "CVE-2017-0145", "CVE-2016-5195",  "CVE-2014-6271",   "CVE-2021-3560",
    "CVE-2020-5902", "CVE-2019-19781", "CVE-2020-0609",   "CVE-2020-0610",
}

# ─────────────────────────────────────────────────────────────────────────────
# Mots-clés pour l'analyse de l'impact
# ─────────────────────────────────────────────────────────────────────────────

IMPACT_KEYWORDS = {
    # Impact maximal
    "RCE":       ["remote code execution", "rce", "arbitrary code", "unauthenticated rce",
                  "code execution", "exécution de code", "execute arbitrary"],
    "CONTAINER_ESCAPE": ["container escape", "vm escape", "évasion de conteneur",
                         "évasion de vm", "escape to host"],
    # Accès non authentifié
    "UNAUTH_ACCESS": ["without authentication", "no authentication", "unauthenticated",
                      "no auth", "pre-auth", "sans authentification", "non authentifié",
                      "pré-authentification", "before authentication"],
    # Escalade de privilèges
    "LPE":       ["privilege escalation", "local privilege", "elevate", "become root",
                  "gain root", "escalade de privilèges", "→ root", "escalade vers root",
                  "local user.*root"],
    # Exfiltration
    "DATA_LEAK": ["arbitrary file read", "read arbitrary", "credential", "password leak",
                  "token leak", "credentials exposed", "information disclosure",
                  "lecture de fichier", "fuite.*credentials"],
}

# Mots-clés pour la non-authentification (bonus)
NO_AUTH_KEYWORDS = [
    "without authentication", "no authentication required", "unauthenticated",
    "no auth", "pre-auth", "pre-authentication", "before authentication",
    "anonymous", "sans authentification", "non authentifié", "sans credentials",
]

AUTH_REQUIRED_KEYWORDS = [
    "authenticated", "requires.*credentials", "admin.*required", "logged.*in",
    "with.*credentials", "valid.*credentials", "authentifié", "avec.*credentials",
]

# ─────────────────────────────────────────────────────────────────────────────
# Structure du score
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CVEScore:
    """Score composite pour une CVE."""
    cve_id:        str
    final_score:   float        # 0.0 → 10.0 normalisé
    letter_grade:  str          # A+ / A / B / C / D
    label:         str          # "CRITICAL+", "CRITICAL", "HIGH", ...

    # Détail des composantes
    cvss_component:     float   # 0.0 → 6.0
    exploit_component:  float   # 0.0 → 2.0
    recency_component:  float   # 0.0 → 1.0
    impact_component:   float   # 0.0 → 0.7
    kev_component:      float   # 0.0 → 0.5
    auth_component:     float   # 0.0 → 0.3
    tag_component:      float   # 0.0 → 1.5  (bonus tags APT/ransomware/…)

    # Flags explicatifs
    exploit_type:    str        # "metasploit", "exploit-db", "github", "none"
    in_cisa_kev:     bool
    year:            int
    impact_type:     str        # "RCE", "LPE", "UNAUTH_ACCESS", etc.
    auth_required:   bool | None

    @property
    def rank_key(self) -> tuple:
        """Clé de tri : score final décroissant, CVSS en tiebreak."""
        return (-self.final_score, -self.cvss_component, -self.tag_component)


# ─────────────────────────────────────────────────────────────────────────────
# Calcul du score
# ─────────────────────────────────────────────────────────────────────────────

CURRENT_YEAR = datetime.now().year


def score_cve(cve: dict) -> CVEScore:
    """
    Calcule le score composite ChocoScan d'une CVE.

    Args:
        cve : entrée CVE depuis cve_db.json

    Returns:
        CVEScore avec toutes les composantes détaillées
    """
    cve_id  = cve.get("id", "")
    refs    = cve.get("references", [])
    desc    = (cve.get("description", "") + " " + cve.get("description_fr", "")).lower()

    # ── 1. CVSS base (0.0 → 6.0) ─────────────────────────────────────────────
    try:
        cvss = float(str(cve.get("cvss", 0)).replace("N/A", "0") or 0)
    except (ValueError, TypeError):
        cvss = 0.0
    cvss_comp = round((cvss / 10.0) * 6.0, 3)

    # ── 2. Exploit disponible (0.0 → 2.0) ────────────────────────────────────
    has_msf = any("metasploit-framework" in r.lower() for r in refs)
    has_edb = any("exploit-db.com/exploits" in r.lower() for r in refs)
    has_gh  = any(
        "github.com" in r.lower() and "metasploit" not in r.lower()
        and "nvd.nist" not in r.lower()
        for r in refs
    )
    has_exploit = cve.get("exploit_available", False)

    if has_msf:
        exploit_comp  = 2.0
        exploit_type  = "metasploit"
    elif has_edb:
        exploit_comp  = 1.7
        exploit_type  = "exploit-db"
    elif has_gh or has_exploit:
        exploit_comp  = 1.3
        exploit_type  = "github"
    else:
        exploit_comp  = 0.0
        exploit_type  = "none"

    # ── 3. Fraîcheur (0.0 → 1.0) ─────────────────────────────────────────────
    year = 0
    m = re.match(r"CVE-(\d{4})-", cve_id, re.IGNORECASE)
    if m:
        year = int(m.group(1))

    if year >= CURRENT_YEAR:
        recency_comp = 1.0          # Année courante ou future (2026+)
    elif year >= CURRENT_YEAR - 1:
        recency_comp = 0.95         # Année dernière (2025)
    elif year >= CURRENT_YEAR - 2:
        recency_comp = 0.80         # 2024
    elif year >= CURRENT_YEAR - 3:
        recency_comp = 0.65         # 2023
    elif year >= CURRENT_YEAR - 5:
        recency_comp = 0.45         # 2021-2022
    elif year >= CURRENT_YEAR - 8:
        recency_comp = 0.25         # 2018-2020
    elif year > 0:
        recency_comp = 0.10         # Avant 2018
    else:
        recency_comp = 0.30         # Année inconnue — neutre

    # ── 4. Type d'impact (0.0 → 0.7) ─────────────────────────────────────────
    impact_type = "OTHER"
    impact_comp = 0.0

    for itype, keywords in IMPACT_KEYWORDS.items():
        if any(re.search(kw, desc) for kw in keywords):
            impact_type = itype
            break

    impact_scores = {
        "RCE":              0.70,
        "CONTAINER_ESCAPE": 0.65,
        "UNAUTH_ACCESS":    0.55,
        "LPE":              0.50,
        "DATA_LEAK":        0.30,
        "OTHER":            0.10,
    }
    impact_comp = impact_scores.get(impact_type, 0.10)

    # ── 5. CISA KEV (0.0 → 0.5) ──────────────────────────────────────────────
    in_kev    = cve_id.upper() in CISA_KEV
    kev_comp  = 0.5 if in_kev else 0.0

    # ── 6. Authentification requise (0.0 → 0.3) ──────────────────────────────
    auth_required = None
    if any(kw in desc for kw in NO_AUTH_KEYWORDS):
        auth_required = False
        auth_comp     = 0.3
    elif any(re.search(kw, desc) for kw in AUTH_REQUIRED_KEYWORDS):
        auth_required = True
        auth_comp     = 0.0
    else:
        auth_comp     = 0.15        # Inconnu — neutre

    # ── 7. Bonus tags (0.0 → 1.5) ───────────────────────────────────────────
    tags       = cve.get("tags", [])
    tag_comp   = round(min(_tag_bonus(tags), 1.5), 3) if _TAGS_AVAILABLE else 0.0

    # ── Score final ───────────────────────────────────────────────────────────────
    raw = cvss_comp + exploit_comp + recency_comp + impact_comp + kev_comp + auth_comp + tag_comp
    # Normaliser sur 10.0 (max théorique = 12.0 avec bonus tags max)
    final = round(min(raw / 12.0 * 10.0, 10.0), 2)

    # ── Grade et label ────────────────────────────────────────────────────────
    if final >= 9.5:
        grade, label = "A+", "CRITICAL+"
    elif final >= 8.5:
        grade, label = "A",  "CRITICAL"
    elif final >= 7.0:
        grade, label = "B",  "HIGH+"
    elif final >= 5.5:
        grade, label = "C",  "HIGH"
    elif final >= 3.5:
        grade, label = "D",  "MEDIUM"
    else:
        grade, label = "F",  "LOW"

    return CVEScore(
        cve_id          = cve_id,
        final_score     = final,
        letter_grade    = grade,
        label           = label,
        cvss_component  = round(cvss_comp,  3),
        exploit_component= round(exploit_comp, 3),
        recency_component= round(recency_comp, 3),
        impact_component = round(impact_comp,  3),
        kev_component   = round(kev_comp,   3),
        auth_component  = round(auth_comp,  3),
        tag_component   = round(tag_comp,   3),
        exploit_type    = exploit_type,
        in_cisa_kev     = in_kev,
        year            = year,
        impact_type     = impact_type,
        auth_required   = auth_required,
    )


def score_and_sort(cves: list[dict]) -> list[tuple[dict, CVEScore]]:
    """
    Score et trie une liste de CVEs par score contextuel décroissant.

    Returns:
        Liste de (cve_dict, CVEScore) triée par score décroissant
    """
    scored = [(cve, score_cve(cve)) for cve in cves]
    scored.sort(key=lambda x: x[1].rank_key)
    return scored


def inject_scores(cves: list[dict]) -> list[dict]:
    """
    Enrichit chaque CVE avec son score contextuel et retourne la liste
    triée par score décroissant.
    Compatible avec le format de données ChocoScan existant.
    """
    scored = score_and_sort(cves)
    result = []
    for cve, sc in scored:
        enriched = dict(cve)
        enriched["ctx_score"]       = sc.final_score
        enriched["ctx_grade"]       = sc.letter_grade
        enriched["ctx_label"]       = sc.label
        enriched["ctx_exploit_type"]= sc.exploit_type
        enriched["ctx_in_kev"]      = sc.in_cisa_kev
        enriched["ctx_impact"]      = sc.impact_type
        enriched["ctx_no_auth"]     = sc.auth_required is False
        enriched["ctx_tags"]         = cve.get("tags", [])
        enriched["ctx_tag_bonus"]    = sc.tag_component
        enriched["ctx_breakdown"]   = {
            "cvss":    sc.cvss_component,
            "exploit": sc.exploit_component,
            "recency": sc.recency_component,
            "impact":  sc.impact_component,
            "kev":     sc.kev_component,
            "tags":    sc.tag_component,
            "auth":    sc.auth_component,
        }
        result.append(enriched)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Affichage terminal
# ─────────────────────────────────────────────────────────────────────────────

# Icônes par type d'exploit
EXPLOIT_ICONS = {
    "metasploit": "🟦 MSF",
    "exploit-db": "🟧 EDB",
    "github":     "⬛ GH ",
    "none":       "     ",
}

# Couleurs des grades
GRADE_COLORS = {
    "A+": "bold red",
    "A":  "red",
    "B":  "bold yellow",
    "C":  "yellow",
    "D":  "dim yellow",
    "F":  "dim",
}

LABEL_COLORS = {
    "CRITICAL+": "bold red",
    "CRITICAL":  "red",
    "HIGH+":     "bold yellow",
    "HIGH":      "yellow",
    "MEDIUM":    "dim yellow",
    "LOW":       "dim",
}


def format_score_bar(score: float, width: int = 12) -> str:
    """Génère une mini barre de progression ASCII pour le score."""
    filled = int((score / 10.0) * width)
    bar    = "█" * filled + "░" * (width - filled)
    return bar


def format_score_inline(sc: CVEScore) -> str:
    """Retourne une représentation compacte du score pour le terminal."""
    kev_flag = " [bold magenta]KEV[/bold magenta]" if sc.in_cisa_kev else ""
    exp_flag = f" [green]{EXPLOIT_ICONS.get(sc.exploit_type, '')}[/green]" if sc.exploit_type != "none" else ""
    no_auth  = " [cyan]no-auth[/cyan]" if sc.auth_required is False else ""
    return f"{sc.final_score:.1f} [{sc.letter_grade}]{kev_flag}{exp_flag}{no_auth}"


# ─────────────────────────────────────────────────────────────────────────────
# Export HTML — composante score pour le rapport
# ─────────────────────────────────────────────────────────────────────────────

def score_to_html_badge(cve: dict) -> str:
    """Génère le badge HTML du score contextuel pour une CVE dans le rapport."""
    ctx_score = cve.get("ctx_score")
    if ctx_score is None:
        return ""

    grade     = cve.get("ctx_grade", "?")
    label     = cve.get("ctx_label", "")
    in_kev    = cve.get("ctx_in_kev", False)
    exp_type  = cve.get("ctx_exploit_type", "none")
    no_auth   = cve.get("ctx_no_auth", False)
    impact    = cve.get("ctx_impact", "")
    breakdown = cve.get("ctx_breakdown", {})

    grade_colors = {
        "A+": "#ef4444", "A": "#f97316", "B": "#eab308",
        "C": "#84cc16", "D": "#6b7280", "F": "#4b5563",
    }
    color = grade_colors.get(grade, "#6b7280")

    # Barre de progression HTML
    pct = int(ctx_score / 10.0 * 100)

    # Flags
    flags = []
    if in_kev:
        flags.append('<span class="ctx-flag kev">🔴 CISA KEV</span>')
    if exp_type == "metasploit":
        flags.append('<span class="ctx-flag msf">🟦 Metasploit</span>')
    elif exp_type == "exploit-db":
        flags.append('<span class="ctx-flag edb">🟧 Exploit-DB</span>')
    elif exp_type == "github":
        flags.append('<span class="ctx-flag gh">⬛ PoC GitHub</span>')
    if no_auth:
        flags.append('<span class="ctx-flag noauth">🔓 No-Auth</span>')
    if impact in ("RCE", "CONTAINER_ESCAPE"):
        flags.append(f'<span class="ctx-flag rce">💥 {impact}</span>')
    elif impact == "LPE":
        flags.append('<span class="ctx-flag lpe">⬆ LPE</span>')

    # Tooltip avec détail
    bk = breakdown
    tooltip = (
        f"CVSS: {bk.get('cvss',0):.2f}/6.0 | "
        f"Exploit: {bk.get('exploit',0):.2f}/2.0 | "
        f"Fraîcheur: {bk.get('recency',0):.2f}/1.0 | "
        f"Impact: {bk.get('impact',0):.2f}/0.7 | "
        f"KEV: {bk.get('kev',0):.2f}/0.5 | "
        f"Auth: {bk.get('auth',0):.2f}/0.3"
    )

    flags_html = " ".join(flags)

    return f"""<div class="ctx-score-block" title="{tooltip}">
  <div class="ctx-score-header">
    <span class="ctx-grade" style="color:{color}">{grade}</span>
    <span class="ctx-score-val" style="color:{color}">{ctx_score:.1f}</span>
    <span class="ctx-label" style="color:{color}">{label}</span>
  </div>
  <div class="ctx-bar-wrap">
    <div class="ctx-bar" style="width:{pct}%;background:{color}88"></div>
  </div>
  <div class="ctx-flags">{flags_html}</div>
</div>"""


CTX_CSS = """
  /* ── Scoring contextuel ────────────────────────────── */
  .ctx-score-block {
    background: #0a0d1a;
    border: 1px solid #1c2240;
    border-radius: 5px;
    padding: .4rem .6rem;
    min-width: 130px;
    cursor: help;
  }
  .ctx-score-header {
    display: flex; align-items: baseline;
    gap: .3rem; margin-bottom: .25rem;
  }
  .ctx-grade {
    font-size: .85rem; font-weight: 900;
    font-family: monospace;
  }
  .ctx-score-val {
    font-size: 1rem; font-weight: 800;
    font-family: 'Courier New', monospace;
  }
  .ctx-label {
    font-size: .65rem; font-weight: 700;
    letter-spacing: .04em;
  }
  .ctx-bar-wrap {
    background: #1e243a; border-radius: 2px;
    height: 3px; margin-bottom: .3rem; overflow: hidden;
  }
  .ctx-bar {
    height: 100%; border-radius: 2px;
    transition: width .3s ease;
  }
  .ctx-flags {
    display: flex; flex-wrap: wrap; gap: .2rem;
  }
  .ctx-flag {
    font-size: .62rem; font-weight: 600;
    padding: .05rem .3rem; border-radius: 3px;
    white-space: nowrap;
  }
  .ctx-flag.kev    { background: rgba(239,68,68,.15);  color: #ef4444; border: 1px solid #ef444433; }
  .ctx-flag.msf    { background: rgba(59,130,246,.15); color: #60a5fa; border: 1px solid #60a5fa33; }
  .ctx-flag.edb    { background: rgba(249,115,22,.15); color: #fb923c; border: 1px solid #fb923c33; }
  .ctx-flag.gh     { background: rgba(156,163,175,.1); color: #9ca3af; border: 1px solid #9ca3af22; }
  .ctx-flag.noauth { background: rgba(34,211,238,.1);  color: #22d3ee; border: 1px solid #22d3ee33; }
  .ctx-flag.rce    { background: rgba(239,68,68,.1);   color: #fca5a5; border: 1px solid #ef444422; }
  .ctx-flag.lpe    { background: rgba(234,179,8,.1);   color: #fde047; border: 1px solid #eab30822; }
"""
