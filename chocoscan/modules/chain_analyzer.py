"""
ChocoScan — Analyseur de CVEs chaînables.

Détecte automatiquement les chemins d'attaque en deux étapes :
  - Accès initial  : AUTH_BYPASS, RCE, SQLI, PATH_TRAVERSAL, XXE, SSRF, DESERIALIZATION
  - Post-exploitation : LPE, RCE (depuis service interne), AUTH_BYPASS sur service adjacent

Deux types de chaînes détectés :
  1. Intra-service  : même service possède une CVE d'accès ET une CVE de privesc
  2. Inter-services : RCE sur service A → LPE via service B (ex: Apache RCE + sudo LPE)

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.rule import Rule
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None


# ─────────────────────────────────────────────────────────────────────────────
# Classification des CVEs par type d'impact
# ─────────────────────────────────────────────────────────────────────────────

CVE_TYPE_RULES: list[tuple[str, list[str]]] = [
    # Accès initial (haut impact offensif)
    ("RCE",             ["remote code execution", "rce", "arbitrary code execution",
                         "unauthenticated rce", "pre-auth rce", "code execution",
                         "exécution de code", "rce non authentifié", "exécution de code arbitraire"]),
    ("AUTH_BYPASS",     ["authentication bypass", "auth bypass", "no authentication",
                         "unauthenticated", "without authentication", "no auth required",
                         "bypass d'authentification", "sans authentification",
                         "bypass.*auth", "authentication.*bypass"]),
    ("DESERIALIZATION", ["deserialization", "unsafe deserialization", "java deserialization",
                         "deserialisation", "désérialisation", "php object injection",
                         "pickle deserialization"]),
    ("SQLI",            ["sql injection", "sqli", "sql-injection",
                         "injection sql", "sql injection"]),
    ("PATH_TRAVERSAL",  ["path traversal", "directory traversal", "arbitrary file read",
                         "file read", "local file inclusion", "lfi",
                         "traversal", "traversée de chemin", "traversée de répertoire",
                         "lecture de fichier arbitraire"]),
    ("SSRF",            ["server-side request forgery", "ssrf", "server side request",
                         "internal network access", "accès réseau interne"]),
    ("XXE",             ["xml external entity", "xxe", "xml entity injection",
                         "injection xxe"]),
    ("SSTI",            ["template injection", "ssti", "server-side template",
                         "injection de template"]),
    # Post-exploitation
    ("LPE",             ["privilege escalation", "local privilege escalation", "lpe",
                         "escalade de privilèges", "escalade vers root",
                         "local user.*root", "become root", "gain root",
                         "obtenir root", "accès root", "→ root", "elevation of privilege",
                         "élévation de privilèges", "escalade locale"]),
    ("CONTAINER_ESCAPE",["container escape", "docker escape", "vm escape",
                         "évasion de conteneur", "évasion de vm"]),
    ("CRED_LEAK",       ["credential", "password", "credentials", "token",
                         "secret", "api key", "credentials leak", "password leak",
                         "fuite.*credentials", "credentials.*exposé"]),
    # Impact secondaire
    ("DOS",             ["denial of service", "dos", "déni de service", "crash"]),
]


def classify_cve(cve: dict) -> set[str]:
    """Retourne l'ensemble des types d'impact d'une CVE."""
    desc = (
        cve.get("description", "") + " " + cve.get("description_fr", "")
    ).lower()
    types = set()
    for ctype, keywords in CVE_TYPE_RULES:
        for kw in keywords:
            if re.search(kw, desc):
                types.add(ctype)
                break
    return types if types else {"OTHER"}


# ─────────────────────────────────────────────────────────────────────────────
# Règles de chaînage
# ─────────────────────────────────────────────────────────────────────────────

# (type_step1, type_step2) -> description du chaînage
CHAIN_RULES: list[tuple[frozenset[str], frozenset[str], str, str]] = [
    # step1_types, step2_types, label, description
    (
        frozenset({"RCE", "AUTH_BYPASS", "DESERIALIZATION", "SSTI"}),
        frozenset({"LPE"}),
        "RCE → LPE",
        "Accès initial via RCE/bypass, puis escalade de privilèges vers root/SYSTEM"
    ),
    (
        frozenset({"AUTH_BYPASS"}),
        frozenset({"RCE"}),
        "Auth Bypass → RCE",
        "Bypass d'authentification ouvre l'accès à une fonctionnalité permettant l'exécution de code"
    ),
    (
        frozenset({"SQLI"}),
        frozenset({"RCE"}),
        "SQLi → RCE",
        "Injection SQL exploitée pour écrire un fichier exécutable ou lire des credentials donnant un accès"
    ),
    (
        frozenset({"SQLI"}),
        frozenset({"AUTH_BYPASS"}),
        "SQLi → Auth Bypass",
        "Injection SQL dans la logique d'authentification permettant un accès non autorisé"
    ),
    (
        frozenset({"PATH_TRAVERSAL"}),
        frozenset({"RCE", "LPE"}),
        "File Read → RCE/LPE",
        "Lecture de fichiers sensibles (config, clés SSH, secrets) menant à une exécution de code"
    ),
    (
        frozenset({"SSRF"}),
        frozenset({"RCE", "AUTH_BYPASS", "CRED_LEAK"}),
        "SSRF → Accès interne",
        "SSRF permet d'atteindre des services internes non exposés (métadonnées cloud, APIs internes)"
    ),
    (
        frozenset({"XXE"}),
        frozenset({"SSRF", "PATH_TRAVERSAL", "CRED_LEAK"}),
        "XXE → Lecture/SSRF",
        "Injection XXE lisant des fichiers locaux ou provoquant des requêtes vers des services internes"
    ),
    (
        frozenset({"DESERIALIZATION"}),
        frozenset({"RCE", "LPE"}),
        "Désérialisation → RCE",
        "Désérialisation non sécurisée d'objet permettant l'exécution de code arbitraire"
    ),
    (
        frozenset({"CRED_LEAK"}),
        frozenset({"RCE", "AUTH_BYPASS", "LPE"}),
        "Credential Leak → Accès",
        "Fuite de credentials (tokens, mots de passe, clés API) donnant accès à d'autres services"
    ),
    (
        frozenset({"RCE"}),
        frozenset({"CONTAINER_ESCAPE"}),
        "RCE → Container Escape",
        "Exécution de code dans un conteneur puis évasion vers l'hôte"
    ),
    (
        frozenset({"AUTH_BYPASS"}),
        frozenset({"LPE"}),
        "Auth Bypass → LPE",
        "Accès non authentifié suivi d'une escalade de privilèges locale"
    ),
    (
        frozenset({"SSTI"}),
        frozenset({"RCE", "LPE"}),
        "SSTI → RCE",
        "Injection de template permettant l'exécution de code arbitraire côté serveur"
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Structures de données
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ChainStep:
    cve_id:   str
    cvss:     float
    severity: str
    types:    set[str]
    service:  str
    port:     int
    desc:     str
    exploit:  bool


@dataclass
class AttackChain:
    label:       str
    description: str
    step1:       ChainStep
    step2:       ChainStep
    is_cross:    bool    # True = inter-services, False = intra-service
    chain_score: float = field(init=False)

    def __post_init__(self):
        # Score composite : max des deux CVEs + bonus si exploit dispo + bonus si cross
        self.chain_score = round(
            max(self.step1.cvss, self.step2.cvss)
            + (0.3 if self.step1.exploit or self.step2.exploit else 0)
            + (0.2 if self.is_cross else 0),
            2
        )

    @property
    def severity_label(self) -> str:
        s = self.chain_score
        if s >= 10.0: return "CRITICAL"
        if s >= 9.0:  return "CRITICAL"
        if s >= 7.0:  return "HIGH"
        if s >= 4.0:  return "MEDIUM"
        return "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Détection des chaînes
# ─────────────────────────────────────────────────────────────────────────────

def detect_chains(results: list[dict]) -> list[AttackChain]:
    """
    Analyse les résultats de scan et retourne les chaînes d'attaque détectées.

    Args:
        results : liste de dicts {service: {...}, cves: [...]} issus du scan

    Returns:
        Liste de AttackChain triée par chain_score décroissant
    """
    chains: list[AttackChain] = []
    seen: set[tuple[str, str]] = set()  # éviter les doublons

    # ── Pré-calculer les types pour chaque CVE ────────────────────────────────
    enriched: list[tuple[dict, dict, ChainStep]] = []
    for result in results:
        svc   = result["service"]
        for cve in result.get("cves", []):
            types = classify_cve(cve)
            step  = ChainStep(
                cve_id   = cve.get("id", ""),
                cvss     = float(str(cve.get("cvss", 0)).replace("N/A", "0") or 0),
                severity = str(cve.get("severity", "UNKNOWN")).upper(),
                types    = types,
                service  = svc.get("service_name", ""),
                port     = svc.get("port", 0),
                desc     = (cve.get("description") or "")[:150],
                exploit  = bool(cve.get("exploit_available") or cve.get("exploits")),
            )
            enriched.append((result, cve, step))

    # ── Intra-service : même service, deux CVEs complémentaires ──────────────
    by_service: dict[str, list[ChainStep]] = {}
    for result, cve, step in enriched:
        key = f"{step.service}:{step.port}"
        by_service.setdefault(key, []).append(step)

    for svc_key, steps in by_service.items():
        for i, s1 in enumerate(steps):
            for s2 in steps[i+1:]:
                if s1.cve_id == s2.cve_id:
                    continue
                chain = _try_chain(s1, s2, is_cross=False)
                if chain:
                    uid = tuple(sorted([s1.cve_id, s2.cve_id]))
                    if uid not in seen:
                        seen.add(uid)
                        chains.append(chain)

    # ── Inter-services : RCE/accès sur A → LPE/privesc sur B ─────────────────
    # Services LPE typiques (sudo, polkit, kernel, SUID)
    lpe_services = {
        "sudo", "polkit", "dirtycow", "screen", "docker",
        "kubernetes", "windows", "smb", "samba",
    }
    # Services d'accès initial typiques
    access_services = {
        "apache", "nginx", "iis", "tomcat", "php", "wordpress",
        "drupal", "joomla", "spring", "nodejs", "laravel", "django",
        "smtp", "ftp", "vsftpd", "proftpd", "openssh", "rdp",
        "mysql", "postgresql", "redis", "mongodb", "elasticsearch",
        "jenkins", "gitlab", "confluence", "jira", "teamcity",
        "weblogic", "jboss", "coldfusion",
    }

    # Toutes les CVEs d'accès initial (RCE, auth bypass, etc.)
    access_steps = [
        s for _, _, s in enriched
        if s.types & {"RCE", "AUTH_BYPASS", "DESERIALIZATION", "SQLI", "SSTI"}
        and s.service in access_services
    ]
    # Toutes les CVEs LPE
    lpe_steps = [
        s for _, _, s in enriched
        if "LPE" in s.types or "CONTAINER_ESCAPE" in s.types
    ]

    for s1 in access_steps:
        for s2 in lpe_steps:
            if s1.cve_id == s2.cve_id:
                continue
            if s1.port == s2.port and s1.service == s2.service:
                continue  # déjà traité en intra
            chain = _try_chain(s1, s2, is_cross=True)
            if chain:
                uid = tuple(sorted([s1.cve_id, s2.cve_id]))
                if uid not in seen:
                    seen.add(uid)
                    chains.append(chain)

    # ── SSRF → services internes ──────────────────────────────────────────────
    ssrf_steps = [s for _, _, s in enriched if "SSRF" in s.types]
    internal_steps = [
        s for _, _, s in enriched
        if s.types & {"RCE", "AUTH_BYPASS", "CRED_LEAK"}
        and s.service not in access_services
    ]
    for s1 in ssrf_steps:
        for s2 in internal_steps:
            if s1.cve_id == s2.cve_id:
                continue
            chain = _try_chain(s1, s2, is_cross=True)
            if chain:
                uid = tuple(sorted([s1.cve_id, s2.cve_id]))
                if uid not in seen:
                    seen.add(uid)
                    chains.append(chain)

    # Trier par chain_score décroissant
    chains.sort(key=lambda c: c.chain_score, reverse=True)
    return chains


def _try_chain(
    s1: ChainStep, s2: ChainStep, is_cross: bool
) -> Optional[AttackChain]:
    """
    Essaie de créer une chaîne entre deux CVEs selon les règles de chaînage.
    Retourne None si aucune règle ne correspond.
    """
    for step1_types, step2_types, label, desc in CHAIN_RULES:
        # s1 → s2
        if s1.types & step1_types and s2.types & step2_types:
            return AttackChain(label, desc, s1, s2, is_cross)
        # s2 → s1 (ordre inverse)
        if s2.types & step1_types and s1.types & step2_types:
            return AttackChain(label, desc, s2, s1, is_cross)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Affichage terminal
# ─────────────────────────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}

TYPE_ICONS = {
    "RCE":              "💥",
    "AUTH_BYPASS":      "🔓",
    "LPE":              "⬆",
    "SQLI":             "💉",
    "PATH_TRAVERSAL":   "📂",
    "SSRF":             "🌐",
    "XXE":              "📄",
    "SSTI":             "🧩",
    "DESERIALIZATION":  "📦",
    "CRED_LEAK":        "🔑",
    "CONTAINER_ESCAPE": "🐳",
    "DOS":              "💣",
}


def display_chains_terminal(chains: list[AttackChain], max_display: int = 10):
    """Affiche les chaînes détectées dans le terminal."""
    if not console:
        return

    if not chains:
        console.print(
            "\n[dim]🔗 Aucune chaîne d'attaque détectée entre les CVEs trouvées.[/dim]"
        )
        return

    console.print()
    console.print(Rule("[bold magenta]🔗 Chaînes d'attaque détectées[/bold magenta]"))
    console.print(
        f"[dim]{len(chains)} chaîne(s) détectée(s) — "
        f"top {min(max_display, len(chains))} affichée(s)[/dim]\n"
    )

    for i, chain in enumerate(chains[:max_display]):
        sev_color = SEV_COLORS.get(chain.severity_label, "white")
        cross_tag = "[cyan](inter-services)[/cyan]" if chain.is_cross else "[dim](même service)[/dim]"

        # Header de la chaîne
        console.print(
            f"  [{sev_color}]▶ {chain.label}[/{sev_color}]  "
            f"[bold]Score {chain.chain_score}[/bold]  {cross_tag}"
        )
        console.print(f"    [dim]{chain.description}[/dim]")
        console.print()

        # Étape 1
        s1_types = " ".join(
            f"{TYPE_ICONS.get(t, '•')}{t}" for t in sorted(chain.step1.types)
            if t != "OTHER"
        )
        exp1 = "[green]⚡PoC[/green]" if chain.step1.exploit else ""
        console.print(
            f"    [bold]1.[/bold] [cyan]{chain.step1.cve_id}[/cyan]  "
            f"CVSS [bold]{chain.step1.cvss}[/bold]  "
            f"[dim]{chain.step1.service}:{chain.step1.port}[/dim]  "
            f"{s1_types}  {exp1}"
        )
        console.print(f"       [dim]{chain.step1.desc[:100]}[/dim]")
        console.print()

        # Flèche
        console.print("    [magenta]    ↓[/magenta]")
        console.print()

        # Étape 2
        s2_types = " ".join(
            f"{TYPE_ICONS.get(t, '•')}{t}" for t in sorted(chain.step2.types)
            if t != "OTHER"
        )
        exp2 = "[green]⚡PoC[/green]" if chain.step2.exploit else ""
        console.print(
            f"    [bold]2.[/bold] [cyan]{chain.step2.cve_id}[/cyan]  "
            f"CVSS [bold]{chain.step2.cvss}[/bold]  "
            f"[dim]{chain.step2.service}:{chain.step2.port}[/dim]  "
            f"{s2_types}  {exp2}"
        )
        console.print(f"       [dim]{chain.step2.desc[:100]}[/dim]")
        console.print()

        if i < min(max_display, len(chains)) - 1:
            console.print("  " + "─" * 60)
            console.print()

    if len(chains) > max_display:
        console.print(
            f"  [dim]… {len(chains) - max_display} chaîne(s) supplémentaire(s) "
            f"dans le rapport HTML.[/dim]"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Export HTML — section chaînes pour le rapport
# ─────────────────────────────────────────────────────────────────────────────

SEV_HEX = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
}


def chains_to_html_section(chains: list[AttackChain]) -> str:
    """Génère la section HTML des chaînes d'attaque pour le rapport."""
    if not chains:
        return ""

    cards = ""
    for chain in chains:
        color   = SEV_HEX.get(chain.severity_label, "#6b7280")
        cross   = "Inter-services" if chain.is_cross else "Même service"
        cross_c = "#38bdf8" if chain.is_cross else "#6b7280"

        def step_card(step: ChainStep, num: int) -> str:
            types_html = " ".join(
                f'<span class="chain-type-badge">'
                f'{TYPE_ICONS.get(t,"•")} {t}</span>'
                for t in sorted(step.types) if t != "OTHER"
            )
            exp = '<span class="chain-exp">⚡ PoC</span>' if step.exploit else ""
            nvd = (
                f'<a href="https://nvd.nist.gov/vuln/detail/{step.cve_id}" '
                f'target="_blank" class="chain-cve-link">{step.cve_id}</a>'
                if step.cve_id.startswith("CVE-")
                else f'<span>{step.cve_id}</span>'
            )
            return f"""
              <div class="chain-step">
                <div class="chain-step-num">{num}</div>
                <div class="chain-step-body">
                  <div class="chain-step-head">
                    {nvd}
                    <span class="chain-score">CVSS {step.cvss}</span>
                    <span class="chain-svc">{step.service}:{step.port}</span>
                    {exp}
                  </div>
                  <div class="chain-types">{types_html}</div>
                  <div class="chain-desc">{step.desc}</div>
                </div>
              </div>"""

        cards += f"""
          <div class="chain-card" style="border-left:3px solid {color}">
            <div class="chain-head">
              <div class="chain-label" style="color:{color}">▶ {chain.label}</div>
              <div class="chain-meta">
                <span class="chain-score-badge" style="color:{color};border-color:{color}44;background:{color}11">
                  Score {chain.chain_score}
                </span>
                <span class="chain-cross-badge" style="color:{cross_c}">{cross}</span>
              </div>
            </div>
            <div class="chain-desc-main">{chain.description}</div>
            <div class="chain-steps">
              {step_card(chain.step1, 1)}
              <div class="chain-arrow">↓</div>
              {step_card(chain.step2, 2)}
            </div>
          </div>"""

    return f"""
<div class="section chain-section" id="chains-section">
  <h2 class="section-h2">🔗 Chaînes d'attaque détectées
    <span class="section-count">{len(chains)}</span>
  </h2>
  <p class="section-intro">
    Paires de CVEs pouvant être enchaînées pour réaliser une attaque en deux étapes —
    accès initial suivi d'une escalade de privilèges ou d'un mouvement latéral.
  </p>
  {cards}
  <style>
    .chain-section {{ margin: 1.5rem 0; }}
    .section-h2 {{
      font-size: 1rem; font-weight: 700; color: #dce8f8;
      margin-bottom: .5rem; display: flex; align-items: center; gap: .5rem;
    }}
    .section-count {{
      background: #1e243a; color: #8aaad0; font-size: .75rem;
      padding: .1rem .5rem; border-radius: 20px; font-weight: 400;
    }}
    .section-intro {{ font-size: .8rem; color: #4a6488; margin-bottom: 1rem; }}
    .chain-card {{
      background: #111428; border: 1px solid #1c2240;
      border-radius: 8px; margin-bottom: .85rem; overflow: hidden;
    }}
    .chain-head {{
      display: flex; justify-content: space-between; align-items: center;
      padding: .75rem 1.25rem; background: #161b30;
      border-bottom: 1px solid #1c2240; flex-wrap: wrap; gap: .5rem;
    }}
    .chain-label {{ font-weight: 700; font-size: .95rem; }}
    .chain-meta {{ display: flex; gap: .5rem; align-items: center; }}
    .chain-score-badge {{
      font-size: .75rem; font-weight: 700;
      padding: .15rem .5rem; border-radius: 4px; border: 1px solid;
    }}
    .chain-cross-badge {{ font-size: .75rem; color: #4a6488; }}
    .chain-desc-main {{
      padding: .5rem 1.25rem; font-size: .8rem; color: #4a6488;
      border-bottom: 1px solid #1c2240;
    }}
    .chain-steps {{ padding: .85rem 1.25rem; display: flex; flex-direction: column; gap: .5rem; }}
    .chain-step {{
      display: flex; gap: .85rem; align-items: flex-start;
      background: #0d0f1f; border: 1px solid #1c2240;
      border-radius: 6px; padding: .65rem .9rem;
    }}
    .chain-step-num {{
      flex-shrink: 0; width: 22px; height: 22px; border-radius: 50%;
      background: #1e243a; color: #8aaad0; font-size: .75rem;
      font-weight: 700; display: flex; align-items: center; justify-content: center;
    }}
    .chain-step-body {{ flex: 1; min-width: 0; }}
    .chain-step-head {{
      display: flex; gap: .6rem; align-items: center;
      flex-wrap: wrap; margin-bottom: .35rem;
    }}
    .chain-cve-link {{
      font-family: 'Courier New', monospace; font-size: .8rem;
      color: #60a0f0; border-bottom: 1px dashed rgba(96,160,240,.3);
    }}
    .chain-cve-link:hover {{ color: #a0d0f0; }}
    .chain-score {{ font-size: .75rem; color: #4a6488; }}
    .chain-svc {{
      font-size: .72rem; background: #1e243a; color: #8aaad0;
      padding: .1rem .4rem; border-radius: 3px; font-family: monospace;
    }}
    .chain-exp {{
      font-size: .72rem; font-weight: 700; color: #38bdf8;
      background: rgba(56,189,248,.1); border: 1px solid rgba(56,189,248,.3);
      border-radius: 3px; padding: .1rem .35rem;
    }}
    .chain-types {{ display: flex; gap: .3rem; flex-wrap: wrap; margin-bottom: .3rem; }}
    .chain-type-badge {{
      font-size: .68rem; background: #1e243a; color: #8aaad0;
      padding: .1rem .35rem; border-radius: 3px; border: 1px solid #252c40;
    }}
    .chain-desc {{ font-size: .78rem; color: #4a6488; line-height: 1.4; }}
    .chain-arrow {{
      text-align: center; color: #7c6af7; font-size: 1.1rem;
      padding: .1rem 0; letter-spacing: .05em;
    }}
  </style>
</div>"""
