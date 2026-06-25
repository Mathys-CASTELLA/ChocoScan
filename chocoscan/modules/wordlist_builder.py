"""
ChocoScan — Wordlist Builder.

Génère des wordlists ciblées à partir du contexte du scan :
noms de domaine, hostnames, produits détectés, entreprise devinée...

Un wordlist ciblé de 500 mots bat souvent rockyou.txt (14M) sur
des cibles réelles, parce qu'il correspond aux conventions de l'organisation.

Fonctionnalités :
  Extraction de mots-clés depuis les résultats Nmap (domaine,
  hostname, produit, service, banner, IPs)

  Mutations automatiques couvrant les politiques courantes :
    - Casse : Mot, MOT, mot
    - Années : Mot2023, Mot2024, Mot2025
    - Symboles : Mot!, Mot@, Mot#, Mot$
    - Combos entreprise : Mot@2024, Mot2024!, Mot!2024
    - Patterns courants : Mot123, Mot123!, Mot@123
    - Saisons : MotSpring2024!, MotWinter2024
    - Leet speak : M0t, m0t, M@t
    - Préfixes admin : adminMot, testMot

  Commandes CeWL pour spider les services web détectés

  Génération de usernames depuis des noms complets
    (john.doe, jdoe, j.doe, johnd, john_doe...)

  Export vers fichier (--wordlist output.txt)

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class WordlistResult:
    target:        str
    domain:        str
    company:       str
    base_words:    list[str]      # Mots extraits bruts
    all_words:     list[str]      # Tous les mots + mutations (dédupliqués)
    cewl_cmds:     list[str]      # Commandes CeWL pour les services web
    username_cmds: list[str]      # Commandes de génération d'usernames
    hashcat_rules: list[str]      # Règles hashcat alternatives
    notes:         list[str]
    stats:         dict[str, int] = field(default_factory=dict)


# ── Extraction de mots depuis le scan ─────────────────────────────────────────

_STOP_WORDS = {
    "the", "and", "for", "with", "http", "https", "tcp", "udp", "open",
    "service", "version", "server", "linux", "windows", "microsoft",
    "apache", "nginx", "not", "from", "port", "ssh", "ftp", "smtp",
    "none", "true", "false", "null", "localhost", "local", "remote",
}

def _extract_words_from_scan(results: list[dict]) -> tuple[str, str, str, list[str]]:
    """
    Extrait les mots-clés pertinents des résultats du scan.

    Retourne : (target_host, domain, company, base_words)
    """
    words:  set[str] = set()
    domain  = ""
    company = ""
    target  = ""

    for r in results:
        svc = r.get("service", {})
        if not target:
            target = svc.get("host", "") or ""

        # ── Nom de service ────────────────────────────────────────────────────
        svc_name = svc.get("service_name", "") or ""
        if svc_name and len(svc_name) >= 3:
            words.add(svc_name.lower().strip())

        # ── Produit ───────────────────────────────────────────────────────────
        product = svc.get("product", "") or ""
        for part in re.split(r"[\s/_\-\.]+", product):
            p = part.strip().lower()
            if len(p) >= 3 and p not in _STOP_WORDS and not p.isdigit():
                words.add(p)

        # ── Banner ────────────────────────────────────────────────────────────
        banner = svc.get("banner", "") or ""

        # Extraire le hostname du banner (ex: "Ubuntu; ... hostname=DC01")
        host_m = re.search(r"(?:hostname|computer)[=:\s]+([A-Za-z0-9\-_]+)", banner, re.I)
        if host_m:
            h = host_m.group(1).strip()
            if len(h) >= 2:
                words.add(h.lower())
                words.add(h)

        # Extraire le domaine (ex: banner SMB, LDAP, Kerberos, SSH banner)
        dom_m = re.search(
            r"(?:domain|realm|fqdn|workgroup)[=:\s]+([A-Za-z0-9\.\-]+)",
            banner, re.I,
        )
        if dom_m:
            raw_dom = dom_m.group(1).strip().lower()
            if "." in raw_dom and not domain:
                domain = raw_dom
            for part in raw_dom.split("."):
                if len(part) >= 3 and part not in _STOP_WORDS:
                    words.add(part)

        # Extraire les mots du banner (longueur 3-20, alphabétiques)
        for word in re.findall(r"[A-Za-z]{3,20}", banner):
            w = word.lower()
            if w not in _STOP_WORDS:
                words.add(w)

        # ── Hostname de l'hôte cible ──────────────────────────────────────────
        host = svc.get("host", "") or ""
        if host and re.match(r"[A-Za-z]", host):
            for part in re.split(r"[\.\-]", host):
                p = part.strip().lower()
                if 2 <= len(p) <= 20 and p not in _STOP_WORDS:
                    words.add(p)
                if "." in host and not domain:
                    domain = host.lower()

    # ── Deviner le nom d'entreprise depuis le domaine ─────────────────────────
    if domain:
        parts = domain.rstrip(".").split(".")
        # Ignorer les TLD courants
        tlds = {"com", "net", "org", "local", "lan", "corp", "int", "io", "fr", "uk", "de"}
        candidates = [p for p in parts if p not in tlds and len(p) >= 3]
        if candidates:
            company = candidates[0]
            words.add(company.lower())
            words.add(company.capitalize())

    # ── Mots de base supplémentaires courants en CTF ──────────────────────────
    ctf_defaults = [
        "admin", "password", "secret", "welcome", "letmein",
        "changeme", "default", "master", "backup", "root",
    ]

    # Filtrage final : garder uniquement les mots significatifs (3-25 chars)
    clean_words = sorted({
        w for w in words
        if 2 <= len(w) <= 25 and w not in _STOP_WORDS
    })

    # Ajouter les defaults CTF si peu de mots extraits
    if len(clean_words) < 5:
        clean_words = ctf_defaults + clean_words

    return target, domain, company, clean_words


# ── Mutations ─────────────────────────────────────────────────────────────────

CURRENT_YEARS = ["2022", "2023", "2024", "2025"]
SEASONS = [
    "Spring", "Summer", "Autumn", "Winter",
    "Printemps", "Ete", "Automne", "Hiver",
]
SYMBOLS = ["!", "@", "#", "$", "1", "123", "1234"]
LEET = {"a": ["@", "4"], "e": ["3"], "i": ["1", "!"], "o": ["0"], "s": ["$", "5"], "t": ["7"]}


def _apply_mutations(base_words: list[str]) -> list[str]:
    """
    Applique les mutations les plus efficaces sur chaque mot de base.
    Priorité : patterns les plus courants en entreprise d'abord.
    """
    results: set[str] = set()

    for w in base_words:
        wl = w.lower()
        wc = w.capitalize()
        wu = w.upper()

        # ── Casse pure ────────────────────────────────────────────────────────
        results.update([wl, wc, wu])

        # ── Années ────────────────────────────────────────────────────────────
        for year in CURRENT_YEARS:
            results.update([
                f"{wc}{year}",    # Password2024
                f"{wl}{year}",    # password2024
                f"{wu}{year}",    # PASSWORD2024
            ])

        # ── Années + symboles (pattern enterprise #1) ─────────────────────────
        for year in CURRENT_YEARS:
            results.update([
                f"{wc}{year}!",   # Password2024!
                f"{wc}{year}@",   # Password2024@
                f"{wc}@{year}",   # Password@2024
                f"{wc}!{year}",   # Password!2024
            ])

        # ── Symboles seuls ────────────────────────────────────────────────────
        for sym in SYMBOLS:
            results.update([
                f"{wc}{sym}",     # Password!
                f"{wl}{sym}",     # password!
                f"{wc}_{sym}",    # Password_!
            ])

        # ── Patterns @123 ─────────────────────────────────────────────────────
        results.update([
            f"{wc}@123",          # Password@123
            f"{wc}123!",          # Password123!
            f"{wc}#1",            # Password#1
            f"{wc}01",            # Password01
            f"{wl}123",           # password123
        ])

        # ── Saisons ───────────────────────────────────────────────────────────
        for season in SEASONS[:4]:
            for year in CURRENT_YEARS[-2:]:  # seulement les 2 dernières années
                results.update([
                    f"{wc}{season}{year}",   # PasswordSpring2024
                    f"{wc}{season}{year}!",  # PasswordSpring2024!
                ])

        # ── Leet speak (1 substitution seulement — rester lisible) ────────────
        for char, subs in LEET.items():
            if char in wl:
                for sub in subs[:1]:  # une seule sub par lettre
                    leet_w = wl.replace(char, sub, 1)
                    results.update([
                        leet_w,
                        leet_w.capitalize(),
                        f"{leet_w.capitalize()}!",
                        f"{leet_w.capitalize()}123",
                    ])

        # ── Préfixes courants ─────────────────────────────────────────────────
        results.update([
            f"admin{wc}",         # adminPassword
            f"Admin{wc}",
            f"{wl}_admin",        # password_admin
            f"test{wc}",          # testPassword
        ])

    return sorted(results)


# ── Commandes CeWL ────────────────────────────────────────────────────────────

def _cewl_commands(results: list[dict], output_dir: str = "/tmp") -> list[str]:
    """Génère les commandes CeWL pour chaque service web détecté."""
    cmds: list[str] = []
    web_ports = {80, 443, 8080, 8443, 8000, 8001, 3000, 5000}
    seen: set[str] = set()

    for r in results:
        svc  = r.get("service", {})
        port = svc.get("port", 0) or 0
        host = svc.get("host", "TARGET") or "TARGET"
        svc_name = (svc.get("service_name", "") or "").lower()

        is_web = port in web_ports or "http" in svc_name
        if not is_web:
            continue

        proto = "https" if port in (443, 8443) or "ssl" in svc_name else "http"
        url   = f"{proto}://{host}:{port}"

        if url in seen:
            continue
        seen.add(url)

        out = f"{output_dir}/cewl_{host}_{port}.txt"
        cmds += [
            f"# ── CeWL → {url} ──────────────────────────────────────────────",
            "",
            f"# Extraction basique (profondeur 2, longueur min 5) :",
            f"cewl {url} -d 2 -m 5 -w {out}",
            "",
            f"# Avec emails et mots du code source :",
            f"cewl {url} -d 3 -m 5 --email -e -w {out}",
            "",
            f"# Avec authentification (si requise) :",
            f"cewl {url} -d 2 -m 5 -a --auth_type digest "
            f"--auth_user USER --auth_pass PASS -w {out}",
            "",
            f"# Combiner CeWL + mutations avec hashcat rules :",
            f"hashcat --stdout {out} -r /usr/share/hashcat/rules/best64.rule > {out}_mutated.txt",
            "",
            f"# Ou avec john :",
            f"john --wordlist={out} --rules=best64 --stdout > {out}_mutated.txt",
            "",
        ]

    if not cmds:
        cmds = [
            "# Aucun service web détecté dans le scan.",
            "# Lancer CeWL manuellement si vous trouvez un site :",
            "cewl http://TARGET -d 3 -m 5 -w /tmp/cewl_TARGET.txt",
        ]

    return cmds


# ── Génération d'usernames ─────────────────────────────────────────────────────

def _username_commands(domain: str = "") -> list[str]:
    """Génère les commandes pour créer une liste d'usernames."""
    dom_flag = f"-d {domain}" if domain else ""
    cmds = [
        "# ── Génération d'usernames depuis des noms complets ─────────────────",
        "",
        "# Si vous avez des noms complets (ex: John Doe, Jane Smith) :",
        "# Créer un fichier names.txt avec un nom par ligne (Prénom Nom)",
        "",
        "# username-anarchy (le plus complet) :",
        "# https://github.com/urbanadventurer/username-anarchy",
        "ruby username-anarchy -f first.last,flast,first,f.last,lastf < names.txt > usernames.txt",
        "",
        "# namemash.py (plus simple) :",
        "# https://gist.github.com/superkojiman/11076951",
        "python3 namemash.py names.txt > usernames.txt",
        "",
        "# Formats générés automatiquement (exemple pour John Doe) :",
        "#   john.doe     jdoe      johnd     j.doe",
        "#   doejohn      doe.john  jd        johndoe",
        "",
        "# ── Énumération LDAP/Kerberos pour valider les usernames ─────────────",
        "",
    ]
    if domain:
        cmds += [
            f"# Kerbrute (valide les usernames sans mot de passe) :",
            f"kerbrute userenum -d {domain} --dc DC_IP usernames.txt",
            "",
            f"# enum4linux-ng (si SMB accessible) :",
            f"enum4linux-ng -U TARGET | tee users_raw.txt",
            f"cat users_raw.txt | grep 'user:' | awk '{{print $2}}' > usernames.txt",
            "",
            f"# CrackMapExec :",
            f"crackmapexec smb DC_IP -u '' -p '' --users 2>/dev/null | "
            f"awk '/SMB.*DC_IP.*\\[\\+\\]/ {{print $5}}' | cut -d'\\\\' -f2 > usernames.txt",
        ]
    else:
        cmds += [
            "# Kerbrute (définir le domaine avec -d DOMAIN) :",
            "kerbrute userenum -d DOMAIN --dc DC_IP usernames.txt",
            "",
            "# enum4linux-ng (si SMB accessible) :",
            "enum4linux-ng -U TARGET | grep 'user:' | awk '{print $2}' > usernames.txt",
        ]
    return cmds


# ── Règles hashcat alternatives ───────────────────────────────────────────────

def _hashcat_rules(wordlist_path: str = "wordlist.txt") -> list[str]:
    """Commandes hashcat pour appliquer des règles sur la wordlist générée."""
    return [
        "# ── Hashcat — appliquer des règles sur la wordlist ──────────────────",
        "",
        "# best64 (rapide, couvre 90% des cas enterprise) :",
        f"hashcat -a 0 -m MODE HASH_FILE {wordlist_path} "
        "-r /usr/share/hashcat/rules/best64.rule",
        "",
        "# OneRuleToRuleThemAll (plus exhaustif) :",
        "# https://github.com/NotSoSecure/password_cracking_rules",
        f"hashcat -a 0 -m MODE HASH_FILE {wordlist_path} -r OneRule.rule",
        "",
        "# Combinator (croiser deux wordlists) :",
        f"hashcat -a 1 -m MODE HASH_FILE {wordlist_path} {wordlist_path}",
        "",
        "# Mask attack (pattern fixe, ex: Mot + 4 chiffres) :",
        f"hashcat -a 6 -m MODE HASH_FILE {wordlist_path} ?d?d?d?d",
        "",
        "# John avec règles :",
        f"john --wordlist={wordlist_path} --rules=best64 HASH_FILE",
    ]


# ── Statistiques ──────────────────────────────────────────────────────────────

def _compute_stats(base_words: list[str], all_words: list[str]) -> dict[str, int]:
    """Calcule quelques métriques sur la wordlist générée."""
    lengths = [len(w) for w in all_words]
    return {
        "base_words":     len(base_words),
        "total_words":    len(all_words),
        "mutations":      len(all_words) - len(base_words),
        "min_len":        min(lengths) if lengths else 0,
        "max_len":        max(lengths) if lengths else 0,
        "avg_len":        round(sum(lengths) / len(lengths)) if lengths else 0,
        "words_gte8":     sum(1 for l in lengths if l >= 8),
        "words_with_sym": sum(1 for w in all_words if any(c in w for c in "!@#$%^&*")),
        "words_with_num": sum(1 for w in all_words if any(c.isdigit() for c in w)),
    }


# ── Moteur principal ──────────────────────────────────────────────────────────

def build_wordlists(
    results:     list[dict],
    output_file: str = "",
    custom_words: list[str] | None = None,
) -> WordlistResult:
    """
    Génère une wordlist ciblée depuis les résultats du scan Nmap.

    Args:
        results:      Résultats ChocoScan (liste de dicts avec clé 'service').
        output_file:  Chemin du fichier de sortie (facultatif).
        custom_words: Mots supplémentaires à inclure (noms d'employés, etc.).

    Returns:
        WordlistResult avec tous les mots, commandes et statistiques.
    """
    target, domain, company, base_words = _extract_words_from_scan(results)

    # Ajouter les mots personnalisés
    if custom_words:
        for w in custom_words:
            w = w.strip()
            if w and w not in base_words:
                base_words.append(w)

    # Appliquer les mutations
    mutated   = _apply_mutations(base_words)
    all_words = sorted(set(base_words + mutated))

    # Écrire dans le fichier si demandé
    if output_file:
        try:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(all_words) + "\n")
        except OSError:
            pass  # L'erreur sera visible dans les notes

    notes: list[str] = []
    if domain:
        notes.append(f"Domaine détecté : {domain}")
    if company:
        notes.append(f"Entreprise devinée : {company}")
    if not base_words:
        notes.append("Aucun mot-clé extrait — scan peu verbeux.")
        notes.append("Ajouter --custom-words ou utiliser CeWL sur un service web.")
    if output_file:
        notes.append(f"Wordlist écrite : {output_file} ({len(all_words)} lignes)")

    notes += [
        "Combiner avec SecLists : cat wordlist.txt "
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt "
        "| sort -u > combined.txt",
        "Pour les services web : CeWL génère des mots depuis le contenu du site (voir ci-dessous).",
    ]

    return WordlistResult(
        target=target,
        domain=domain,
        company=company,
        base_words=base_words,
        all_words=all_words,
        cewl_cmds=_cewl_commands(results),
        username_cmds=_username_commands(domain),
        hashcat_rules=_hashcat_rules(output_file or "wordlist.txt"),
        notes=notes,
        stats=_compute_stats(base_words, all_words),
    )
