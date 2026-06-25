"""
ChocoScan — Hash Cracker Suggéré.

Détecte automatiquement le type de hash et génère la commande
hashcat avec le bon mode -m, la bonne wordlist et les meilleures
règles. Fonctionne avec les hashes trouvés dans le loot (shadow,
NTLM, AS-REP, Kerberoast, NetNTLM...).

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class HashInfo:
    hash_type:   str
    hashcat_mode: int
    john_format: str
    description: str
    example:     str
    difficulty:  str        # easy | medium | hard
    commands:    list[str] = field(default_factory=list)


# ── Base de modes hashcat ─────────────────────────────────────────────────────

HASHCAT_MODES: dict[str, HashInfo] = {

    # ── Linux shadow ─────────────────────────────────────────────────────────
    "sha512crypt": HashInfo(
        hash_type="sha512crypt",
        hashcat_mode=1800,
        john_format="sha512crypt",
        description="Hash Linux /etc/shadow ($6$) — SHA-512",
        example="$6$salt$hash...",
        difficulty="hard",
    ),
    "sha256crypt": HashInfo(
        hash_type="sha256crypt",
        hashcat_mode=7400,
        john_format="sha256crypt",
        description="Hash Linux /etc/shadow ($5$) — SHA-256",
        example="$5$salt$hash...",
        difficulty="hard",
    ),
    "md5crypt": HashInfo(
        hash_type="md5crypt",
        hashcat_mode=500,
        john_format="md5crypt",
        description="Hash Linux /etc/shadow ($1$) — MD5 crypt",
        example="$1$salt$hash...",
        difficulty="medium",
    ),
    "yescrypt": HashInfo(
        hash_type="yescrypt",
        hashcat_mode=11600,
        john_format="yescrypt",
        description="Hash Linux /etc/shadow ($y$) — yescrypt (Ubuntu 22.04+)",
        example="$y$j9T$...",
        difficulty="hard",
    ),
    "blowfish": HashInfo(
        hash_type="blowfish",
        hashcat_mode=3200,
        john_format="bcrypt",
        description="bcrypt — PHP, Node.js, etc.",
        example="$2a$10$...",
        difficulty="hard",
    ),

    # ── Windows ───────────────────────────────────────────────────────────────
    "ntlm": HashInfo(
        hash_type="NTLM",
        hashcat_mode=1000,
        john_format="NT",
        description="Hash NTLM Windows — SAM, LSASS, secretsdump",
        example="aad3b435b51404eeaad3b435b51404ee",
        difficulty="easy",
    ),
    "lm": HashInfo(
        hash_type="LM",
        hashcat_mode=3000,
        john_format="LM",
        description="Hash LM Windows — très ancien, facile à cracker",
        example="aad3b435b51404ee",
        difficulty="easy",
    ),
    "netntlmv1": HashInfo(
        hash_type="NetNTLMv1",
        hashcat_mode=5500,
        john_format="netntlm",
        description="NetNTLMv1 — capturé avec Responder",
        example="user::domain:challenge:hash",
        difficulty="medium",
    ),
    "netntlmv2": HashInfo(
        hash_type="NetNTLMv2",
        hashcat_mode=5600,
        john_format="netntlmv2",
        description="NetNTLMv2 — capturé avec Responder (le plus courant)",
        example="user::domain:challenge:hash::data",
        difficulty="medium",
    ),
    "dcc2": HashInfo(
        hash_type="DCC2/mscache2",
        hashcat_mode=2100,
        john_format="mscash2",
        description="Domain Cached Credentials v2 — depuis HKLM\\SECURITY",
        example="$DCC2$10240#user#hash",
        difficulty="hard",
    ),

    # ── Kerberos ──────────────────────────────────────────────────────────────
    "asrep": HashInfo(
        hash_type="AS-REP (Kerberos)",
        hashcat_mode=18200,
        john_format="krb5asrep",
        description="AS-REP Roasting — compte sans pre-auth Kerberos",
        example="$krb5asrep$23$user@domain:...",
        difficulty="medium",
    ),
    "kerberoast": HashInfo(
        hash_type="Kerberoast TGS",
        hashcat_mode=13100,
        john_format="krb5tgs",
        description="Kerberoasting — ticket TGS service account",
        example="$krb5tgs$23$*user$domain$...",
        difficulty="medium",
    ),
    "kerberoast_17": HashInfo(
        hash_type="Kerberoast TGS AES-128",
        hashcat_mode=19600,
        john_format="krb5tgs",
        description="Kerberoasting AES-128 — RC4 desactivé",
        example="$krb5tgs$17$...",
        difficulty="hard",
    ),
    "kerberoast_18": HashInfo(
        hash_type="Kerberoast TGS AES-256",
        hashcat_mode=19700,
        john_format="krb5tgs",
        description="Kerberoasting AES-256 — RC4 desactivé",
        example="$krb5tgs$18$...",
        difficulty="hard",
    ),

    # ── Hashes simples ────────────────────────────────────────────────────────
    "md5": HashInfo(
        hash_type="MD5",
        hashcat_mode=0,
        john_format="raw-md5",
        description="MD5 brut — non salé",
        example="5f4dcc3b5aa765d61d8327deb882cf99",
        difficulty="easy",
    ),
    "md5_salted": HashInfo(
        hash_type="MD5 salted",
        hashcat_mode=20,
        john_format="dynamic_20",
        description="MD5 salté (md5($pass.$salt) ou md5($salt.$pass))",
        example="hash:salt",
        difficulty="easy",
    ),
    "sha1": HashInfo(
        hash_type="SHA1",
        hashcat_mode=100,
        john_format="raw-sha1",
        description="SHA1 brut — non salé",
        example="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        difficulty="easy",
    ),
    "sha256": HashInfo(
        hash_type="SHA256",
        hashcat_mode=1400,
        john_format="raw-sha256",
        description="SHA256 brut — non salé",
        example="e3b0c44298fc1c149afbf4c8996fb92427...",
        difficulty="easy",
    ),
    "sha512": HashInfo(
        hash_type="SHA512",
        hashcat_mode=1700,
        john_format="raw-sha512",
        description="SHA512 brut — non salé",
        example="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83...",
        difficulty="easy",
    ),

    # ── Applications ──────────────────────────────────────────────────────────
    "mysql41": HashInfo(
        hash_type="MySQL 4.1+",
        hashcat_mode=300,
        john_format="mysql-sha1",
        description="Hash MySQL 4.1+ (*HASH)",
        example="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",
        difficulty="easy",
    ),
    "wordpress": HashInfo(
        hash_type="WordPress (phpass)",
        hashcat_mode=400,
        john_format="phpass",
        description="Hash WordPress ($P$) — phpass",
        example="$P$BVqldltJ1...",
        difficulty="medium",
    ),
    "joomla": HashInfo(
        hash_type="Joomla (MD5 salté)",
        hashcat_mode=11,
        john_format="md5-gen",
        description="Hash Joomla — MD5(MD5($pass).$salt)",
        example="hash:salt",
        difficulty="easy",
    ),
    "wpa2": HashInfo(
        hash_type="WPA2-PSK",
        hashcat_mode=22000,
        john_format="wpapsk",
        description="WPA2 PMKID/EAPOL — capturé avec hcxdumptool",
        example="WPA*01*PMKID*...",
        difficulty="hard",
    ),
    "jwt": HashInfo(
        hash_type="JWT",
        hashcat_mode=16500,
        john_format="hmac-sha256",
        description="JSON Web Token — signature HMAC-SHA256",
        example="header.payload.signature",
        difficulty="medium",
    ),
}

# ── Patterns de détection ─────────────────────────────────────────────────────

PATTERNS: list[tuple[str, str]] = [
    # Format spéciaux d'abord (plus spécifiques)
    (r"^\$krb5asrep\$",              "asrep"),
    (r"^\$krb5tgs\$23\$",            "kerberoast"),
    (r"^\$krb5tgs\$17\$",            "kerberoast_17"),
    (r"^\$krb5tgs\$18\$",            "kerberoast_18"),
    (r"^\$6\$",                      "sha512crypt"),
    (r"^\$5\$",                      "sha256crypt"),
    (r"^\$1\$",                      "md5crypt"),
    (r"^\$y\$",                      "yescrypt"),
    (r"^\$2[aby]\$",                 "blowfish"),
    (r"^\$P\$",                      "wordpress"),
    (r"^\$DCC2\$",                   "dcc2"),
    (r"^\*[A-F0-9]{40}$",           "mysql41"),
    # NetNTLM (contient ::)
    (r"^[^:]+::[^:]+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$", "netntlmv2"),
    (r"^[^:]+::[^:]+:[a-f0-9]{16}:[a-f0-9]{48}$",           "netntlmv1"),
    # Hashes simples par longueur
    (r"^[a-f0-9]{128}$",            "sha512"),
    (r"^[a-f0-9]{64}$",             "sha256"),
    (r"^[a-f0-9]{40}$",             "sha1"),
    (r"^[a-f0-9]{32}$",             "ntlm"),   # NTLM ou MD5 — contexte Windows = NTLM
    (r"^[a-f0-9]{16}$",             "lm"),
]


def detect_hash_type(hash_str: str) -> HashInfo | None:
    """Détecte automatiquement le type de hash."""
    h = hash_str.strip()
    for pattern, key in PATTERNS:
        if re.match(pattern, h, re.IGNORECASE):
            return HASHCAT_MODES.get(key)
    return None


def detect_hashes_in_text(text: str) -> list[tuple[str, HashInfo]]:
    """
    Cherche des hashes dans un texte (ex: contenu de /etc/shadow,
    output de secretsdump...) et retourne les paires (hash, info).
    """
    results = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        # /etc/shadow format : user:$6$salt$hash:...
        shadow_match = re.search(r":\$(\d+|[a-z])\$[^:]+", line)
        if shadow_match:
            hash_part = shadow_match.group(0)[1:]  # retire le :
            if hash_part not in seen:
                info = detect_hash_type(hash_part)
                if info:
                    results.append((hash_part, info))
                    seen.add(hash_part)
            continue
        # secretsdump NTLM format : user:RID:LM:NTLM:::
        ntlm_match = re.search(r":[0-9a-f]{32}:[0-9a-f]{32}:::", line, re.IGNORECASE)
        if ntlm_match:
            full = ntlm_match.group(0)
            parts = full.split(":")
            if len(parts) >= 3:
                ntlm_hash = parts[2]
                if ntlm_hash not in seen and ntlm_hash != "aad3b435b51404eeaad3b435b51404ee":
                    info = HASHCAT_MODES["ntlm"]
                    results.append((ntlm_hash, info))
                    seen.add(ntlm_hash)
            continue
        # Hash standalone
        for pattern, key in PATTERNS[:12]:  # patterns spécifiques seulement
            if re.match(pattern, line, re.IGNORECASE):
                if line not in seen:
                    info = HASHCAT_MODES.get(key)
                    if info:
                        results.append((line, info))
                        seen.add(line)
                break
    return results


def generate_crack_commands(hash_file: str, info: HashInfo,
                             output_dir: str = "output") -> list[str]:
    """Génère les commandes hashcat + john pour cracker un hash."""
    m = info.hashcat_mode
    pot = f"{output_dir}/hashcat_{info.hash_type.lower().replace(' ','_')}.pot"
    cmds = [
        f"# Type    : {info.hash_type} (mode {m})",
        f"# Description : {info.description}",
        f"# Difficulte  : {info.difficulty.upper()}",
        "",
        f"# Attaque dictionnaire — rockyou",
        f"hashcat -m {m} {hash_file} /usr/share/wordlists/rockyou.txt "
        f"--potfile-path {pot} -O",
        "",
        f"# Attaque dictionnaire + règles best64",
        f"hashcat -m {m} {hash_file} /usr/share/wordlists/rockyou.txt "
        f"-r /usr/share/hashcat/rules/best64.rule --potfile-path {pot} -O",
        "",
        f"# Attaque dictionnaire + règles OneRuleToRuleThemAll (si disponible)",
        f"hashcat -m {m} {hash_file} /usr/share/wordlists/rockyou.txt "
        f"-r ~/OneRuleToRuleThemAll.rule --potfile-path {pot} -O",
        "",
        f"# SecLists common credentials",
        f"hashcat -m {m} {hash_file} "
        f"/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt "
        f"--potfile-path {pot} -O",
    ]
    if info.difficulty == "easy":
        cmds += [
            "",
            f"# Attaque bruteforce (hash simple — faisable)",
            f"hashcat -m {m} {hash_file} -a 3 ?a?a?a?a?a?a?a?a --potfile-path {pot}",
        ]
    cmds += [
        "",
        f"# John the Ripper (alternative)",
        f"john --format={info.john_format} {hash_file} "
        f"--wordlist=/usr/share/wordlists/rockyou.txt",
        "",
        f"# Afficher les mots de passe trouvés",
        f"hashcat -m {m} {hash_file} --show --potfile-path {pot}",
        f"john --show {hash_file}",
    ]
    return cmds


def analyze_loot_for_hashes(loot_items: list) -> list[tuple[str, HashInfo, str]]:
    """
    Analyse les items de loot et extrait les hashes détectables.
    Retourne une liste de (hash, info, source_path).
    """
    results = []
    for item in loot_items:
        if item.category not in ("system", "config", "secret"):
            continue
        if not item.preview:
            continue
        found = detect_hashes_in_text(item.preview)
        for h, info in found:
            results.append((h, info, item.path))
    return results
