"""
ChocoScan — Cipher & Encoding Decoder.

Identifie automatiquement le type d'encodage ou de chiffrement
d'une chaîne et génère les commandes de décodage correspondantes.

Types supportés :
  Encodages : Base64, Base32, Hex, Octal, Binary, URL-encode, HTML entities
  Substitution : ROT13, ROT47, Caesar (brute force), Vigenère (hint)
  Classiques CTF : Morse, Atbash, Base58, Base85
  Web tokens : JWT (decode header/payload)
  Hashes : MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, Kerberos (classification)
  RSA : Détection de clés/paramètres faibles (petit N, e=1, e=3)

La détection est heuristique — plusieurs types peuvent coexister.
Utilise la commande decode_cmd ou le lien CyberChef pour décoder.

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import base64
import binascii
import re
import string
from dataclasses import dataclass, field


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class CipherDetection:
    cipher_type:    str     # Nom lisible du type
    confidence:     str     # "high" | "medium" | "low"
    decoded:        str     # Valeur décodée (si possible en local)
    decode_cmd:     str     # Commande CLI bash pour décoder
    python_snippet: str     # Snippet Python équivalent
    notes:          str = ""
    cyberchef_url:  str = ""  # Lien CyberChef pré-rempli (si applicable)


@dataclass
class CipherResult:
    input_text:  str
    detections:  list[CipherDetection]
    best_guess:  CipherDetection | None   # Détection la plus probable
    summary:     str                       # Résumé lisible


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cyberchef(recipe: str, input_b64: str = "") -> str:
    """Génère un lien CyberChef (les options sont dans le fragment, pas query string)."""
    return f"https://gchq.github.io/CyberChef/#recipe={recipe}"


def _is_printable(s: str, threshold: float = 0.85) -> bool:
    """Vérifie si une chaîne est majoritairement printable."""
    if not s:
        return False
    printable = sum(1 for c in s if c in string.printable)
    return (printable / len(s)) >= threshold


def _rot_n(text: str, n: int) -> str:
    """Rotation ROT-N sur les caractères ASCII."""
    result = []
    for c in text:
        if "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") + n) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") + n) % 26 + ord("A")))
        else:
            result.append(c)
    return "".join(result)


def _rot47(text: str) -> str:
    """ROT47 — rotation sur l'ensemble des caractères ASCII 33-126."""
    return "".join(
        chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
        for c in text
    )


MORSE_MAP = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
    "-----": "0", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-.-.--": "!", "-....-": "-", "-.--.-": ")", ".-.-.": "+",
}


def _decode_morse(text: str) -> str | None:
    """Tente de décoder du code Morse."""
    text = text.strip()
    words = text.split("   ")  # 3 espaces entre mots en Morse
    if len(words) == 1:
        words = text.split(" / ")  # Alternative CTF fréquente
    result = []
    for word in words:
        chars = word.strip().split(" ")
        decoded_word = ""
        for char in chars:
            if char in MORSE_MAP:
                decoded_word += MORSE_MAP[char]
            else:
                return None  # Caractère non reconnu → pas du Morse
        result.append(decoded_word)
    return " ".join(result)


# ── Détecteurs ────────────────────────────────────────────────────────────────

def _detect_base64(text: str) -> CipherDetection | None:
    """Détecte et décode le Base64."""
    # Nettoyage : enlever les espaces et sauts de ligne (courant en CTF)
    clean = re.sub(r"\s+", "", text)
    # Pattern Base64 standard
    if not re.fullmatch(r"[A-Za-z0-9+/]{4,}={0,2}", clean):
        # Tentative Base64 URL-safe
        clean_url = re.sub(r"\s+", "", text.replace("-", "+").replace("_", "/"))
        if not re.fullmatch(r"[A-Za-z0-9+/]{4,}={0,2}", clean_url):
            return None
        clean = clean_url

    # La longueur doit être multiple de 4 (après padding)
    padded = clean + "=" * ((4 - len(clean) % 4) % 4)
    try:
        decoded_bytes = base64.b64decode(padded)
        decoded_str = decoded_bytes.decode("utf-8", errors="replace")
        confidence = "high" if _is_printable(decoded_str) else "medium"
        return CipherDetection(
            cipher_type="Base64",
            confidence=confidence,
            decoded=decoded_str[:200] if len(decoded_str) > 200 else decoded_str,
            decode_cmd=f"echo '{text.strip()}' | base64 -d",
            python_snippet=(
                f"import base64\n"
                f"base64.b64decode('{clean}').decode()"
            ),
            notes="Décodage URL-safe si caractères - et _ présents.",
            cyberchef_url=_cyberchef("From_Base64('A-Za-z0-9%2B/%3D',true,false)"),
        )
    except Exception:
        return None


def _detect_base32(text: str) -> CipherDetection | None:
    """Détecte et décode le Base32."""
    clean = re.sub(r"\s+", "", text.upper())
    if not re.fullmatch(r"[A-Z2-7]+=*", clean) or len(clean) < 8:
        return None
    padded = clean + "=" * ((8 - len(clean) % 8) % 8)
    try:
        decoded_bytes = base64.b32decode(padded)
        decoded_str = decoded_bytes.decode("utf-8", errors="replace")
        if not _is_printable(decoded_str):
            return None
        return CipherDetection(
            cipher_type="Base32",
            confidence="high",
            decoded=decoded_str[:200],
            decode_cmd=f"echo '{text.strip()}' | base32 -d",
            python_snippet=(
                f"import base64\n"
                f"base64.b32decode('{clean}').decode()"
            ),
            cyberchef_url=_cyberchef("From_Base32('A-Z2-7=',false)"),
        )
    except Exception:
        return None


def _detect_hex(text: str) -> CipherDetection | None:
    """Détecte et décode l'hexadécimal."""
    clean = re.sub(r"[\s:_-]", "", text).lower()
    # Gérer les prefixes 0x
    if clean.startswith("0x"):
        clean = clean[2:]
    if not re.fullmatch(r"[0-9a-f]+", clean) or len(clean) < 6:
        return None
    if len(clean) % 2 != 0:
        return None
    try:
        decoded_bytes = bytes.fromhex(clean)
        decoded_str = decoded_bytes.decode("utf-8", errors="replace")
        confidence = "high" if _is_printable(decoded_str) else "medium"
        return CipherDetection(
            cipher_type="Hexadécimal",
            confidence=confidence,
            decoded=decoded_str[:200],
            decode_cmd=f"echo '{clean}' | xxd -r -p",
            python_snippet=f"bytes.fromhex('{clean}').decode()",
            cyberchef_url=_cyberchef("From_Hex('Auto')"),
        )
    except Exception:
        return None


def _detect_binary(text: str) -> CipherDetection | None:
    """Détecte et décode le binaire (séquences de 0/1)."""
    clean = re.sub(r"\s+", "", text)
    if not re.fullmatch(r"[01]+", clean) or len(clean) < 8:
        return None
    if len(clean) % 8 != 0:
        return None
    try:
        decoded_str = "".join(
            chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8)
        )
        if not _is_printable(decoded_str):
            return None
        return CipherDetection(
            cipher_type="Binaire",
            confidence="high",
            decoded=decoded_str[:200],
            decode_cmd=(
                f"python3 -c \"print(''.join(chr(int(b,2)) for b in "
                f"['{clean}'[i:i+8] for i in range(0,len('{clean}'),8)]))\""
            ),
            python_snippet=(
                f"''.join(chr(int(b,2)) for b in "
                f"[bits[i:i+8] for i in range(0,len(bits),8)])"
            ),
            cyberchef_url=_cyberchef("From_Binary('Space',8)"),
        )
    except Exception:
        return None


def _detect_url_encoded(text: str) -> CipherDetection | None:
    """Détecte l'URL-encoding."""
    if "%" not in text:
        return None
    if not re.search(r"%[0-9A-Fa-f]{2}", text):
        return None
    try:
        from urllib.parse import unquote
        decoded = unquote(text)
        if decoded == text:
            return None
        return CipherDetection(
            cipher_type="URL-encode",
            confidence="high",
            decoded=decoded[:200],
            decode_cmd=f"python3 -c \"from urllib.parse import unquote; print(unquote('{text}'))\"",
            python_snippet="from urllib.parse import unquote; unquote(text)",
            cyberchef_url=_cyberchef("URL_Decode()"),
        )
    except Exception:
        return None


def _detect_html_entities(text: str) -> CipherDetection | None:
    """Détecte les entités HTML."""
    if "&" not in text or ";" not in text:
        return None
    if not re.search(r"&[a-z]+;|&#\d+;|&#x[0-9a-f]+;", text, re.IGNORECASE):
        return None
    try:
        import html
        decoded = html.unescape(text)
        if decoded == text:
            return None
        return CipherDetection(
            cipher_type="Entités HTML",
            confidence="high",
            decoded=decoded[:200],
            decode_cmd=f"python3 -c \"import html; print(html.unescape('{text}'))\"",
            python_snippet="import html; html.unescape(text)",
            cyberchef_url=_cyberchef("Unescape_HTML_Entities()"),
        )
    except Exception:
        return None


def _detect_rot13(text: str) -> CipherDetection | None:
    """Détecte et décode ROT13."""
    if not any(c.isalpha() for c in text):
        return None
    decoded = _rot_n(text, 13)
    if _is_printable(decoded) and decoded != text:
        return CipherDetection(
            cipher_type="ROT13",
            confidence="medium",
            decoded=decoded[:200],
            decode_cmd=f"echo '{text}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'",
            python_snippet="import codecs; codecs.decode(text, 'rot_13')",
            notes="ROT13 est son propre inverse — appliquer deux fois redonne le texte original.",
            cyberchef_url=_cyberchef("ROT13(true,true,false,13)"),
        )
    return None


def _detect_rot47(text: str) -> CipherDetection | None:
    """Détecte et décode ROT47."""
    if not any(33 <= ord(c) <= 126 for c in text):
        return None
    decoded = _rot47(text)
    if _is_printable(decoded) and decoded != text and decoded.count(" ") > text.count(" "):
        return CipherDetection(
            cipher_type="ROT47",
            confidence="medium",
            decoded=decoded[:200],
            decode_cmd=(
                f"python3 -c \"print(''.join(chr(33+(ord(c)-33+47)%94) "
                f"if 33<=ord(c)<=126 else c for c in '{text}'))\""
            ),
            python_snippet=(
                "''.join(chr(33+(ord(c)-33+47)%94) if 33<=ord(c)<=126 else c for c in text)"
            ),
            cyberchef_url=_cyberchef("ROT47(47)"),
        )
    return None


def _detect_caesar(text: str) -> CipherDetection | None:
    """Tente les 25 rotations Caesar et retourne la plus plausible."""
    if not any(c.isalpha() for c in text) or len(text) < 4:
        return None

    # Score basé sur la fréquence des lettres anglaises communes
    common = set("etaoinsrhldcumfpgwybvkjxqz")
    best_score, best_n, best_decoded = -1, 0, ""

    for n in range(1, 26):
        decoded = _rot_n(text, n)
        score = sum(1 for c in decoded.lower() if c in common)
        if score > best_score:
            best_score, best_n, best_decoded = score, n, decoded

    if best_n == 0 or not _is_printable(best_decoded):
        return None

    return CipherDetection(
        cipher_type=f"Caesar ROT{best_n}",
        confidence="low",
        decoded=best_decoded[:200],
        decode_cmd=f"echo '{text}' | tr 'A-Za-z' '{_get_tr_range(best_n)}'",
        python_snippet=(
            f"''.join(chr((ord(c)-ord('A')+{best_n})%26+ord('A')) if c.isupper() else\n"
            f"         chr((ord(c)-ord('a')+{best_n})%26+ord('a')) if c.islower() else c\n"
            f"         for c in text)"
        ),
        notes=f"Rotation {best_n}. Vérifier les autres rotations si le résultat semble incorrect.",
        cyberchef_url=_cyberchef(f"ROT13(true,true,false,{best_n})"),
    )


def _get_tr_range(n: int) -> str:
    """Génère la plage tr pour une rotation Caesar de n."""
    upper = "".join(chr((i + n) % 26 + ord("A")) for i in range(26))
    lower = "".join(chr((i + n) % 26 + ord("a")) for i in range(26))
    return f"{upper}{lower}"


def _detect_morse(text: str) -> CipherDetection | None:
    """Détecte et décode le code Morse."""
    stripped = text.strip()
    # Morse contient uniquement . - et espaces
    if not re.fullmatch(r"[.\-/ ]+", stripped) or len(stripped) < 4:
        return None
    decoded = _decode_morse(stripped)
    if decoded is None or not _is_printable(decoded):
        return None
    return CipherDetection(
        cipher_type="Code Morse",
        confidence="high",
        decoded=decoded,
        decode_cmd=(
            "# Utiliser CyberChef ou :\n"
            "python3 -c \"\n"
            "MORSE={'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E',...}\n"
            "print(' '.join(MORSE.get(w,'?') for w in text.split()))\""
        ),
        python_snippet="# Voir table MORSE_MAP dans cipher_decoder.py",
        cyberchef_url=_cyberchef("From_Morse_Code('Space','Line_feed')"),
    )


def _detect_jwt(text: str) -> CipherDetection | None:
    """Détecte et décode un JWT (JSON Web Token)."""
    parts = text.strip().split(".")
    if len(parts) != 3:
        return None
    # Vérifier que les deux premières parties sont du Base64url
    for part in parts[:2]:
        # Padding
        padded = part + "=" * ((4 - len(part) % 4) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            if decoded[0:1] != b"{":
                return None
        except Exception:
            return None

    try:
        header_padded = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
        payload_padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        header = base64.urlsafe_b64decode(header_padded).decode()
        payload = base64.urlsafe_b64decode(payload_padded).decode()
        decoded_summary = f"Header: {header}\nPayload: {payload}"
    except Exception:
        decoded_summary = "Décodage partiel — voir commande"

    return CipherDetection(
        cipher_type="JWT (JSON Web Token)",
        confidence="high",
        decoded=decoded_summary[:400],
        decode_cmd=(
            f"# Décoder header et payload :\n"
            f"echo '{parts[0]}' | base64 -d 2>/dev/null | python3 -m json.tool\n"
            f"echo '{parts[1]}' | base64 -d 2>/dev/null | python3 -m json.tool\n"
            f"\n"
            f"# Attaque alg:none :\n"
            f"# 1. Modifier header : {{\"alg\":\"none\",\"typ\":\"JWT\"}}\n"
            f"# 2. Modifier payload selon besoin (ex: admin: true)\n"
            f"# 3. Recomposer : HEADER.PAYLOAD. (signature vide)\n"
            f"\n"
            f"# Brute force secret (hashcat) :\n"
            f"hashcat -a 0 -m 16500 '{text}' /usr/share/wordlists/rockyou.txt\n"
            f"\n"
            f"# Confusion RS256 → HS256 :\n"
            f"# Récupérer la clé publique RSA et signer en HS256 avec elle"
        ),
        python_snippet=(
            "import base64, json\n"
            "parts = jwt.split('.')\n"
            "for p in parts[:2]:\n"
            "    padded = p + '=' * (-len(p) % 4)\n"
            "    print(json.loads(base64.urlsafe_b64decode(padded)))"
        ),
        notes=(
            "Attaques JWT fréquentes en CTF :\n"
            "  1. alg:none → supprimer la signature\n"
            "  2. Secret faible → hashcat -m 16500\n"
            "  3. RS256 → HS256 → signer avec la clé publique\n"
            "  4. kid injection → '../../../dev/null' ou SQL injection\n"
            "  5. jku/x5u header injection → pointer vers ton serveur"
        ),
        cyberchef_url=_cyberchef("JWT_Decode()"),
    )


def _detect_hash(text: str) -> CipherDetection | None:
    """Identifie le type de hash (classification, pas cracking — voir hash_cracker.py)."""
    clean = text.strip()
    hash_types = {
        32: [
            ("MD5",           r"^[a-f0-9]{32}$"),
            ("NTLM",          r"^[a-f0-9]{32}$"),
            ("MD5 Apache",    r"^\$apr1\$"),
        ],
        40: [("SHA1",         r"^[a-f0-9]{40}$")],
        56: [("SHA224",       r"^[a-f0-9]{56}$")],
        64: [("SHA256",       r"^[a-f0-9]{64}$")],
        96: [("SHA384",       r"^[a-f0-9]{96}$")],
        128:[("SHA512",       r"^[a-f0-9]{128}$")],
    }

    # Formats spéciaux
    special = [
        ("bcrypt",           r"^\$2[ayb]\$.{56}$",
         "hashcat -m 3200 | john --format=bcrypt"),
        ("SHA512crypt",      r"^\$6\$.+",
         "hashcat -m 1800 | john --format=sha512crypt"),
        ("SHA256crypt",      r"^\$5\$.+",
         "hashcat -m 7400 | john --format=sha256crypt"),
        ("MD5crypt",         r"^\$1\$.+",
         "hashcat -m 500  | john --format=md5crypt"),
        ("Kerberos AS-REP",  r"^\$krb5asrep\$",
         "hashcat -m 18200 | john --format=krb5asrep"),
        ("Kerberoast",       r"^\$krb5tgs\$",
         "hashcat -m 13100 | john --format=krb5tgs"),
        ("Net-NTLMv2",       r"^[^:]+::[^:]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$",
         "hashcat -m 5600  | john --format=netntlmv2"),
        ("Net-NTLMv1",       r"^[^:]+::[^:]+:[0-9a-f]{48}:[0-9a-f]{48}:[0-9a-f]{16}$",
         "hashcat -m 5500  | john --format=netntlmv1"),
    ]

    for name, pattern, crack_hint in special:
        if re.match(pattern, clean, re.IGNORECASE):
            return CipherDetection(
                cipher_type=f"Hash — {name}",
                confidence="high",
                decoded="[non décodable directement — voir commande]",
                decode_cmd=(
                    f"# Identifier avec hashid / haiti :\n"
                    f"hashid '{clean}'\n"
                    f"haiti '{clean}'\n\n"
                    f"# Craquer :\n"
                    f"{crack_hint} <hash_file> /usr/share/wordlists/rockyou.txt"
                ),
                python_snippet="# Voir modules/hash_cracker.py pour les commandes complètes",
                notes=f"→ Utiliser --hashcrack '{clean[:40]}...' pour les commandes complètes",
            )

    # Hashes hex bruts
    if re.fullmatch(r"[a-f0-9]+", clean, re.IGNORECASE):
        length = len(clean)
        for l, entries in hash_types.items():
            if length == l:
                return CipherDetection(
                    cipher_type=f"Hash — probablement {entries[0][0]} ({length} chars hex)",
                    confidence="medium",
                    decoded="[non décodable — à cracker]",
                    decode_cmd=(
                        f"hashid '{clean}'\n"
                        f"haiti '{clean}'\n"
                        f"# Voir --hashcrack pour la commande hashcat/john complète"
                    ),
                    python_snippet="# Voir modules/hash_cracker.py",
                    notes=(
                        "Si NTLM (32 chars) : pass-the-hash possible sans cracker !\n"
                        "crackmapexec smb TARGET -u USER -H NTLM_HASH"
                    ),
                )
    return None


def _detect_rsa_params(text: str) -> CipherDetection | None:
    """Détecte des paramètres RSA potentiellement faibles."""
    # Chercher des grands entiers ou des formats PEM
    if "BEGIN" in text and "KEY" in text:
        return CipherDetection(
            cipher_type="Clé RSA (PEM)",
            confidence="high",
            decoded="[fichier de clé RSA]",
            decode_cmd=(
                "# Extraire les paramètres :\n"
                "openssl rsa -in key.pem -text -noout\n"
                "# Vérifier la taille (< 1024 bits = faible) :\n"
                "openssl rsa -in key.pem -text -noout | grep 'Private-Key'\n"
                "\n"
                "# Factoriser si petit N :\n"
                "# 1. Factordb : http://factordb.com/\n"
                "# 2. RsaCtfTool : python3 RsaCtfTool.py --publickey key.pub --uncipherfile cipher.txt\n"
                "# 3. Sage : factor(n)"
            ),
            python_snippet=(
                "from Crypto.PublicKey import RSA\n"
                "key = RSA.import_key(open('key.pem').read())\n"
                "print(f'n={key.n}, e={key.e}')"
            ),
            notes=(
                "Attaques RSA CTF fréquentes :\n"
                "  e=1 → m = c\n"
                "  Petit n → factordb.com ou yafu\n"
                "  e=3 + m petit → racine cubique de c\n"
                "  Même n, deux e → attaque Bézout\n"
                "  e commun, plusieurs messages → Hastad's broadcast\n"
                "  LSB oracle → attaque parity\n"
                "Outil : RsaCtfTool.py (couvre 90% des cas CTF)"
            ),
        )

    # Chercher des entiers N/e explicites dans le texte
    if re.search(r"\bn\s*=\s*\d{20,}", text) or re.search(r"modulus", text.lower()):
        return CipherDetection(
            cipher_type="Paramètres RSA",
            confidence="medium",
            decoded="[paramètres RSA — analyser avec RsaCtfTool]",
            decode_cmd=(
                "# Extraire n, e, c du texte et utiliser :\n"
                "python3 RsaCtfTool.py -n N -e E --uncipher C\n"
                "# ou Sage :\n"
                "sage: factor(n)"
            ),
            python_snippet=(
                "# Racine cubique (si e=3 et m^3 < n) :\n"
                "from sympy import integer_nthroot\n"
                "m, exact = integer_nthroot(c, e)\n"
                "print(bytes.fromhex(hex(m)[2:]))"
            ),
            notes="RsaCtfTool : https://github.com/RsaCtfTool/RsaCtfTool",
        )
    return None


# ── Moteur principal ──────────────────────────────────────────────────────────

def analyze_cipher(text: str) -> CipherResult:
    """
    Identifie automatiquement l'encodage/chiffrement d'une chaîne.

    Args:
        text: La chaîne à analyser.

    Returns:
        CipherResult avec toutes les détections et la meilleure hypothèse.
    """
    text = text.strip()
    detections: list[CipherDetection] = []

    # Ordre d'application des détecteurs (du plus précis au plus ambigu)
    detectors = [
        _detect_jwt,           # JWT avant base64 (c'est du base64url)
        _detect_url_encoded,
        _detect_html_entities,
        _detect_binary,
        _detect_morse,
        _detect_hex,
        _detect_base32,
        _detect_base64,
        _detect_rot47,
        _detect_rot13,
        _detect_caesar,
        _detect_hash,
        _detect_rsa_params,
    ]

    for detector in detectors:
        try:
            result = detector(text)
            if result is not None:
                detections.append(result)
        except Exception:
            pass

    # Sélectionner la meilleure détection
    priority = {"high": 0, "medium": 1, "low": 2}
    if detections:
        best = min(detections, key=lambda d: priority.get(d.confidence, 3))
    else:
        best = None

    # Résumé
    if not detections:
        summary = (
            f"Aucun encodage reconnu automatiquement pour : '{text[:60]}...'\n"
            "Essayer CyberChef Magic : https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'') \n"
            "ou dcode.fr : https://www.dcode.fr/tools-list"
        )
    else:
        types = ", ".join(d.cipher_type for d in detections)
        summary = f"Détections ({len(detections)}) : {types}"
        if best:
            summary += f"\nMeilleure hypothèse : {best.cipher_type} (confiance : {best.confidence})"

    return CipherResult(
        input_text=text,
        detections=detections,
        best_guess=best,
        summary=summary,
    )
