"""
ChocoScan — Web Fingerprinter.

Détecte activement le CMS, framework ou application web qui tourne
derrière un service HTTP/HTTPS détecté par Nmap, et crée des services
synthétiques que le CVE matcher peut exploiter.

Problème résolu :
  Nmap voit "nginx 1.18.0" → ChocoScan ne matche aucune CVE applicative.
  Ce module fait des requêtes HTTP ciblées et détecte "Craft CMS 5.6.12",
  "WordPress 6.4.2", "Jenkins 2.401.1"... → CVE matching complet.

Méthodes de détection (par ordre de fiabilité) :
  1. Headers HTTP  — X-Powered-By, X-Generator, X-Craft-Version,
                    X-Jenkins, X-Drupal-Cache, kbn-name...
  2. Meta HTML     — <meta name="generator" content="WordPress 6.4.2">
  3. Body patterns — chemins caractéristiques, signatures JS/CSS
  4. Path probing  — /wp-login.php (200), /admin/login (Craft CMS)...
  5. API endpoints — /api/status (Kibana), /wp-json (WordPress)...
  6. Cookies       — CRAFTSESSIONID, MoodleSession, roundcube_sessid...

Applications supportées (50+) :
  CMS     : WordPress, Joomla, Drupal, Craft CMS, Typo3, PrestaShop,
            Magento, OpenCart, CMS Made Simple, Concrete CMS, Ghost,
            Wagtail, Umbraco
  Applis  : Jenkins, GitLab, Gitea, Grafana, Kibana, Elasticsearch,
            Nextcloud, Roundcube, phpMyAdmin, Moodle, Webmin
  Stacks  : Laravel, Django, Rails, ASP.NET, Spring Boot, Symfony

Après détection, crée des entrées résultats compatibles avec le pipeline
ChocoScan (CVE matching, scoring, rapport HTML).

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class WebFingerprint:
    app_name:         str          # "Craft CMS", "WordPress", "Jenkins"...
    service_key:      str          # Clé pour SERVICE_ALIASES : "craft_cms", "wordpress"...
    version:          str          # "5.6.12", "6.4.2", "" si inconnue
    confidence:       str          # "high" | "medium" | "low"
    detection_method: str          # Ce qui a déclenché la détection
    notes:            list[str] = field(default_factory=list)


@dataclass
class WebFingerprintResult:
    host:         str
    port:         int
    protocol:     str              # "http" | "https"
    fingerprints: list[WebFingerprint]
    server:       str              # Header Server brut
    headers:      dict             # Tous les headers de la réponse
    title:        str              # <title> de la page
    status_code:  int
    error:        str = ""


# ── Règles de détection ───────────────────────────────────────────────────────
#
# Format par règle :
#   (app_name, service_key, version_regex_or_None, confidence)
#
# Les règles sont évaluées dans l'ordre — la première match gagne.

# ── Headers HTTP ──────────────────────────────────────────────────────────────

HEADER_RULES: list[tuple[str, str, str, str | None, str]] = [
    # (header_name, pattern_in_value, app_name, service_key, version_regex)
    ("X-Craft-Version",    r".",          "Craft CMS",      "craft_cms",      r"([\d.]+)"),
    ("X-Craft-Token",      r".",          "Craft CMS",      "craft_cms",      None),
    ("X-Jenkins",          r".",          "Jenkins",        "jenkins",        r"([\d.]+)"),
    ("X-Jenkins-Session",  r".",          "Jenkins",        "jenkins",        None),
    ("X-Hudson",           r".",          "Jenkins",        "jenkins",        r"Hudson/([\d.]+)"),
    ("X-Drupal-Cache",     r".",          "Drupal",         "drupal",         None),
    ("X-Drupal-Dynamic-Cache", r".",      "Drupal",         "drupal",         None),
    ("X-Generator",        r"(?i)drupal", "Drupal",         "drupal",         r"Drupal\s+([\d.]+)"),
    ("X-Generator",        r"(?i)joomla", "Joomla",         "joomla",         r"Joomla!\s*([\d.]+)"),
    ("X-Generator",        r"(?i)typo3",  "TYPO3",          "typo3",          r"TYPO3\s+([\d.]+)"),
    ("X-Powered-By",       r"(?i)nextcloud", "Nextcloud",   "nextcloud",      r"Nextcloud\s*([\d.]+)"),
    ("Powered-By",         r"(?i)nextcloud", "Nextcloud",   "nextcloud",      None),
    ("X-Gitlab-Workhorse", r".",          "GitLab",         "gitlab",         r"([\d.]+)"),
    ("X-Gitea-Version",    r".",          "Gitea",          "gitea",          r"([\d.]+)"),
    ("X-Gitea-Object-Format", r".",       "Gitea",          "gitea",          None),
    ("X-Frame-Options",    r".",          "",               "",               None),  # skip
    ("kbn-name",           r".",          "Kibana",         "kibana",         None),
    ("kbn-version",        r".",          "Kibana",         "kibana",         r"([\d.]+)"),
    ("X-Webmin-Version",   r".",          "Webmin",         "webmin",         r"([\d.]+)"),
    ("X-Roundcube-Skin",   r".",          "Roundcube",      "roundcube",      None),
    ("X-Moodle-Version",   r".",          "Moodle",         "moodle",         r"([\d.]+)"),
    ("X-Opencart-Version", r".",          "OpenCart",       "opencart",       r"([\d.]+)"),
    ("X-Umbraco-Version",  r".",          "Umbraco",        "umbraco",        r"([\d.]+)"),
    ("X-Ghost-Cache-Status", r".",        "Ghost",          "ghost",          None),
    ("X-Wagtail-Version",  r".",          "Wagtail",        "wagtail",        r"([\d.]+)"),
    ("X-Wix-Meta-Site-Id", r".",          "Wix",            "wix",            None),
    ("X-Shopify-Stage",    r".",          "Shopify",        "shopify",        None),
    ("X-AspNet-Version",   r".",          "ASP.NET",        "aspnet",         r"([\d.]+)"),
    ("X-Powered-By",       r"(?i)asp\.net","ASP.NET",       "aspnet",         None),
]

# ── Cookies caractéristiques ──────────────────────────────────────────────────

COOKIE_RULES: list[tuple[str, str, str, str]] = [
    # (cookie_name_pattern, app_name, service_key, confidence)
    (r"CRAFTSESSIONID",   "Craft CMS",    "craft_cms",    "high"),
    (r"craft_csrf_token", "Craft CMS",    "craft_cms",    "high"),
    (r"wordpress_",       "WordPress",    "wordpress",    "high"),
    (r"wp-settings-",     "WordPress",    "wordpress",    "high"),
    (r"PHPSESSID",        "",             "",             "low"),   # skip (trop générique)
    (r"MoodleSession",    "Moodle",       "moodle",       "high"),
    (r"roundcube_sessid", "Roundcube",    "roundcube",    "high"),
    (r"roundcube_",       "Roundcube",    "roundcube",    "medium"),
    (r"GitLab_Session",   "GitLab",       "gitlab",       "high"),
    (r"grafana_sess",     "Grafana",      "grafana",      "high"),
    (r"oc_sessionPassphrase", "Nextcloud", "nextcloud",   "high"),
    (r"nc_sameSiteCookieLax", "Nextcloud", "nextcloud",   "high"),
    (r"PrestaShop-",      "PrestaShop",   "prestashop",   "high"),
    (r"magento",          "Magento",      "magento",      "medium"),
    (r"frontend",         "Magento",      "magento",      "low"),
    (r"typo3",            "TYPO3",        "typo3",        "high"),
    (r"joomla_user_state","Joomla",       "joomla",       "high"),
    (r"b1e24ca0db",       "Joomla",       "joomla",       "medium"),
    (r"Drupal\.",         "Drupal",       "drupal",       "high"),
    (r"SESSi?[0-9a-f]+",  "Drupal",       "drupal",       "medium"),
]

# ── Patterns dans le body HTML ────────────────────────────────────────────────

BODY_RULES: list[tuple[str, str, str, str, str | None]] = [
    # (regex_pattern, app_name, service_key, confidence, version_regex)
    (r"(?i)wp-content/",          "WordPress",   "wordpress",   "high",   None),
    (r"(?i)wp-includes/",         "WordPress",   "wordpress",   "high",   None),
    (r"(?i)/wp-json/",            "WordPress",   "wordpress",   "high",   None),
    (r"(?i)wpengine",             "WordPress",   "wordpress",   "medium", None),
    (r"(?i)csrfTokenName.*craft", "Craft CMS",   "craft_cms",   "high",   None),
    (r"(?i)craftcms",             "Craft CMS",   "craft_cms",   "high",   None),
    (r"(?i)/craft/app/",          "Craft CMS",   "craft_cms",   "high",   None),
    (r"(?i)application/json.*craft", "Craft CMS","craft_cms",   "medium", None),
    (r"(?i)/components/com_",     "Joomla",      "joomla",      "high",   None),
    (r"(?i)joomla!",              "Joomla",      "joomla",      "high",   None),
    (r"(?i)Drupal\.settings",     "Drupal",      "drupal",      "high",   None),
    (r"(?i)/sites/default/files/","Drupal",      "drupal",      "high",   None),
    (r"(?i)Mage\.Cookies",        "Magento",     "magento",     "high",   None),
    (r"(?i)/skin/frontend/",      "Magento",     "magento",     "high",   None),
    (r"(?i)typo3/",               "TYPO3",       "typo3",       "high",   None),
    (r"(?i)prestashop",           "PrestaShop",  "prestashop",  "high",   None),
    (r"(?i)/modules/presta",      "PrestaShop",  "prestashop",  "high",   None),
    (r"(?i)data-moodle",          "Moodle",      "moodle",      "high",   None),
    (r"(?i)M\.str\s*=",           "Moodle",      "moodle",      "medium", None),
    (r"(?i)oc_token",             "Nextcloud",   "nextcloud",   "high",   None),
    (r"(?i)nextcloud",            "Nextcloud",   "nextcloud",   "high",   None),
    (r"(?i)ghost-url",            "Ghost",       "ghost",       "high",   None),
    (r"(?i)data-ghost-root",      "Ghost",       "ghost",       "high",   None),
    (r"(?i)roundcube",            "Roundcube",   "roundcube",   "high",   None),
    (r"(?i)grafana",              "Grafana",     "grafana",     "medium", None),
    (r"(?i)ng-version=",          "Angular",     "angular",     "medium",
     r'ng-version="([\d.]+)"'),
    (r"(?i)__NEXT_DATA__",        "Next.js",     "nextjs",      "high",   None),
    (r"(?i)__nuxt",               "Nuxt.js",     "nuxtjs",      "high",   None),
    (r"(?i)laravel_session",      "Laravel",     "laravel",     "high",   None),
    (r"(?i)csrf-token.*laravel",  "Laravel",     "laravel",     "medium", None),
    (r"(?i)django",               "Django",      "django",      "low",    None),
    (r"(?i)csrfmiddlewaretoken",  "Django",      "django",      "medium", None),
    (r"(?i)spring",               "Spring Boot", "spring",      "low",    None),
    (r"(?i)Whoa there",           "Webmin",      "webmin",      "high",   None),
    (r"(?i)webmin",               "Webmin",      "webmin",      "high",   None),
    (r"(?i)phpMyAdmin",           "phpMyAdmin",  "phpmyadmin",  "high",   None),
    (r"(?i)pma_",                 "phpMyAdmin",  "phpmyadmin",  "medium", None),
    (r"(?i)opencart",             "OpenCart",    "opencart",    "high",   None),
    (r"(?i)/index.php\?route=",   "OpenCart",    "opencart",    "high",   None),
    (r"(?i)concrete5",            "Concrete CMS","concrete5",   "high",   None),
    (r"(?i)/ccm/assets/",         "Concrete CMS","concrete5",   "high",   None),
    (r"(?i)/cms/page/",           "CMS Made Simple","cmsms",    "high",   None),
    (r"(?i)cmsmadesimple",        "CMS Made Simple","cmsms",    "high",   None),
    (r"(?i)wagtail",              "Wagtail",     "wagtail",     "medium", None),
]

# ── Paths à sonder ────────────────────────────────────────────────────────────
# Format : (path, attendu_status, app_name, service_key, confidence)
# Sondés uniquement si aucune autre détection n'a abouti (mode confirmatoire)

PROBE_PATHS: list[tuple[str, int, str, str, str]] = [
    # WordPress
    ("/wp-login.php",               200, "WordPress",    "wordpress",   "high"),
    ("/wp-admin/",                  200, "WordPress",    "wordpress",   "high"),
    ("/wp-json/wp/v2/",             200, "WordPress",    "wordpress",   "high"),
    # Craft CMS
    ("/index.php?p=admin/login",    200, "Craft CMS",    "craft_cms",   "high"),
    ("/actions/users/session-info", 200, "Craft CMS",    "craft_cms",   "high"),
    # Joomla
    ("/administrator/",             200, "Joomla",       "joomla",      "medium"),
    ("/index.php?option=com_users", 200, "Joomla",       "joomla",      "high"),
    # Drupal
    ("/user/login",                 200, "Drupal",       "drupal",      "medium"),
    ("/core/misc/drupal.js",        200, "Drupal",       "drupal",      "high"),
    # Jenkins
    ("/login",                      200, "Jenkins",      "jenkins",     "low"),
    ("/api/json",                   200, "Jenkins",      "jenkins",     "medium"),
    # GitLab
    ("/users/sign_in",              200, "GitLab",       "gitlab",      "medium"),
    ("/-/health",                   200, "GitLab",       "gitlab",      "high"),
    # Grafana
    ("/api/health",                 200, "Grafana",      "grafana",     "high"),
    ("/login",                      200, "Grafana",      "grafana",     "low"),
    # Kibana
    ("/api/status",                 200, "Kibana",       "kibana",      "high"),
    # Nextcloud
    ("/ocs/v1.php/cloud/capabilities", 200, "Nextcloud", "nextcloud",  "high"),
    ("/status.php",                 200, "Nextcloud",    "nextcloud",   "high"),
    # phpMyAdmin
    ("/phpmyadmin/",                200, "phpMyAdmin",   "phpmyadmin",  "high"),
    ("/pma/",                       200, "phpMyAdmin",   "phpmyadmin",  "high"),
    # Roundcube
    ("/?_task=login",               200, "Roundcube",    "roundcube",   "medium"),
    # Moodle
    ("/login/index.php",            200, "Moodle",       "moodle",      "medium"),
    # Webmin
    ("/session_login.cgi",          200, "Webmin",       "webmin",      "high"),
    # PrestaShop
    ("/admin/",                     200, "PrestaShop",   "prestashop",  "low"),
    # Magento
    ("/magento_version",            200, "Magento",      "magento",     "high"),
    # Ghost
    ("/ghost/",                     200, "Ghost",        "ghost",       "high"),
    # Gitea
    ("/api/swagger",                200, "Gitea",        "gitea",       "high"),
    ("/-/api/v4/version",           200, "Gitea",        "gitea",       "medium"),
]

# ── Endpoints API pour récupérer la version ───────────────────────────────────

VERSION_API_ENDPOINTS: list[tuple[str, str, str]] = [
    # (path, app_name, json_version_key_path)
    ("/wp-json/",                           "WordPress",   "$.namespaces"),
    ("/api/health",                         "Grafana",     "$.version"),
    ("/api/status",                         "Kibana",      "$.version.number"),
    ("/ocs/v1.php/cloud/capabilities",      "Nextcloud",   "$.ocs.data.version.string"),
    ("/status.php",                         "Nextcloud",   "$.versionstring"),
    ("/api/v1/version",                     "Gitea",       "$.version"),
    ("/api/json?pretty=true",              "Jenkins",     "$.version"),
    ("/-/health",                           "GitLab",      "$.status"),
    ("/api/v4/version",                     "GitLab",      "$.version"),
]


# ── Meta generator ────────────────────────────────────────────────────────────

META_RULES: list[tuple[str, str, str]] = [
    # (pattern_in_content, app_name, service_key)
    (r"(?i)wordpress\s*([\d.]+)",     "WordPress",   "wordpress"),
    (r"(?i)joomla!\s*([\d.]+)",       "Joomla",      "joomla"),
    (r"(?i)drupal\s*([\d.]+)?",       "Drupal",      "drupal"),
    (r"(?i)typo3\s*([\d.]+)?",        "TYPO3",       "typo3"),
    (r"(?i)moodle\s*([\d.]+)?",       "Moodle",      "moodle"),
    (r"(?i)concrete\s?cms\s*([\d.]+)?","Concrete CMS","concrete5"),
    (r"(?i)ghost\s*([\d.]+)?",        "Ghost",       "ghost"),
    (r"(?i)wagtail\s*([\d.]+)?",      "Wagtail",     "wagtail"),
    (r"(?i)nextcloud\s*([\d.]+)?",    "Nextcloud",   "nextcloud"),
]


# ── Requête HTTP ──────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: float = 5.0, allow_redirects: bool = True) -> tuple[int, dict, str] | None:
    """Effectue une requête GET et retourne (status, headers, body[:8000])."""
    if not REQUESTS_OK:
        return None
    try:
        r = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=allow_redirects,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ChocoScan/1.0)"},
        )
        return r.status_code, dict(r.headers), r.text[:8000]
    except Exception:
        return None


# ── Extraction de version ─────────────────────────────────────────────────────

def _extract_version(text: str, pattern: str) -> str:
    """Extrait une version depuis un texte avec un pattern regex."""
    if not pattern:
        return ""
    m = re.search(pattern, text)
    return m.group(1) if m else ""


def _extract_meta_generator(html: str) -> tuple[str, str]:
    """Extrait le contenu du meta generator."""
    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']',
        html, re.IGNORECASE
    )
    if not m:
        m = re.search(
            r'<meta[^>]+content=["\'](.*?)["\'][^>]+name=["\']generator["\']',
            html, re.IGNORECASE
        )
    return m.group(1) if m else ""


def _extract_title(html: str) -> str:
    """Extrait le titre de la page."""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:100] if m else ""


def _get_json_value(data: dict, path: str) -> str:
    """Navigue dans un dict JSON selon un chemin '$.key1.key2'."""
    keys = path.lstrip("$").lstrip(".").split(".")
    current = data
    for k in keys:
        if isinstance(current, dict) and k in current:
            current = current[k]
        else:
            return ""
    return str(current) if current else ""


# ── Moteur de fingerprinting ──────────────────────────────────────────────────

def fingerprint_service(host: str, port: int, protocol: str) -> WebFingerprintResult:
    """
    Fingerprinte un service web en analysant headers, body et paths connus.

    Args:
        host:     IP ou hostname de la cible
        port:     Port du service
        protocol: "http" ou "https"

    Returns:
        WebFingerprintResult avec toutes les détections
    """
    base_url = f"{protocol}://{host}:{port}"
    fingerprints: list[WebFingerprint] = []
    detected_keys: set[str] = set()   # Éviter les doublons

    def add_fp(app_name, service_key, version, confidence, method):
        if not app_name or not service_key:
            return
        if service_key in detected_keys and confidence != "high":
            return
        detected_keys.add(service_key)
        fingerprints.append(WebFingerprint(
            app_name=app_name,
            service_key=service_key,
            version=version,
            confidence=confidence,
            detection_method=method,
        ))

    # ── Requête principale ────────────────────────────────────────────────────
    resp = _fetch(base_url + "/", timeout=5.0)
    if resp is None:
        return WebFingerprintResult(
            host=host, port=port, protocol=protocol,
            fingerprints=[], server="", headers={},
            title="", status_code=0,
            error="Connexion impossible",
        )

    status, headers, body = resp
    headers_lower = {k.lower(): v for k, v in headers.items()}
    server = headers.get("Server", headers.get("server", ""))
    title  = _extract_title(body)

    # ── 1. Headers HTTP ───────────────────────────────────────────────────────
    for hdr_name, val_pattern, app_name, service_key, ver_regex in HEADER_RULES:
        if not service_key:
            continue
        hdr_val = headers.get(hdr_name, headers.get(hdr_name.lower(), ""))
        if hdr_val and re.search(val_pattern, hdr_val):
            version = _extract_version(hdr_val, ver_regex) if ver_regex else ""
            add_fp(app_name, service_key, version, "high",
                   f"Header {hdr_name}: {hdr_val[:60]}")

    # ── 2. Cookies ────────────────────────────────────────────────────────────
    set_cookie = headers.get("Set-Cookie", headers.get("set-cookie", ""))
    for cookie_pat, app_name, service_key, confidence in COOKIE_RULES:
        if not service_key:
            continue
        if re.search(cookie_pat, set_cookie, re.IGNORECASE):
            add_fp(app_name, service_key, "", confidence,
                   f"Cookie: {cookie_pat}")

    # ── 3. Meta generator ─────────────────────────────────────────────────────
    meta_content = _extract_meta_generator(body)
    if meta_content:
        for pattern, app_name, service_key in META_RULES:
            m = re.search(pattern, meta_content, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex else ""
                add_fp(app_name, service_key, version, "high",
                       f"meta generator: {meta_content[:60]}")

    # ── 4. Body patterns ──────────────────────────────────────────────────────
    for pattern, app_name, service_key, confidence, ver_regex in BODY_RULES:
        if re.search(pattern, body):
            version = _extract_version(body, ver_regex) if ver_regex else ""
            add_fp(app_name, service_key, version, confidence,
                   f"Body pattern: {pattern[:40]}")

    # ── 5. Endpoints API (version précise) ────────────────────────────────────
    for path, app_name, json_key in VERSION_API_ENDPOINTS:
        if app_name.lower().replace(" ", "_").replace(".", "") not in \
           {k.replace("_", "") for k in detected_keys}:
            # Ne sonder l'endpoint que si l'app est déjà détectée
            continue
        api_resp = _fetch(base_url + path, timeout=3.0)
        if api_resp and api_resp[0] == 200:
            try:
                data = json.loads(api_resp[2])
                ver = _get_json_value(data, json_key)
                if ver:
                    # Mettre à jour la version de la détection existante
                    for fp in fingerprints:
                        if fp.app_name == app_name and not fp.version:
                            fp.version = ver
                            fp.notes.append(f"Version récupérée via {path}")
            except (json.JSONDecodeError, Exception):
                pass

    # ── 6. Path probing (si peu de détections) ────────────────────────────────
    if len(detected_keys) < 2:
        for path, exp_status, app_name, service_key, confidence in PROBE_PATHS:
            if service_key in detected_keys:
                continue
            probe = _fetch(base_url + path, timeout=3.0)
            if probe and probe[0] == exp_status:
                # Confirmer par un pattern dans le body
                _, _, pbody = probe
                add_fp(app_name, service_key, "", confidence,
                       f"Path probe {path} → {exp_status}")

    # ── 7. Version WordPress depuis /wp-json/ ──────────────────────────────────
    if "wordpress" in detected_keys:
        wp_resp = _fetch(base_url + "/wp-json/", timeout=3.0)
        if wp_resp and wp_resp[0] == 200:
            try:
                wp_data = json.loads(wp_resp[2])
                ver = wp_data.get("gmt_offset", "")
                # Version dans wp-includes/version.php pas accessible directement
                # Chercher dans le body
                ver_m = re.search(r'"version"\s*:\s*"([\d.]+)"', wp_resp[2])
                if ver_m:
                    for fp in fingerprints:
                        if fp.service_key == "wordpress" and not fp.version:
                            fp.version = ver_m.group(1)
            except Exception:
                pass

        # Chercher la version dans les URLs de ressources
        ver_m = re.search(r"wp-includes/[^'\"]+\?ver=([\d.]+)", body)
        if ver_m:
            for fp in fingerprints:
                if fp.service_key == "wordpress" and not fp.version:
                    fp.version = ver_m.group(1)
                    fp.notes.append("Version extraite des URLs de ressources")

    # ── 8. Craft CMS — version via headers ou login page ──────────────────────
    if "craft_cms" not in detected_keys:
        # Essayer /index.php?p=admin/login
        cp_resp = _fetch(base_url + "/index.php?p=admin/login", timeout=3.0)
        if cp_resp and cp_resp[0] == 200 and "craft" in cp_resp[2].lower():
            ver_m = re.search(r"Craft\s+CMS\s+([\d.]+)", cp_resp[2], re.IGNORECASE)
            add_fp("Craft CMS", "craft_cms",
                   ver_m.group(1) if ver_m else "",
                   "high", "Admin login page Craft CMS")

    return WebFingerprintResult(
        host=host,
        port=port,
        protocol=protocol,
        fingerprints=fingerprints,
        server=server,
        headers=headers,
        title=title,
        status_code=status,
    )


# ── Fingerprinting de tous les services web ───────────────────────────────────

def fingerprint_all(results: list[dict]) -> list[WebFingerprintResult]:
    """
    Fingerprinte tous les services HTTP/HTTPS détectés dans les résultats.

    Args:
        results: Résultats ChocoScan (liste de dicts avec clé 'service').

    Returns:
        Liste de WebFingerprintResult, un par service web sondé.
    """
    if not REQUESTS_OK:
        return []

    fp_results: list[WebFingerprintResult] = []
    seen: set[tuple] = set()

    for r in results:
        svc  = r.get("service", {})
        port = svc.get("port", 0) or 0
        host = svc.get("host", "") or ""
        svc_name = (svc.get("service_name", "") or "").lower()

        # Filtre : uniquement HTTP/HTTPS
        is_web = (
            port in (80, 443, 8080, 8443, 8000, 8001, 8888, 3000, 5000, 9000, 9443)
            or "http" in svc_name
            or "ssl" in svc_name
        )
        if not is_web or not host:
            continue

        protocol = "https" if (port in (443, 8443) or "ssl" in svc_name) else "http"
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)

        fp = fingerprint_service(host, port, protocol)
        fp_results.append(fp)

    return fp_results


# ── Conversion en services synthétiques pour le CVE matcher ──────────────────

def fingerprints_to_synthetic_results(fp_results: list[WebFingerprintResult]) -> list[dict]:
    """
    Convertit les résultats de fingerprinting en dicts compatibles
    avec le pipeline ChocoScan (CVE matcher, scoring, rapport).

    Chaque application détectée devient un service distinct avec
    le product/version/banner correct pour que le CVE matcher
    trouve les CVE correspondantes.

    Args:
        fp_results: Résultats de fingerprint_all().

    Returns:
        Liste de dicts service prêts à être ajoutés aux résultats.
    """
    synthetic: list[dict] = []

    for fp in fp_results:
        for fingerprint in fp.fingerprints:
            if not fingerprint.service_key:
                continue

            version = fingerprint.version or ""
            banner  = f"{fingerprint.app_name} {version}".strip()

            synthetic.append({
                "service": {
                    "host":         fp.host,
                    "port":         fp.port,
                    "protocol":     fp.protocol,
                    "state":        "open",
                    "service_name": fingerprint.service_key,
                    "product":      fingerprint.app_name,
                    "version":      version,
                    "extrainfo":    f"Détecté par web fingerprinting ({fingerprint.confidence})",
                    "banner":       banner,
                },
                "cves":   [],
                "_source": "web_fingerprint",
                "_fingerprint_confidence": fingerprint.confidence,
                "_detection_method": fingerprint.detection_method,
            })

    return synthetic
