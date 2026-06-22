"""
ChocoScan — Résolution CPE (Common Platform Enumeration).

Transforme un (service_key, version) détecté en identifiant CPE 2.3
normalisé NVD, pour des requêtes API plus précises (cpeName) que le
matching texte actuel (keywordSearch), et pour enrichir la base
locale avec des CPE.

Stratégie hybride :
    1. Table statique PRODUCT_CPE_MAP pour les produits courants
       (rapide, zéro latence, zéro dépendance réseau)
    2. Fallback API NVD CPE Dictionary si non trouvé en statique,
       avec cache disque (même pattern que le cache CVE existant)

Format CPE 2.3 : cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    (on ne gère que part="a" — applications — les services qu'on
    scanne ne sont pas des OS ni du matériel)

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import json
import time
import requests
from pathlib import Path
from datetime import datetime, timedelta

try:
    from modules.cve_matcher import get_nvd_api_key, _warn_no_api_key_once
except ImportError:
    def get_nvd_api_key():
        return None
    def _warn_no_api_key_once():
        pass


# ── Table statique service_key → (vendor, product) ──────────────────────
#
# Couvre les entrées les plus fréquentes de SERVICE_ALIASES (cve_matcher.py).
# Vendor/product proviennent du dictionnaire CPE officiel NVD
# (https://nvd.nist.gov/products/cpe/search).

PRODUCT_CPE_MAP: dict[str, tuple[str, str]] = {
    "openssh":       ("openbsd", "openssh"),
    "apache":        ("apache", "http_server"),
    "nginx":         ("nginx", "nginx"),
    "vsftpd":        ("vsftpd_project", "vsftpd"),
    "proftpd":       ("proftpd", "proftpd"),
    "mysql":         ("mysql", "mysql"),
    "postgresql":    ("postgresql", "postgresql"),
    "smb":           ("samba", "samba"),
    "samba":         ("samba", "samba"),
    "rdp":           ("microsoft", "remote_desktop_services"),
    "iis":           ("microsoft", "internet_information_services"),
    "php":           ("php", "php"),
    "ssl":           ("openssl", "openssl"),
    "telnet":        ("gnu", "inetutils"),
    "smtp":          ("postfix", "postfix"),
    "tomcat":        ("apache", "tomcat"),
    "vnc":           ("realvnc", "vnc"),
    "redis":         ("redis", "redis"),
    "mongodb":       ("mongodb", "mongodb"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "wordpress":     ("wordpress", "wordpress"),
    "drupal":        ("drupal", "drupal"),
    "joomla":        ("joomla", "joomla\\!"),
    "jenkins":       ("jenkins", "jenkins"),
    "docker":        ("docker", "docker"),
    "dns":           ("isc", "bind"),
    "rsync":         ("samba", "rsync"),
    "memcached":     ("memcached", "memcached"),
    "gitlab":        ("gitlab", "gitlab"),
    "confluence":    ("atlassian", "confluence"),
    "spring":        ("vmware", "spring_framework"),
    "fortinet":      ("fortinet", "fortios"),
    "vmware":        ("vmware", "vcenter_server"),
    "citrix":        ("citrix", "netscaler_application_delivery_controller"),
    "snmp":          ("net-snmp", "net-snmp"),
    "glibc":         ("gnu", "glibc"),
    "openssl":       ("openssl", "openssl"),
}


# ── Cache disque pour le fallback API CPE Dictionary ─────────────────────

CPE_CACHE_PATH = Path(__file__).parent.parent / "data" / "cpe_cache.json"
CPE_CACHE_TTL_HOURS = 24 * 7  # les CPE bougent peu, cache plus long que les CVE

NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def _load_cpe_cache() -> dict:
    if not CPE_CACHE_PATH.exists():
        return {}
    try:
        with open(CPE_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cpe_cache(cache: dict):
    try:
        CPE_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CPE_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def _cache_is_valid(entry: dict) -> bool:
    try:
        cached_at = datetime.fromisoformat(entry["_cached_at"])
        return datetime.now() - cached_at < timedelta(hours=CPE_CACHE_TTL_HOURS)
    except (KeyError, ValueError):
        return False


# ── Résolution ─────────────────────────────────────────────────────────

def build_cpe_string(vendor: str, product: str, version: str = "*") -> str:
    """Construit un identifiant CPE 2.3 à partir de vendor/product/version."""
    version = version.strip() if version else "*"
    version = version or "*"
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def resolve_cpe_static(service_key: str, version: str = "") -> str | None:
    """Résolution rapide via la table statique PRODUCT_CPE_MAP."""
    entry = PRODUCT_CPE_MAP.get(service_key)
    if not entry:
        return None
    vendor, product = entry
    return build_cpe_string(vendor, product, version)


def resolve_cpe_api(product_name: str, use_cache: bool = True) -> str | None:
    """
    Résout un CPE via l'API NVD CPE Dictionary (keywordSearch),
    avec cache disque pour éviter de re-requêter le même produit.

    Le cache est sauvegardé immédiatement après chaque résolution
    (succès ou échec) pour ne perdre aucun travail en cas
    d'interruption (timeout, Ctrl+C, coupure réseau).

    Retourne le CPE le plus pertinent (premier résultat) sans la
    version (générique, ex: cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*),
    ou None si rien trouvé / erreur réseau.
    """
    cache_key = product_name.lower().strip()
    cache = _load_cpe_cache() if use_cache else {}

    if use_cache and cache_key in cache and _cache_is_valid(cache[cache_key]):
        return cache[cache_key].get("cpe")

    api_key = get_nvd_api_key()
    if not api_key:
        _warn_no_api_key_once()

    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": product_name, "resultsPerPage": 1}

    try:
        # Rate limit minimal de courtoisie sans clé API
        if not api_key:
            time.sleep(6)
        resp = requests.get(NVD_CPE_API_URL, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, json.JSONDecodeError):
        return None

    products = data.get("products", [])
    if not products:
        cache[cache_key] = {"cpe": None, "_cached_at": datetime.now().isoformat()}
        if use_cache:
            _save_cpe_cache(cache)  # écriture immédiate : pas de perte si interruption après
        return None

    cpe_name = products[0].get("cpe", {}).get("cpeName")

    cache[cache_key] = {"cpe": cpe_name, "_cached_at": datetime.now().isoformat()}
    if use_cache:
        _save_cpe_cache(cache)  # écriture immédiate : pas de perte si interruption après

    return cpe_name


def resolve_cpe(service_key: str, product_name: str = "", version: str = "",
                 use_api_fallback: bool = True) -> str | None:
    """
    Point d'entrée principal : résout un CPE pour un service donné.

    1. Essaie la table statique (rapide, zéro latence)
    2. Fallback API NVD CPE Dictionary si rien trouvé en statique
       et qu'un nom de produit est fourni

    `service_key` : la clé normalisée (ex: "openssh", "apache")
    `product_name` : nom brut éventuel pour le fallback API (ex: banner Nmap)
    """
    static_result = resolve_cpe_static(service_key, version)
    if static_result:
        return static_result

    if use_api_fallback and product_name:
        base_cpe = resolve_cpe_api(product_name)
        if base_cpe:
            # Injecte la version dans le CPE générique retourné par l'API
            parts = base_cpe.split(":")
            if len(parts) >= 6:
                parts[5] = version if version else "*"
                return ":".join(parts)
            return base_cpe

    return None
