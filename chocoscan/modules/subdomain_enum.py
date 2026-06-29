"""
ChocoScan — Module d'énumération de sous-domaines.

Deux modes complémentaires :
  - Passif  : interroge crt.sh (Certificate Transparency), HackerTarget
               et RapidDNS sans envoyer de paquets vers la cible.
  - Actif   : bruteforce DNS via socket (threading), avec détection
               wildcard préalable pour éviter les faux positifs.

Le module génère également les commandes pour les outils externes
courants (subfinder, amass, dnsx, gobuster dns, dnsrecon, theHarvester)
avec les flags optimisés pour HTB / CTF et Bug Bounty.

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import socket
import threading
import time
import re
import random
import string
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
    from rich.rule import Rule
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None


# ── Wordlist embarquée ────────────────────────────────────────────────────────
# ~250 sous-domaines les plus fréquents (CTF + prod réelle)
# Pour un bruteforce complet, utiliser --sub-wordlist avec SecLists

BUILTIN_WORDLIST: list[str] = [
    # Très communs
    "www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "ns", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2",
    # Admin / accès
    "admin", "administrator", "panel", "cpanel", "whm", "webmail", "portal",
    "manage", "management", "control", "dashboard", "backend", "backoffice",
    "staff", "helpdesk", "support", "servicedesk", "crm",
    # Dev / staging
    "dev", "develop", "development", "stage", "staging", "pre", "preprod",
    "preprod", "qa", "uat", "test", "testing", "demo", "sandbox",
    "beta", "alpha", "preview", "lab", "labs",
    # Infra
    "api", "api2", "api3", "rest", "graphql", "gateway", "gw",
    "proxy", "vpn", "remote", "rdp", "bastion", "jump", "ssh",
    "git", "gitlab", "github", "svn", "repo", "registry",
    "ci", "cd", "jenkins", "travis", "drone", "build",
    "docker", "k8s", "kubernetes", "rancher", "harbor",
    "monitor", "monitoring", "metrics", "grafana", "prometheus",
    "kibana", "elk", "splunk", "nagios", "zabbix",
    "logger", "logging", "log", "logs",
    # Apps web
    "blog", "shop", "store", "ecommerce", "cart",
    "forum", "community", "wiki", "docs", "doc", "help",
    "static", "assets", "cdn", "media", "img", "images",
    "download", "downloads", "files", "uploads", "upload",
    # DB / services internes
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "kafka", "rabbitmq", "mq", "queue",
    "cache", "memcache", "memcached",
    # Cloud / infra moderne
    "s3", "storage", "backup", "archive",
    "auth", "oauth", "sso", "login", "id", "identity",
    "pay", "payment", "billing", "invoice",
    # HTB/CTF spécifiques
    "internal", "intranet", "local", "private", "hidden", "secret",
    "uat", "corp", "office", "it", "hr", "finance",
    "ops", "devops", "sre", "security", "infosec",
    "erp", "sap", "jira", "confluence", "trello",
    "waf", "firewall", "router",
    "old", "legacy", "v1", "v2", "new",
    "web", "web1", "web2", "app", "app1", "app2",
    "server", "server1", "server2", "host", "host1",
    "mx0", "mx3", "mail1", "mail2", "smtp1", "smtp2",
    "autodiscover", "autoconfig", "exchange",
    "citrix", "remote", "workspace",
    "mobile", "m", "wap",
    "news", "press", "media",
    "status", "health", "ping",
    "owa", "webaccess",
    "extranet", "partner", "vendor", "client",
    "data", "report", "reports", "analytics",
    "chat", "slack", "messaging",
    "video", "stream", "live",
    "vpn1", "vpn2", "ras",
]

# Wordlists SecLists recommandées pour un bruteforce complet
SECLISTS_WORDLISTS = {
    "small":  "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "medium": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "large":  "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    "jhaddix": "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",
    "bitquark": "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
}


# ── Modèles de données ────────────────────────────────────────────────────────

@dataclass
class Subdomain:
    name:      str          # sous-domaine complet (ex: api.target.htb)
    ip:        Optional[str]  # IP résolue (None si non résolu)
    source:    str          # crtsh | hackertarget | rapiddns | dns_brute | manual
    cname:     Optional[str] = None  # CNAME si détecté
    status:    str = "found"  # found | wildcard | nxdomain | error


@dataclass
class SubdomainResult:
    domain:             str
    subdomains:         list[Subdomain]     = field(default_factory=list)
    wildcard_detected:  bool               = False
    wildcard_ip:        Optional[str]       = None
    passive_count:      int                = 0
    active_count:       int                = 0
    commands:           list[dict]         = field(default_factory=list)
    errors:             list[str]          = field(default_factory=list)
    notes:              list[str]          = field(default_factory=list)


# ── Utilitaires DNS ───────────────────────────────────────────────────────────

def _resolve(hostname: str, timeout: float = 2.0) -> Optional[str]:
    """Résoud un hostname en IP. Retourne None si NXDOMAIN/timeout."""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(None)


def _detect_wildcard(domain: str) -> tuple[bool, Optional[str]]:
    """
    Détecte un wildcard DNS en résolvant un sous-domaine aléatoire.
    Si *.domain répond, tout bruteforce serait un faux positif.
    """
    rand_prefix = "".join(random.choices(string.ascii_lowercase, k=16))
    test_host   = f"{rand_prefix}.{domain}"
    ip = _resolve(test_host)
    if ip:
        return True, ip
    return False, None


# ── Recon passif ─────────────────────────────────────────────────────────────

def _passive_crtsh(domain: str, timeout: int = 10) -> list[Subdomain]:
    """
    Interroge crt.sh (Certificate Transparency logs).
    Source la plus riche pour les domaines publics.
    """
    if not REQUESTS_AVAILABLE:
        return []
    results = []
    try:
        url  = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=timeout, verify=False)
        if resp.status_code != 200:
            return []
        entries = resp.json()
        seen: set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            # Peut contenir plusieurs lignes / wildcards
            for name in name_value.replace("\\n", "\n").split("\n"):
                name = name.strip().lower()
                # Exclure wildcards et hors-domaine
                if name.startswith("*") or not name.endswith(f".{domain}"):
                    continue
                if name in seen:
                    continue
                seen.add(name)
                ip = _resolve(name)
                results.append(Subdomain(
                    name=name, ip=ip, source="crtsh",
                    status="found" if ip else "nxdomain",
                ))
    except Exception:
        pass
    return results


def _passive_hackertarget(domain: str, timeout: int = 10) -> list[Subdomain]:
    """
    Interroge l'API gratuite HackerTarget (hostsearch).
    Limite : ~100 résultats en mode non-authentifié.
    """
    if not REQUESTS_AVAILABLE:
        return []
    results = []
    try:
        url  = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200 or "error" in resp.text.lower()[:50]:
            return []
        seen: set[str] = set()
        for line in resp.text.strip().split("\n"):
            parts = line.split(",")
            if len(parts) < 2:
                continue
            name, ip = parts[0].strip().lower(), parts[1].strip()
            if not name.endswith(f".{domain}") or name in seen:
                continue
            seen.add(name)
            results.append(Subdomain(
                name=name, ip=ip or None, source="hackertarget",
                status="found" if ip else "nxdomain",
            ))
    except Exception:
        pass
    return results


def _passive_rapiddns(domain: str, timeout: int = 10) -> list[Subdomain]:
    """
    Interroge RapidDNS (scraping léger de l'API publique).
    Bon complément à crt.sh pour des domaines moins connus.
    """
    if not REQUESTS_AVAILABLE:
        return []
    results = []
    try:
        url  = f"https://rapiddns.io/subdomain/{domain}?full=1"
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
        resp = requests.get(url, timeout=timeout, headers=headers)
        if resp.status_code != 200:
            return []
        # Extraction simple par regex
        pattern = re.compile(
            r'<td>\s*([\w\-\.]+\.' + re.escape(domain) + r')\s*</td>',
            re.IGNORECASE,
        )
        seen: set[str] = set()
        for m in pattern.finditer(resp.text):
            name = m.group(1).strip().lower()
            if name in seen:
                continue
            seen.add(name)
            ip = _resolve(name)
            results.append(Subdomain(
                name=name, ip=ip, source="rapiddns",
                status="found" if ip else "nxdomain",
            ))
    except Exception:
        pass
    return results


def run_passive_enum(domain: str,
                     verbose: bool = False) -> list[Subdomain]:
    """Lance toutes les sources passives et déduplique les résultats."""
    if console and verbose:
        console.print("  [dim][crt.sh] Certificate Transparency...[/dim]")
    crtsh   = _passive_crtsh(domain)

    if console and verbose:
        console.print("  [dim][HackerTarget] hostsearch...[/dim]")
    ht      = _passive_hackertarget(domain)

    if console and verbose:
        console.print("  [dim][RapidDNS] lookup...[/dim]")
    rapid   = _passive_rapiddns(domain)

    # Fusion + déduplication (priorité : crtsh > hackertarget > rapiddns)
    seen: dict[str, Subdomain] = {}
    for sub in crtsh + ht + rapid:
        if sub.name not in seen:
            seen[sub.name] = sub
        elif sub.ip and not seen[sub.name].ip:
            # Enrichir avec l'IP si on ne l'avait pas
            seen[sub.name].ip = sub.ip
            seen[sub.name].status = "found"

    return list(seen.values())


# ── Brute-force actif ─────────────────────────────────────────────────────────

def run_active_enum(domain:       str,
                    wordlist:     list[str] | None = None,
                    threads:      int = 30,
                    wildcard_ip:  Optional[str] = None,
                    verbose:      bool = False) -> list[Subdomain]:
    """
    Bruteforce DNS multi-threadé.
    - Résoud chaque <word>.<domain>
    - Filtre les wildcards (si wildcard_ip détecté)
    - Retourne les sous-domaines qui résolvent vraiment
    """
    words   = wordlist or BUILTIN_WORDLIST
    results: list[Subdomain] = []
    lock    = threading.Lock()
    sem     = threading.Semaphore(threads)

    def probe(word: str):
        hostname = f"{word}.{domain}"
        with sem:
            ip = _resolve(hostname)
            if ip is None:
                return
            # Filtrer wildcard
            if wildcard_ip and ip == wildcard_ip:
                return
            with lock:
                results.append(Subdomain(
                    name=hostname, ip=ip,
                    source="dns_brute", status="found",
                ))

    if console and verbose:
        console.print(f"  [dim]Lancement bruteforce ({len(words)} mots, {threads} threads)...[/dim]")

    thread_pool = []
    for word in words:
        t = threading.Thread(target=probe, args=(word,), daemon=True)
        thread_pool.append(t)
        t.start()

    # Progress bar si rich disponible
    if RICH_AVAILABLE and console:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            transient=True,
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]DNS bruteforce...", total=len(thread_pool))
            for t in thread_pool:
                t.join()
                progress.advance(task)
    else:
        for t in thread_pool:
            t.join()

    return results


# ── Génération de commandes outils ────────────────────────────────────────────

def _build_tool_commands(domain: str, resolvers: str = "1.1.1.1,8.8.8.8") -> list[dict]:
    """Génère les commandes pour les outils d'énumération externes."""
    wl_small  = SECLISTS_WORDLISTS["small"]
    wl_medium = SECLISTS_WORDLISTS["medium"]
    wl_jhaddix = SECLISTS_WORDLISTS["jhaddix"]

    return [
        {
            "title": "subfinder — Reconnaissance passive (recommandé)",
            "desc": (
                "Agrège de nombreuses sources passives (crt.sh, Shodan, Censys, "
                "VirusTotal...). Très rapide, idéal en premier passage."
            ),
            "cmd": (
                f"# Installation :\n"
                f"go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n\n"
                f"# Usage basique :\n"
                f"subfinder -d {domain} -o subdomains.txt\n\n"
                f"# Avec résolution et verbose :\n"
                f"subfinder -d {domain} -v -all -o subdomains_all.txt\n\n"
                f"# Chaîné avec dnsx pour résolution :\n"
                f"subfinder -d {domain} -silent | dnsx -silent -a -resp -o resolved.txt"
            ),
        },
        {
            "title": "amass — Recon passif + actif avancé",
            "desc": (
                "Outil le plus complet (passif + actif + brute). "
                "Plus lent mais très exhaustif. Idéal Bug Bounty."
            ),
            "cmd": (
                f"# Installation :\n"
                f"go install github.com/owasp-amass/amass/v4/...@master\n\n"
                f"# Mode passif uniquement (discret) :\n"
                f"amass enum -passive -d {domain} -o amass_passive.txt\n\n"
                f"# Mode actif complet :\n"
                f"amass enum -active -d {domain} -o amass_active.txt\n\n"
                f"# Avec bruteforce wordlist :\n"
                f"amass enum -brute -d {domain} -w {wl_medium} -o amass_brute.txt"
            ),
        },
        {
            "title": "dnsx — Résolution et validation en masse",
            "desc": (
                "Résout rapidement une liste de sous-domaines. "
                "Parfait en post-traitement après subfinder/amass."
            ),
            "cmd": (
                f"# Installation :\n"
                f"go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest\n\n"
                f"# Résoudre une liste existante :\n"
                f"cat subdomains.txt | dnsx -silent -a -resp -o resolved.txt\n\n"
                f"# Bruteforce DNS direct avec dnsx :\n"
                f"dnsx -d {domain} -w {wl_small} -r {resolvers} -o dnsx_brute.txt\n\n"
                f"# Wildcard detection :\n"
                f"dnsx -d {domain} -wc -r {resolvers}"
            ),
        },
        {
            "title": "gobuster dns — Bruteforce DNS wordlist",
            "desc": (
                "Bruteforce DNS classique avec gobuster. "
                "Bon pour CTF / environnements locaux (HTB, AD labs)."
            ),
            "cmd": (
                f"# Bruteforce avec wordlist SecLists :\n"
                f"gobuster dns -d {domain} -w {wl_small} -t 50 --timeout 3s\n\n"
                f"# Avec résolution et affichage IP :\n"
                f"gobuster dns -d {domain} -w {wl_medium} -t 50 -r {resolvers} -i\n\n"
                f"# Mode verbose + wordlist jhaddix (CTF) :\n"
                f"gobuster dns -d {domain} -w {wl_jhaddix} -t 100 -v 2>/dev/null"
            ),
        },
        {
            "title": "dnsrecon — Recon DNS complet",
            "desc": (
                "Enumération DNS complète : zone transfer, SRV, SOA, "
                "bruteforce. Indispensable pour tester le zone transfer (AXFR)."
            ),
            "cmd": (
                f"# Enumération standard :\n"
                f"dnsrecon -d {domain} -t std\n\n"
                f"# Tentative de transfert de zone (AXFR) — souvent oublié en CTF :\n"
                f"dnsrecon -d {domain} -t axfr\n\n"
                f"# Bruteforce + bruteforce reverse :\n"
                f"dnsrecon -d {domain} -t brt -D {wl_small}\n\n"
                f"# Tout en une commande :\n"
                f"dnsrecon -d {domain} -t std,axfr,brt -D {wl_small} -c dnsrecon_output.csv"
            ),
        },
        {
            "title": "theHarvester — OSINT multi-sources",
            "desc": (
                "Agrège emails, IPs et sous-domaines depuis Google, Bing, "
                "LinkedIn, Shodan, etc. Utile pour l'OSINT avant un pentest."
            ),
            "cmd": (
                f"# Sources passives principales :\n"
                f"theHarvester -d {domain} -b google,bing,crtsh,hackertarget -f results.html\n\n"
                f"# Avec Shodan (clé API nécessaire) :\n"
                f"theHarvester -d {domain} -b all -f results_full.html\n\n"
                f"# Rapide sans fichier de sortie :\n"
                f"theHarvester -d {domain} -b crtsh,hackertarget"
            ),
        },
        {
            "title": "dig / host — Tests manuels DNS",
            "desc": (
                "Commandes manuelles pour valider un sous-domaine, "
                "tester le zone transfer ou inspecter les enregistrements DNS."
            ),
            "cmd": (
                f"# Enregistrements NS (nameservers) :\n"
                f"dig NS {domain} +short\n\n"
                f"# Tentative de zone transfer (AXFR) :\n"
                f"dig AXFR {domain} @$(dig NS {domain} +short | head -1)\n\n"
                f"# Résolution simple :\n"
                f"host -t A sub.{domain}\n\n"
                f"# Tous les enregistrements :\n"
                f"dig ANY {domain} +noall +answer\n\n"
                f"# Vérifier wildcard :\n"
                f"dig $(openssl rand -hex 8).{domain} +short"
            ),
        },
        {
            "title": "Pipeline complet recommandé (Bug Bounty / HTB)",
            "desc": (
                "Chaîne optimale : subfinder (passif) → dnsx (résolution) "
                "→ httpx (probe HTTP) → affichage des surfaces d'attaque."
            ),
            "cmd": (
                f"# Étape 1 — Passive recon (sources multiples) :\n"
                f"subfinder -d {domain} -silent -all > subs_raw.txt\n"
                f"# Ajouter les résultats crt.sh :\n"
                f"curl -s 'https://crt.sh/?q=%.{domain}&output=json' | "
                f"jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u >> subs_raw.txt\n\n"
                f"# Étape 2 — Résolution DNS :\n"
                f"sort -u subs_raw.txt | dnsx -silent -a -resp -o subs_resolved.txt\n\n"
                f"# Étape 3 — Probe HTTP (services web actifs) :\n"
                f"cat subs_resolved.txt | awk '{{print $1}}' | "
                f"httpx -silent -title -status-code -o subs_http.txt\n\n"
                f"# Étape 4 — Afficher la surface d'attaque :\n"
                f"cat subs_http.txt"
            ),
        },
    ]


# ── Point d'entrée principal ─────────────────────────────────────────────────

def enumerate_subdomains(
    domain:        str,
    passive:       bool = True,
    active:        bool = True,
    wordlist_path: Optional[str] = None,
    threads:       int  = 30,
    verbose:       bool = False,
) -> SubdomainResult:
    """
    Enumère les sous-domaines d'un domaine cible.

    Args:
        domain:        Domaine cible (ex: target.htb, example.com)
        passive:       Activer la recon passive (crt.sh, HackerTarget, RapidDNS)
        active:        Activer le bruteforce DNS
        wordlist_path: Chemin vers une wordlist externe (None = wordlist embarquée)
        threads:       Nombre de threads pour le bruteforce actif
        verbose:       Afficher la progression détaillée

    Returns:
        SubdomainResult avec tous les sous-domaines trouvés + commandes outils
    """
    domain = domain.strip().lower().rstrip(".")
    result = SubdomainResult(domain=domain)
    result.commands = _build_tool_commands(domain)

    all_subs: dict[str, Subdomain] = {}

    # ── Détection wildcard ────────────────────────────────────────────────────
    if active:
        if console:
            console.print(f"  [dim]Détection wildcard DNS pour {domain}...[/dim]")
        wc, wc_ip = _detect_wildcard(domain)
        if wc:
            result.wildcard_detected = True
            result.wildcard_ip       = wc_ip
            result.notes.append(
                f"⚠️  Wildcard DNS détecté ({wc_ip}) — les résultats du bruteforce "
                f"actif filtrent cette IP pour éviter les faux positifs."
            )

    # ── Recon passive ─────────────────────────────────────────────────────────
    if passive:
        if console:
            console.print(f"\n  [bold cyan]● Recon passive...[/bold cyan]")
        passive_subs = run_passive_enum(domain, verbose=verbose)
        for sub in passive_subs:
            all_subs[sub.name] = sub
        result.passive_count = len(passive_subs)

    # ── Bruteforce actif ──────────────────────────────────────────────────────
    if active:
        if console:
            console.print(f"\n  [bold cyan]● Bruteforce DNS actif...[/bold cyan]")

        # Charger wordlist externe si fournie
        wordlist: list[str] | None = None
        if wordlist_path:
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    wordlist = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                if console:
                    console.print(f"  [dim]Wordlist : {wordlist_path} ({len(wordlist)} mots)[/dim]")
            except OSError as e:
                result.errors.append(f"Impossible de lire la wordlist : {e}")
                wordlist = None

        active_subs = run_active_enum(
            domain,
            wordlist=wordlist,
            threads=threads,
            wildcard_ip=result.wildcard_ip,
            verbose=verbose,
        )

        new_active = 0
        for sub in active_subs:
            if sub.name not in all_subs:
                all_subs[sub.name] = sub
                new_active += 1
        result.active_count = new_active

    result.subdomains = sorted(all_subs.values(), key=lambda s: s.name)
    return result


# ── Affichage terminal ────────────────────────────────────────────────────────

def display_subdomain_results(result: SubdomainResult,
                               show_commands: bool = True,
                               max_cmds: int = 3) -> None:
    """Affiche les résultats dans le terminal avec rich."""
    if not RICH_AVAILABLE or not console:
        # Fallback texte brut
        print(f"\n[Subdomain Enum] {result.domain}")
        for sub in result.subdomains:
            print(f"  {sub.name:50s}  {sub.ip or 'N/A':16s}  [{sub.source}]")
        return

    # ── En-tête ───────────────────────────────────────────────────────────────
    found   = [s for s in result.subdomains if s.status == "found"]
    nxdomain = [s for s in result.subdomains if s.status == "nxdomain"]

    console.print(f"\n[bold green]● Subdomain Enumeration — {result.domain}[/bold green]")
    console.print(
        f"  [cyan]{len(found)} sous-domaines résolus[/cyan]  "
        f"[dim]{len(nxdomain)} non-résolus[/dim]  "
        f"[dim](passif: {result.passive_count}, bruteforce: {result.active_count})[/dim]"
    )

    # Wildcard warning
    if result.wildcard_detected:
        console.print(
            f"\n  [bold yellow]⚠  Wildcard DNS actif[/bold yellow] → {result.wildcard_ip}\n"
            f"  [dim]Les sous-domaines non-existants répondent aussi — vérifier manuellement.[/dim]"
        )

    if not result.subdomains:
        console.print("\n  [dim]Aucun sous-domaine trouvé.[/dim]")
        return

    # ── Tableau des résultats ─────────────────────────────────────────────────
    if found:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            expand=False,
            padding=(0, 1),
        )
        table.add_column("Sous-domaine",  style="bold white",  no_wrap=True, min_width=30)
        table.add_column("IP",            style="green",        no_wrap=True, min_width=16)
        table.add_column("Source",        style="dim",          no_wrap=True, min_width=12)

        source_colors = {
            "crtsh":        "cyan",
            "hackertarget": "blue",
            "rapiddns":     "magenta",
            "dns_brute":    "yellow",
        }

        for sub in found:
            color = source_colors.get(sub.source, "white")
            table.add_row(
                sub.name,
                sub.ip or "—",
                f"[{color}]{sub.source}[/{color}]",
            )

        console.print(table)

    # Sous-domaines non-résolus (DNS passif uniquement)
    if nxdomain:
        console.print(
            f"\n  [dim]Non-résolus (passif DNS, peut être expiré) : "
            f"{', '.join(s.name for s in nxdomain[:5])}"
            + (" ..." if len(nxdomain) > 5 else "")
            + "[/dim]"
        )

    # Notes
    for note in result.notes:
        console.print(f"\n  [yellow]{note}[/yellow]")

    # ── Commandes outils ──────────────────────────────────────────────────────
    if show_commands and result.commands:
        console.print(f"\n  [bold dim]── Commandes recommandées ──[/bold dim]")
        for cmd in result.commands[:max_cmds]:
            console.print(f"\n  [bold dim]{cmd['title']}[/bold dim]")
            console.print(f"  [italic dim]{cmd['desc']}[/italic dim]")
            for line in cmd["cmd"].split("\n")[:6]:
                if line.startswith("#"):
                    console.print(f"  [dim]{line}[/dim]")
                elif line.strip():
                    console.print(f"  [green]{line}[/green]")


def subdomain_results_to_html_section(result: SubdomainResult) -> str:
    """Génère un bloc HTML pour l'intégrer dans le rapport ChocoScan."""
    if not result.subdomains:
        return ""

    found    = [s for s in result.subdomains if s.status == "found"]
    nxdomain = [s for s in result.subdomains if s.status == "nxdomain"]

    source_badge = {
        "crtsh":        "#06b6d4",
        "hackertarget": "#3b82f6",
        "rapiddns":     "#a855f7",
        "dns_brute":    "#f59e0b",
    }

    rows_html = ""
    for sub in found:
        color = source_badge.get(sub.source, "#6b7280")
        rows_html += (
            f"<tr>"
            f"<td style='font-family:monospace'>{sub.name}</td>"
            f"<td style='color:#22c55e'>{sub.ip or '—'}</td>"
            f"<td><span style='color:{color};font-size:0.8em'>{sub.source}</span></td>"
            f"</tr>\n"
        )

    wildcard_html = ""
    if result.wildcard_detected:
        wildcard_html = (
            f"<div style='background:#451a03;border-left:4px solid #f59e0b;"
            f"padding:8px 12px;margin:8px 0;border-radius:4px'>"
            f"⚠ Wildcard DNS détecté → {result.wildcard_ip}"
            f"</div>"
        )

    cmds_html = ""
    for cmd in result.commands[:3]:
        cmds_html += (
            f"<div style='margin:8px 0'>"
            f"<strong>{cmd['title']}</strong><br>"
            f"<span style='color:#94a3b8;font-size:0.85em'>{cmd['desc']}</span>"
            f"<pre style='background:#1e293b;padding:8px;border-radius:4px;"
            f"overflow-x:auto;margin:4px 0'>{cmd['cmd']}</pre>"
            f"</div>"
        )

    return f"""
<div class="section" id="subdomain-enum">
  <h2>🔍 Subdomain Enumeration — {result.domain}</h2>
  <p>
    <strong>{len(found)}</strong> sous-domaines résolus
    &nbsp;|&nbsp; <span style='color:#6b7280'>{len(nxdomain)} non-résolus</span>
    &nbsp;|&nbsp; Passif : {result.passive_count} &nbsp;|&nbsp; Bruteforce : {result.active_count}
  </p>
  {wildcard_html}
  <table>
    <thead>
      <tr><th>Sous-domaine</th><th>IP</th><th>Source</th></tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
  <h3>Commandes recommandées</h3>
  {cmds_html}
</div>
"""
