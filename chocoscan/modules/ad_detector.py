"""
ChocoScan — Détection automatique du contexte Active Directory.

Analyse les ports/services Nmap pour détecter si la cible est un
contrôleur de domaine Windows ou un membre de domaine AD, puis
retourne une analyse structurée avec :
  - Type de cible détecté (DC, membre de domaine, serveur AD-adjacent)
  - CVEs AD critiques regroupées par catégorie d'attaque
  - Techniques d'attaque AD recommandées (BloodHound, Kerberoasting, etc.)
  - Outils adaptés au contexte détecté

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.columns import Columns
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None


# ─────────────────────────────────────────────────────────────────────────────
# Signatures de ports AD
# ─────────────────────────────────────────────────────────────────────────────

# Ports → rôle AD
AD_PORT_ROLES: dict[int, str] = {
    88:   "Kerberos KDC",
    135:  "RPC Endpoint Mapper",
    139:  "NetBIOS Session",
    389:  "LDAP",
    445:  "SMB",
    464:  "Kerberos Password Change",
    593:  "RPC over HTTP",
    636:  "LDAPS",
    3268: "Global Catalog LDAP",
    3269: "Global Catalog LDAPS",
    3389: "Remote Desktop (RDP)",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    49152: "RPC Dynamic",
    49153: "RPC Dynamic",
    49154: "RPC Dynamic",
}

# Ports qui confirment quasi-certainement un DC
DC_DEFINITIVE_PORTS = {88, 389, 3268}

# Ports qui suggèrent un membre de domaine Windows
DOMAIN_MEMBER_PORTS = {445, 135, 139, 3389, 5985}

# Services dans la base CVE liés à AD/Windows
AD_CVE_SERVICES = {
    "kerberos", "ldap", "smb", "rdp", "winrm", "rpc",
    "dns", "windows", "samba", "exchange", "sharepoint",
}


# ─────────────────────────────────────────────────────────────────────────────
# Catégories d'attaques AD
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ADAttackCategory:
    name:        str
    description: str
    techniques:  list[str]
    tools:       list[str]
    cves:        list[dict] = field(default_factory=list)
    requires_creds: bool = False


AD_ATTACK_CATEGORIES = [
    ADAttackCategory(
        name="Élévation vers Domain Admin",
        description="CVEs permettant de passer d'un utilisateur de domaine à Domain Admin sans credentials admin",
        techniques=[
            "BadSuccessor (CVE-2025-53779) — dMSA privilege escalation sur Windows Server 2025",
            "NoPac / Sam-the-Admin (CVE-2021-42278 + CVE-2021-42287) — sAMAccountName spoofing",
            "Zerologon (CVE-2020-1472) — reset du mot de passe du DC sans auth",
            "MS14-068 (CVE-2014-6324) — forgery de ticket Kerberos Domain Admin",
            "Bronze Bit (CVE-2020-17049) — bypass de Kerberos constrained delegation",
        ],
        tools=["bloodyAD", "impacket", "Rubeus", "mimikatz"],
        requires_creds=False,
    ),
    ADAttackCategory(
        name="Mouvement latéral",
        description="CVEs facilitant le déplacement entre machines du domaine",
        techniques=[
            "Pass-the-Hash (PTH) — réutilisation du hash NTLM sans déchiffrement",
            "Pass-the-Ticket (PTT) — réutilisation de tickets Kerberos TGT/TGS",
            "EternalBlue (CVE-2017-0144) — SMBv1 RCE non authentifié",
            "PrintNightmare (CVE-2021-34527) — RCE via Windows Print Spooler",
            "BlueKeep (CVE-2019-0708) — RDP pré-auth RCE wormable",
        ],
        tools=["impacket (psexec, wmiexec, smbexec)", "CrackMapExec", "evil-winrm"],
        requires_creds=True,
    ),
    ADAttackCategory(
        name="Reconnaissance AD",
        description="Enumération de l'infrastructure Active Directory",
        techniques=[
            "BloodHound — cartographie des chemins d'attaque AD",
            "LDAP anonymous/auth bind — dump des objets AD (users, groups, GPOs)",
            "AS-REP Roasting — comptes sans pré-authentification Kerberos",
            "Kerberoasting — SPN accounts ticket cracking offline",
            "LDAP relay — relais NTLM vers LDAP (CVE-2017-8563)",
        ],
        tools=["BloodHound + SharpHound/BloodHound.py", "ldapdomaindump", "GetNPUsers.py", "GetUserSPNs.py"],
        requires_creds=False,
    ),
    ADAttackCategory(
        name="Credential Dumping",
        description="Extraction de credentials depuis des services exposés ou la mémoire",
        techniques=[
            "DCSync — réplication du NTDS.dit via DRS protocol (si droits)",
            "NTLM relay — vol de hash via Responder/ntlmrelayx",
            "Kerberos AS-REP Roasting — hash crackables hors ligne",
            "Outlook NTLM leak (CVE-2023-23397) — vol de hash NTLMv2 zero-click",
            "WinRM credential access via evil-winrm",
        ],
        tools=["Responder", "ntlmrelayx.py", "secretsdump.py", "mimikatz", "evil-winrm"],
        requires_creds=True,
    ),
    ADAttackCategory(
        name="Persistance",
        description="Maintien de l'accès après compromission initiale",
        techniques=[
            "Golden Ticket — forgery de TGT avec hash KRBTGT",
            "Silver Ticket — forgery de TGS pour un service spécifique",
            "Skeleton Key — backdoor dans le processus LSASS",
            "AdminSDHolder abuse — modification des ACLs de protection",
            "DSRM account — activation du compte Directory Services Restore Mode",
        ],
        tools=["impacket", "mimikatz", "bloodyAD"],
        requires_creds=True,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Structures de données
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ADContext:
    host:          str
    is_dc:         bool
    is_domain_member: bool
    confidence:    str          # HIGH / MEDIUM / LOW
    detected_ports: dict[int, str]
    domain_hint:   Optional[str]

    # CVEs AD pertinentes groupées
    cve_by_service: dict[str, list[dict]] = field(default_factory=dict)

    # Score de surface d'attaque AD (0-100)
    ad_score: int = 0

    @property
    def target_type(self) -> str:
        if self.is_dc:
            return "Contrôleur de domaine Windows (DC)"
        if self.is_domain_member:
            return "Membre de domaine Windows"
        return "Serveur AD-adjacent"

    @property
    def total_ad_cves(self) -> int:
        return sum(len(v) for v in self.cve_by_service.values())


# ─────────────────────────────────────────────────────────────────────────────
# Détection du contexte AD
# ─────────────────────────────────────────────────────────────────────────────

def detect_ad_context(
    services: list,        # liste de NmapService
    results: list[dict],   # liste de résultats CVE
    cve_db: dict,          # base CVE complète
) -> Optional[ADContext]:
    """
    Analyse les services Nmap et retourne un ADContext si la cible semble
    être un environnement Windows/Active Directory.

    Retourne None si aucun indicateur AD n'est trouvé.
    """
    open_ports = {svc.port: svc for svc in services}
    detected_ports: dict[int, str] = {}
    domain_hint = None

    # ── Détecter les ports AD ouverts ─────────────────────────────────────────
    for port, role in AD_PORT_ROLES.items():
        if port in open_ports:
            detected_ports[port] = role

    # Pas du tout AD si aucun port caractéristique
    if not detected_ports:
        return None

    # ── Déterminer le type de cible ───────────────────────────────────────────
    is_dc = bool(DC_DEFINITIVE_PORTS & set(detected_ports.keys()))
    is_domain_member = (
        not is_dc and
        len(DOMAIN_MEMBER_PORTS & set(detected_ports.keys())) >= 2
    )

    if not is_dc and not is_domain_member and len(detected_ports) < 2:
        return None

    # ── Confidence level ──────────────────────────────────────────────────────
    if is_dc and len(detected_ports) >= 4:
        confidence = "HIGH"
    elif is_dc:
        confidence = "MEDIUM"
    elif is_domain_member and len(detected_ports) >= 3:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # ── Chercher un indice de nom de domaine ──────────────────────────────────
    for svc in services:
        banner = (svc.banner or "").lower()
        # Ex : "Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb)"
        m = re.search(r'domain[:\s]+([a-z0-9\-\.]+\.[a-z]{2,})', banner, re.IGNORECASE)
        if m:
            domain_hint = m.group(1)
            break
        # Hostname style : DC01.checkpoint.htb
        m2 = re.search(r'([a-z0-9\-]+\.[a-z0-9\-]+\.[a-z]{2,})', banner, re.IGNORECASE)
        if m2:
            domain_hint = ".".join(m2.group(1).split(".")[1:])
            break

    # ── Collecter les CVEs AD pertinentes depuis les résultats ───────────────
    cve_by_service: dict[str, list[dict]] = {}
    for result in results:
        svc_name = result["service"]["service_name"]
        if svc_name in AD_CVE_SERVICES and result["cves"]:
            cve_by_service[svc_name] = sorted(
                result["cves"],
                key=lambda c: float(str(c.get("cvss", 0)).replace("N/A", "0") or 0),
                reverse=True,
            )

    # Compléter avec des CVEs de la base pour les services AD détectés
    # mais sans résultats (ex: port 88/kerberos présent mais pas dans les results filtrés)
    for port in detected_ports:
        svc_obj = open_ports.get(port)
        if not svc_obj:
            continue
        svc_name = svc_obj.service_name

        # Essayer de mapper vers un service de la base CVE
        ad_svc_map = {
            "kerberos": "kerberos", "kpasswd5": "kerberos",
            "ldap": "ldap", "ldaps": "ldap",
            "microsoft-ds": "smb", "netbios-ssn": "smb",
            "msrpc": "rpc", "epmap": "rpc",
            "ms-wbt-server": "rdp",
            "wsman": "winrm", "winrm": "winrm",
            "domain": "dns",
            "http": "windows", "https": "windows",
        }
        mapped = ad_svc_map.get(svc_name.lower(), svc_name)
        if mapped in cve_db and mapped not in cve_by_service:
            top_cves = sorted(
                cve_db[mapped],
                key=lambda c: float(str(c.get("cvss", 0)).replace("N/A", "0") or 0),
                reverse=True,
            )[:8]
            if top_cves:
                cve_by_service[mapped] = top_cves

    # ── Ajouter toujours les CVEs Windows/Kerberos/SMB les plus critiques ─────
    for key in ["kerberos", "smb", "windows", "ldap"]:
        if key in cve_db and key not in cve_by_service:
            cve_by_service[key] = sorted(
                cve_db[key],
                key=lambda c: float(str(c.get("cvss", 0)).replace("N/A", "0") or 0),
                reverse=True,
            )[:6]

    # ── Score de surface d'attaque ────────────────────────────────────────────
    score = 0
    if is_dc:            score += 40
    if 88  in detected_ports: score += 15   # Kerberos
    if 389 in detected_ports: score += 10   # LDAP
    if 445 in detected_ports: score += 15   # SMB
    if 3389 in detected_ports: score += 10  # RDP
    if 5985 in detected_ports: score += 10  # WinRM
    if 3268 in detected_ports: score += 5   # GC
    score = min(score, 100)

    return ADContext(
        host=services[0].host if services else "unknown",
        is_dc=is_dc,
        is_domain_member=is_domain_member,
        confidence=confidence,
        detected_ports=detected_ports,
        domain_hint=domain_hint,
        cve_by_service=cve_by_service,
        ad_score=score,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Affichage terminal
# ─────────────────────────────────────────────────────────────────────────────

CONF_COLORS = {"HIGH": "bold green", "MEDIUM": "yellow", "LOW": "dim"}
SEV_COLORS  = {
    "CRITICAL": "bold red", "HIGH": "bold yellow",
    "MEDIUM": "yellow", "LOW": "green",
}


def display_ad_context_terminal(ctx: ADContext):
    """Affiche le contexte AD détecté dans le terminal."""
    if not console:
        return

    console.print()
    console.print(Rule("[bold blue]🏢 Contexte Active Directory détecté[/bold blue]"))

    # En-tête
    conf_color = CONF_COLORS.get(ctx.confidence, "white")
    console.print(
        f"\n  [bold blue]▶ {ctx.target_type}[/bold blue]  "
        f"[{conf_color}](confiance : {ctx.confidence})[/{conf_color}]  "
        f"Surface d'attaque AD : [bold]{ctx.ad_score}/100[/bold]"
    )
    if ctx.domain_hint:
        console.print(f"  [dim]Domaine détecté : [cyan]{ctx.domain_hint}[/cyan][/dim]")

    # Ports AD détectés
    console.print()
    ports_table = Table(box=box.SIMPLE, show_header=True, header_style="bold",
                        padding=(0, 1))
    ports_table.add_column("Port", style="cyan bold", width=8)
    ports_table.add_column("Rôle AD", style="white")
    for port, role in sorted(ctx.detected_ports.items()):
        ports_table.add_row(str(port), role)
    console.print(
        Panel(ports_table, title="[dim]Ports AD ouverts[/dim]",
              border_style="blue", padding=(0, 1))
    )

    # CVEs AD critiques
    if ctx.cve_by_service:
        console.print()
        console.print("  [bold]CVEs AD critiques par service :[/bold]")
        console.print()

        for svc, cves in ctx.cve_by_service.items():
            top = [c for c in cves if c.get("cvss", 0) >= 9.0][:3] or cves[:2]
            svc_label = f"[bold cyan]{svc.upper()}[/bold cyan]"
            console.print(f"  {svc_label}")
            for c in top:
                score = c.get("cvss", "?")
                sev   = str(c.get("severity", "?")).upper()
                color = SEV_COLORS.get(sev, "white")
                cid   = c.get("id", "?")
                desc  = (c.get("description_fr") or c.get("description") or "")[:90]
                exp   = " [green]⚡PoC[/green]" if c.get("exploit_available") else ""
                console.print(
                    f"    [{color}]{cid}[/{color}] "
                    f"[dim]CVSS {score}[/dim] — {desc}{exp}"
                )
            console.print()

    # Techniques d'attaque recommandées
    console.print()
    console.print("  [bold]Techniques d'attaque AD recommandées :[/bold]")
    console.print()

    for cat in AD_ATTACK_CATEGORIES:
        creds = " [dim](credentials requis)[/dim]" if cat.requires_creds else " [green](sans credentials)[/green]"
        console.print(f"  [bold blue]▸ {cat.name}[/bold blue]{creds}")
        for tech in cat.techniques[:3]:
            console.print(f"    [dim]•[/dim] {tech}")
        tools_str = " · ".join(f"[cyan]{t}[/cyan]" for t in cat.tools[:3])
        console.print(f"    Outils : {tools_str}")
        console.print()

    # Commandes de démarrage
    domain = ctx.domain_hint or "domain.local"
    dc_ip  = ctx.host
    console.print()
    console.print(Rule("[dim]Commandes de reconnaissance AD suggérées[/dim]", style="dim"))
    console.print()

    cmds = [
        ("BloodHound.py (sans credentials)", f"bloodhound-python -d {domain} -dc {dc_ip} -c All --zip"),
        ("AS-REP Roasting",                  f"GetNPUsers.py {domain}/ -dc-ip {dc_ip} -no-pass -usersfile users.txt"),
        ("Kerberoasting",                    f"GetUserSPNs.py {domain}/user:'pass' -dc-ip {dc_ip} -request"),
        ("LDAP dump",                        f"ldapdomaindump -u '{domain}\\\\user' -p 'pass' {dc_ip}"),
        ("bloodyAD writable",                f"bloodyAD -H {dc_ip} -d {domain} -u user -p 'pass' get writable"),
        ("Zerologon check",                  f"zerologon_tester.py {dc_ip} DCNAME$"),
    ]

    for label, cmd in cmds:
        console.print(f"  [dim]# {label}[/dim]")
        console.print(f"  [green]{cmd}[/green]")
        console.print()


# ─────────────────────────────────────────────────────────────────────────────
# Export HTML
# ─────────────────────────────────────────────────────────────────────────────

def ad_context_to_html_section(ctx: ADContext) -> str:
    """Génère la section HTML du contexte AD pour le rapport ChocoScan."""

    conf_colors = {"HIGH": "#22c55e", "MEDIUM": "#eab308", "LOW": "#6b7280"}
    conf_color = conf_colors.get(ctx.confidence, "#6b7280")
    score_color = "#ef4444" if ctx.ad_score >= 70 else "#f97316" if ctx.ad_score >= 40 else "#eab308"

    # Ports AD
    ports_rows = ""
    for port, role in sorted(ctx.detected_ports.items()):
        ports_rows += f"""
        <tr>
          <td class="ad-port-num">{port}</td>
          <td class="ad-port-role">{role}</td>
        </tr>"""

    # CVEs par service
    cve_blocks = ""
    for svc, cves in ctx.cve_by_service.items():
        top_cves = [c for c in cves if c.get("cvss", 0) >= 9.0][:4] or cves[:3]
        sev_map = {
            "CRITICAL": "#ef4444", "HIGH": "#f97316",
            "MEDIUM": "#eab308", "LOW": "#22c55e",
        }
        cve_rows = ""
        for c in top_cves:
            cid   = c.get("id", "")
            score = c.get("cvss", "?")
            sev   = str(c.get("severity", "?")).upper()
            color = sev_map.get(sev, "#6b7280")
            desc  = (c.get("description_fr") or c.get("description") or "")[:160]
            exp   = '<span class="ad-exp">⚡PoC</span>' if c.get("exploit_available") else ""
            link  = f'<a href="https://nvd.nist.gov/vuln/detail/{cid}" target="_blank" class="ad-cve-link">{cid}</a>' if cid.startswith("CVE-") else cid
            cve_rows += f"""
          <tr>
            <td>{link}</td>
            <td><span class="ad-sev" style="color:{color};border-color:{color}44;background:{color}11">{sev}</span></td>
            <td class="ad-score-cell" style="color:{color}">{score}</td>
            <td class="ad-desc">{desc}</td>
            <td>{exp}</td>
          </tr>"""

        cve_blocks += f"""
      <div class="ad-svc-block">
        <div class="ad-svc-name">{svc.upper()}</div>
        <table class="ad-cve-table">
          <thead><tr>
            <th>CVE</th><th>Sévérité</th><th>CVSS</th><th>Description</th><th>Exploit</th>
          </tr></thead>
          <tbody>{cve_rows}</tbody>
        </table>
      </div>"""

    # Techniques par catégorie
    cat_cards = ""
    for cat in AD_ATTACK_CATEGORIES:
        creds_badge = (
            '<span class="ad-creds-badge need">🔑 credentials requis</span>'
            if cat.requires_creds
            else '<span class="ad-creds-badge free">✓ sans credentials</span>'
        )
        techs = "".join(f"<li>{t}</li>" for t in cat.techniques)
        tools = " · ".join(
            f'<span class="ad-tool">{t}</span>' for t in cat.tools
        )
        cat_cards += f"""
      <div class="ad-cat-card">
        <div class="ad-cat-head">
          <span class="ad-cat-name">{cat.name}</span>
          {creds_badge}
        </div>
        <p class="ad-cat-desc">{cat.description}</p>
        <ul class="ad-tech-list">{techs}</ul>
        <div class="ad-tools">Outils : {tools}</div>
      </div>"""

    # Commandes suggérées
    domain = ctx.domain_hint or "domain.local"
    dc_ip  = ctx.host
    cmds_html = ""
    cmds = [
        ("BloodHound (sans credentials)",
         f"bloodhound-python -d {domain} -dc {dc_ip} -c All --zip"),
        ("AS-REP Roasting (comptes sans pré-auth)",
         f"GetNPUsers.py {domain}/ -dc-ip {dc_ip} -no-pass -usersfile users.txt"),
        ("Kerberoasting (cracking offline de tickets)",
         f"GetUserSPNs.py {domain}/user:'pass' -dc-ip {dc_ip} -request"),
        ("Dump LDAP complet",
         f"ldapdomaindump -u '{domain}\\\\user' -p 'pass' {dc_ip}"),
        ("bloodyAD — objets accessibles en écriture",
         f"bloodyAD -H {dc_ip} -d {domain} -u user -p 'pass' get writable"),
        ("Vérification Zerologon",
         f"zerologon_tester.py {dc_ip} DCNAME$"),
        ("BadSuccessor (CVE-2025-53779) — dMSA check",
         f"bloodyAD -H {dc_ip} -d {domain} -u user -p 'pass' get children 'CN=Managed Service Accounts,{','.join('DC='+p for p in domain.split('.'))}' "),
    ]
    for label, cmd in cmds:
        cmds_html += f"""
      <div class="ad-cmd-block">
        <div class="ad-cmd-label"># {label}</div>
        <code class="ad-cmd">{cmd}</code>
      </div>"""

    domain_line = f'<span class="ad-domain">🌐 Domaine : <strong>{ctx.domain_hint}</strong></span>' if ctx.domain_hint else ""

    return f"""
<div class="section ad-section" id="ad-section">
  <h2 class="section-h2">🏢 Contexte Active Directory
    <span class="section-count">{ctx.total_ad_cves} CVEs AD</span>
  </h2>

  <!-- En-tête -->
  <div class="ad-header">
    <div class="ad-header-left">
      <div class="ad-target-type">
        <span class="ad-dc-icon">{'🏛' if ctx.is_dc else '💻'}</span>
        {ctx.target_type}
      </div>
      <div class="ad-meta-row">
        <span class="ad-conf" style="color:{conf_color}">
          ● Confiance : {ctx.confidence}
        </span>
        {domain_line}
        <span class="ad-score-badge" style="color:{score_color};border-color:{score_color}44">
          Surface AD : {ctx.ad_score}/100
        </span>
      </div>
    </div>
    <!-- Ports ouverts -->
    <div class="ad-ports-box">
      <div class="ad-ports-title">Ports AD détectés</div>
      <table class="ad-ports-table">
        <tbody>{ports_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- CVEs AD -->
  <div class="ad-sub-title">CVEs critiques par service AD</div>
  <div class="ad-cve-blocks">{cve_blocks}</div>

  <!-- Techniques d'attaque -->
  <div class="ad-sub-title">Techniques d'attaque recommandées</div>
  <div class="ad-cat-grid">{cat_cards}</div>

  <!-- Commandes -->
  <div class="ad-sub-title">Commandes de reconnaissance suggérées</div>
  <div class="ad-cmds">{cmds_html}</div>

  <style>
    .ad-section {{ margin: 1.5rem 0; }}
    .section-h2 {{
      font-size: 1rem; font-weight: 700; color: #dce8f8;
      margin-bottom: 1rem; display: flex; align-items: center; gap: .5rem;
    }}
    .section-count {{
      background: #1e243a; color: #8aaad0;
      font-size: .75rem; padding: .1rem .5rem;
      border-radius: 20px; font-weight: 400;
    }}

    /* Header */
    .ad-header {{
      display: flex; gap: 1.5rem; flex-wrap: wrap;
      background: #0d1829; border: 1px solid #1c3060;
      border-radius: 8px; padding: 1.25rem; margin-bottom: 1.25rem;
    }}
    .ad-header-left {{ flex: 1; min-width: 200px; }}
    .ad-target-type {{
      font-size: 1.1rem; font-weight: 700; color: #60a0f0;
      margin-bottom: .5rem; display: flex; align-items: center; gap: .5rem;
    }}
    .ad-dc-icon {{ font-size: 1.3rem; }}
    .ad-meta-row {{ display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; font-size: .8rem; }}
    .ad-conf {{ font-weight: 600; }}
    .ad-domain {{ color: #8aaad0; }}
    .ad-score-badge {{
      border: 1px solid; border-radius: 4px;
      padding: .1rem .5rem; font-size: .78rem; font-weight: 700;
    }}

    /* Ports */
    .ad-ports-box {{
      background: #111428; border: 1px solid #1c2240;
      border-radius: 6px; padding: .75rem 1rem; min-width: 220px;
    }}
    .ad-ports-title {{
      font-size: .7rem; text-transform: uppercase; letter-spacing: .07em;
      color: #4a6488; margin-bottom: .5rem;
    }}
    .ad-ports-table {{ border-collapse: collapse; width: 100%; }}
    .ad-port-num {{
      font-family: monospace; font-size: .82rem; font-weight: 700;
      color: #60a0f0; padding: .15rem .5rem .15rem 0; width: 60px;
    }}
    .ad-port-role {{ font-size: .8rem; color: #8aaad0; padding: .15rem 0; }}

    /* CVEs par service */
    .ad-sub-title {{
      font-size: .75rem; text-transform: uppercase; letter-spacing: .07em;
      color: #4a6488; margin: 1.25rem 0 .6rem;
      padding-bottom: .35rem; border-bottom: 1px solid #1c2240;
    }}
    .ad-cve-blocks {{ display: flex; flex-direction: column; gap: .6rem; }}
    .ad-svc-block {{
      background: #111428; border: 1px solid #1c2240;
      border-radius: 6px; overflow: hidden;
    }}
    .ad-svc-name {{
      background: #161b30; padding: .45rem 1rem;
      font-size: .75rem; font-weight: 700; color: #60a0f0;
      letter-spacing: .06em; border-bottom: 1px solid #1c2240;
    }}
    .ad-cve-table {{ width: 100%; border-collapse: collapse; font-size: .8rem; }}
    .ad-cve-table thead th {{
      background: #0d0f1f; color: #4a6488;
      font-size: .68rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: .06em; padding: .4rem .75rem;
      text-align: left; border-bottom: 1px solid #1c2240;
    }}
    .ad-cve-table tbody tr {{ border-bottom: 1px solid #1c2240; }}
    .ad-cve-table tbody tr:last-child {{ border-bottom: none; }}
    .ad-cve-table tbody tr:hover {{ background: rgba(255,255,255,.02); }}
    .ad-cve-table td {{ padding: .5rem .75rem; vertical-align: top; }}
    .ad-cve-link {{
      font-family: monospace; font-size: .8rem; color: #60a0f0;
      border-bottom: 1px dashed rgba(96,160,240,.3);
    }}
    .ad-cve-link:hover {{ color: #a0d0f0; }}
    .ad-sev {{
      font-size: .7rem; font-weight: 700; padding: .1rem .4rem;
      border-radius: 3px; border: 1px solid; white-space: nowrap;
    }}
    .ad-score-cell {{
      font-family: monospace; font-size: .95rem; font-weight: 800;
    }}
    .ad-desc {{ color: #4a6488; font-size: .78rem; line-height: 1.4; max-width: 400px; }}
    .ad-exp {{
      font-size: .7rem; font-weight: 700; color: #38bdf8;
      background: rgba(56,189,248,.1); border: 1px solid rgba(56,189,248,.3);
      border-radius: 3px; padding: .1rem .35rem; white-space: nowrap;
    }}

    /* Catégories d'attaque */
    .ad-cat-grid {{
      display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: .75rem; margin-bottom: .5rem;
    }}
    .ad-cat-card {{
      background: #111428; border: 1px solid #1c2240;
      border-radius: 6px; padding: .85rem 1rem;
    }}
    .ad-cat-head {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: .4rem; flex-wrap: wrap; gap: .3rem; }}
    .ad-cat-name {{ font-size: .85rem; font-weight: 700; color: #dce8f8; }}
    .ad-creds-badge {{
      font-size: .68rem; padding: .1rem .4rem;
      border-radius: 3px; font-weight: 600;
    }}
    .ad-creds-badge.need {{ background: rgba(234,179,8,.1); color: #eab308; border: 1px solid rgba(234,179,8,.3); }}
    .ad-creds-badge.free {{ background: rgba(34,197,94,.1); color: #22c55e; border: 1px solid rgba(34,197,94,.3); }}
    .ad-cat-desc {{ font-size: .75rem; color: #4a6488; margin-bottom: .5rem; line-height: 1.4; }}
    .ad-tech-list {{ padding-left: 1.1rem; margin-bottom: .5rem; }}
    .ad-tech-list li {{ font-size: .75rem; color: #8aaad0; margin-bottom: .2rem; line-height: 1.4; }}
    .ad-tools {{ font-size: .72rem; color: #4a6488; }}
    .ad-tool {{
      display: inline-block; background: #1e243a; color: #60a0f0;
      padding: .05rem .35rem; border-radius: 3px;
      font-family: monospace; font-size: .72rem; margin: .1rem .1rem .1rem 0;
    }}

    /* Commandes */
    .ad-cmds {{ display: flex; flex-direction: column; gap: .6rem; }}
    .ad-cmd-block {{
      background: #0a0d1a; border: 1px solid #1c2240;
      border-radius: 6px; padding: .6rem 1rem;
    }}
    .ad-cmd-label {{
      font-size: .72rem; color: #4a6488; margin-bottom: .3rem;
      font-family: monospace;
    }}
    .ad-cmd {{
      display: block; font-family: 'Courier New', monospace;
      font-size: .8rem; color: #4ade80; word-break: break-all;
      line-height: 1.5;
    }}

    @media (max-width: 700px) {{
      .ad-header {{ flex-direction: column; }}
      .ad-cat-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</div>"""
