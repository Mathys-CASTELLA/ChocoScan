"""
ChocoScan — Mode interactif CLI
================================
Navigation style fzf dans les résultats du scan.

Vues :
  [1] Liste des ports  — naviguer entre services, voir sévérité max + nb CVEs
  [2] Liste CVEs       — détail d'un service, dépliage CVE, marquage, filtres
  [3] Détail CVE       — description complète, références, exploit info

Actions :
  E  → marquer CVE comme Exploitée       (tag rouge)
  N  → marquer CVE comme Non applicable  (tag gris)
  ?  → marquer CVE comme Incertaine      (tag jaune)
  U  → démarquer (undo)
  /  → filtrer par mot-clé (ID, description, sévérité)
  S  → trier par CVSS / Sévérité / ID
  X  → exporter les CVEs marquées (JSON)
  Q  → quitter

Touches de navigation :
  ↑/↓ ou j/k   naviguer dans la liste
  Entrée        ouvrir / dépiler
  Echap / q     remonter d'un niveau
  Tab           basculer entre les panneaux
"""

from __future__ import annotations

import curses
import curses.ascii
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


# ─── Constantes de couleurs ───────────────────────────────────────────────────

class C:
    """Indices de paires de couleurs curses."""
    NORMAL      = 0
    HEADER      = 1
    SELECTED    = 2
    CRITICAL    = 3
    HIGH        = 4
    MEDIUM      = 5
    LOW         = 6
    DIM         = 7
    STATUS_BAR  = 8
    TAG_EXPLOIT = 9
    TAG_NA      = 10
    TAG_UNSURE  = 11
    TITLE       = 12
    BANNER      = 13
    BORDER      = 14
    KEY_HINT    = 15


# ─── Tags de marquage ─────────────────────────────────────────────────────────

class Tag(Enum):
    NONE       = ""
    EXPLOITED  = "EXPLOITÉ"
    NA         = "NON APPL."
    UNCERTAIN  = "INCERTAIN"


TAG_COLORS = {
    Tag.EXPLOITED: C.TAG_EXPLOIT,
    Tag.NA:        C.TAG_NA,
    Tag.UNCERTAIN: C.TAG_UNSURE,
    Tag.NONE:      C.DIM,
}

TAG_ICONS = {
    Tag.EXPLOITED: "★",
    Tag.NA:        "✗",
    Tag.UNCERTAIN: "?",
    Tag.NONE:      " ",
}


# ─── État global de l'UI ──────────────────────────────────────────────────────

@dataclass
class UIState:
    results: list[dict]                  # résultats ChocoScan complets
    tags: dict[str, Tag]                 # cve_id → Tag
    filter_text: str = ""                # filtre texte actif
    tag_filter: set = None                # tags actifs (None = tous)

    def __post_init__(self):
        if self.tag_filter is None:
            object.__setattr__(self, "tag_filter", set())
    sort_key: str = "cvss"               # "cvss" | "severity" | "id"
    port_cursor: int = 0                 # index sélectionné dans vue ports
    cve_cursor: int = 0                  # index sélectionné dans vue CVEs
    view: str = "ports"                  # "ports" | "cves" | "detail"
    current_port_idx: int = 0            # port ouvert dans la vue CVEs
    scroll_detail: int = 0               # scroll dans la vue détail
    status_msg: str = ""                 # message temporaire dans la status bar
    output_dir: Path = field(default_factory=lambda: Path("output"))

    def current_result(self) -> dict:
        return self.results[self.current_port_idx]

    def filtered_cves(self) -> list[dict]:
        """CVEs du port courant, filtrées par texte + tags et triées."""
        cves = self.current_result().get("cves", [])
        if self.filter_text:
            ft = self.filter_text.lower()
            cves = [c for c in cves if
                    ft in c.get("id", "").lower()
                    or ft in (c.get("description") or "").lower()
                    or ft in (c.get("description_fr") or "").lower()
                    or ft in str(c.get("severity", "")).lower()
                    or any(ft in t for t in c.get("tags", []))]
        if self.tag_filter:
            cves = [c for c in cves
                    if self.tag_filter & set(c.get("tags", []))]
        return sorted(cves, key=self._sort_fn, reverse=True)

    def _sort_fn(self, cve: dict):
        if self.sort_key == "cvss":
            try:
                return float(str(cve.get("cvss", 0)).replace("N/A", "0") or 0)
            except (ValueError, TypeError):
                return 0
        elif self.sort_key == "severity":
            order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1}
            return order.get(str(cve.get("severity", "")).upper(), 0)
        else:
            return cve.get("id", "")

    def tag_cve(self, cve_id: str, tag: Tag):
        self.tags[cve_id] = tag

    def get_tag(self, cve_id: str) -> Tag:
        return self.tags.get(cve_id, Tag.NONE)

    def tagged_cves(self) -> list[tuple[dict, dict, Tag]]:
        """Retourne [(service_dict, cve_dict, tag)] pour toutes les CVEs taguées."""
        out = []
        for result in self.results:
            for cve in result.get("cves", []):
                t = self.get_tag(cve.get("id", ""))
                if t != Tag.NONE:
                    out.append((result["service"], cve, t))
        return out


# ─── Helpers d'affichage ──────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRITICAL": C.CRITICAL,
    "HIGH":     C.HIGH,
    "MEDIUM":   C.MEDIUM,
    "LOW":      C.LOW,
}

SEVERITY_ICON = {
    "CRITICAL": "●",
    "HIGH":     "●",
    "MEDIUM":   "●",
    "LOW":      "●",
}

def severity_max(cves: list[dict]) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    found = {str(c.get("severity", "")).upper() for c in cves}
    for s in order:
        if s in found:
            return s
    return "UNKNOWN"

def cvss_str(cve: dict) -> str:
    v = cve.get("cvss", "N/A")
    if v is None:
        return " N/A"
    try:
        return f"{float(v):4.1f}"
    except (ValueError, TypeError):
        return " N/A"

def clamp(val: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, val))

def addstr_safe(win, y: int, x: int, text: str, attr: int = 0):
    """addstr sans lever d'exception sur les débordements de fenêtre."""
    try:
        max_y, max_x = win.getmaxyx()
        if y < 0 or y >= max_y or x < 0:
            return
        available = max_x - x - 1
        if available <= 0:
            return
        win.addstr(y, x, text[:available], attr)
    except curses.error:
        pass

def hline_safe(win, y: int, x: int, ch, n: int, attr: int = 0):
    try:
        max_y, max_x = win.getmaxyx()
        if y < 0 or y >= max_y:
            return
        n = min(n, max_x - x - 1)
        if n <= 0:
            return
        win.hline(y, x, ch | attr, n)
    except curses.error:
        pass


# ─── Initialisation des couleurs ─────────────────────────────────────────────

def init_colors():
    curses.start_color()
    curses.use_default_colors()

    bg = -1  # transparent (utilise le fond du terminal)

    curses.init_pair(C.NORMAL,      curses.COLOR_WHITE,   bg)
    curses.init_pair(C.HEADER,      curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(C.SELECTED,    curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(C.CRITICAL,    curses.COLOR_RED,     bg)
    curses.init_pair(C.HIGH,        curses.COLOR_YELLOW,  bg)
    curses.init_pair(C.MEDIUM,      curses.COLOR_YELLOW,  bg)
    curses.init_pair(C.LOW,         curses.COLOR_GREEN,   bg)
    curses.init_pair(C.DIM,         curses.COLOR_WHITE,   bg)
    curses.init_pair(C.STATUS_BAR,  curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(C.TAG_EXPLOIT, curses.COLOR_RED,     bg)
    curses.init_pair(C.TAG_NA,      curses.COLOR_WHITE,   bg)
    curses.init_pair(C.TAG_UNSURE,  curses.COLOR_YELLOW,  bg)
    curses.init_pair(C.TITLE,       curses.COLOR_CYAN,    bg)
    curses.init_pair(C.BANNER,      curses.COLOR_MAGENTA, bg)
    curses.init_pair(C.BORDER,      curses.COLOR_CYAN,    bg)
    curses.init_pair(C.KEY_HINT,    curses.COLOR_CYAN,    bg)


# ─── Vue : liste des ports ────────────────────────────────────────────────────

def draw_ports_view(stdscr, state: UIState):
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()

    # ── Header ──
    header = " ChocoScan  ›  Ports "
    addstr_safe(stdscr, 0, 0, " " * max_x, curses.color_pair(C.HEADER) | curses.A_BOLD)
    addstr_safe(stdscr, 0, 2, header, curses.color_pair(C.HEADER) | curses.A_BOLD)
    total_cves = sum(len(r.get("cves", [])) for r in state.results)
    tagged     = len(state.tagged_cves())
    info_right = f" {len(state.results)} services | {total_cves} CVEs | {tagged} marquées "
    addstr_safe(stdscr, 0, max_x - len(info_right) - 1,
                info_right, curses.color_pair(C.HEADER))

    # ── Colonne header ──
    col_header = f" {'PORT':<10} {'PROTOCOLE':<10} {'SERVICE':<20} {'BANNER':<35} {'CVEs':>5}  SÉVÉRITÉ MAX"
    addstr_safe(stdscr, 1, 0, col_header[:max_x], curses.A_DIM)
    hline_safe(stdscr, 2, 0, curses.ACS_HLINE, max_x, curses.color_pair(C.BORDER))

    # ── Liste des ports ──
    list_h = max_y - 5  # lignes disponibles pour la liste
    results = state.results
    n = len(results)

    # Scroll pour garder le curseur visible
    scroll = max(0, state.port_cursor - list_h + 3)
    scroll = min(scroll, max(0, n - list_h))

    for i, result in enumerate(results[scroll:scroll + list_h]):
        real_idx = i + scroll
        svc  = result["service"]
        cves = result.get("cves", [])
        sev  = severity_max(cves) if cves else "—"
        sev_col = SEVERITY_COLOR.get(sev, C.DIM)

        port_str    = f"{svc['port']}/{svc['protocol']}"
        proto_str   = svc.get("protocol", "")
        service_str = svc.get("service_name", "")[:19]
        banner_str  = (svc.get("banner") or "")[:34]
        cve_count   = str(len(cves)) if cves else "—"
        sev_icon    = SEVERITY_ICON.get(sev, " ")

        tagged_count = sum(1 for c in cves if state.get_tag(c.get("id","")) != Tag.NONE)
        tag_hint = f" [{tagged_count}✓]" if tagged_count else ""

        row = f" {port_str:<10} {proto_str:<10} {service_str:<20} {banner_str:<35} {cve_count:>5}{tag_hint}"

        y = 3 + i
        if real_idx == state.port_cursor:
            addstr_safe(stdscr, y, 0, " " * max_x, curses.color_pair(C.SELECTED))
            addstr_safe(stdscr, y, 0, row[:max_x - 15], curses.color_pair(C.SELECTED) | curses.A_BOLD)
            # Sévérité colorée même sur sélection
            sev_x = max_x - 14
            addstr_safe(stdscr, y, sev_x, f" {sev_icon} {sev:<10}",
                        curses.color_pair(C.SELECTED) | curses.A_BOLD)
        else:
            attr = curses.color_pair(C.NORMAL)
            addstr_safe(stdscr, y, 0, row[:max_x - 14], attr)
            sev_x = max_x - 14
            sev_attr = curses.color_pair(sev_col) | curses.A_BOLD if sev != "—" else curses.color_pair(C.DIM)
            addstr_safe(stdscr, y, sev_x, f" {sev_icon} {sev:<10}", sev_attr)

    # ── Scrollbar indicateur ──
    if n > list_h:
        sb_pct = int((state.port_cursor / max(1, n - 1)) * (list_h - 1))
        for sy in range(list_h):
            ch = "█" if sy == sb_pct else "│"
            addstr_safe(stdscr, 3 + sy, max_x - 1, ch, curses.color_pair(C.BORDER))

    # ── Status bar ──
    _draw_status_bar(stdscr, state,
        "[↑↓/jk] Naviguer  [Entrée] Ouvrir  [X] Exporter marquées  [Q] Quitter")


def _draw_status_bar(stdscr, state: UIState, hints: str):
    max_y, max_x = stdscr.getmaxyx()
    y = max_y - 1
    addstr_safe(stdscr, y, 0, " " * max_x, curses.color_pair(C.STATUS_BAR))
    if state.status_msg:
        addstr_safe(stdscr, y, 2, state.status_msg[:max_x - 4], curses.color_pair(C.STATUS_BAR) | curses.A_BOLD)
    else:
        # Afficher les raccourcis en alternant couleur clé / texte
        x = 2
        for part in hints.split("  "):
            if x >= max_x - 2:
                break
            m = re.match(r'^\[(.+?)\]\s*(.*)', part)
            if m:
                key_str  = f"[{m.group(1)}]"
                desc_str = f" {m.group(2)}  "
                addstr_safe(stdscr, y, x, key_str,
                            curses.color_pair(C.KEY_HINT) | curses.A_BOLD)
                x += len(key_str)
                addstr_safe(stdscr, y, x, desc_str, curses.color_pair(C.STATUS_BAR))
                x += len(desc_str)
            else:
                addstr_safe(stdscr, y, x, part + "  ", curses.color_pair(C.STATUS_BAR))
                x += len(part) + 2


# ─── Vue : liste des CVEs d'un port ──────────────────────────────────────────

def draw_cves_view(stdscr, state: UIState):
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()

    result = state.current_result()
    svc    = result["service"]
    cves   = state.filtered_cves()
    n      = len(cves)

    # ── Header ──
    svc_label = f"{svc['host']}:{svc['port']}/{svc['protocol']}  {svc.get('service_name','')}  {svc.get('banner','')}"
    addstr_safe(stdscr, 0, 0, " " * max_x, curses.color_pair(C.HEADER) | curses.A_BOLD)
    header = f" ChocoScan  ›  Ports  ›  {svc['port']}/{svc['protocol']} "
    addstr_safe(stdscr, 0, 2, header, curses.color_pair(C.HEADER) | curses.A_BOLD)
    info_r = f" {n} CVEs "
    addstr_safe(stdscr, 0, max_x - len(info_r) - 1, info_r, curses.color_pair(C.HEADER))

    # ── Sous-header service ──
    addstr_safe(stdscr, 1, 2, svc_label[:max_x - 4], curses.color_pair(C.DIM))

    # ── Filtre actif ──
    filter_line = ""
    if state.filter_text:
        filter_line = f" Filtre: [{state.filter_text}]  "
    if state.tag_filter:
        filter_line += "Tags: " + " ".join(f"#{t}" for t in sorted(state.tag_filter)) + "  "
    sort_label  = f"Tri: {state.sort_key.upper()}"
    addstr_safe(stdscr, 2, 2,
                (filter_line + sort_label)[:max_x - 4],
                curses.color_pair(C.KEY_HINT))
    hline_safe(stdscr, 3, 0, curses.ACS_HLINE, max_x, curses.color_pair(C.BORDER))

    # ── Colonne header ──
    col_h = f" {'TAG':<2} {'CVE ID':<20} {'CVSS':>5}  {'SÉVÉRITÉ':<10} {'DESCRIPTION'}"
    addstr_safe(stdscr, 4, 0, col_h[:max_x], curses.A_DIM)
    hline_safe(stdscr, 5, 0, curses.ACS_HLINE, max_x, curses.color_pair(C.BORDER))

    # ── Liste CVEs ──
    list_h  = max_y - 8
    scroll  = max(0, state.cve_cursor - list_h + 3)
    scroll  = min(scroll, max(0, n - list_h))

    if n == 0:
        msg = "  Aucune CVE" + (f" correspondant à « {state.filter_text} »" if state.filter_text else "")
        addstr_safe(stdscr, 6, 2, msg, curses.color_pair(C.DIM))
    else:
        for i, cve in enumerate(cves[scroll:scroll + list_h]):
            real_idx = i + scroll
            y   = 6 + i
            tag = state.get_tag(cve.get("id", ""))
            sev = str(cve.get("severity", "UNKNOWN")).upper()
            sev_col   = SEVERITY_COLOR.get(sev, C.DIM)
            tag_icon  = TAG_ICONS[tag]
            tag_col   = TAG_COLORS[tag]
            cve_id    = cve.get("id", "N/A")
            cvss      = cvss_str(cve)
            desc_raw  = cve.get("description_fr") or cve.get("description") or ""
            cve_tags  = cve.get("tags", [])
            # Réserver de la place pour les tags s'ils existent
            tag_str   = " ".join(f"#{t}" for t in cve_tags[:4]) if cve_tags else ""
            tag_reserve = len(tag_str) + 2 if tag_str else 0
            desc_max  = max(20, max_x - 45 - tag_reserve)
            desc      = desc_raw[:desc_max - 3] + "…" if len(desc_raw) > desc_max else desc_raw

            is_sel = (real_idx == state.cve_cursor)
            base_attr = curses.color_pair(C.SELECTED) | curses.A_BOLD if is_sel else curses.color_pair(C.NORMAL)

            if is_sel:
                addstr_safe(stdscr, y, 0, " " * max_x, curses.color_pair(C.SELECTED))

            # Tag icon
            addstr_safe(stdscr, y, 1, tag_icon,
                        curses.color_pair(tag_col) | curses.A_BOLD if tag != Tag.NONE
                        else (curses.color_pair(C.SELECTED) if is_sel else curses.color_pair(C.DIM)))

            # CVE ID
            addstr_safe(stdscr, y, 3, f"{cve_id:<20}", base_attr)

            # CVSS
            try:
                score_f = float(str(cve.get("cvss", 0)).replace("N/A","0") or 0)
                if score_f >= 9.0:   score_col = C.CRITICAL
                elif score_f >= 7.0: score_col = C.HIGH
                elif score_f >= 4.0: score_col = C.MEDIUM
                else:                score_col = C.LOW
            except (ValueError, TypeError):
                score_col = C.DIM
            cvss_attr = (curses.color_pair(C.SELECTED) | curses.A_BOLD) if is_sel else (curses.color_pair(score_col) | curses.A_BOLD)
            addstr_safe(stdscr, y, 24, f"{cvss:>5}", cvss_attr)

            # Sévérité
            sev_attr = (curses.color_pair(C.SELECTED) | curses.A_BOLD) if is_sel else (curses.color_pair(sev_col) | curses.A_BOLD)
            addstr_safe(stdscr, y, 31, f"  {sev:<10}", sev_attr)

            # Description
            addstr_safe(stdscr, y, 43, desc, base_attr)
            if tag_str:
                tx = 43 + len(desc) + 1
                addstr_safe(stdscr, y, tx, tag_str,
                            curses.color_pair(C.KEY_HINT) | (curses.A_BOLD if is_sel else 0))

    # ── Status bar ──
    _draw_status_bar(stdscr, state,
        "[↑↓] Naviguer  [Entrée] Détail  [E] Exploité  [N] Non appl.  [?] Incertain  [U] Démarquer  [/] Filtrer  [S] Trier  [X] Exporter  [Esc/Q] Retour")


# ─── Vue : détail d'une CVE ───────────────────────────────────────────────────

def draw_detail_view(stdscr, state: UIState):
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()

    cves = state.filtered_cves()
    if not cves or state.cve_cursor >= len(cves):
        return

    cve  = cves[state.cve_cursor]
    cve_id = cve.get("id", "N/A")
    tag  = state.get_tag(cve_id)
    sev  = str(cve.get("severity", "UNKNOWN")).upper()
    sev_col = SEVERITY_COLOR.get(sev, C.DIM)

    # ── Header ──
    addstr_safe(stdscr, 0, 0, " " * max_x, curses.color_pair(C.HEADER) | curses.A_BOLD)
    header = f" ChocoScan  ›  Ports  ›  CVEs  ›  {cve_id} "
    addstr_safe(stdscr, 0, 2, header, curses.color_pair(C.HEADER) | curses.A_BOLD)
    hline_safe(stdscr, 1, 0, curses.ACS_HLINE, max_x, curses.color_pair(C.BORDER))

    # ── Contenu scrollable ──
    # Construire les lignes à afficher
    lines: list[tuple[str, int]] = []  # (texte, color_pair_idx)

    def add(text: str, color: int = C.NORMAL, bold: bool = False):
        attr = curses.color_pair(color)
        if bold:
            attr |= curses.A_BOLD
        lines.append((text, attr))

    # Titre CVE
    add(f"  {cve_id}", C.TITLE, bold=True)

    # Tag actuel
    if tag != Tag.NONE:
        add(f"  Tag : {TAG_ICONS[tag]} {tag.value}", TAG_COLORS[tag], bold=True)

    add("")

    # Métriques
    add("  ─ Métriques ─────────────────────────────", C.BORDER)
    add(f"  CVSS      : {cve.get('cvss', 'N/A')}", C.NORMAL, bold=True)
    add(f"  Sévérité  : {sev}", sev_col, bold=True)
    add(f"  Source    : {cve.get('source', 'Local DB')}")
    cve_tags = cve.get("tags", [])
    if cve_tags:
        add("")
        add("  ─ Tags ──────────────────────────────────", C.BORDER)
        add("  " + "  ".join(f"#{t}" for t in cve_tags), C.KEY_HINT, bold=True)

    # Confidence (nouveau moteur)
    conf = cve.get("_confidence")
    if conf:
        conf_colors = {"certain": C.LOW, "likely": C.MEDIUM, "uncertain": C.HIGH, "not_affected": C.DIM}
        add(f"  Confidence: {conf.upper()}", conf_colors.get(conf, C.DIM), bold=True)
        reason = cve.get("_match_reason", "")
        if reason:
            add(f"  Raison    : {reason}", C.DIM)

    add("")

    # Versions affectées
    affected = cve.get("affected_versions", [])
    if affected:
        add("  ─ Versions affectées ────────────────────", C.BORDER)
        for av in affected:
            add(f"    • {av}", C.MEDIUM)
        add("")

    # Description FR puis EN
    desc_fr = cve.get("description_fr", "")
    desc_en = cve.get("description", "")

    if desc_fr:
        add("  ─ Description (FR) ──────────────────────", C.BORDER)
        # Wrap le texte à max_x - 4
        wrap_w = max(20, max_x - 4)
        for word_line in _wrap_text(desc_fr, wrap_w):
            add(f"  {word_line}")
        add("")

    if desc_en:
        add("  ─ Description (EN) ──────────────────────", C.BORDER)
        wrap_w = max(20, max_x - 4)
        for word_line in _wrap_text(desc_en, wrap_w):
            add(f"  {word_line}", C.DIM)
        add("")

    # Exploit info (depuis update_db_ctf)
    exploit_db  = cve.get("exploit_db")
    metasploit  = cve.get("metasploit")
    ctf_machines = cve.get("ctf_machines", [])
    exploit_avail = cve.get("exploit_available", False)

    if exploit_avail or exploit_db or metasploit or ctf_machines:
        add("  ─ Exploit & CTF ─────────────────────────", C.BORDER)
        if exploit_avail:
            add("  Exploit disponible : OUI", C.TAG_EXPLOIT, bold=True)
        if exploit_db:
            add(f"  ExploitDB    : https://www.exploit-db.com/exploits/{exploit_db}",
                C.TAG_EXPLOIT)
        if metasploit:
            add(f"  Metasploit   : {metasploit}", C.HIGH, bold=True)
        if ctf_machines:
            add(f"  Machines CTF : {', '.join(ctf_machines)}", C.MEDIUM)
        add("")

    # Références
    refs = cve.get("references", [])
    if refs:
        add("  ─ Références ────────────────────────────", C.BORDER)
        for ref in refs:
            add(f"    {ref}", C.DIM)
        add("")

    # ── Rendu avec scroll ──
    content_h = max_y - 4  # lignes dispo (header=2 + status=1 + nav=1)
    max_scroll = max(0, len(lines) - content_h)
    state.scroll_detail = clamp(state.scroll_detail, 0, max_scroll)

    for i, (text, attr) in enumerate(lines[state.scroll_detail:state.scroll_detail + content_h]):
        addstr_safe(stdscr, 2 + i, 0, text[:max_x - 1], attr)

    # Indicateur scroll
    if len(lines) > content_h:
        pct   = int((state.scroll_detail / max_scroll) * 100) if max_scroll else 100
        nav   = f"  ↑↓ Scroll  ({pct}%  ligne {state.scroll_detail + 1}/{len(lines)})  "
        addstr_safe(stdscr, max_y - 2, 2, nav, curses.color_pair(C.DIM))

    # ── Status bar ──
    _draw_status_bar(stdscr, state,
        "[↑↓] Scroll  [E] Exploité  [N] Non appl.  [?] Incertain  [U] Démarquer  [Esc/Q] Retour")


def _wrap_text(text: str, width: int) -> list[str]:
    """Coupe le texte en lignes de longueur max `width`."""
    words  = text.split()
    lines  = []
    current = ""
    for word in words:
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


# ─── Export JSON des CVEs marquées ───────────────────────────────────────────

def export_tagged(state: UIState) -> str:
    """Exporte les CVEs marquées dans output/interactive_export_<ts>.json."""
    tagged = state.tagged_cves()
    if not tagged:
        return "Aucune CVE marquée à exporter."

    payload = []
    for svc, cve, tag in tagged:
        entry = {
            "host":     svc.get("host", ""),
            "port":     svc.get("port", ""),
            "protocol": svc.get("protocol", ""),
            "service":  svc.get("service_name", ""),
            "banner":   svc.get("banner", ""),
            "cve_id":   cve.get("id", ""),
            "cvss":     cve.get("cvss", "N/A"),
            "severity": cve.get("severity", "UNKNOWN"),
            "tag":      tag.value,
            "description": cve.get("description_fr") or cve.get("description", ""),
            "exploit_db":  cve.get("exploit_db"),
            "metasploit":  cve.get("metasploit"),
            "references":  cve.get("references", []),
        }
        payload.append(entry)

    state.output_dir.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = state.output_dir / f"interactive_export_{ts}.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    return f"Exporté : {out_path}  ({len(payload)} CVEs)"


# ─── Saisie de filtre inline ──────────────────────────────────────────────────

def prompt_filter(stdscr, state: UIState):
    """Mini prompt de saisie en bas de l'écran pour le filtre /."""
    max_y, max_x = stdscr.getmaxyx()
    y = max_y - 1
    prompt = " Filtre (Entrée=valider, Esc=annuler) : "
    text   = state.filter_text

    curses.curs_set(1)
    while True:
        addstr_safe(stdscr, y, 0, " " * max_x, curses.color_pair(C.STATUS_BAR))
        addstr_safe(stdscr, y, 0, prompt, curses.color_pair(C.STATUS_BAR) | curses.A_BOLD)
        addstr_safe(stdscr, y, len(prompt), text, curses.color_pair(C.STATUS_BAR))
        stdscr.move(y, len(prompt) + len(text))
        stdscr.refresh()

        ch = stdscr.getch()
        if ch in (curses.KEY_ENTER, ord('\n'), ord('\r')):
            break
        elif ch in (27, curses.ascii.ESC):
            text = state.filter_text  # annuler
            break
        elif ch in (curses.KEY_BACKSPACE, 127, curses.ascii.BS):
            text = text[:-1]
        elif 32 <= ch <= 126:
            text += chr(ch)

    curses.curs_set(0)
    state.filter_text = text
    state.cve_cursor  = 0  # reset curseur après filtre


# ─── Boucle principale ────────────────────────────────────────────────────────

def run_interactive(results: list[dict], output_dir: str = "output"):
    """Point d'entrée public — lance le TUI interactif."""
    if not results:
        print("[!] Aucun résultat à afficher en mode interactif.")
        return

    def _main(stdscr):
        curses.curs_set(0)
        curses.noecho()
        curses.cbreak()
        stdscr.keypad(True)

        init_colors()

        state = UIState(
            results    = results,
            tags       = {},
            output_dir = Path(output_dir),
        )

        while True:
            max_y, max_x = stdscr.getmaxyx()

            # ── Rendu selon la vue active ──
            if state.view == "ports":
                draw_ports_view(stdscr, state)
            elif state.view == "cves":
                draw_cves_view(stdscr, state)
            elif state.view == "detail":
                draw_detail_view(stdscr, state)

            stdscr.refresh()

            # ── Lecture d'une touche ──
            ch = stdscr.getch()
            n_ports = len(state.results)
            state.status_msg = ""  # reset message

            # ── Navigation universelle ──
            if ch in (ord('q'), ord('Q')):
                if state.view == "ports":
                    break  # quitter
                elif state.view == "cves":
                    state.view = "ports"
                elif state.view == "detail":
                    state.view = "cves"

            elif ch in (27,):  # Escape
                if state.view == "cves":
                    state.view = "ports"
                elif state.view == "detail":
                    state.view = "cves"
                    state.scroll_detail = 0

            # ── Touches de navigation ──
            elif ch in (curses.KEY_UP, ord('k')):
                if state.view == "ports":
                    state.port_cursor = clamp(state.port_cursor - 1, 0, n_ports - 1)
                elif state.view == "cves":
                    n_cves = len(state.filtered_cves())
                    state.cve_cursor = clamp(state.cve_cursor - 1, 0, max(0, n_cves - 1))
                elif state.view == "detail":
                    state.scroll_detail = max(0, state.scroll_detail - 1)

            elif ch in (curses.KEY_DOWN, ord('j')):
                if state.view == "ports":
                    state.port_cursor = clamp(state.port_cursor + 1, 0, n_ports - 1)
                elif state.view == "cves":
                    n_cves = len(state.filtered_cves())
                    state.cve_cursor = clamp(state.cve_cursor + 1, 0, max(0, n_cves - 1))
                elif state.view == "detail":
                    state.scroll_detail += 1  # clamp appliqué au rendu

            elif ch in (curses.KEY_PPAGE,):  # Page Up
                if state.view == "ports":
                    state.port_cursor = clamp(state.port_cursor - 10, 0, n_ports - 1)
                elif state.view == "cves":
                    n_cves = len(state.filtered_cves())
                    state.cve_cursor = clamp(state.cve_cursor - 10, 0, max(0, n_cves - 1))
                elif state.view == "detail":
                    state.scroll_detail = max(0, state.scroll_detail - 10)

            elif ch in (curses.KEY_NPAGE,):  # Page Down
                if state.view == "ports":
                    state.port_cursor = clamp(state.port_cursor + 10, 0, n_ports - 1)
                elif state.view == "cves":
                    n_cves = len(state.filtered_cves())
                    state.cve_cursor = clamp(state.cve_cursor + 10, 0, max(0, n_cves - 1))
                elif state.view == "detail":
                    state.scroll_detail += 10

            elif ch in (curses.KEY_HOME, ord('g')):
                if state.view == "ports":   state.port_cursor = 0
                elif state.view == "cves":  state.cve_cursor  = 0
                elif state.view == "detail": state.scroll_detail = 0

            elif ch in (curses.KEY_END, ord('G')):
                if state.view == "ports":
                    state.port_cursor = n_ports - 1
                elif state.view == "cves":
                    state.cve_cursor = max(0, len(state.filtered_cves()) - 1)

            # ── Entrée = ouvrir ──
            elif ch in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                if state.view == "ports":
                    state.current_port_idx = state.port_cursor
                    state.cve_cursor       = 0
                    state.view             = "cves"
                elif state.view == "cves":
                    cves = state.filtered_cves()
                    if cves:
                        state.scroll_detail = 0
                        state.view          = "detail"

            # ── Actions de marquage (disponibles depuis cves et detail) ──
            elif ch in (ord('e'), ord('E')) and state.view in ("cves", "detail"):
                cves = state.filtered_cves()
                if cves and state.cve_cursor < len(cves):
                    cve_id = cves[state.cve_cursor].get("id", "")
                    cur_tag = state.get_tag(cve_id)
                    new_tag = Tag.NONE if cur_tag == Tag.EXPLOITED else Tag.EXPLOITED
                    state.tag_cve(cve_id, new_tag)
                    action = "démarqué" if new_tag == Tag.NONE else "marqué EXPLOITÉ"
                    state.status_msg = f"  {cve_id} {action}"

            elif ch in (ord('n'), ord('N')) and state.view in ("cves", "detail"):
                cves = state.filtered_cves()
                if cves and state.cve_cursor < len(cves):
                    cve_id = cves[state.cve_cursor].get("id", "")
                    cur_tag = state.get_tag(cve_id)
                    new_tag = Tag.NONE if cur_tag == Tag.NA else Tag.NA
                    state.tag_cve(cve_id, new_tag)
                    action = "démarqué" if new_tag == Tag.NONE else "marqué NON APPLICABLE"
                    state.status_msg = f"  {cve_id} {action}"

            elif ch == ord('?') and state.view in ("cves", "detail"):
                cves = state.filtered_cves()
                if cves and state.cve_cursor < len(cves):
                    cve_id = cves[state.cve_cursor].get("id", "")
                    cur_tag = state.get_tag(cve_id)
                    new_tag = Tag.NONE if cur_tag == Tag.UNCERTAIN else Tag.UNCERTAIN
                    state.tag_cve(cve_id, new_tag)
                    action = "démarqué" if new_tag == Tag.NONE else "marqué INCERTAIN"
                    state.status_msg = f"  {cve_id} {action}"

            elif ch in (ord('u'), ord('U')) and state.view in ("cves", "detail"):
                cves = state.filtered_cves()
                if cves and state.cve_cursor < len(cves):
                    cve_id = cves[state.cve_cursor].get("id", "")
                    state.tag_cve(cve_id, Tag.NONE)
                    state.status_msg = f"  {cve_id} démarqué"

            # ── Filtre / ──
            elif ch == ord('/') and state.view == "cves":
                prompt_filter(stdscr, state)

            # ── Réinitialiser le filtre ──
            elif ch in (ord('c'), ord('C')) and state.view == "cves":
                state.filter_text = ""
                state.cve_cursor  = 0
                state.status_msg  = "  Filtre réinitialisé"

            # ── Tri S ──
            elif ch in (ord('s'), ord('S')) and state.view == "cves":
                cycle = ["cvss", "severity", "id"]
                idx   = cycle.index(state.sort_key)
                state.sort_key   = cycle[(idx + 1) % len(cycle)]
                state.cve_cursor = 0
                state.status_msg = f"  Tri : {state.sort_key.upper()}"

            # ── Export X ──
            elif ch in (ord('x'), ord('X')):
                msg = export_tagged(state)
                state.status_msg = f"  {msg}"

            # ── Redimensionnement terminal ──
            elif ch == curses.KEY_RESIZE:
                stdscr.clear()

    curses.wrapper(_main)
