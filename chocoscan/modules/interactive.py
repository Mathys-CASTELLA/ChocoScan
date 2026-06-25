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

Vue Modules (nouveau) :
  M            → Ouvrir la vue des modules recommandés
  ↑↓/jk        → Naviguer dans la liste des modules
  Entrée        → Exécuter le module sélectionné et afficher le résultat
  Esc / q       → Revenir à la vue précédente
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
from typing import Any, Optional


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
    MOD_DONE    = 16  # Module exécuté avec succès
    MOD_SEL     = 17  # Ligne sélectionnée vue modules


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



# ─── Module Suggestions ───────────────────────────────────────────────────────

@dataclass
class ModuleSuggestion:
    """Représente un module recommandé pour les services détectés dans le scan."""
    key:      str          # "web" | "smb" | "brute" | "pivot" | "container" | "tokens"
    icon:     str          # Icône ASCII/unicode
    title:    str          # Titre lisible
    trigger:  str          # Raison de la recommandation (port/service détecté)
    cli_flag: str          # Flag CLI équivalent (ex: --smb)
    status:   str = "pending"  # pending | running | done | error
    output:   list = field(default_factory=list)   # list[tuple[str, int]]


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
    # ── Module recommendations ──
    lhost:              str  = ""
    lport:              int  = 4444
    module_cursor:      int  = 0
    module_scroll:      int  = 0
    module_suggestions: list = field(default_factory=list)

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
    curses.init_pair(C.MOD_DONE,    curses.COLOR_GREEN,   bg)
    curses.init_pair(C.MOD_SEL,     curses.COLOR_BLACK,   curses.COLOR_CYAN)


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
        "[↑↓/jk] Naviguer  [Entrée] Ouvrir  [M] Modules  [X] Exporter  [Q] Quitter")


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



# ─── Moteur de recommandation ────────────────────────────────────────────────

def _recommend_modules(results: list[dict], lhost: str = "", lport: int = 4444) -> list[ModuleSuggestion]:
    """Analyse les résultats du scan et retourne les modules pertinents."""
    suggestions: list[ModuleSuggestion] = []
    ports_open   = {r.get("service", {}).get("port", 0)  for r in results}
    svc_names    = {(r.get("service", {}).get("service_name", "") or "").lower() for r in results}

    # ── Web payloads ──────────────────────────────────────────────────────────
    web_ports = sorted(p for p in ports_open if p in (80, 443, 8080, 8443, 8000, 8001, 3000, 5000))
    has_http  = bool(web_ports) or any("http" in s for s in svc_names)
    if has_http:
        trigger = "HTTP sur ports : " + ", ".join(str(p) for p in web_ports) if web_ports else "HTTP détecté"
        suggestions.append(ModuleSuggestion(
            key="web", icon="[WEB]", title="Web Payload Generator",
            trigger=trigger, cli_flag=f"--web-payloads --lhost {lhost or 'LHOST'}",
        ))

    # ── SMB ───────────────────────────────────────────────────────────────────
    has_smb = 445 in ports_open or 139 in ports_open or any("smb" in s or "microsoft-ds" in s for s in svc_names)
    if has_smb:
        host_smb = next((r["service"].get("host", "") for r in results
                         if r.get("service", {}).get("port") in (445, 139)), "")
        suggestions.append(ModuleSuggestion(
            key="smb", icon="[SMB]", title="SMB Helper + Impacket",
            trigger=f"SMB détecté → {host_smb}:445", cli_flag="--smb",
        ))

    # ── Brute force ───────────────────────────────────────────────────────────
    brute_ports = {22, 21, 80, 443, 445, 3389, 3306, 5432, 5985, 389, 25, 23, 5900}
    bruteable   = sorted(brute_ports & ports_open)
    if bruteable:
        trigger = "Services : " + ", ".join(str(p) for p in bruteable[:5])
        suggestions.append(ModuleSuggestion(
            key="brute", icon="[BRF]", title="Brute Force Helper",
            trigger=trigger, cli_flag="--brute",
        ))

    # ── Pivot ─────────────────────────────────────────────────────────────────
    ssh_open = 22 in ports_open or any("ssh" in s for s in svc_names)
    if ssh_open or len({r.get("service", {}).get("host", "") for r in results}) > 1:
        trigger = "SSH:22 détecté" if ssh_open else "Multiples hôtes détectés"
        suggestions.append(ModuleSuggestion(
            key="pivot", icon="[PIV]", title="Pivot Helper",
            trigger=trigger, cli_flag=f"--pivot {lhost or 'LHOST'}",
        ))

    # ── Container escape ──────────────────────────────────────────────────────
    container_ports = {2375, 2376, 6443, 10250, 9000, 9443}
    found_ct = sorted(container_ports & ports_open)
    if found_ct or any(k in " ".join(svc_names) for k in ("docker", "kubernetes", "k8s")):
        trigger = "Ports conteneurs : " + ", ".join(str(p) for p in found_ct) if found_ct else "Docker/K8s détecté"
        suggestions.append(ModuleSuggestion(
            key="container", icon="[CTR]", title="Container Escape",
            trigger=trigger, cli_flag="--container",
        ))

    # ── Token helper (Windows) ────────────────────────────────────────────────
    win_ports = {3389, 5985, 5986, 1433}
    found_win = sorted(win_ports & ports_open)
    has_win   = bool(found_win) or any(k in " ".join(svc_names) for k in ("rdp", "winrm", "mssql", "ms-wbt"))
    if has_win:
        trigger = "Windows (ports : " + ", ".join(str(p) for p in found_win) + ")" if found_win else "Services Windows détectés"
        suggestions.append(ModuleSuggestion(
            key="tokens", icon="[TOK]", title="Token Privilege Helper",
            trigger=trigger, cli_flag="--tokens",
        ))

    # ── Cloud enum (si services web ou IPs cloud détectés) ───────────────────
    cloud_ports = {80, 443, 8080, 8443}
    has_web = bool(ports_open & cloud_ports)
    cloud_keywords = ("amazonaws", "azure", "googleapis", "cloudapp", "s3.", "blob")
    has_cloud_sig  = any(
        any(kw in (r.get("service", {}).get("banner", "") or "").lower() for kw in cloud_keywords)
        for r in results
    )
    if has_web or has_cloud_sig:
        trigger = "Signature cloud détectée" if has_cloud_sig else "Services web → SSRF metadata possible"
        suggestions.append(ModuleSuggestion(
            key="cloud", icon="[CLD]", title="Cloud Enumeration",
            trigger=trigger, cli_flag="--cloud",
        ))

    # ── Lateral movement (si AD/Windows détecté) ─────────────────────────────
    win_ports = {445, 3389, 5985, 1433, 88, 389, 636}
    has_windows = bool(ports_open & win_ports)
    if has_windows:
        dc_flag = 88 in ports_open and 389 in ports_open
        trigger = "DC détecté" if dc_flag else f"Windows (ports: {', '.join(str(p) for p in sorted(win_ports & ports_open)[:4])})"
        suggestions.append(ModuleSuggestion(
            key="lateral", icon="[LAT]", title="Lateral Movement",
            trigger=trigger, cli_flag="--lateral",
        ))

    # ── Wordlist builder (toujours suggéré) ─────────────────────────────────
    suggestions.append(ModuleSuggestion(
        key="wordlist", icon="[WLB]", title="Wordlist Builder",
        trigger=f"Mots extraits : domaine, hostname, produits détectés",
        cli_flag="--wordlist /tmp/chocoscan_wl.txt",
    ))

    # Fallback si aucun module suggéré
    if not suggestions:
        suggestions.append(ModuleSuggestion(
            key="brute", icon="[BRF]", title="Brute Force Helper",
            trigger="Aucun service spécifique détecté — brute force générique",
            cli_flag="--brute",
        ))

    return suggestions


# ─── Helper : reconstructeur de services ─────────────────────────────────────

def _results_to_services(results: list[dict]) -> list:
    """Reconstitue des objets pseudo-NmapService depuis les dicts résultats."""
    class _Svc:
        __slots__ = ("host","port","protocol","service_name","product","version","banner")
        def __init__(self, d: dict):
            self.host         = d.get("host", "")
            self.port         = d.get("port", 0)
            self.protocol     = d.get("protocol", "tcp")
            self.service_name = d.get("service_name", "")
            self.product      = d.get("product", "")
            self.version      = d.get("version", "")
            self.banner       = d.get("banner", "")
    return [_Svc(r.get("service", {})) for r in results]


# ─── Colorisation des lignes ──────────────────────────────────────────────────

def _colorize(line: str) -> int:
    """Retourne l'indice de couleur C.* adapté au contenu de la ligne."""
    s = line.lstrip()
    if not s:
        return C.NORMAL
    if s.startswith("── ") or s.startswith("─ "):
        return C.TITLE
    if s.startswith("#"):
        return C.DIM
    if "[CRITICAL]" in s[:20] or s.startswith("⚠"):
        return C.CRITICAL
    if "[HIGH]" in s[:15]:
        return C.HIGH
    if s.startswith("•") or s.startswith("Note") or s.startswith("→") or s.startswith("Télécharger"):
        return C.DIM
    return C.LOW   # vert pour les commandes

def _text_lines(text: str) -> list[tuple[str, int]]:
    return [(line, _colorize(line)) for line in text.split("\n")]


# ─── Formatters par module ────────────────────────────────────────────────────

def _fmt_web(results) -> list[tuple[str, int]]:
    if not results:
        return [("Aucun service HTTP/HTTPS détecté.", C.DIM)]
    out: list[tuple[str, int]] = []
    for wp in results:
        out.append((f"── {wp.protocol.upper()}://{wp.host}:{wp.port}  [{', '.join(wp.detected_tech) or 'stack inconnue'}]", C.TITLE))
        out.append((f"   OS hint : {wp.os_hint}", C.DIM))
        out.append(("", C.NORMAL))
        out.append(("── LFI / Path Traversal", C.HIGH))
        for p in wp.lfi_payloads[:8]:
            out.append((f"  {p.payload}", C.LOW))
            if p.description:
                out.append((f"    # {p.description}", C.DIM))
        out.append(("", C.NORMAL))
        out.append(("── SSTI — Moteurs détectés", C.HIGH))
        for e in wp.ssti_engines[:4]:
            out.append((f"  [{e.name}]  tech: {', '.join(e.tech)}", C.MEDIUM))
            out.append((f"    detect  : {e.detect}", C.LOW))
            rce_first = next((l for l in e.rce_linux.split("\n") if l.strip() and not l.startswith("#")), "")
            if rce_first:
                out.append((f"    rce     : {rce_first}", C.LOW))
        out.append(("", C.NORMAL))
        out.append(("── SQLi — DBMS détectés", C.HIGH))
        for sq in wp.sqli_entries[:3]:
            out.append((f"  [{sq.dbms}]", C.MEDIUM))
            first_err = next((l for l in sq.error_based.split("\n") if l.strip() and not l.startswith("#")), "")
            first_blind = next((l for l in sq.blind_time.split("\n") if l.strip() and not l.startswith("#")), "")
            if first_err:   out.append((f"    error  : {first_err}", C.LOW))
            if first_blind: out.append((f"    blind  : {first_blind}", C.LOW))
        out.append(("", C.NORMAL))
        out.append(("── sqlmap", C.HIGH))
        for line in wp.sqlmap_cmds[:6]:
            out.append((line, _colorize(line)))
        out.append(("", C.NORMAL))
    return out


def _fmt_smb(result) -> list[tuple[str, int]]:
    if result is None:
        return [("Aucun service SMB détecté.", C.DIM)]
    out: list[tuple[str, int]] = []
    ctx = result.context
    out.append((f"SMB : {ctx.host}:{ctx.port}   domaine : {ctx.domain}", C.TITLE))
    if not ctx.signing:
        out.append(("[CRITICAL] Signing DÉSACTIVÉ — NTLM relay possible !", C.CRITICAL))
    if ctx.dc:
        out.append(("Contrôleur de domaine (port 88+389) → Kerberoasting disponible", C.HIGH))
    out.append(("", C.NORMAL))
    sections = [
        ("Null session",       result.null_session),
        ("Énumération (auth)", result.enumeration),
        ("Impacket",           result.impacket),
        ("Relay NTLM",         result.relay if result.relay_possible else []),
        ("Pass-the-Hash",      result.pass_the_hash),
        ("Kerberos",           result.kerberos),
    ]
    for title, cmds in sections:
        if not cmds:
            continue
        out.append((f"── {title}", C.TITLE))
        for cmd in cmds:
            out.append((f"  {cmd.title}", C.HIGH))
            for line in cmd.command.split("\n")[:5]:
                out.append(("    " + line, _colorize(line)))
            if cmd.notes:
                out.append((f"    # {cmd.notes[0]}", C.DIM))
            out.append(("", C.NORMAL))
    return out


def _fmt_brute(results) -> list[tuple[str, int]]:
    if not results:
        return [("Aucun service bruteforçable détecté.", C.DIM)]
    out: list[tuple[str, int]] = []
    for br in results:
        out.append((f"── Host : {br.host}", C.TITLE))
        for cmd in br.commands:
            out.append((f"  [{cmd.tool.upper()}] {cmd.title}", C.HIGH))
            first_cmd = next((l for l in cmd.command.split("\n") if l.strip() and not l.startswith("#")), "")
            if first_cmd:
                out.append((f"    {first_cmd}", C.LOW))
            if cmd.notes:
                out.append((f"    # {cmd.notes[0]}", C.DIM))
            out.append(("", C.NORMAL))
        for note in br.notes[:2]:
            out.append((f"  # {note}", C.DIM))
    return out


def _fmt_pivot(result) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    out.append((f"── Pivot → {result.target}   LHOST : {result.lhost}", C.TITLE))
    out.append((f"   SSH : {'ouvert' if result.ssh_available else 'non détecté'}   "
                f"Réseaux internes : {', '.join(result.internal_nets) or 'aucun détecté'}", C.DIM))
    out.append(("", C.NORMAL))
    out.append(("── Quick start", C.HIGH))
    for line in result.quick_start.split("\n"):
        out.append((line, _colorize(line)))
    out.append(("", C.NORMAL))
    for guide in result.guides:
        out.append((f"── {guide.title}", C.TITLE))
        out.append((f"   {guide.description}", C.DIM))
        for line in guide.attacker[:6]:
            out.append(("  " + line, _colorize(line)))
        if guide.target:
            out.append(("  # — sur la cible :", C.DIM))
            for line in guide.target[:4]:
                out.append(("  " + line, _colorize(line)))
        out.append(("", C.NORMAL))
    for note in result.notes[:3]:
        out.append((f"  # {note}", C.DIM))
    return out


def _fmt_container(checks, ext_checks) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    if ext_checks:
        out.append(("── Services conteneurs exposés (attaque externe)", C.CRITICAL))
        for ec in ext_checks:
            out.append((f"  [{ec.severity.upper()}] {ec.title}", C.CRITICAL if ec.severity == "critical" else C.HIGH))
            for line in ec.command.split("\n")[:5]:
                out.append(("    " + line, _colorize(line)))
            out.append(("", C.NORMAL))
    out.append(("── Checklist shell interne", C.TITLE))
    for check in checks:
        sev_c = {"critical": C.CRITICAL, "high": C.HIGH, "medium": C.MEDIUM}.get(check.severity, C.DIM)
        out.append((f"  [{check.severity.upper()}] {check.title}", sev_c))
        out.append((f"    # {check.description[:90]}", C.DIM))
        for line in check.check_cmd.split("\n")[:3]:
            out.append(("    " + line, _colorize(line)))
        exploit_lines = [l for l in check.exploit_cmd.split("\n") if l.strip() and not l.startswith("#")]
        for line in exploit_lines[:2]:
            out.append(("    " + line, C.LOW))
        out.append(("", C.NORMAL))
    return out


def _fmt_tokens(checks) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    cat_current = ""
    cat_labels = {
        "potato": "Potato Attacks (SeImpersonate → SYSTEM direct)",
        "debug":  "SeDebugPrivilege — LSASS dump",
        "ownership": "SeTakeOwnershipPrivilege",
        "backup":    "SeBackupPrivilege / SeRestorePrivilege",
        "driver":    "SeLoadDriverPrivilege — BYOVD",
        "misc":      "Autres (AlwaysInstallElevated, Incognito, winPEAS)",
    }
    for check in checks:
        if check.category != cat_current:
            cat_current = check.category
            out.append((f"── {cat_labels.get(check.category, check.category)}", C.TITLE))
        sev_c = {"critical": C.CRITICAL, "high": C.HIGH}.get(check.severity, C.MEDIUM)
        out.append((f"  [{check.severity.upper()}] {check.title}", sev_c))
        out.append((f"    # privilege : {check.privilege}", C.DIM))
        for line in check.check_cmd.split("\n")[:3]:
            out.append(("    " + line, _colorize(line)))
        exploit_lines = [l for l in check.exploit_cmd.split("\n") if l.strip() and not l.startswith("#")]
        for line in exploit_lines[:3]:
            out.append(("    " + line, C.LOW))
        out.append(("", C.NORMAL))
    return out






def _fmt_cloud(result) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    prov = ", ".join(result.detected_providers).upper() or "GÉNÉRIQUE"
    out.append((f"Cloud Enum — {result.target}  providers: {prov}", C.TITLE))
    out.append((f"  SSRF context: {'oui → tester metadata services' if result.ssrf_context else 'non détecté'}", C.HIGH if result.ssrf_context else C.DIM))
    out.append((f"  {len(result.checks)} checks disponibles", C.DIM))
    if result.bucket_candidates:
        out.append((f"  Candidats buckets: {', '.join(result.bucket_candidates[:6])}", C.DIM))
    out.append(("", C.NORMAL))
    cat_labels = {
        "storage": "Stockage (S3 / Blob / GCS)",
        "iam":     "IAM & Credentials",
        "metadata":"Metadata Service via SSRF",
        "secrets": "Secrets & Tokens leakés",
        "misc":    "Outils multi-cloud",
    }
    prov_colors = {"aws": C.HIGH, "azure": C.TITLE, "gcp": C.CRITICAL, "generic": C.MEDIUM}
    current_cat = ""
    for check in result.checks:
        if check.category != current_cat:
            current_cat = check.category
            col = prov_colors.get(check.provider, C.MEDIUM)
            out.append((f"── [{check.provider.upper()}] {cat_labels.get(check.category, check.category)}", col))
        sev_c = {"critical": C.CRITICAL, "high": C.HIGH}.get(check.severity, C.MEDIUM)
        out.append((f"  [{check.severity.upper()}] {check.title}", sev_c))
        out.append((f"    # {check.description[:90]}", C.DIM))
        for line in [l for l in check.exploit_cmd.split("\n") if l.strip() and not l.startswith("#")][:3]:
            out.append(("    " + line, C.LOW))
        if check.notes:
            out.append((f"    # {check.notes[0]}", C.DIM))
        out.append(("", C.NORMAL))
    for note in result.notes[:5]:
        out.append((f"# {note}", C.DIM))
    return out

def _fmt_lateral(result) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    out.append((f"Lateral Movement — domaine: {result.domain}  cible: {result.target}", C.TITLE))
    flags = []
    if result.dc_detected:    flags.append("DC détecté")
    if result.mssql_detected: flags.append("MSSQL détecté")
    if result.rdp_detected:   flags.append("RDP détecté")
    out.append((f"  Contexte : {' | '.join(flags) or 'générique Windows'}", C.HIGH))
    out.append((f"  {len(result.techniques)} techniques disponibles", C.DIM))
    out.append(("", C.NORMAL))
    cat_labels = {
        "dcom": "DCOM", "wmi": "WMI natif", "mssql": "MSSQL Linked Servers",
        "laps": "LAPS", "delegation": "Délégation Kerberos",
        "coercion": "Coercition NTLM", "adcs": "AD CS / certipy",
        "shadow": "Shadow Credentials", "rdp": "RDP Hijacking",
    }
    current_cat = ""
    for tech in result.techniques:
        if tech.category != current_cat:
            current_cat = tech.category
            out.append((f"── {cat_labels.get(tech.category, tech.category)}", C.TITLE))
        sev_c = {"critical": C.CRITICAL, "high": C.HIGH}.get(tech.severity, C.MEDIUM)
        out.append((f"  [{tech.severity.upper()}] {tech.title}", sev_c))
        out.append((f"    # {tech.description[:90]}", C.DIM))
        for line in tech.check_cmd.split("\n")[:2]:
            out.append(("    " + line, _colorize(line)))
        for line in [l for l in tech.exploit_cmd.split("\n") if l.strip() and not l.startswith("#")][:3]:
            out.append(("    " + line, C.LOW))
        if tech.notes:
            out.append((f"    # {tech.notes[0]}", C.DIM))
        out.append(("", C.NORMAL))
    return out

def _fmt_wordlist(result) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    s = result.stats
    out.append((f"Wordlist — {result.target}  domaine: {result.domain or 'N/A'}  société: {result.company or 'N/A'}", C.TITLE))
    out.append((f"  {s['base_words']} mots de base  →  {s['total_words']} après mutations", C.HIGH))
    out.append((f"  avec symbole: {s['words_with_sym']}  avec chiffre: {s['words_with_num']}  min/moy/max: {s['min_len']}/{s['avg_len']}/{s['max_len']} chars", C.DIM))
    out.append(("", C.NORMAL))
    out.append(("── Mots de base extraits", C.TITLE))
    for w in result.base_words[:15]:
        out.append((f"  {w}", C.LOW))
    if len(result.base_words) > 15:
        out.append((f"  ... {len(result.base_words)-15} autres", C.DIM))
    out.append(("", C.NORMAL))
    out.append(("── Aperçu wordlist mutée (30 premiers)", C.TITLE))
    for w in result.all_words[:30]:
        out.append((f"  {w}", C.LOW))
    if len(result.all_words) > 30:
        out.append((f"  ... {len(result.all_words)-30} autres — exporter avec --wordlist /tmp/out.txt", C.DIM))
    out.append(("", C.NORMAL))
    out.append(("── CeWL — spider les services web", C.TITLE))
    for line in result.cewl_cmds[:10]:
        out.append((line, _colorize(line)))
    out.append(("", C.NORMAL))
    out.append(("── Génération usernames", C.TITLE))
    for line in result.username_cmds[:8]:
        out.append((line, _colorize(line)))
    out.append(("", C.NORMAL))
    out.append(("── Règles hashcat", C.TITLE))
    for line in result.hashcat_rules[:6]:
        out.append((line, _colorize(line)))
    for note in result.notes[:3]:
        out.append((f"  # {note}", C.DIM))
    return out

# ─── Exécuteur de module ──────────────────────────────────────────────────────

def _run_module(sugg: ModuleSuggestion, results: list[dict],
                lhost: str, lport: int) -> None:
    """Appelle le module correspondant et remplit sugg.output."""
    sugg.status = "running"
    try:
        if sugg.key == "smb":
            from modules.smb_helper import generate_smb_commands
            sugg.output = _fmt_smb(generate_smb_commands(results))

        elif sugg.key == "web":
            from modules.web_payload_gen import analyze_web_payloads
            svcs = _results_to_services(results)
            sugg.output = _fmt_web(analyze_web_payloads(svcs, lhost=lhost, lport=lport))

        elif sugg.key == "brute":
            from modules.brute_helper import generate_brute_commands
            sugg.output = _fmt_brute(generate_brute_commands(results))

        elif sugg.key == "pivot":
            from modules.pivot_helper import generate_pivot_commands
            sugg.output = _fmt_pivot(generate_pivot_commands(results, lhost=lhost, lport=lport))

        elif sugg.key == "container":
            from modules.container_escape import (get_container_escape_checklist,
                                                   analyze_container_host)
            checks = get_container_escape_checklist()
            ext    = analyze_container_host(results, lhost=lhost)
            sugg.output = _fmt_container(checks, ext)

        elif sugg.key == "cloud":
            from modules.cloud_enum import enumerate_cloud
            sugg.output = _fmt_cloud(enumerate_cloud(results))

        elif sugg.key == "lateral":
            from modules.lateral_movement import generate_lateral_commands
            sugg.output = _fmt_lateral(generate_lateral_commands(results))

        elif sugg.key == "wordlist":
            from modules.wordlist_builder import build_wordlists
            sugg.output = _fmt_wordlist(build_wordlists(results))

        elif sugg.key == "tokens":
            from modules.token_helper import get_token_checks
            sugg.output = _fmt_tokens(get_token_checks())

        else:
            sugg.output = [("Module non reconnu.", C.DIM)]

        sugg.status = "done"

    except Exception as exc:
        sugg.output = [
            ("[ERREUR] Impossible d'exécuter le module.", C.CRITICAL),
            (str(exc)[:120], C.DIM),
            ("Vérifier que les modules sont dans modules/", C.DIM),
        ]
        sugg.status = "error"


# ─── Vue : liste des modules recommandés ─────────────────────────────────────

def draw_modules_view(stdscr, state: UIState) -> None:
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()

    # ── Header ──
    addstr_safe(stdscr, 0, 0, " " * max_x, curses.color_pair(C.HEADER) | curses.A_BOLD)
    addstr_safe(stdscr, 0, 2,
                " ChocoScan  ›  Modules recommandés ",
                curses.color_pair(C.HEADER) | curses.A_BOLD)
    n_done = sum(1 for s in state.module_suggestions if s.status == "done")
    info_r = f" {len(state.module_suggestions)} modules | {n_done} exécutés "
    addstr_safe(stdscr, 0, max_x - len(info_r) - 1,
                info_r, curses.color_pair(C.HEADER))

    # ── Sous-titre ──
    lhost_info = f"LHOST : {state.lhost or '(non défini — utiliser --lhost)'}  "
    addstr_safe(stdscr, 1, 2, lhost_info, curses.color_pair(C.DIM))
    if not state.lhost:
        addstr_safe(stdscr, 1, 2 + len(lhost_info),
                    "→ passer --lhost 10.x.x.x pour les modules qui en ont besoin",
                    curses.color_pair(C.HIGH))
    hline_safe(stdscr, 2, 0, curses.ACS_HLINE, max_x, curses.color_pair(C.BORDER))

    # ── Colonne header ──
    col_h = f"  {'#':<3} {'ICÔNE':<6} {'MODULE':<28} {'DÉCLENCHEUR':<32} STATUT"
    addstr_safe(stdscr, 3, 0, col_h[:max_x], curses.A_DIM)
    hline_safe(stdscr, 4, 0, curses.ACS_HLINE, max_x, curses.color_pair(C.BORDER))

    # ── Liste ──
    suggestions = state.module_suggestions
    n      = len(suggestions)
    list_h = max_y - 8
    scroll = max(0, state.module_cursor - list_h + 3)
    scroll = min(scroll, max(0, n - list_h))

    for i, sugg in enumerate(suggestions[scroll:scroll + list_h]):
        real_idx = i + scroll
        is_sel   = (real_idx == state.module_cursor)
        y        = 5 + i

        if is_sel:
            addstr_safe(stdscr, y, 0, " " * max_x, curses.color_pair(C.MOD_SEL))

        sel_char = "▶" if is_sel else " "
        num_str  = f"{real_idx + 1:<3}"

        status_text, status_col = {
            "pending": ("● Prêt",    C.DIM),
            "running": ("⟳ En cours", C.MEDIUM),
            "done":    ("✓ Exécuté", C.MOD_DONE),
            "error":   ("✗ Erreur",  C.CRITICAL),
        }.get(sugg.status, ("? Inconnu", C.DIM))

        base_attr = curses.color_pair(C.MOD_SEL) | curses.A_BOLD if is_sel else curses.color_pair(C.NORMAL)
        st_attr   = (curses.color_pair(C.MOD_SEL) | curses.A_BOLD) if is_sel else (curses.color_pair(status_col) | curses.A_BOLD)

        row = f" {sel_char} {num_str} {sugg.icon:<6} {sugg.title:<28} {sugg.trigger[:31]:<32}"
        addstr_safe(stdscr, y, 0, row[:max_x - 14], base_attr)
        addstr_safe(stdscr, y, max_x - 13, f" {status_text:<12}", st_attr)

    hline_safe(stdscr, max_y - 3, 0, curses.ACS_HLINE, max_x, curses.color_pair(C.BORDER))

    # ── Astuce CLI ──
    if 0 <= state.module_cursor < len(suggestions):
        cli_hint = f"  Équivalent CLI : python3 chocoscan.py -x scan.xml {suggestions[state.module_cursor].cli_flag}"
        addstr_safe(stdscr, max_y - 2, 0, cli_hint[:max_x - 1], curses.color_pair(C.DIM))

    _draw_status_bar(stdscr, state,
        "[↑↓/jk] Naviguer  [Entrée] Exécuter+Afficher  [Esc/Q] Retour ports")


# ─── Vue : résultat d'un module ───────────────────────────────────────────────

def draw_module_output_view(stdscr, state: UIState) -> None:
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()

    if not (0 <= state.module_cursor < len(state.module_suggestions)):
        return
    sugg = state.module_suggestions[state.module_cursor]

    # ── Header ──
    addstr_safe(stdscr, 0, 0, " " * max_x, curses.color_pair(C.HEADER) | curses.A_BOLD)
    header = f" ChocoScan  ›  Modules  ›  {sugg.title} "
    addstr_safe(stdscr, 0, 2, header, curses.color_pair(C.HEADER) | curses.A_BOLD)
    addstr_safe(stdscr, 0, max_x - 22,
                f" CLI: {sugg.cli_flag[:16]} ", curses.color_pair(C.HEADER))
    hline_safe(stdscr, 1, 0, curses.ACS_HLINE, max_x, curses.color_pair(C.BORDER))

    lines = sugg.output
    n_lines  = len(lines)
    content_h = max_y - 4
    max_scroll = max(0, n_lines - content_h)
    state.module_scroll = clamp(state.module_scroll, 0, max_scroll)

    if not lines:
        addstr_safe(stdscr, 3, 2, "Aucun résultat.", curses.color_pair(C.DIM))
    else:
        for i, (text, color_id) in enumerate(lines[state.module_scroll:state.module_scroll + content_h]):
            attr = curses.color_pair(color_id)
            if color_id in (C.TITLE,):
                attr |= curses.A_BOLD
            addstr_safe(stdscr, 2 + i, 0, text[:max_x - 1], attr)

    # ── Indicateur de scroll ──
    if n_lines > content_h:
        pct = int((state.module_scroll / max_scroll) * 100) if max_scroll else 100
        nav = f"  ligne {state.module_scroll + 1}/{n_lines}  ({pct}%)  "
        addstr_safe(stdscr, max_y - 2, 2, nav, curses.color_pair(C.DIM))
        # Mini scrollbar
        bar_h  = content_h
        bar_y  = int((state.module_scroll / max(1, max_scroll)) * (bar_h - 1))
        for sy in range(bar_h):
            ch = "█" if sy == bar_y else "│"
            addstr_safe(stdscr, 2 + sy, max_x - 1, ch, curses.color_pair(C.BORDER))

    _draw_status_bar(stdscr, state,
        "[↑↓/jk] Scroll  [PgUp/PgDn] Page  [Esc/Q] Retour modules")


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

def run_interactive(results: list[dict], output_dir: str = "output",
                    lhost: str = "", lport: int = 4444):
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
            results             = results,
            tags                = {},
            output_dir          = Path(output_dir),
            lhost               = lhost,
            lport               = lport,
            module_suggestions  = _recommend_modules(results, lhost, lport),
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
            elif state.view == "modules":
                draw_modules_view(stdscr, state)
            elif state.view == "module_output":
                draw_module_output_view(stdscr, state)

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
                elif state.view == "modules":
                    state.view = "ports"
                elif state.view == "module_output":
                    state.view = "modules"
                    state.module_scroll = 0

            elif ch in (27,):  # Escape
                if state.view == "cves":
                    state.view = "ports"
                elif state.view == "detail":
                    state.view = "cves"
                    state.scroll_detail = 0
                elif state.view == "modules":
                    state.view = "ports"
                elif state.view == "module_output":
                    state.view = "modules"
                    state.module_scroll = 0

            # ── Touches de navigation ──
            elif ch in (curses.KEY_UP, ord('k')):
                if state.view == "ports":
                    state.port_cursor = clamp(state.port_cursor - 1, 0, n_ports - 1)
                elif state.view == "cves":
                    n_cves = len(state.filtered_cves())
                    state.cve_cursor = clamp(state.cve_cursor - 1, 0, max(0, n_cves - 1))
                elif state.view == "detail":
                    state.scroll_detail = max(0, state.scroll_detail - 1)
                elif state.view == "modules":
                    state.module_cursor = clamp(state.module_cursor - 1, 0, max(0, len(state.module_suggestions) - 1))
                elif state.view == "module_output":
                    state.module_scroll = max(0, state.module_scroll - 1)

            elif ch in (curses.KEY_DOWN, ord('j')):
                if state.view == "ports":
                    state.port_cursor = clamp(state.port_cursor + 1, 0, n_ports - 1)
                elif state.view == "cves":
                    n_cves = len(state.filtered_cves())
                    state.cve_cursor = clamp(state.cve_cursor + 1, 0, max(0, n_cves - 1))
                elif state.view == "detail":
                    state.scroll_detail += 1  # clamp appliqué au rendu
                elif state.view == "modules":
                    state.module_cursor = clamp(state.module_cursor + 1, 0, max(0, len(state.module_suggestions) - 1))
                elif state.view == "module_output":
                    state.module_scroll += 1  # clamp dans draw_module_output_view

            elif ch in (curses.KEY_PPAGE,):  # Page Up
                if state.view == "ports":
                    state.port_cursor = clamp(state.port_cursor - 10, 0, n_ports - 1)
                elif state.view == "cves":
                    n_cves = len(state.filtered_cves())
                    state.cve_cursor = clamp(state.cve_cursor - 10, 0, max(0, n_cves - 1))
                elif state.view == "detail":
                    state.scroll_detail = max(0, state.scroll_detail - 10)
                elif state.view in ("modules",):
                    state.module_cursor = clamp(state.module_cursor - 5, 0, max(0, len(state.module_suggestions) - 1))
                elif state.view == "module_output":
                    state.module_scroll = max(0, state.module_scroll - 15)

            elif ch in (curses.KEY_NPAGE,):  # Page Down
                if state.view == "ports":
                    state.port_cursor = clamp(state.port_cursor + 10, 0, n_ports - 1)
                elif state.view == "cves":
                    n_cves = len(state.filtered_cves())
                    state.cve_cursor = clamp(state.cve_cursor + 10, 0, max(0, n_cves - 1))
                elif state.view == "detail":
                    state.scroll_detail += 10
                elif state.view in ("modules",):
                    state.module_cursor = clamp(state.module_cursor + 5, 0, max(0, len(state.module_suggestions) - 1))
                elif state.view == "module_output":
                    state.module_scroll += 15

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
                elif state.view == "modules":
                    if 0 <= state.module_cursor < len(state.module_suggestions):
                        sugg = state.module_suggestions[state.module_cursor]
                        if sugg.status != "done":
                            state.status_msg = f"  Exécution : {sugg.title}..."
                            draw_modules_view(stdscr, state)
                            stdscr.refresh()
                            _run_module(sugg, state.results, state.lhost, state.lport)
                        state.module_scroll = 0
                        state.view = "module_output"

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

            # ── Touche M → vue modules recommandés ──
            elif ch in (ord('m'), ord('M')):
                if state.view != "modules" and state.view != "module_output":
                    state.view = "modules"
                elif state.view == "module_output":
                    state.view = "modules"

            # ── Redimensionnement terminal ──
            elif ch == curses.KEY_RESIZE:
                stdscr.clear()

    curses.wrapper(_main)
