<div align="center">

<img src="assets/chocoscan_cli.png" alt="ChocoScan Logo" width="220"/>

# ChocoScan

**Scanner de vulnérabilités post-Nmap — CVE matching, scoring contextuel & interface web**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-Frontend-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![NVD](https://img.shields.io/badge/Source-NVD%20%2B%20CISA%20KEV-red?style=flat-square)](https://nvd.nist.gov)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

*Développé par [Kinder-Bueno](https://github.com/Mathys-CASTELLA) — BUT R&T Cybersécurité, IUT de Blagnac*

</div>

---

## Présentation

ChocoScan prend en entrée un scan réseau (Nmap, Masscan, RustScan, Nessus…) et associe automatiquement chaque service détecté à ses CVE connues. Au-delà du simple matching, il calcule un **score contextuel** (CVSS + CISA KEV + exploit public disponible + type d'impact), détecte les **chaînes d'exploitation**, s'intègre à **BloodHound CE** pour les environnements Active Directory, et dispose d'une **interface web complète** pour visualiser et exporter les résultats.

```bash
nmap -sV -oX scan.xml 10.10.10.50
python3 chocoscan.py -x scan.xml --severity CRITICAL,HIGH --exploits --export-html
```

---

## Fonctionnalités

| | Fonctionnalité | Détail |
|---|---|---|
| 🔍 | **Multi-format** | Nmap XML/texte, Masscan, RustScan, Nessus CSV/.nessus, JSON |
| 🎯 | **CVE matching** | Base locale (~145 services) + fallback API NVD avec cache |
| 🏷️ | **Matching CPE** | Requêtes NVD précises via `cpeName` (moins de faux positifs) |
| 📊 | **Scoring contextuel** | CVSS + CISA KEV + exploit public + fraîcheur + type d'impact |
| ⛓️ | **Chaînes d'exploit** | Détection des enchaînements RCE → LPE entre services |
| 🔐 | **Scan SSH authentifié** | Inventaire des paquets installés (dpkg/rpm/pacman) |
| 🏰 | **Active Directory** | Détection de contexte AD + intégration BloodHound CE |
| 🌐 | **Énumération web** | Wordlists adaptées à la stack détectée |
| 🚫 | **Whitelist** | `.chocoscanignore` — masquer les faux positifs connus |
| 🔄 | **Diff de scans** | Comparaison avant/après correctifs |
| 💻 | **Interface web** | Dashboard React, filtres temps réel, historique SQLite |
| 📄 | **Exports** | Rapport HTML complet, JSON |

---

## Installation

```bash
git clone https://github.com/Mathys-CASTELLA/chocoscan.git
cd chocoscan

# Environnement virtuel (recommandé)
python3 -m venv venv && source venv/bin/activate

# Dépendances
pip install -r requirements.txt

# Initialisation de la base CVE locale
python3 init_db.py
```

> **Clé API NVD** (facultative mais recommandée — passe de 5 à 50 req/30s) :
> Demande gratuite sur [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key), puis dans `~/.chocoscan.conf` : `nvd_api_key = "ta-clé"`

---

## Utilisation

### Scan depuis un fichier

```bash
# Basique
python3 chocoscan.py -x scan.xml

# Filtré : Critical/High avec PoC, CVE depuis 2022, rapport HTML
python3 chocoscan.py -x scan.xml \
  --severity CRITICAL,HIGH \
  --after-year 2022 \
  --exploits \
  --export-html
```

### Scan direct (nmap intégré)

```bash
python3 chocoscan.py --scan 10.10.10.50 --nmap-args "-T4 --open" --exploits
```

### Scan SSH authentifié

```bash
# Inventaire complet des paquets installés sur la cible
python3 chocoscan.py --ssh-scan 10.10.10.50 \
  --ssh-user admin \
  --ssh-key ~/.ssh/id_rsa \
  --min-cvss 7.0 \
  --export-html
```

### Contexte Active Directory

```bash
python3 chocoscan.py -x scan.xml --bloodhound sharphound.zip --export-html
```

### Comparer deux scans

```bash
python3 chocoscan.py --diff scan_avant.xml scan_apres.xml --export-html
```

### Mode interactif

```bash
python3 chocoscan.py -x scan.xml --interactive
```

---

## Whitelist `.chocoscanignore`

Pour ignorer des CVE déjà traitées ou des faux positifs connus, sans refiltrer à chaque scan :

```bash
# .chocoscanignore (à la racine du projet ou dans ~/.chocoscanignore)
CVE-2021-41617    # SSH config non applicable
CVE-2023-38408    # ForwardAgent désactivé
```

```bash
python3 chocoscan.py -x scan.xml                          # Charge automatiquement
python3 chocoscan.py -x scan.xml --ignore-file ma_liste   # Fichier personnalisé
python3 chocoscan.py -x scan.xml --no-ignore              # Désactiver
```

---

## Interface web

```bash
# Terminal 1 — backend FastAPI
uvicorn web.app:app --reload --port 8000
# → Swagger UI : http://localhost:8000/docs

# Terminal 2 — frontend React (dev)
cd web/frontend && npm install && npm run dev
# → http://localhost:5173

# Ou tout-en-un (prod)
cd web/frontend && npm run build
uvicorn web.app:app --port 8000
# → http://localhost:8000
```

**Fonctionnalités de l'interface :**
- **Dashboard** — stats globales, graphique de sévérité, derniers scans
- **Nouveau scan** — upload drag & drop, scan IP direct, scan SSH
- **Résultats** — filtres temps réel (sévérité, CVSS, exploit, CISA KEV), CVE détaillées
- **Historique** — tous les scans avec statuts, suppression
- **Export** — téléchargement JSON / rapport HTML depuis l'interface

---

## Fichier de configuration

```bash
python3 chocoscan.py config init   # Génère ~/.chocoscan.conf avec toutes les options
python3 chocoscan.py config show   # Affiche la configuration active
python3 chocoscan.py config set min_cvss 7.0
```

Exemple `~/.chocoscan.conf` :

```toml
# Filtrage
min_cvss    = 7.0
severity    = "CRITICAL,HIGH"
after_year  = 2022
top_cves    = 5

# Comportement
no_api      = false
exploits    = true
nvd_api_key = "votre-clé-ici"

# Export
export_html = true
output_dir  = "rapports"

[scan]
nmap_args = "-T4 --open"
```

Toute option CLI écrase la valeur du fichier. Variables d'environnement supportées : `CHOCOSCAN_<CLÉ>`.

---

## Base CVE locale

```bash
python3 init_db.py              # Initialisation (une seule fois)
python3 update_db.py            # Mise à jour générale (NVD)
python3 update_db_critical.py   # CVE CVSS >= 9.0
python3 update_db_ctf.py        # Services fréquents CTF (HTB, Root-Me)
python3 update_db_cpe.py        # Enrichissement CPE (matching API précis)
python3 update_exploits.py      # PoC GitHub
```

---

## Formats d'entrée supportés

| Format | `--input-format` |
|---|---|
| Nmap XML / texte | `nmap_xml` · `nmap_text` |
| Masscan XML / JSON / texte | `masscan_xml` · `masscan_json` · `masscan_text` |
| RustScan JSON / texte | `rustscan_json` · `rustscan_text` |
| Nessus CSV / `.nessus` | `nessus_csv` · `nessus_xml` |
| ChocoScan JSON | `chocoscan_json` |

La détection est automatique (`--input-format auto` par défaut).

---

## Architecture

```
chocoscan/
├── chocoscan.py              # Point d'entrée CLI
├── modules/
│   ├── cve_matcher.py        # Moteur de matching CVE + API NVD
│   ├── cpe_resolver.py       # Résolution CPE (statique + API)
│   ├── version_checker.py    # Comparaison de versions
│   ├── contextual_scorer.py  # Scoring contextuel
│   ├── chain_analyzer.py     # Chaînes d'exploitation
│   ├── credentialed_scan.py  # Scan SSH authentifié
│   ├── ignore_list.py        # Whitelist .chocoscanignore
│   ├── ad_detector.py        # Détection AD
│   ├── bloodhound_integration.py
│   ├── diff_engine.py        # Comparaison de scans
│   ├── report_generator.py   # Exports HTML / JSON
│   └── ...
├── web/
│   ├── app.py                # FastAPI
│   ├── database.py           # SQLite async
│   ├── routers/              # Endpoints REST
│   └── frontend/             # React + TypeScript + Tailwind
├── data/
│   ├── cve_db.json           # Base CVE locale (~145 services)
│   └── cve_recent.json
└── assets/                   # Logo CLI, images rapports
```

---

## Options CLI — référence rapide

```
Modes de scan
  -x FILE, --xml FILE     Analyser un fichier de scan
  --scan TARGET           Lancer nmap directement
  --ssh-scan TARGET       Scan SSH authentifié
  --diff AVANT APRES      Comparer deux scans

Filtres
  --min-cvss N            CVSS minimum (0.0–10.0)
  --severity LISTE        CRITICAL,HIGH,MEDIUM,LOW
  --after-year N          CVE depuis l'année N
  --top-cves N            Max CVE par service (défaut : 5)

Comportement
  --exploits              Rechercher les PoC GitHub
  --no-api                Base locale uniquement
  --no-scoring            CVSS brut uniquement
  --no-chains             Désactiver l'analyse de chaînes
  --no-ad                 Désactiver la détection AD
  --bloodhound FILE       Croiser avec BloodHound CE
  --verbose, -v           Services non couverts par la base locale
  --interactive, -i       Mode interactif TUI
  --ignore-file FILE      Whitelist CVE personnalisée
  --no-ignore             Ignorer .chocoscanignore

Scan SSH
  --ssh-user USER         Utilisateur SSH
  --ssh-pass PASS         Mot de passe (prompt masqué si omis)
  --ssh-key FILE          Clé privée SSH
  --ssh-port PORT         Port SSH (défaut : 22)

Export
  --export-html           Rapport HTML complet
  --export-json           Export JSON
  --output-dir DIR        Dossier de sortie (défaut : output/)

Énumération web
  --enum-web              Activer
  --enum-threads N        Threads (défaut : 10)
  --enum-delay N          Délai entre requêtes (défaut : 0.05s)
```

---

## Sources de données

| Source | Usage |
|---|---|
| [NVD](https://nvd.nist.gov/) | Base principale des CVE |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE activement exploitées |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Proof-of-concept publics |
| [BloodHound CE](https://github.com/SpecterOps/BloodHound) | Chemins d'attaque AD |

---

## Auteur

**Mathys CASTELLA** — alias *Kinder-Bueno*

Étudiant en BUT Réseaux & Télécommunications, spécialisation Cybersécurité — IUT de Blagnac

- GitHub : [@Mathys-CASTELLA](https://github.com/Mathys-CASTELLA)
- Plateformes CTF : `Kinder-Bueno` (HackTheBox · Root-Me)

---

<div align="center">
<sub>ChocoScan s'appuie exclusivement sur des sources publiques (NVD, CISA KEV, GitHub).
Outil destiné à un usage CTF et pentest autorisé uniquement.</sub>
</div>
