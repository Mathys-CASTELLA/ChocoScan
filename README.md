<div align="center">

<img width="637" height="425" alt="image" src="https://github.com/user-attachments/assets/19547661-9f58-4165-b50c-3c158aaab2e1" />

# ChocoScan

**Scanner de vulnérabilités post-scan réseau — CVE matching, scoring contextuel, reconnaissance & interface web**

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-Frontend-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![NVD](https://img.shields.io/badge/Source-NVD%20%2B%20CISA%20KEV-red?style=flat-square)](https://nvd.nist.gov)
[![HTB](https://img.shields.io/badge/CTF-HackTheBox%20%7C%20Root--Me-9FEF00?style=flat-square)](https://hackthebox.com)

*Développé par [Mathys-CASTELLA](https://github.com/Mathys-CASTELLA) — BUT R&T Cybersécurité, IUT de Blagnac*

</div>

---

## Présentation

ChocoScan est un framework de post-traitement de scans réseau orienté pentest et CTF. Il prend en entrée un scan Nmap (ou Masscan, RustScan, Nessus…) et enchaîne automatiquement :

1. **CVE matching** — associe chaque service détecté à ses CVE connues (base locale + API NVD)
2. **Scoring contextuel** — pondère le CVSS brut avec les données CISA KEV, les exploits publics et le type d'impact
3. **Analyse des chaînes** — détecte les enchaînements RCE → LPE entre services
4. **Modules offensifs** — génère les commandes et checklists adaptées à chaque contexte détecté
5. **Reconnaissance** — énumération sous-domaines, vhosts, fingerprinting web, cloud, AD…
6. **Rapport** — export HTML complet ou JSON, ou interface web React

```bash
# Flux typique HTB
nmap -sV -oX scan.xml 10.10.10.50
python3 chocoscan.py -x scan.xml --severity CRITICAL,HIGH --exploits --subdomain target.htb --export-html
```

---

## Table des matières

- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Utilisation rapide](#utilisation-rapide)
- [Modules détaillés](#modules-détaillés)
- [Configuration](#configuration)
- [Interface web](#interface-web)
- [Architecture](#architecture)
- [Référence CLI complète](#référence-cli-complète)
- [Sources de données](#sources-de-données)
- [Auteur](#auteur)

---

## Fonctionnalités

### Analyse & scoring

| | Fonctionnalité | Détail |
|---|---|---|
| 🔍 | **Multi-format** | Nmap XML/texte, Masscan, RustScan, Nessus CSV/.nessus, JSON |
| 🎯 | **CVE matching** | Base locale (~145 services) + fallback API NVD avec cache |
| 🏷️ | **Matching CPE** | Requêtes NVD précises via `cpeName` (moins de faux positifs) |
| 📊 | **Scoring contextuel** | CVSS × CISA KEV × exploit public × fraîcheur × type d'impact |
| ⛓️ | **Chaînes d'exploit** | Détection des enchaînements RCE → LPE entre services |
| 🔄 | **Diff de scans** | Comparaison avant/après correctifs |
| 🚫 | **Whitelist** | `.chocoscanignore` — masquer les faux positifs connus |

### Reconnaissance

| | Fonctionnalité | Détail |
|---|---|---|
| 🌐 | **Subdomain enum** | Passif (crt.sh, HackerTarget, RapidDNS) + bruteforce DNS multi-threadé |
| 🏠 | **Vhost discovery** | Commandes ffuf/gobuster optimisées par service HTTP détecté |
| 🔎 | **Web fingerprinting** | Détection active de stack (Craft CMS, Laravel, Drupal, WordPress…) |
| 🌍 | **Énumération web** | Wordlists adaptées à chaque technologie détectée |
| ☁️ | **Cloud enum** | Misconfigurations AWS S3, Azure Blob, GCP — IMDSv1/v2 SSRF |

### Post-exploitation

| | Fonctionnalité | Détail |
|---|---|---|
| 🔐 | **Scan SSH authentifié** | Inventaire des paquets installés (dpkg/rpm/pacman) |
| 🏰 | **Active Directory** | Détection AD + BloodHound CE + modules Kerberoasting/AS-REP |
| 🔑 | **Default creds** | Credentials par défaut Tomcat, Jenkins, Grafana, routeurs… |
| 💣 | **MSF mapper** | Modules Metasploit correspondants aux CVE détectées |
| 🐚 | **Reverse shells** | Payloads adaptés au service + OS détecté, avec listener |
| 🔒 | **Privesc** | Checklists Linux/Windows : SUID, sudo, cron, tokens, kernel… |
| 🪙 | **Token privileges** | SeImpersonate → Potato, SeDebug → LSASS dump |
| 🐳 | **Container escape** | Docker/LXC/Kubernetes — détection + vecteurs d'évasion |
| 🔗 | **Lateral movement** | DCOM, LAPS, délégation Kerberos, AD CS |

### Interface & export

| | Fonctionnalité | Détail |
|---|---|---|
| 💻 | **Interface web** | Dashboard React, filtres temps réel, historique SQLite |
| 📄 | **Exports** | Rapport HTML complet, JSON structuré |
| ⚙️ | **Config TOML** | `~/.chocoscan.conf` — référence Nmap embarquée, profils CTF |
| 🖥️ | **Mode interactif** | TUI pour naviguer les résultats sans relancer le scan |

---

## Installation

```bash
git clone https://github.com/Mathys-CASTELLA/chocoscan.git
cd chocoscan

# Environnement virtuel (recommandé)
python3 -m venv venv && source venv/bin/activate

# Dépendances Python
pip install -r requirements.txt

# Initialisation de la base CVE locale
python3 init_db.py
```

**Clé API NVD** (optionnelle, mais passe de 5 à 50 req/30s) :
```bash
# Demande gratuite → https://nvd.nist.gov/developers/request-an-api-key
echo 'nvd_api_key = "votre-clé"' >> ~/.chocoscan.conf
```

**Fichier de configuration personnelle** :
```bash
python3 chocoscan.py config init   # Génère ~/.chocoscan.conf avec toutes les options
                                    # et la référence complète des arguments Nmap
```

---

## Utilisation rapide

### Depuis un fichier de scan existant

```bash
# Analyse basique
python3 chocoscan.py -x scan.xml

# Filtré : Critical/High depuis 2022, avec exploits PoC
python3 chocoscan.py -x scan.xml --severity CRITICAL,HIGH --after-year 2022 --exploits

# Rapport HTML complet
python3 chocoscan.py -x scan.xml --severity CRITICAL,HIGH --exploits --export-html
```

### Scan direct intégré

```bash
# ChocoScan lance nmap et enchaîne l'analyse
python3 chocoscan.py --scan 10.10.10.50

# Avec profil nmap personnalisé
python3 chocoscan.py --scan 10.10.10.50 --nmap-args "-sV -sC -p- --min-rate 5000 -T4 --open"
```

### Scan SSH authentifié

```bash
# Inventaire des paquets installés + matching CVE
python3 chocoscan.py --ssh-scan 10.10.10.50 \
  --ssh-user admin --ssh-key ~/.ssh/id_rsa \
  --min-cvss 7.0 --export-html
```

### Comparer deux scans (avant/après patch)

```bash
python3 chocoscan.py --diff scan_avant.xml scan_apres.xml --export-html
```

---

## Modules détaillés

### 🌐 Subdomain Enumeration — `--subdomain`

Module de découverte de sous-domaines en deux modes complémentaires :

**Mode passif** — interroge des sources publiques sans toucher la cible :
- **crt.sh** — Certificate Transparency logs (source la plus exhaustive)
- **HackerTarget** — API hostsearch
- **RapidDNS** — lookup passif

**Mode actif** — bruteforce DNS multi-threadé :
- Détection wildcard préalable pour éviter les faux positifs
- Wordlist embarquée (~250 mots orientés CTF/prod) ou externe (SecLists)
- Threading configurable (défaut : 30, jusqu'à 100 sur HTB VPN)

```bash
# Mode par défaut — passif + bruteforce (wordlist embarquée)
python3 chocoscan.py --subdomain target.htb

# Passif uniquement (zéro bruit réseau — mode OPSEC)
python3 chocoscan.py --subdomain example.com --sub-passive

# Bruteforce avec SecLists (recommandé pour CTF)
python3 chocoscan.py --subdomain target.htb \
  --sub-wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --sub-threads 50

# Combiné avec le reste du scan
python3 chocoscan.py -x scan.xml \
  --subdomain target.htb \
  --vhost target.htb \
  --exploits --export-html
```

Le module génère également les commandes prêtes à l'emploi pour : `subfinder`, `amass`, `dnsx`, `gobuster dns`, `dnsrecon`, `theHarvester`, ainsi qu'un pipeline complet (subfinder → dnsx → httpx).

**Configuration dans `~/.chocoscan.conf`** :
```toml
[subdomain]
# Wordlist par défaut pour tous les scans --subdomain
sub_wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
sub_threads  = 50
# sub_passive = true   # pour forcer le mode passif par défaut
```

---

### 🏰 Active Directory — `--ad-enum`, `--bloodhound`

```bash
# Détection automatique du contexte AD depuis le scan
python3 chocoscan.py -x scan.xml --ad-enum

# Croisement avec un export BloodHound CE
python3 chocoscan.py -x scan.xml --bloodhound sharphound.zip --export-html
```

### 💣 Modules offensifs — génération de commandes

Chaque module analyse le scan et génère des commandes adaptées au contexte détecté :

```bash
# Vhost discovery (ffuf/gobuster) sur tous les HTTP détectés
python3 chocoscan.py -x scan.xml --vhost target.htb

# Payloads web (LFI, SSTI, SQLi, SSRF, XXE) par service
python3 chocoscan.py -x scan.xml --web-payloads --lhost 10.10.14.5

# Reverse shells adaptés au service et à l'OS
python3 chocoscan.py -x scan.xml --revshell --lhost 10.10.14.5 --lport 4444

# Checklist privesc Linux + Windows
python3 chocoscan.py -x scan.xml --privesc

# Énumération SMB complète + impacket
python3 chocoscan.py -x scan.xml --smb

# Bruteforce par service (hydra/medusa/CrackMapExec)
python3 chocoscan.py -x scan.xml --brute

# Cloud misconfigurations (AWS/Azure/GCP)
python3 chocoscan.py -x scan.xml --cloud

# Container escape (Docker/K8s/LXC)
python3 chocoscan.py -x scan.xml --container

# Pivoting (Ligolo-ng, Chisel, SSH tunnels)
python3 chocoscan.py -x scan.xml --pivot --lhost 10.10.14.5

# Tout d'un coup (profil CTF complet)
python3 chocoscan.py -x scan.xml \
  --subdomain target.htb \
  --exploits --msf --vhost target.htb \
  --web-payloads --revshell --privesc \
  --lhost 10.10.14.5 --export-html
```

### 🖥️ Mode interactif

```bash
python3 chocoscan.py -x scan.xml --interactive   # ou -i
```

TUI qui permet de naviguer les résultats, filtrer, lancer des modules et exporter sans relancer le scan.

---

## Configuration

### Initialisation

```bash
python3 chocoscan.py config init    # Crée ~/.chocoscan.conf
python3 chocoscan.py config show    # Affiche la config active avec les sources
```

### Exemple `~/.chocoscan.conf` — profil CTF

```toml
# ── Filtrage ──────────────────────────────────────────────────────────────────
min_cvss    = 0.0
severity    = ""          # toutes les sévérités
top_cves    = 5

# ── Comportement ─────────────────────────────────────────────────────────────
exploits    = true        # rechercher les PoC GitHub
export_html = true        # toujours générer le rapport HTML

# ── Réseau / attaquant ────────────────────────────────────────────────────────
lhost = "10.10.14.5"      # ton IP tun0 HTB — évite de retaper --lhost
lport = 4444

# ── Scan Nmap ─────────────────────────────────────────────────────────────────
# config init génère la référence complète des flags Nmap avec exemples
[scan]
nmap_args = "-sV -sC -T4 --open"

# ── Sous-domaines ─────────────────────────────────────────────────────────────
[subdomain]
sub_wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
sub_threads  = 50

# ── Modules actifs par défaut ─────────────────────────────────────────────────
[modules]
exploits      = true
web_payloads  = true
vhost         = true
```

> **Priorité de résolution** : argument CLI > variable d'environnement `CHOCOSCAN_<CLÉ>` > `~/.chocoscan.conf` > défaut argparse

Le fichier généré par `config init` contient une **référence complète des arguments Nmap** commentée directement au-dessus de `[scan]` : types de scan (-sS/-sT/-sU/-sV/-sC/-A/-O/-Pn), sélection de ports, templates timing (-T0 à -T5), performance fine (`--min-rate`, `--max-retries`…), scripts NSE avec exemples ciblés CTF, options d'évasion, formats de sortie, et 6 profils prêts à décommenter.

---

## Whitelist `.chocoscanignore`

```bash
# .chocoscanignore (racine projet ou ~/.chocoscanignore)
CVE-2021-41617    # SSH config non applicable ici
CVE-2023-38408    # ForwardAgent désactivé
```

```bash
python3 chocoscan.py -x scan.xml                           # Charge automatiquement
python3 chocoscan.py -x scan.xml --ignore-file ma_liste    # Fichier personnalisé
python3 chocoscan.py -x scan.xml --no-ignore               # Désactiver
```

---

## Interface web

```bash
# Backend FastAPI
uvicorn web.app:app --reload --port 8000
# → API docs : http://localhost:8000/docs

# Frontend React (développement)
cd web/frontend && npm install && npm run dev
# → http://localhost:5173

# Production (tout-en-un)
cd web/frontend && npm run build
uvicorn web.app:app --port 8000
# → http://localhost:8000
```

**Fonctionnalités de l'interface :**
- **Dashboard** — stats globales, graphique de sévérité, derniers scans
- **Nouveau scan** — upload drag & drop, scan IP direct, scan SSH authentifié
- **Résultats** — filtres temps réel (sévérité, CVSS, exploit, CISA KEV), CVE détaillées
- **Historique** — tous les scans avec statuts
- **Export** — téléchargement JSON / rapport HTML depuis l'interface

---

## Base CVE locale

```bash
python3 init_db.py               # Initialisation (une seule fois)
python3 update_db.py             # Mise à jour générale (NVD)
python3 update_db_critical.py    # CVE CVSS ≥ 9.0
python3 update_db_ctf.py         # Services fréquents CTF (HTB, Root-Me)
python3 update_db_cpe.py         # Enrichissement CPE (matching API précis)
python3 update_exploits.py       # PoC GitHub
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
├── chocoscan.py                  # Point d'entrée CLI (tous les modules)
│
├── modules/
│   ├── cve_matcher.py            # Moteur CVE matching + API NVD
│   ├── cpe_resolver.py           # Résolution CPE (statique + API)
│   ├── version_checker.py        # Comparaison de versions sémantiques
│   ├── contextual_scorer.py      # Scoring contextuel (CVSS × KEV × exploit…)
│   ├── chain_analyzer.py         # Détection chaînes d'exploitation
│   ├── tag_definitions.py        # Catégorisation des services
│   ├── msf_mapper.py             # Mapping CVE → modules Metasploit
│   │
│   ├── subdomain_enum.py         # ← Énumération sous-domaines (passif + DNS brute)
│   ├── vhost_discovery.py        # Commandes ffuf/gobuster vhost
│   ├── web_enumerator.py         # Énumération web (wordlists par stack)
│   ├── web_fingerprinter.py      # Fingerprinting actif (CMS, frameworks)
│   ├── web_payload_gen.py        # Payloads LFI/SSTI/SQLi/SSRF/XXE
│   │
│   ├── credentialed_scan.py      # Scan SSH authentifié (inventaire paquets)
│   ├── default_creds.py          # Credentials par défaut par service
│   ├── brute_helper.py           # Commandes hydra/medusa/CrackMapExec
│   ├── hash_cracker.py           # Détection type hash + commandes hashcat/john
│   │
│   ├── ad_detector.py            # Détection contexte Active Directory
│   ├── ad_enum.py                # Énumération AD (Kerberoasting, LDAP…)
│   ├── bloodhound_integration.py # Croisement BloodHound CE
│   ├── smb_helper.py             # Énumération SMB + impacket
│   ├── lateral_movement.py       # Mouvement latéral (DCOM, LAPS, délégation)
│   │
│   ├── privesc_checker.py        # Checklists privesc Linux/Windows
│   ├── gtfobins.py               # SUID/sudo/capabilities exploitables
│   ├── token_helper.py           # Token privileges Windows
│   ├── misconfig_detector.py     # Misconfigurations système
│   ├── shell_upgrader.py         # Upgrade shell → TTY interactif
│   ├── reverse_shell.py          # Reverse shells multi-langages/OS
│   ├── kill_chain.py             # Kill chain MITRE ATT&CK
│   ├── loot_collector.py         # Collecte fichiers sensibles via SSH
│   │
│   ├── cloud_enum.py             # Misconfigurations AWS/Azure/GCP
│   ├── container_escape.py       # Container escape Docker/LXC/K8s
│   ├── pivot_helper.py           # Pivoting (Ligolo-ng, Chisel, SSH)
│   │
│   ├── diff_engine.py            # Comparaison de scans avant/après
│   ├── wordlist_builder.py       # Wordlist contextuelle depuis le scan
│   ├── cipher_decoder.py         # Décodage (base64, ROT, hex, morse…)
│   ├── report_generator.py       # Export HTML / JSON
│   ├── ignore_list.py            # Whitelist .chocoscanignore
│   ├── input_parser.py           # Parsing multi-formats
│   ├── nmap_parser.py            # Parser Nmap XML/texte
│   ├── config.py                 # ← Config TOML + référence Nmap
│   ├── interactive.py            # Mode interactif TUI
│   └── image_art.py              # Logo ASCII CLI
│
├── web/
│   ├── app.py                    # FastAPI
│   ├── database.py               # SQLite async (aiosqlite)
│   ├── models.py                 # Modèles SQLAlchemy
│   ├── pipeline.py               # Pipeline scan → analyse → stockage
│   └── routers/                  # Endpoints REST (scans, export, SSH)
│       └── frontend/             # React + TypeScript + Tailwind CSS
│
├── data/
│   ├── cve_db.json               # Base CVE locale (~145 services)
│   └── cve_recent.json           # CVE récentes (CVSS ≥ 9.0)
│
├── tests/                        # Tests pytest
├── assets/                       # Logo CLI, images rapports
└── init_db.py / update_db*.py    # Gestion de la base CVE
```

---

## Référence CLI complète

```
MODES D'ENTRÉE
  -x FILE, --xml FILE          Analyser un fichier de scan (Nmap, Masscan…)
  --scan TARGET                Lancer nmap directement sur la cible
  --ssh-scan TARGET            Scan SSH authentifié (inventaire paquets)
  --diff AVANT APRÈS           Comparer deux scans

FILTRAGE CVE
  --min-cvss N                 Score CVSS minimum (0.0–10.0)
  --severity LISTE             CRITICAL,HIGH,MEDIUM,LOW,INFO
  --after-year N               CVE publiées depuis l'année N
  --top-cves N                 Max CVE affichées par service (défaut: 5)

COMPORTEMENT
  --exploits                   Rechercher les PoC GitHub
  --no-api                     Base locale uniquement (pas d'API NVD)
  --no-scoring                 CVSS brut uniquement
  --no-chains                  Désactiver l'analyse de chaînes
  --no-ad                      Désactiver la détection Active Directory
  --bloodhound FILE            Croiser avec un export BloodHound CE
  --interactive, -i            Mode interactif TUI
  --verbose, -v                Afficher les services non couverts
  --ignore-file FILE           Whitelist CVE personnalisée
  --no-ignore                  Ignorer .chocoscanignore

SCAN NMAP (avec --scan)
  --nmap-args "ARGS"           Arguments supplémentaires nmap
                               (Ex: "-sV -sC -p- --min-rate 5000 -T4 --open")

SSH (avec --ssh-scan ou --loot)
  --ssh-user USER              Utilisateur SSH
  --ssh-pass PASS              Mot de passe (prompt masqué si omis)
  --ssh-key FILE               Clé privée SSH
  --ssh-port PORT              Port SSH (défaut: 22)

RECONNAISSANCE
  --subdomain DOMAIN           Énumération sous-domaines (passif + bruteforce DNS)
  --sub-passive                Mode passif uniquement (crt.sh, HackerTarget, RapidDNS)
  --sub-active                 Bruteforce DNS uniquement
  --sub-threads N              Threads bruteforce DNS (défaut config/30)
  --sub-wordlist FILE          Wordlist externe (défaut: wordlist embarquée ~250 mots)
  --vhost [DOMAIN]             Commandes ffuf/gobuster vhost (auto = détection)
  --enum-web                   Énumération web active (wordlists par stack)
  --enum-threads N             Threads énumération web (défaut: 10)
  --enum-delay SEC             Délai entre requêtes (défaut: 0.05s)
  --web-fingerprint            Fingerprinting actif CMS/frameworks

MODULES OFFENSIFS
  --web-payloads [SERVICE]     Payloads LFI/SSTI/SQLi/SSRF/XXE
  --revshell [SERVICE:PORT]    Reverse shells adaptés (auto = tous les services)
  --all-shells                 Toutes les variantes de reverse shells
  --lhost IP                   IP attaquant (listener, payloads…)
  --lport PORT                 Port attaquant (défaut: 4444)
  --privesc                    Checklists privesc Linux + Windows
  --gtfobins                   GTFOBins SUID/sudo/capabilities
  --tokens [WHOAMI_OUTPUT]     Token privileges Windows
  --misconfig                  Détection misconfigurations système
  --upgrade-shell              Guide upgrade shell → TTY
  --brute                      Commandes bruteforce par service
  --default-creds              Credentials par défaut (Tomcat, Jenkins…)
  --hashcrack [HASH]           Identification hash + commandes hashcat/john
  --smb                        Énumération SMB complète + impacket
  --ad-enum                    Modules Active Directory (Kerberoasting, LDAP…)
  --ad-auto                    Détection AD automatique depuis le scan
  --lateral                    Mouvement latéral (DCOM, LAPS, délégation)
  --cloud                      Misconfigurations AWS/Azure/GCP
  --container [MODE]           Container escape Docker/LXC/K8s (all|quick)
  --pivot [LHOST]              Commandes pivoting (Ligolo-ng, Chisel, SSH)
  --kill-chain                 Kill chain MITRE ATT&CK
  --loot                       Collecte fichiers sensibles via SSH
  --msf                        Modules Metasploit pour les CVE détectées
  --msf-script                 Générer un script rc Metasploit

EXPORT & RAPPORT
  --export-html                Rapport HTML complet
  --export-json                Export JSON structuré
  --output-dir DIR             Dossier de sortie (défaut: output/)
  --wordlist [OUTPUT]          Wordlist contextuelle depuis le scan
  --custom-words MOT…          Mots supplémentaires pour la wordlist

CONFIGURATION
  config init                  Créer ~/.chocoscan.conf (avec référence Nmap)
  config init --force          Écraser la config existante
  config show                  Afficher la config active et ses sources
```

---

## Sources de données

| Source | Usage |
|---|---|
| [NVD](https://nvd.nist.gov/) | Base principale des CVE (CVSS, CPE, descriptions) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE activement exploitées en conditions réelles |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Proof-of-concept publics référencés |
| [BloodHound CE](https://github.com/SpecterOps/BloodHound) | Chemins d'attaque Active Directory |
| [crt.sh](https://crt.sh) | Certificate Transparency (sous-domaines passifs) |
| [HackerTarget](https://hackertarget.com) | API hostsearch (sous-domaines passifs) |
| [SecLists](https://github.com/danielmiessler/SecLists) | Wordlists DNS, web, brute force |

---

## Auteur

**Mathys CASTELLA** 

Étudiant en BUT Réseaux & Télécommunications, spécialisation Cybersécurité — IUT de Blagnac.
Projet portfolio développé en parallèle de la formation et de la pratique CTF.

- GitHub : [@Mathys-CASTELLA](https://github.com/Mathys-CASTELLA)
- CTF : [HackTheBox](https://hackthebox.com](https://profile.hackthebox.com/profile/019e3a6a-d43e-70b1-82ce-8ca3aeaccb63) et [Root-Me](https://www.root-me.org/Kinder-Bueno)

---

<div align="center">
<sub>ChocoScan s'appuie exclusivement sur des sources publiques (NVD, CISA KEV, GitHub, crt.sh).<br>
Outil destiné à un usage CTF et pentest sur environnements autorisés uniquement.</sub>
</div>
