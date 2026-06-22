<div align="center">

# 🍫 ChocoScan

**Scanner de vulnérabilités post-Nmap — associe automatiquement services détectés et CVE**

*Croise un scan Nmap (ou Masscan, RustScan, Nessus...) avec une base de CVE locale enrichie,
avec scoring contextuel, détection Active Directory, intégration BloodHound et bien plus.*

</div>

---

## Sommaire

- [Présentation](#présentation)
- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Démarrage rapide](#démarrage-rapide)
- [Exemples d'utilisation](#exemples-dutilisation)
- [Fichier de configuration](#fichier-de-configuration)
- [Whitelist de CVE (`.chocoscanignore`)](#whitelist-de-cve-chocoscanignore)
- [Scan authentifié SSH](#scan-authentifié-ssh)
- [Matching CPE](#matching-cpe)
- [Mode interactif](#mode-interactif)
- [Mise à jour de la base CVE](#mise-à-jour-de-la-base-cve)
- [Architecture du projet](#architecture-du-projet)
- [Tests](#tests)
- [Auteur](#auteur)

---

## Présentation

ChocoScan prend en entrée le résultat d'un scan réseau (Nmap, Masscan, RustScan, Nessus...) et
associe automatiquement chaque service détecté — nom + version — aux CVE connues le concernant.
En complément du simple matching CVE, l'outil propose :

- un **scoring contextuel** (au-delà du CVSS brut : exploit public disponible, présence dans le
  catalogue CISA KEV, type d'impact...) ;
- une **analyse de chaînes d'exploitation** (CVE A permettant un accès initial → CVE B permettant
  une élévation de privilèges) ;
- une **détection de contexte Active Directory** et une **intégration BloodHound** ;
- un **mode interactif** façon `fzf` pour naviguer et exporter les résultats ;
- des **exports HTML / JSON** prêts à intégrer dans un rapport de pentest ou CTF.

Pensé pour un usage CTF (HackTheBox, Root-Me...) et pentest, ChocoScan reste 100 % basé sur des
sources publiques (NVD, CISA KEV, PoC-in-GitHub).

---

## Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| Matching CVE local + API | Base locale (`data/cve_db.json`) avec fallback automatique vers l'API NVD |
| Multi-format d'entrée | Nmap XML/texte, Masscan, RustScan, Nessus CSV/.nessus, JSON |
| Scan direct | Lance `nmap` directement depuis ChocoScan (`--scan`) |
| **Scan authentifié SSH** | Liste les paquets installés via `dpkg`/`rpm`/`pacman` (`--ssh-scan`) |
| **Matching CPE** | Requêtes NVD précises par CPE plutôt que mots-clés |
| Scoring contextuel | CVSS + CISA KEV + disponibilité d'exploit + fraîcheur |
| Détection AD | Repère un environnement Active Directory dans le scan |
| Intégration BloodHound | Croise les CVE avec les chemins d'attaque BloodHound CE |
| Recherche d'exploits | PoC GitHub publics via `nomi-sec/PoC-in-GitHub` |
| Analyse de chaînes | Détecte les enchaînements RCE → LPE entre services |
| **Whitelist** | `.chocoscanignore` pour masquer les faux positifs connus |
| **Diagnostic de couverture** | `--verbose` repère les services non couverts par la base locale |
| Mode interactif | Navigation, marquage et export façon `fzf` |
| Diff de scans | Compare deux scans dans le temps |
| Énumération web | Wordlists adaptées à la stack détectée |
| Export | HTML (rapport complet) et JSON (intégration externe) |

---

## Installation

```bash
git clone https://github.com/Mathys-CASTELLA/chocoscan.git
cd chocoscan

python3 -m venv venv
source venv/bin/activate          # Windows : venv\Scripts\activate

pip install -r requirements.txt
```

> Le scan authentifié SSH nécessite `paramiko` (inclus dans `requirements.txt`).
> Le scan direct (`--scan`) nécessite `nmap` installé sur le système.

### Initialiser la base CVE locale

```bash
python3 init_db.py
```

---

## Démarrage rapide

```bash
# 1. Scanner une cible avec nmap
nmap -sV -oX scan.xml 10.10.10.50

# 2. Analyser le scan avec ChocoScan
python3 chocoscan.py -x scan.xml
```

Ou en une seule commande, en laissant ChocoScan piloter nmap :

```bash
python3 chocoscan.py --scan 10.10.10.50
```

---

## Exemples d'utilisation

### Scan basique

```bash
python3 chocoscan.py -x scan.xml
```

### Filtrer par sévérité et score CVSS minimum

```bash
python3 chocoscan.py -x scan.xml --severity CRITICAL,HIGH --min-cvss 7.0
```

### Ne garder que les CVE récentes (2023+) avec PoC public

```bash
python3 chocoscan.py -x scan.xml --after-year 2023 --exploits
```

### Lancer le scan nmap directement, avec des options personnalisées

```bash
python3 chocoscan.py --scan 10.10.10.50 --nmap-args "-T4 --open -p 1-65535"
```

### Désactiver le fallback API NVD (mode local uniquement, plus rapide)

```bash
python3 chocoscan.py -x scan.xml --no-api
```

### Croiser avec un export BloodHound CE

```bash
python3 chocoscan.py -x scan.xml --bloodhound sharphound_export.zip
```

### Générer un rapport HTML et JSON

```bash
python3 chocoscan.py -x scan.xml --export-html --export-json --output-dir rapports/
```

### Mode interactif

```bash
python3 chocoscan.py -x scan.xml --interactive
```

### Comparer deux scans (avant / après correctifs)

```bash
python3 chocoscan.py --diff scan_avant.xml scan_apres.xml
```

### Repérer les services non couverts par la base locale

```bash
python3 chocoscan.py -x scan.xml --verbose
```

### Scan authentifié SSH (liste des paquets installés)

```bash
python3 chocoscan.py --ssh-scan 10.10.10.50 --ssh-user admin --ssh-pass 'motdepasse'
```

### Combiner plusieurs options

```bash
python3 chocoscan.py -x scan.xml \
  --severity CRITICAL,HIGH \
  --min-cvss 8.0 \
  --exploits \
  --export-html \
  --interactive
```

---

## Fichier de configuration

ChocoScan lit un fichier de configuration TOML optionnel à `~/.chocoscan.conf`, pour fixer des
valeurs par défaut sans avoir à les répéter sur chaque commande. **Toute option CLI passée
explicitement écrase la valeur du fichier de configuration.**

Génère un fichier de config commenté avec toutes les clés disponibles :

```bash
python3 chocoscan.py config init
```

### Exemple complet (`~/.chocoscan.conf`)

```toml
# ~/.chocoscan.conf
#
# Toutes les valeurs ici sont des DÉFAUTS — elles sont surchargées
# par les arguments CLI (ex: --min-cvss 9.0 écrase min_cvss ci-dessous).
#
# Variables d'environnement : CHOCOSCAN_<CLÉ_MAJUSCULE>
#   ex: export CHOCOSCAN_MIN_CVSS=9.0

# ─── Filtrage ────────────────────────────────────────────────────

# Score CVSS minimum pour afficher une CVE (0.0 = toutes)
min_cvss = 7.0

# Sévérités à afficher — laisser vide pour toutes
# Valeurs : CRITICAL, HIGH, MEDIUM, LOW (séparées par virgules)
severity = "CRITICAL,HIGH"

# Afficher uniquement les CVE publiées depuis cette année
after_year = 2022

# Nombre max de CVE affichées par port dans le terminal (0 = toutes)
top_cves = 5

# ─── Comportement ────────────────────────────────────────────────

# Désactiver le fallback vers l'API NVD (plus rapide, résultats locaux seuls)
no_api = false

# Clé API NVD — accélère le fallback de 5 à 50 requêtes/30s.
# Gratuite : https://nvd.nist.gov/developers/request-an-api-key
nvd_api_key = "votre-clé-ici"

# Rechercher des exploits PoC GitHub pour chaque CVE
exploits = true

# Désactiver le scoring contextuel (CVSS brut uniquement)
no_scoring = false

# Désactiver la détection Active Directory
no_ad = false

# Désactiver l'analyse des CVE chaînables
no_chains = false

# Lancer le mode interactif après chaque scan
interactive = false

# ─── Export ──────────────────────────────────────────────────────

export_html = true
export_json = false
output_dir = "rapports"

# Format d'entrée (auto = détection automatique)
input_format = "auto"

# ─── Scan Nmap ───────────────────────────────────────────────────

[scan]
nmap_args = "-T4 --open"

# ─── Énumération web ─────────────────────────────────────────────

[web]
enum_web = false
enum_threads = 10
enum_delay = 0.05
```

### Commandes de gestion de la config

```bash
python3 chocoscan.py config init       # Crée ~/.chocoscan.conf avec des valeurs par défaut commentées
python3 chocoscan.py config show       # Affiche la config actuellement chargée
python3 chocoscan.py config set min_cvss 8.0
python3 chocoscan.py config path       # Affiche le chemin du fichier utilisé
```

### Via variables d'environnement

Toute clé de config peut aussi être définie via une variable d'environnement
`CHOCOSCAN_<CLÉ_EN_MAJUSCULES>`, utile en CI ou en environnement partagé :

```bash
export CHOCOSCAN_MIN_CVSS=9.0
export CHOCOSCAN_NVD_API_KEY="votre-clé"
python3 chocoscan.py -x scan.xml
```

---

## Whitelist de CVE (`.chocoscanignore`)

Pour masquer des CVE déjà traitées ou des faux positifs connus sur une cible, sans avoir à
refiltrer manuellement à chaque scan.

```bash
cat > .chocoscanignore << 'EOF'
# .chocoscanignore — CVE à exclure des résultats sur cette cible
CVE-2021-41617    # SSH config non applicable, pas de Match block
CVE-2023-38408    # ForwardAgent désactivé sur la cible
EOF

python3 chocoscan.py -x scan.xml
# → "Whitelist : 2 CVE ignorée(s) depuis .chocoscanignore"
```

Résolution du fichier, par ordre de priorité :
1. `--ignore-file FICHIER` (chemin explicite)
2. `.chocoscanignore` dans le dossier courant
3. `~/.chocoscanignore` (whitelist globale)

```bash
python3 chocoscan.py -x scan.xml --no-ignore   # Ignorer la whitelist pour ce scan
```

---

## Scan authentifié SSH

Se connecte à la cible avec des identifiants fournis et liste les paquets réellement installés
(`dpkg`/`rpm`/`pacman`), plutôt que de déduire les versions depuis le banner Nmap — utile quand
les services masquent leur version ou pour une vue complète de la surface installée.

```bash
python3 chocoscan.py --ssh-scan 10.10.10.50 --ssh-user admin --ssh-pass 'motdepasse'
python3 chocoscan.py --ssh-scan 10.10.10.50 --ssh-user admin --ssh-key ~/.ssh/id_rsa
```

| Option | Description |
|---|---|
| `--ssh-scan CIBLE` | IP ou hostname de la cible |
| `--ssh-user USER` | Utilisateur SSH |
| `--ssh-pass PASS` | Mot de passe (sinon : clé SSH par défaut, puis prompt masqué) |
| `--ssh-key FICHIER` | Clé privée SSH |
| `--ssh-port PORT` | Port SSH (défaut : 22) |

Distributions supportées : Debian/Ubuntu (`dpkg`), RHEL/CentOS/Fedora (`rpm`), Arch/Manjaro
(`pacman`) — détection automatique via `/etc/os-release`.

---

## Matching CPE

ChocoScan résout automatiquement un identifiant **CPE** (Common Platform Enumeration) normalisé
NVD pour chaque service reconnu, et l'utilise pour des requêtes API NVD plus précises
(`cpeName`) que la recherche par mots-clés classique. Entièrement transparent — aucune option à
activer.

Pour enrichir manuellement la base locale avec les CPE :

```bash
python3 update_db_cpe.py              # Enrichissement complet (statique + API NVD)
python3 update_db_cpe.py --no-api     # Statique uniquement, instantané
python3 update_db_cpe.py --service openssh
python3 update_db_cpe.py --dry-run    # Aperçu sans modifier les fichiers
python3 update_db_cpe.py --stats      # Statistiques de couverture
```

---

## Mode interactif

```bash
python3 chocoscan.py -x scan.xml --interactive
```

Navigation façon `fzf` parmi les résultats : filtrage en direct, marquage de CVE, export ciblé.

---

## Mise à jour de la base CVE

Plusieurs scripts dédiés à l'enrichissement de `data/cve_db.json` :

```bash
python3 update_db.py            # Mise à jour générale depuis l'API NVD
python3 update_db_critical.py   # Ajout de CVE critiques ciblées
python3 update_db_ctf.py        # Services fréquents en CTF (HTB, Root-Me...)
python3 update_db_tags.py       # Tags de classification des CVE
python3 update_exploits.py      # Rafraîchissement du mapping CVE → PoC GitHub
python3 update_db_cpe.py        # Enrichissement CPE (voir section dédiée)
```

---

## Architecture du projet

```
chocoscan/
├── chocoscan.py              # Point d'entrée CLI principal
├── init_db.py                # Initialisation de la base CVE locale
├── update_db*.py             # Scripts de mise à jour/enrichissement de la base
├── update_exploits.py        # Mapping CVE → PoC GitHub
│
├── modules/
│   ├── nmap_parser.py        # Parsing Nmap XML/texte
│   ├── input_parser.py       # Parsing multi-format (Masscan, RustScan, Nessus...)
│   ├── cve_matcher.py        # Cœur du matching CVE (local + API NVD)
│   ├── version_checker.py    # Comparaison de versions / contraintes affectées
│   ├── cpe_resolver.py       # Résolution CPE (statique + API NVD CPE Dictionary)
│   ├── contextual_scorer.py  # Scoring au-delà du CVSS brut (KEV, exploits...)
│   ├── chain_analyzer.py     # Détection de chaînes d'exploitation
│   ├── ad_detector.py        # Détection de contexte Active Directory
│   ├── bloodhound_integration.py  # Croisement avec BloodHound CE
│   ├── exploit_finder.py     # Recherche de PoC GitHub publics
│   ├── credentialed_scan.py  # Scan authentifié SSH (dpkg/rpm/pacman)
│   ├── ignore_list.py        # Whitelist .chocoscanignore
│   ├── diff_engine.py        # Comparaison de deux scans
│   ├── web_enumerator.py     # Énumération web par stack détectée
│   ├── interactive.py        # Mode interactif CLI
│   ├── report_generator.py   # Export HTML / JSON
│   ├── config.py             # Gestion de ~/.chocoscan.conf
│   └── tag_definitions.py    # Classification des CVE
│
├── data/
│   ├── cve_db.json           # Base CVE principale
│   ├── cve_db.seed.json      # Base de départ (seed)
│   └── cve_recent.json       # CVE récentes
│
└── tests/                    # Tests unitaires (pytest)
```

---

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

---

## Auteur

Développé par **Kinder-Bueno** (Mathys CASTELLA)
Étudiant en BUT Réseaux & Télécommunications, spécialisation cybersécurité — IUT de Blagnac

- GitHub : [github.com/Mathys-CASTELLA](https://github.com/Mathys-CASTELLA)
- Root-Me / HackTheBox : `Kinder-Bueno`

---

<div align="center">
<sub>ChocoScan s'appuie exclusivement sur des sources publiques (NVD, CISA KEV, PoC-in-GitHub).
Outil destiné à un usage CTF et pentest autorisé.</sub>
</div>
