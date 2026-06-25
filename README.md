<div align="center">

<img width="637" height="425" alt="image" src="https://github.com/user-attachments/assets/c477bc29-21a8-4e3f-bfbb-3ff66656fd00" />

# ChocoScan

**Outil de pentest post-Nmap — CVE matching, scoring contextuel & modules offensifs CTF**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-Frontend-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![NVD](https://img.shields.io/badge/Source-NVD%20%2B%20CISA%20KEV-red?style=flat-square)](https://nvd.nist.gov)
[![CTF](https://img.shields.io/badge/CTF-HackTheBox%20%7C%20Root--Me-brightgreen?style=flat-square)](https://hackthebox.com)

*Développé par [Mathys CASTELLA](https://github.com/Mathys-CASTELLA) — BUT R&T Cybersécurité, IUT de Blagnac*

</div>

---

## Présentation

ChocoScan prend en entrée un scan réseau (Nmap, Masscan, RustScan, Nessus…) et enchaîne automatiquement :

1. **CVE matching** — association service → CVE via base locale + fallback NVD/CISA KEV
2. **Scoring contextuel** — CVSS + exploit public disponible + criticité CISA → score actionnable
3. **Modules offensifs** — payloads web, pivoting, SMB/AD, brute force, reverse shells, cloud…
4. **Mode interactif** — TUI curses avec recommandations de modules selon le scan
5. **Interface web** — dashboard FastAPI + React pour visualiser et exporter les résultats

Conçu pour les CTF (HTB, Root-Me) et les étudiants en cybersécurité.

```bash
# Analyser un scan et afficher les CVE critiques + modules recommandés
nmap -sV -oX scan.xml 10.10.10.50
python3 chocoscan.py -x scan.xml --severity CRITICAL,HIGH --exploits --export-html

# Enchaîner les modules offensifs en une commande
python3 chocoscan.py -x scan.xml --web-payloads --smb --brute --pivot --lhost 10.10.14.5
```

---

## Fonctionnalités

### Analyse de vulnérabilités
- Parsing de fichiers Nmap XML, JSON, Masscan, RustScan, Nessus `.nessus`
- CVE matching sur base locale SQLite + fallback API NVD en temps réel
- Scoring contextuel : CVSS × pondération (exploit public, CISA KEV, impact réseau)
- Détection de chaînes d'exploitation (kill chain MITRE ATT&CK)
- Diff entre deux scans pour suivre l'évolution d'une cible
- Tags automatiques : `exploit-public`, `kev-listed`, `rce`, `auth-bypass`…

### Modules offensifs (CTF / pentest)
| Catégorie | Modules |
|---|---|
| **Web** | Payloads LFI/SSTI/SQLi/SSRF/XXE/XSS, fuzzing vhost, énumération web |
| **Réseau** | Reverse shells, pivoting (Ligolo-ng/Chisel/SSH), shell upgrade |
| **Credentials** | Brute force (Hydra/CMA), credentials par défaut, hash cracker |
| **Windows / AD** | SMB + Impacket, énumération AD, BloodHound, privesc, token privileges, lateral movement |
| **Linux** | GTFOBins, privesc checklist, shell upgrade, loot collector |
| **Container** | Docker/LXC/Kubernetes escape, DCOM/WMI, LAPS, délégation Kerberos |
| **Cloud** | AWS S3/IAM/metadata, Azure Blob/AD, GCP GCS, ScoutSuite |
| **CTF** | Cipher decoder, wordlist builder, kill chain visualizer |

### Interface & exports
- TUI curses interactif avec vue modules recommandés (touche `M`)
- Interface web FastAPI + React (port 8000)
- Export HTML et JSON des rapports
- Mode diff pour comparer deux scans

---

## Prérequis

```
Python 3.10+
nmap (pour --scan)
```

Dépendances Python :
```bash
pip install -r requirements.txt
```

Dépendances optionnelles selon les modules utilisés :
```
crackmapexec / netexec   →  --smb, --brute, --lateral
impacket                 →  --smb, --lateral, --ad-enum
certipy-ad               →  --lateral (AD CS)
bloodhound-python        →  --bloodhound
```

---

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/Mathys-CASTELLA/chocoscan.git
cd chocoscan

# Installer les dépendances Python
pip install -r requirements.txt

# Initialiser la base CVE locale (téléchargement NVD ~200 Mo)
python3 update_db.py

# Optionnel : initialiser le fichier de configuration
python3 chocoscan.py config init
# → Crée ~/.chocoscan.conf avec les valeurs par défaut

# Vérifier l'installation
python3 chocoscan.py --help
```

> La base CVE locale est stockée dans `data/cve_db.json`. La mettre à jour régulièrement avec `python3 update_db.py`.

---

## Utilisation rapide

### Depuis un fichier XML Nmap

```bash
# Scan basique
python3 chocoscan.py -x scan.xml

# Filtrer CRITICAL et HIGH, afficher les exploits
python3 chocoscan.py -x scan.xml --severity CRITICAL,HIGH --exploits

# Générer un rapport HTML
python3 chocoscan.py -x scan.xml --export-html --output-dir ./reports
```

### Scan Nmap intégré

```bash
# Lancer le scan et analyser dans la foulée
python3 chocoscan.py --scan 10.10.10.50

# Avec arguments nmap personnalisés
python3 chocoscan.py --scan 10.10.10.50 --nmap-args "-p- -T4 --open"
```

### Scan SSH authentifié

```bash
# Se connecter en SSH pour collecter les infos système
python3 chocoscan.py -x scan.xml --ssh-scan 10.10.10.50 \
  --ssh-user administrator --ssh-pass P@ssw0rd

# Avec clé privée
python3 chocoscan.py -x scan.xml --ssh-scan 10.10.10.50 \
  --ssh-user ubuntu --ssh-key ~/.ssh/id_rsa
```

### Mode interactif

```bash
# Lancer le TUI (navigation style fzf)
python3 chocoscan.py -x scan.xml --interactive --lhost 10.10.14.5

# Raccourcis dans le TUI :
#   ↑↓ / j k   Naviguer
#   Entrée      Ouvrir la vue CVEs d'un service
#   M           Vue modules recommandés selon le scan
#   E / N / ?   Marquer une CVE (Exploitée / Non applicable / Incertaine)
#   /           Filtrer par mot-clé
#   S           Trier (CVSS / Sévérité / ID)
#   X           Exporter les CVEs marquées en JSON
#   Q / Esc     Remonter d'un niveau
```

### Interface web

```bash
# Démarrer le serveur FastAPI + React
python3 chocoscan.py -x scan.xml --web

# Ouvrir http://localhost:8000 dans le navigateur
```

---

## Modules offensifs

### Web

```bash
# Générer les payloads LFI, SSTI, SQLi, SSRF, XXE, XSS
# adaptés au stack détecté (PHP/Python/Java/Ruby...)
python3 chocoscan.py -x scan.xml --web-payloads --lhost 10.10.14.5

# Énumération web (dirbusting, vhosts, technologies)
python3 chocoscan.py -x scan.xml --enum-web --vhost target.htb
```

### Réseau & pivoting

```bash
# Reverse shells adaptés aux services détectés
python3 chocoscan.py -x scan.xml --revshell --lhost 10.10.14.5 --lport 4444

# Guide de pivoting (Ligolo-ng, Chisel, SSH, socat, sshuttle)
python3 chocoscan.py -x scan.xml --pivot 10.10.14.5

# Upgrade du shell (stty / pty / socat)
python3 chocoscan.py -x scan.xml --upgrade-shell
```

### Brute force & credentials

```bash
# Commandes hydra/medusa/CMA par service détecté
python3 chocoscan.py -x scan.xml --brute

# Credentials par défaut (base intégrée)
python3 chocoscan.py -x scan.xml --default-creds

# Wordlist ciblée depuis le contexte du scan
python3 chocoscan.py -x scan.xml --wordlist /tmp/target_wl.txt
python3 chocoscan.py -x scan.xml --wordlist --custom-words john sarah "IT-Admin"
```

### SMB & Active Directory

```bash
# Énumération SMB complète (null session, CMA, impacket)
python3 chocoscan.py -x scan.xml --smb

# Énumération AD (Kerberoasting, AS-REP, BloodHound, LDAP)
python3 chocoscan.py -x scan.xml --ad-enum
python3 chocoscan.py -x scan.xml --ad-auto  # exécution automatique

# Mouvement latéral post-compromise (DCOM, LAPS, délégation, AD CS…)
python3 chocoscan.py -x scan.xml --lateral

# BloodHound (depuis un fichier .zip ou .json déjà collecté)
python3 chocoscan.py -x scan.xml --bloodhound bloodhound_data.zip
```

### Privilege escalation

```bash
# Checklist privesc Linux + Windows selon l'OS détecté
python3 chocoscan.py -x scan.xml --privesc

# GTFOBins (binaires SUID/sudo exploitables)
python3 chocoscan.py -x scan.xml --gtfobins

# Token privileges Windows (SeImpersonate → Potato, SeDebug → LSASS…)
python3 chocoscan.py -x scan.xml --tokens
python3 chocoscan.py -x scan.xml --tokens 'SeImpersonatePrivilege   Enabled'
```

### Container & Cloud

```bash
# Évasion de conteneur (Docker/LXC/Kubernetes)
python3 chocoscan.py -x scan.xml --container
python3 chocoscan.py -x scan.xml --container quick  # vérifications rapides

# Énumération cloud (AWS/Azure/GCP)
python3 chocoscan.py -x scan.xml --cloud
```

### CTF / Divers

```bash
# Identifier et décoder un encodage (Base64, Hex, JWT, Morse, hashes…)
python3 chocoscan.py -x scan.xml --cipher 'aGVsbG8gd29ybGQ='

# Hash cracker (commandes hashcat/john adaptées)
python3 chocoscan.py -x scan.xml --hashcrack '$6$salt$hash...'

# Misconfigurations (SUID, capabilities, services mal configurés…)
python3 chocoscan.py -x scan.xml --misconfig

# Kill chain (MITRE ATT&CK, chemins d'exploitation)
python3 chocoscan.py -x scan.xml --kill-chain

# Loot collector (fichiers sensibles après accès SSH)
python3 chocoscan.py -x scan.xml --loot --ssh-user root --ssh-key ./id_rsa
```

### Comparer deux scans

```bash
# Identifier les nouveaux services / CVE entre deux dates
python3 chocoscan.py --diff scan_avant.xml scan_apres.xml
```

---

## Combo CTF typique

```bash
# 1. Scanner la cible et analyser les CVE
nmap -sV -sC -oX scan.xml 10.10.10.50

# 2. Analyse complète avec tous les modules offensifs
python3 chocoscan.py -x scan.xml \
  --severity CRITICAL,HIGH \
  --exploits \
  --web-payloads \
  --smb \
  --brute \
  --pivot \
  --wordlist /tmp/target_wl.txt \
  --lhost 10.10.14.5 \
  --export-html

# 3. Explorer en mode interactif avec les modules recommandés
python3 chocoscan.py -x scan.xml --interactive --lhost 10.10.14.5
# → Touche M pour voir les modules recommandés selon les services détectés
```

---

## Fichier de configuration

ChocoScan lit automatiquement `~/.chocoscan.conf` (format TOML) pour éviter de répéter les options à chaque commande.

```toml
# ~/.chocoscan.conf — exemple profil CTF
min_cvss    = 6.0
top_cves    = 10
exploits    = true
export_html = false
output_dir  = "~/ctf/reports"
severity    = "CRITICAL,HIGH"

[scan]
nmap_args = "-T4 --open -sV -sC"

[web]
enum_web     = false
enum_threads = 20
```

```bash
# Initialiser le fichier de config avec les valeurs par défaut
python3 chocoscan.py config init

# Afficher la configuration active
python3 chocoscan.py config show

# Écraser la config existante
python3 chocoscan.py config init --force
```

Priorité de résolution : **CLI > Variable d'env > `~/.chocoscan.conf` > Défauts**

Voir [CONFIGURATION.md](CONFIGURATION.md) pour la référence complète de toutes les options.

---

## Whitelist `.chocoscanignore`

Pour ignorer certains CVE (faux positifs, non exploitables dans le contexte) :

```bash
# Format : un pattern par ligne (CVE ID, service, port, tag)
CVE-2021-44228          # Ignorer un CVE spécifique
openssh                 # Ignorer tous les CVE liés à OpenSSH
#80                     # Ignorer le port 80 (commentaire avec #)
kev-listed              # Ignorer les CVE avec ce tag
```

```bash
# Utiliser un fichier ignore personnalisé
python3 chocoscan.py -x scan.xml --ignore-file ./my_ignore.txt

# Désactiver le fichier ignore
python3 chocoscan.py -x scan.xml --no-ignore
```

---

## Base CVE locale

```bash
# Mise à jour complète (NVD + CISA KEV + exploits)
python3 update_db.py

# Mise à jour ciblée
python3 update_db_critical.py   # CVE critiques uniquement (plus rapide)
python3 update_exploits.py      # Mise à jour des références exploit
python3 update_db_ctf.py        # Machines HTB/THM connues pour chaque CVE
python3 update_db_tags.py       # Mise à jour des tags sémantiques
```

---

## Structure du projet

```
chocoscan/
├── chocoscan.py              # Point d'entrée CLI
├── modules/                  # 42 modules Python
│   ├── cve_matcher.py        # CVE matching principal
│   ├── contextual_scorer.py  # Scoring contextuel
│   ├── interactive.py        # TUI curses + vue modules
│   ├── web_payload_gen.py    # Payloads web offensifs
│   ├── smb_helper.py         # SMB + Impacket
│   ├── lateral_movement.py   # Mouvement latéral AD
│   ├── cloud_enum.py         # Énumération AWS/Azure/GCP
│   └── ...                   # Voir docs/MODULES.md
├── web/                      # Interface web (FastAPI + React)
│   ├── main.py               # Serveur FastAPI
│   └── src/                  # Frontend React + Tailwind
├── data/
│   └── cve_db.json           # Base CVE locale (généré par update_db.py)
├── output/                   # Rapports HTML/JSON (gitignored)
├── update_db.py              # Script de mise à jour de la base
├── requirements.txt
└── ~/.chocoscan.conf         # Config utilisateur (hors dépôt)
```

---

## Référence complète

| Fichier | Contenu |
|---|---|
| [CONFIGURATION.md](CONFIGURATION.md) | Toutes les options du fichier de configuration avec exemples de profils |
| [docs/MODULES.md](docs/MODULES.md) | Catalogue des 42 modules avec description et exemples d'usage |

---

## Auteur

**Mathys CASTELLA** — étudiant en BUT R&T, spécialité Cybersécurité (IUT de Blagnac)

- GitHub : [@Mathys-CASTELLA](https://github.com/Mathys-CASTELLA)
- Projet réalisé dans le cadre de l'apprentissage du pentesting (CTF HackTheBox / Root-Me)

---

## Licence

MIT — voir [LICENSE](LICENSE)
