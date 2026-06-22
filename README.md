Présentation

ChocoScan prend en entrée un scan réseau (Nmap, Masscan, RustScan, Nessus…) et associe automatiquement chaque service détecté à ses CVE connues. Au-delà du simple matching, il calcule un score contextuel (CVSS + CISA KEV + exploit public disponible + type d'impact), détecte les chaînes d'exploitation, s'intègre à BloodHound CE pour les environnements Active Directory, et dispose d'une interface web complète pour visualiser et exporter les résultats.

nmap -sV -oX scan.xml 10.10.10.50
python3 chocoscan.py -x scan.xml --severity CRITICAL,HIGH --exploits --export-html


Fonctionnalités

Multi-formatNmap XML/texte, Masscan, RustScan, Nessus CSV/.nessus, JSON
CVE matchingBase locale (~145 services) + fallback API NVD avec cache
Matching CPERequêtes NVD précises via cpeName (moins de faux positifs)
Scoring contextuelCVSS + CISA KEV + exploit public + type d'impact
Chaînes d'exploitDétection des enchaînements RCE → LPE entre services
Scan SSH authentifié Inventaire des paquets installés (dpkg/rpm/pacman)
Active DirectoryDétection de contexte AD + intégration BloodHound CE
Énumération webWordlists adaptées à la stack détectée
Whitelist.chocoscanignore — masquer les faux positifs connus
Diff de scansComparaison avant/après correctifs
Interface webDashboard React, filtres temps réel, historique SQLite
ExportsRapport HTML complet, JSON


Installation

git clone https://github.com/Mathys-CASTELLA/chocoscan.git
cd chocoscan

# Environnement virtuel (recommandé)
python3 -m venv venv && source venv/bin/activate

# Dépendances
pip install -r requirements.txt

# Initialisation de la base CVE locale
python3 init_db.py


Clé API NVD (facultative mais recommandée — passe de 5 à 50 req/30s) :
Demande gratuite sur nvd.nist.gov/developers/request-an-api-key, puis dans ~/.chocoscan.conf : nvd_api_key = "ta-clé"




Utilisation

Scan depuis un fichier

# Basique
python3 chocoscan.py -x scan.xml

# Filtré : Critical/High avec PoC, CVE depuis 2022, rapport HTML
python3 chocoscan.py -x scan.xml \
  --severity CRITICAL,HIGH \
  --after-year 2022 \
  --exploits \
  --export-html

Scan direct (nmap intégré)

python3 chocoscan.py --scan 10.10.10.50 --nmap-args "-T4 --open" --exploits

Scan SSH authentifié

# Inventaire complet des paquets installés sur la cible
python3 chocoscan.py --ssh-scan 10.10.10.50 \
  --ssh-user admin \
  --ssh-key ~/.ssh/id_rsa \
  --min-cvss 7.0 \
  --export-html

Contexte Active Directory

python3 chocoscan.py -x scan.xml --bloodhound sharphound.zip --export-html

Comparer deux scans

python3 chocoscan.py --diff scan_avant.xml scan_apres.xml --export-html

Mode interactif

python3 chocoscan.py -x scan.xml --interactive


Whitelist .chocoscanignore

Pour ignorer des CVE déjà traitées ou des faux positifs connus, sans refiltrer à chaque scan :

# .chocoscanignore (à la racine du projet ou dans ~/.chocoscanignore)
CVE-2021-41617    # SSH config non applicable
CVE-2023-38408    # ForwardAgent désactivé

python3 chocoscan.py -x scan.xml                          # Charge automatiquement
python3 chocoscan.py -x scan.xml --ignore-file ma_liste   # Fichier personnalisé
python3 chocoscan.py -x scan.xml --no-ignore              # Désactiver


Interface web

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

Fonctionnalités de l'interface :


Dashboard — stats globales, graphique de sévérité, derniers scans
Nouveau scan — upload drag & drop, scan IP direct, scan SSH
Résultats — filtres temps réel (sévérité, CVSS, exploit, CISA KEV), CVE détaillées
Historique — tous les scans avec statuts, suppression
Export — téléchargement JSON / rapport HTML depuis l'interface



Fichier de configuration

python3 chocoscan.py config init   # Génère ~/.chocoscan.conf avec toutes les options
python3 chocoscan.py config show   # Affiche la configuration active
python3 chocoscan.py config set min_cvss 7.0

Exemple ~/.chocoscan.conf :

toml# Filtrage
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

Toute option CLI écrase la valeur du fichier. Variables d'environnement supportées : CHOCOSCAN_<CLÉ>.


Base CVE locale

python3 init_db.py              # Initialisation (une seule fois)
python3 update_db.py            # Mise à jour générale (NVD)
python3 update_db_critical.py   # CVE CVSS >= 9.0
python3 update_db_ctf.py        # Services fréquents CTF (HTB, Root-Me)
python3 update_db_cpe.py        # Enrichissement CPE (matching API précis)
python3 update_exploits.py      # PoC GitHub


Formats d'entrée supportés

Format--input-formatNmap XML / textenmap_xml · nmap_textMasscan XML / JSON / textemasscan_xml · masscan_json · masscan_textRustScan JSON / texterustscan_json · rustscan_textNessus CSV / .nessusnessus_csv · nessus_xmlChocoScan JSONchocoscan_json

La détection est automatique (--input-format auto par défaut).

Options CLI — référence rapide

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


Sources de données

SourceUsageNVDBase principale des CVECISA KEVCVE activement exploitéesPoC-in-GitHubProof-of-concept publicsBloodHound CEChemins d'attaque AD


Auteur

Mathys CASTELLA 
Étudiant en BUT Réseaux & Télécommunications, spécialisation Cybersécurité — IUT de Blagnac

Avertissement légal

ChocoScan est conçu pour être utilisé uniquement sur des systèmes pour lesquels vous disposez d'une autorisation explicite : machines personnelles, laboratoires CTF (HackTheBox, TryHackMe, VulnHub), ou dans le cadre d'une mission de pentest avec contrat signé.

Toute utilisation sur des systèmes tiers sans autorisation est illégale et contraire à l'éthique. L'auteur décline toute responsabilité en cas d'utilisation malveillante.

Exemple d'exécution (ancienne version) :

<img width="767" height="527" alt="image" src="https://github.com/user-attachments/assets/b67a24a4-d58f-43b1-8dd0-06d28006c4b6" />


<img width="1091" height="1056" alt="image" src="https://github.com/user-attachments/assets/68d9c9f6-5408-47d3-bb10-3a266c5225db" />


<img width="2552" height="1184" alt="image" src="https://github.com/user-attachments/assets/6986b689-2aff-41e6-8dfd-6df39a957803" />

