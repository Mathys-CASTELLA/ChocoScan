Présentation

ChocoScan est un outil de mapping CVE post-Nmap : il prend en entrée les résultats d'un scan réseau et associe automatiquement chaque service détecté à ses vulnérabilités connues, enrichies d'un score contextuel, de tags threat intel, et d'informations d'exploitation directement exploitables.

L'objectif est de combler le vide entre "j'ai une liste de ports ouverts" et "je sais quoi attaquer en premier" — en CTF comme en pentest réel.

Fonctionnalités

Moteur CVE


Base locale de 1 496 CVEs couvrant 145 services (Apache, OpenSSH, SMB, Log4j, Spring, Jenkins, Confluence, Tomcat, Redis, Docker…)
Fallback automatique vers l'API NVD avec cache persistant 24h pour les services non couverts
Moteur de comparaison de versions robuste : extrait et normalise les versions depuis les bannières Nmap réelles, gère les epochs Debian, préfixes MariaDB, suffixes OS — et retourne un niveau de confiance (CERTAIN / LIKELY / UNCERTAIN) plutôt qu'un booléen sec


Scoring contextuel

Le CVSS seul ne suffit pas pour prioriser. ChocoScan calcule un score composite 0–10 :

FacteurPoids maxCVSS base score6.0 ptsQualité de l'exploit disponible2.0 ptsFraîcheur (année de publication)1.0 ptsType d'impact (RCE > LPE > info)0.7 ptsPrésence dans la liste CISA KEV0.5 ptsAuthentification requise0.3 ptsBonus tags (APT, ransomware…)jusqu'à +1.5 pts

Une CVE CVSS 9.8 sans contexte peut ainsi être déclassée derrière une CVE CVSS 8.1 avec module Metasploit, exploitation active et tag #apt.

Système de tags

19 tags répartis en 4 catégories pour filtrer par contexte plutôt que par score :

CatégorieTagsMenace#apt #ransomware #supply-chain #initial-access #lateralTechnique#web #windows #linux #network #database #devops #iotSurface#active-directory #container #cloudExploitation#ctf-frequent #exploit-public #no-auth #rce-chain

Mode interactif CLI

Interface de navigation style fzf entièrement dans le terminal (curses, zéro dépendance supplémentaire) :


Navigation entre ports et CVEs (↑↓, j/k, PgUp/PgDn)
Détail complet d'une CVE avec scroll (description, versions affectées, module Metasploit, machines CTF connues)
Marquage de CVEs : Exploitée E, Non applicable N, Incertaine ?
Filtre live / par mot-clé ou tag
Tri par CVSS / Sévérité / ID (S)
Export JSON des seules CVEs marquées (X)


Autres fonctionnalités


Rapport HTML interactif avec tri, filtres, score contextuel et badges de tags
Mode diff : compare deux scans et met en évidence les nouvelles vulnérabilités
Détection Active Directory : identifie automatiquement les environnements AD/Kerberos et adapte l'analyse
Analyse de chaînage : détecte les CVEs pouvant être enchaînées (ex : LFI → RCE)
Intégration BloodHound : croise les données AD avec les CVEs détectées
Énumération web intelligente avec wordlists adaptées à la stack détectée
Fichier de configuration ~/.chocoscan.conf (TOML) pour ne plus retaper --min-cvss 7.0 --exploits --top-cves 10 à chaque commande



Installation

Prérequis : Python 3.11+, pip

bash# Cloner le dépôt
git clone https://github.com/<votre-user>/chocoscan.git
cd chocoscan

# Installer les dépendances
pip install -r requirements.txt

# (Optionnel) Enrichir la base avec les CVEs CTF orientées pentest
python update_db_ctf.py

# (Optionnel) Appliquer les tags threat intel sur toute la base
python update_db_tags.py

# (Optionnel) Créer votre fichier de configuration personnel
python chocoscan.py config init

Dépendances :

PaquetUsagerichInterface terminal coloréerequestsAppels API NVDpackagingComparaison de versions sémantiquesPillowRendu de l'art ASCII du banner


Démarrage rapide

bash# Depuis un fichier Nmap XML existant
python chocoscan.py -x scan.xml

# Lancer le scan directement
python chocoscan.py --scan 10.10.10.1

# Filtrer sur les CVEs critiques avec exploit disponible
python chocoscan.py -x scan.xml --min-cvss 7.0 --severity CRITICAL,HIGH --exploits

# Générer un rapport HTML
python chocoscan.py -x scan.xml --export-html

# Mode interactif — naviguer dans les résultats, marquer, exporter
python chocoscan.py -x scan.xml --interactive


Guide d'utilisation détaillé

Entrées supportées

ChocoScan accepte les sorties de la majorité des scanners réseau. La détection du format est automatique.

FormatCommande de générationNmap XMLnmap -sV -sC -oX scan.xml <cible>Nmap textenmap -sV -oN scan.txt <cible>Masscan JSONmasscan -p1-65535 --rate 1000 -oJ scan.json <cible>RustScan JSONrustscan -a <cible> --range 1-65535 -- -oX scan.xmlNessus CSVExport depuis l'interface NessusNessus .nessusExport natif Nessus

Pour forcer un format spécifique :

bashpython chocoscan.py -x scan.csv --input-format nessus_csv


Filtrage des résultats

bash# Seuil CVSS minimum
python chocoscan.py -x scan.xml --min-cvss 7.0

# Sévérité(s) uniquement
python chocoscan.py -x scan.xml --severity CRITICAL,HIGH

# CVEs publiées à partir de 2022
python chocoscan.py -x scan.xml --after-year 2022

# Nombre de CVEs affichées par port en terminal (0 = toutes)
python chocoscan.py -x scan.xml --top-cves 10

# Combiner les filtres
python chocoscan.py -x scan.xml --min-cvss 7.0 --severity CRITICAL --after-year 2021 --top-cves 5


Mode interactif

bashpython chocoscan.py -x scan.xml --interactive
# ou
python chocoscan.py -x scan.xml -i

L'interface s'ouvre après l'analyse. Trois vues accessibles :

Vue Ports — liste des services détectés avec sévérité max et compteur CVEs.

Vue CVEs — CVEs d'un service sélectionné. Touches disponibles :

ToucheAction↑ ↓ ou j kNaviguerEntréeOuvrir le détailEMarquer ExploitéeNMarquer Non applicable?Marquer IncertaineUDémarquer/Filtrer (texte ou #tag)SChanger le tri (CVSS / Sévérité / ID)XExporter les CVEs marquées en JSONEsc / QRemonter / Quitter

Vue Détail — description complète, versions affectées, module Metasploit, liens ExploitDB, machines CTF connues, niveau de confiance du matching de version.

L'export X génère output/interactive_export_<timestamp>.json avec uniquement les CVEs que vous avez taguées — utile pour alimenter directement un rapport de pentest.


Rapports HTML et JSON

bash# Rapport HTML interactif
python chocoscan.py -x scan.xml --export-html

# Rapport JSON (pour intégration dans d'autres outils)
python chocoscan.py -x scan.xml --export-json

# Les deux + dossier personnalisé
python chocoscan.py -x scan.xml --export-html --export-json --output-dir ~/rapports/pentest_client

Le rapport HTML inclut :


Tableau interactif avec tri et filtres côté navigateur
Badge de score contextuel avec détail des composantes au survol
Badges de tags colorés par catégorie
Liens directs NVD, ExploitDB et références GitHub



Mode diff — comparer deux scans

Idéal pour suivre l'évolution de la surface d'attaque entre deux dates, ou vérifier qu'un patch a bien été appliqué.

bashpython chocoscan.py --diff scan_avant.xml scan_apres.xml
python chocoscan.py --diff scan_avant.xml scan_apres.xml --export-html

Affiche les nouveaux ports ouverts, les services nouvellement vulnérables, et les CVEs disparues après patch.


Active Directory et BloodHound

ChocoScan détecte automatiquement la présence de services AD (Kerberos, LDAP, SMB, RPC) et adapte son analyse :

bash# Détection AD automatique (activée par défaut)
python chocoscan.py -x scan.xml

# Avec données BloodHound pour croiser les chemins d'attaque AD avec les CVEs
python chocoscan.py -x scan.xml --bloodhound chemin/vers/bloodhound.zip


Énumération web

bash# Énumération web intelligente après le scan CVE
python chocoscan.py -x scan.xml --enum-web

# Avec paramètres personnalisés
python chocoscan.py -x scan.xml --enum-web --enum-threads 20 --enum-delay 0.1

ChocoScan détecte la stack applicative (Apache, Nginx, PHP, WordPress…) et adapte ses wordlists en conséquence.


Configuration personnelle

Pour ne plus retaper les mêmes options à chaque commande :

bash# Créer ~/.chocoscan.conf avec toutes les options commentées
python chocoscan.py config init

# Afficher la configuration active (fichier + variables env + défauts)
python chocoscan.py config show

Exemple de ~/.chocoscan.conf :

toml# Filtrage
min_cvss  = 7.0
severity  = "CRITICAL,HIGH"
top_cves  = 10

# Comportement
exploits     = true
export_html  = true
interactive  = false

# Dossier de sortie
output_dir = "~/chocoscan_reports"

[scan]
nmap_args = "-T4 --open"

[web]
enum_threads = 20

Les arguments CLI ont toujours la priorité sur le fichier de config. Des variables d'environnement CHOCOSCAN_<CLÉ> permettent également de surcharger ponctuellement :

bashCHOCOSCAN_MIN_CVSS=9.0 python chocoscan.py -x scan.xml


Mise à jour de la base CVE

bash# Mettre à jour toutes les CVEs (interroge l'API NVD — lent sans clé API)
python update_db.py

# Mettre à jour uniquement les CVEs critiques (CVSS ≥ 9.0)
python update_db_critical.py --api-key VOTRE_CLE_NVD

# Injecter la sélection CTF/pentest curated (69 CVEs classiques HTB/THM)
python update_db_ctf.py

# Appliquer les tags threat intel sur toute la base après mise à jour
python update_db_tags.py

# Voir la taxonomie des tags
python update_db_tags.py --list-tags

Une clé API NVD gratuite est disponible sur nvd.nist.gov/developers/request-an-api-key — elle multiplie la vitesse de mise à jour par 10.

Référence des options CLI

python chocoscan.py [-x FILE | --scan TARGET | --diff AVANT APRES]
                    [options]

Entrée :
  -x, --xml FILE            Fichier de scan (Nmap XML, Masscan, RustScan, Nessus…)
  --scan TARGET             Lancer un scan nmap directement
  --diff AVANT APRES        Comparer deux fichiers de scan
  --input-format FORMAT     Forcer le format (défaut : auto)

Filtres :
  --min-cvss SCORE          Seuil CVSS minimum (ex: 7.0)
  --severity NIVEAUX        Sévérités à afficher (ex: CRITICAL,HIGH)
  --after-year AAAA         CVEs publiées à partir de cette année
  --top-cves N              CVEs affichées par port en terminal (0 = toutes)

Comportement :
  --no-api                  Désactiver le fallback API NVD
  --no-scoring              Utiliser uniquement le CVSS brut
  --no-ad                   Désactiver la détection Active Directory
  --no-chains               Désactiver l'analyse des CVEs chaînables
  --exploits                Rechercher des exploits PoC sur GitHub
  -i, --interactive         Mode interactif TUI post-analyse

Export :
  --export-html             Générer un rapport HTML interactif
  --export-json             Générer un rapport JSON
  --output-dir DIR          Dossier de sortie (défaut : output/)

Nmap :
  --nmap-args ARGS          Arguments supplémentaires passés à nmap

Énumération web :
  --enum-web                Activer l'énumération web intelligente
  --enum-threads N          Threads (défaut : 10)
  --enum-delay SEC          Délai entre requêtes (défaut : 0.05)

BloodHound :
  --bloodhound FILE         Fichier BloodHound à croiser avec les CVEs

Configuration :
  config show               Afficher la configuration active
  config init               Créer ~/.chocoscan.conf
  config init --force       Écraser ~/.chocoscan.conf existant


Exemples de workflows

CTF / HackTheBox

bash# Scan rapide + mode interactif pour prioriser l'attaque
nmap -sV -sC -oX scan.xml 10.10.10.1
python chocoscan.py -x scan.xml --min-cvss 7.0 -i

# Dans le mode interactif :
# → Naviguer sur le port 445 (SMB)
# → Entrée pour voir les CVEs
# → E pour marquer EternalBlue comme à exploiter
# → X pour exporter les CVEs marquées

Audit de sécurité

bash# Scan complet avec rapport HTML et détails d'exploitation
nmap -sV -sC -p- -oX audit_client.xml 192.168.1.0/24
python chocoscan.py -x audit_client.xml \
    --min-cvss 5.0 \
    --exploits \
    --export-html \
    --export-json \
    --output-dir ~/audits/client_2025

# Comparer avec un scan précédent pour mesurer les progrès
python chocoscan.py --diff audit_j1.xml audit_j30.xml --export-html

Environnement Active Directory

bash# Avec BloodHound pour les chemins d'escalade AD
nmap -sV -p 88,135,139,389,443,445,3268,3389 -oX ad_scan.xml 192.168.1.0/24
python chocoscan.py -x ad_scan.xml \
    --bloodhound ~/bloodhound_data.zip \
    --export-html


Avertissement légal

ChocoScan est conçu pour être utilisé uniquement sur des systèmes pour lesquels vous disposez d'une autorisation explicite : machines personnelles, laboratoires CTF (HackTheBox, TryHackMe, VulnHub), ou dans le cadre d'une mission de pentest avec contrat signé.

Toute utilisation sur des systèmes tiers sans autorisation est illégale et contraire à l'éthique. L'auteur décline toute responsabilité en cas d'utilisation malveillante.

Exemple d'exécution (ancienne version) :

<img width="767" height="527" alt="image" src="https://github.com/user-attachments/assets/b67a24a4-d58f-43b1-8dd0-06d28006c4b6" />


<img width="1091" height="1056" alt="image" src="https://github.com/user-attachments/assets/68d9c9f6-5408-47d3-bb10-3a266c5225db" />


<img width="2552" height="1184" alt="image" src="https://github.com/user-attachments/assets/6986b689-2aff-41e6-8dfd-6df39a957803" />

