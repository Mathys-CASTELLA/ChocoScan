# Catalogue des modules — ChocoScan

ChocoScan est composé de **42 modules** organisés par catégorie.
Chaque module est un fichier Python indépendant dans `modules/` et
peut être appelé directement depuis la CLI ou depuis le mode interactif (`M`).

---

## Analyse de vulnérabilités

### `cve_matcher.py` — CVE Matching
Associe chaque service Nmap à ses CVE via la base locale SQLite et un fallback NVD.
Supporte la résolution CPE et les alias de produits.

```bash
# Actif par défaut — aucun flag nécessaire
python3 chocoscan.py -x scan.xml
```

---

### `contextual_scorer.py` — Scoring contextuel
Calcule un score d'exploitation pour chaque CVE en combinant le CVSS,
la présence d'un exploit public, le listing CISA KEV et l'impact sur le réseau.
Permet de prioriser les CVE réellement exploitables.

```bash
python3 chocoscan.py -x scan.xml               # actif par défaut
python3 chocoscan.py -x scan.xml --no-scoring  # désactiver
```

---

### `chain_analyzer.py` — Kill Chain (MITRE ATT&CK)
Détecte les enchaînements d'exploitation possibles entre les services et les CVE.
Modélise les chemins d'attaque selon le framework MITRE ATT&CK.

```bash
python3 chocoscan.py -x scan.xml --kill-chain
python3 chocoscan.py -x scan.xml --no-chains   # désactiver
```

---

### `diff_engine.py` — Comparaison de scans
Compare deux fichiers de scan pour identifier les nouveaux services,
les CVE apparus ou disparus, et les changements de configuration.

```bash
python3 chocoscan.py --diff scan_avant.xml scan_apres.xml
```

---

## Parsing & entrées

### `nmap_parser.py` — Parser Nmap XML
Parse les fichiers XML produits par Nmap (`-oX`). Extrait les services,
banners, versions, états et OS.

### `input_parser.py` — Parser multi-format
Détecte automatiquement le format d'entrée : Nmap XML/JSON, Masscan,
RustScan, Nessus `.nessus`.

```bash
python3 chocoscan.py -x scan.xml                          # Nmap XML (auto)
python3 chocoscan.py -x scan.json --input-format masscan  # Masscan JSON
python3 chocoscan.py -x rapport.nessus                    # Nessus
```

---

### `credentialed_scan.py` — Scan SSH authentifié
Se connecte en SSH à la cible pour collecter des informations système
complémentaires (OS exact, packages installés, processus, utilisateurs).

```bash
python3 chocoscan.py -x scan.xml --ssh-scan 10.10.10.50 \
  --ssh-user ubuntu --ssh-key ~/.ssh/id_rsa
```

---

## Modules offensifs — Web

### `web_payload_gen.py` — Web Payload Generator
Génère des payloads offensifs adaptés au stack web détecté par Nmap.
Détecte automatiquement PHP/Python/Java/Ruby/Node.js depuis les banners.

**Couvre :**
- **LFI/Path Traversal** — paths Linux & Windows, bypasses de filtres (double encoding, null byte, wrappers PHP)
- **SSTI** — 7 moteurs : Jinja2, Twig, Smarty, Velocity, FreeMarker, Pebble, ERB (payloads detect + RCE)
- **SQLi** — 5 DBMS : MySQL, PostgreSQL, MSSQL, Oracle, SQLite (error-based, union, time-blind, RCE)
- **SSRF** — 15+ bypasses IP (hex, octal, decimal, nip.io, IPv6) + endpoints cloud metadata (AWS/GCP/Azure)
- **XXE** — file read, SSRF via XXE, OOB blind DTD
- **XSS** — reflected, cookie stealer, keylogger, CSP bypass
- **sqlmap** — commandes adaptées au DBMS et à l'authentification

```bash
python3 chocoscan.py -x scan.xml --web-payloads --lhost 10.10.14.5
python3 chocoscan.py -x scan.xml --web-payloads http:8080  # service spécifique
```

---

### `web_enumerator.py` — Énumération web
Fuzzing de répertoires et fichiers, détection de technologies,
recherche de fichiers sensibles (`.git`, `.env`, `backup.zip`…).

```bash
python3 chocoscan.py -x scan.xml --enum-web
python3 chocoscan.py -x scan.xml --enum-web --enum-threads 30 --enum-delay 0.1
```

---

### `vhost_discovery.py` — Virtual Host Discovery
Bruteforce de sous-domaines et virtual hosts sur les services HTTP détectés.

```bash
python3 chocoscan.py -x scan.xml --vhost target.htb
python3 chocoscan.py -x scan.xml --vhost auto  # détection automatique
```

---

## Modules offensifs — Réseau

### `reverse_shell.py` — Reverse Shell Generator
Génère des payloads reverse shell adaptés aux services détectés.
Couvre bash, Python, PHP, PowerShell, Perl, Ruby, netcat, socat, Java, etc.

```bash
python3 chocoscan.py -x scan.xml --revshell --lhost 10.10.14.5 --lport 4444
python3 chocoscan.py -x scan.xml --revshell http:80  # pour un service spécifique
python3 chocoscan.py -x scan.xml --all-shells         # tous les shells disponibles
```

---

### `pivot_helper.py` — Pivot Helper
Génère des guides complets de pivoting et tunneling selon les services
et réseaux internes détectés dans le scan.

**Couvre :** Ligolo-ng (TUN interface transparente), Chisel (HTTP tunnel),
SSH local/remote/dynamic, sshuttle (VPN over SSH), socat relay.

```bash
python3 chocoscan.py -x scan.xml --pivot 10.10.14.5
python3 chocoscan.py -x scan.xml --pivot auto  # utilise --lhost
```

---

### `shell_upgrader.py` — Shell Upgrade
Génère les commandes pour upgrader un shell basique en TTY interactif.
Linux (stty/pty/socat) et Windows (ConPTY/PowerShell).

```bash
python3 chocoscan.py -x scan.xml --upgrade-shell
```

---

## Modules offensifs — Credentials & Brute Force

### `brute_helper.py` — Brute Force Helper
Génère les commandes Hydra/Medusa/CrackMapExec/Ncrack optimisées
pour chaque service réseau détecté, avec les wordlists SecLists recommandées.

**Services :** SSH, FTP, HTTP Basic/Form, SMB, RDP, MySQL, PostgreSQL,
MSSQL, VNC, Telnet, WinRM, LDAP, SNMP, SMTP.

```bash
python3 chocoscan.py -x scan.xml --brute
```

---

### `default_creds.py` — Credentials par défaut
Base de données de credentials par défaut pour les équipements réseau,
applications web et services courants (Tomcat, Jenkins, Grafana, etc.).

```bash
python3 chocoscan.py -x scan.xml --default-creds
```

---

### `hash_cracker.py` — Hash Cracker
Identifie le type de hash et génère les commandes hashcat/john adaptées
(mode `-m`, wordlists, règles). Couvre les hashes Linux, Windows NTLM,
Kerberos (AS-REP, Kerberoast), Net-NTLMv2, bcrypt, etc.

```bash
python3 chocoscan.py -x scan.xml --hashcrack '$6$salt$hashvalue...'
python3 chocoscan.py -x scan.xml --hashcrack auto  # depuis le loot collecté
```

---

### `wordlist_builder.py` — Wordlist Builder
Génère une wordlist ciblée depuis le contexte du scan : domaine, hostname,
produits détectés, nom d'entreprise deviné.

**Mutations :** années (2023/2024/2025), symboles (!@#$), patterns enterprise
(Mot@2024!, MotSpring2024), leet speak, préfixes admin. Inclut aussi les
commandes CeWL pour spider les services web, la génération d'usernames
(username-anarchy, kerbrute) et les règles hashcat.

```bash
python3 chocoscan.py -x scan.xml --wordlist
python3 chocoscan.py -x scan.xml --wordlist /tmp/target_wl.txt
python3 chocoscan.py -x scan.xml --wordlist --custom-words john sarah "IT-Admin"
```

---

### `cipher_decoder.py` — Cipher & Encoding Decoder
Identifie et décode automatiquement les encodages et chiffrements courants en CTF.

**Détecte :** Base64, Base32, Hex, Octal, Binaire, URL-encode, HTML entities,
ROT13, ROT47, Caesar (brute force 25 rotations), Morse, JWT (header/payload
+ attaques alg:none, hashcat -m 16500), classification de hashes (MD5/NTLM/
SHA1/SHA256/SHA512/bcrypt/AS-REP/Kerberoast/Net-NTLMv2), clés RSA PEM.
Génère les liens CyberChef correspondants.

```bash
python3 chocoscan.py -x scan.xml --cipher 'aGVsbG8gd29ybGQ='
python3 chocoscan.py -x scan.xml --cipher '.- .-.. .-.. --- '
```

---

## Modules offensifs — SMB & Active Directory

### `smb_helper.py` — SMB Helper + Impacket
Génère les commandes d'énumération SMB complètes et la suite impacket
adaptées au contexte (signing, DC détecté, domaine).

**Couvre :**
- Null session (smbclient, smbmap, enum4linux-ng, nmap scripts)
- Énumération auth (CrackMapExec, rpcclient, smbget, mount.cifs)
- Impacket (secretsdump avec `-just-dc`, wmiexec, psexec, smbexec, atexec)
- NTLM Relay (Responder + ntlmrelayx, vérification signing)
- Pass-the-Hash (CMA, impacket, evil-winrm, overpass-the-hash)
- Kerberos si DC détecté (AS-REP roasting, Kerberoasting, Pass-the-Ticket)

```bash
python3 chocoscan.py -x scan.xml --smb
```

---

### `ad_enum.py` — Active Directory Enumeration
Énumération complète d'un environnement AD : LDAP, utilisateurs,
groupes, Kerberoasting, AS-REP roasting, BloodHound, DCSync,
Zerologon/NoPac/PrintNightmare.

```bash
python3 chocoscan.py -x scan.xml --ad-enum
python3 chocoscan.py -x scan.xml --ad-auto   # exécution automatique des commandes
```

---

### `bloodhound_integration.py` — BloodHound CE
Analyse un fichier de données BloodHound (`.zip` ou `.json`) et affiche
les chemins d'attaque vers le DA, les comptes AS-REP/Kerberoastables,
les ACL dangereuses, les machines avec délégation non contrainte.

```bash
python3 chocoscan.py -x scan.xml --bloodhound bloodhound_data.zip
```

---

### `lateral_movement.py` — Lateral Movement
Techniques de mouvement latéral post-compromise. Complémentaire à
`smb_helper.py` et `ad_enum.py` — ne duplique aucune commande.

**Couvre :**
- **DCOM** — impacket-dcomexec (MMC20.Application, ShellWindows, ShellBrowserWindow)
- **WMI** — wmic.exe, Invoke-WmiMethod, CIM sessions, WMI Event Subscription (persistance)
- **MSSQL Linked Servers** — sp_linkedservers, EXEC AT, xp_cmdshell chaîné, PowerUpSQL
- **LAPS** — dump via CrackMapExec, bloodyAD, ldapsearch
- **Délégation Kerberos** — Unconstrained (Rubeus + PrinterBug), Constrained S4U2Proxy, RBCD
- **Coercition** — PrinterBug, PetitPotam (sans creds), DFSCoerce, Coercer
- **AD CS (certipy)** — ESC1 (SAN arbitraire), ESC4 (template ACL), ESC8 (relay vers CA)
- **Shadow Credentials** — certipy shadow auto, pyWhisker
- **RDP Hijacking** — tscon depuis SYSTEM, sticky keys backdoor

```bash
python3 chocoscan.py -x scan.xml --lateral
```

---

## Modules offensifs — Privilege Escalation

### `privesc_checker.py` — Privesc Checklist
Checklist de privilege escalation Linux et Windows adaptée à l'OS détecté.
Commandes de vérification + exploitation pour chaque vecteur.

**Linux :** SUID/GUID, sudo -l, cron jobs, capabilities, PATH hijacking,
NFS no_root_squash, writable /etc/passwd, kernel exploits.

**Windows :** AlwaysInstallElevated, services non cités, DLL hijacking,
unquoted service paths, registry autoruns, token privileges.

```bash
python3 chocoscan.py -x scan.xml --privesc
```

---

### `token_helper.py` — Windows Token Privilege Helper
Guide d'exploitation des privilèges Windows dangereux avec commandes
exactes et outils recommandés. Peut parser la sortie de `whoami /priv`
pour filtrer les checks pertinents.

**Couvre :** SeImpersonatePrivilege (GodPotato, PrintSpoofer, RoguePotato,
JuicyPotato, SweetPotato), SeDebugPrivilege (LSASS dump via comsvcs.dll,
procdump, pypykatz), SeTakeOwnershipPrivilege, SeBackupPrivilege
(SAM/SYSTEM/NTDS.dit), SeRestorePrivilege, SeLoadDriverPrivilege (BYOVD),
AlwaysInstallElevated, Incognito.

```bash
python3 chocoscan.py -x scan.xml --tokens
python3 chocoscan.py -x scan.xml --tokens 'SeImpersonatePrivilege   Enabled'
```

---

### `gtfobins.py` — GTFOBins
Cherche les binaires SUID, sudo et capabilities exploitables dans la base
GTFOBins. Génère la commande d'exploitation exacte pour chaque binaire.

```bash
python3 chocoscan.py -x scan.xml --gtfobins
```

---

### `misconfig_detector.py` — Misconfiguration Detector
Détecte les misconfigurations courantes : SUID suspects, capabilities
dangereuses, services mal configurés, fichiers sensibles writables.

```bash
python3 chocoscan.py -x scan.xml --misconfig
```

---

## Modules offensifs — Container & Cloud

### `container_escape.py` — Container Escape
Checklist de détection et d'évasion de conteneurs.
Deux modes : analyse externe du scan (Docker API 2375, K8s 6443, Kubelet 10250)
et checklist interne à exécuter depuis un shell dans le conteneur.

**Couvre :** Détection (.dockerenv, cgroups, env vars), capabilities dangereuses
(CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, CAP_SYS_MODULE,
`--privileged`), Docker socket (curl API REST), montages sensibles, cgroups v1
release_agent, Kubernetes (serviceaccount token, RBAC, pod privilégié, SSRF API),
CVEs connues (CVE-2019-5736 runc, CVE-2020-15257 containerd).

```bash
python3 chocoscan.py -x scan.xml --container
python3 chocoscan.py -x scan.xml --container quick  # vérifications rapides (easy)
```

---

### `cloud_enum.py` — Cloud Enumeration
Énumération des misconfigurations cloud depuis le scan ou un contexte SSRF.
Détecte automatiquement AWS/Azure/GCP depuis les banners et signatures IP.

**AWS :** S3 buckets (s3scanner, lazys3, awscli), IAM enum (Pacu, enumerate-iam,
privilege escalation paths), EC2 metadata IMDSv1/IMDSv2, Secrets Manager,
SSM Parameter Store, truffleHog (secrets dans repos/images Docker).

**Azure :** Blob Storage (BlobHunter, cloud_enum), Azure AD (o365spray,
AADInternals, MFASweep), Managed Identity metadata service, Key Vault.

**GCP :** GCS buckets (GCPBucketBrute, gsutil), Compute metadata service
(header `Metadata-Flavor: Google`), service account impersonation.

**Multi-cloud :** cloud_enum, ScoutSuite, Prowler, truffleHog.

```bash
python3 chocoscan.py -x scan.xml --cloud
```

---

## Modules utilitaires

### `loot_collector.py` — Loot Collector
Se connecte en SSH et collecte automatiquement les fichiers sensibles :
clés SSH, fichiers de config, historiques shell, hashes `/etc/shadow`,
certificats, credentials dans les fichiers de configuration web.

```bash
python3 chocoscan.py -x scan.xml --loot --ssh-user root --ssh-key ./id_rsa
```

---

### `msf_mapper.py` — Metasploit Mapper
Associe chaque CVE à son module Metasploit correspondant et génère
les commandes `msfconsole` prêtes à l'emploi.

```bash
python3 chocoscan.py -x scan.xml --msf
python3 chocoscan.py -x scan.xml --msf-script  # générer un script RC
```

---

### `kill_chain.py` — Kill Chain Visualizer
Modélise les chemins d'attaque MITRE ATT&CK depuis les services et CVE détectés.
Affiche les tactiques enchaînées : Initial Access → Execution → Persistence →
Privilege Escalation → Lateral Movement → Exfiltration.

```bash
python3 chocoscan.py -x scan.xml --kill-chain
```

---

## Reporting & Interface

### `report_generator.py` — Report Generator
Génère des rapports HTML interactifs et JSON structurés depuis les résultats
de l'analyse. Le rapport HTML inclut les CVE, scores, tags, chaînes d'attaque
et les résultats des modules offensifs.

```bash
python3 chocoscan.py -x scan.xml --export-html --output-dir ./reports
python3 chocoscan.py -x scan.xml --export-json
```

---

### `interactive.py` — Mode interactif (TUI)
Interface curses style fzf avec 5 vues :
- **Ports** — liste des services avec sévérité max et nombre de CVE
- **CVEs** — liste des CVE d'un service avec filtres, tri, marquage
- **Détail** — description complète, CVSS, références, exploit info
- **Modules** — modules recommandés selon les services détectés (`M`)
- **Résultat** — sortie scrollable d'un module exécuté

| Touche | Action |
|---|---|
| `↑↓` / `j k` | Naviguer |
| `Entrée` | Ouvrir / Exécuter |
| `M` | Vue modules recommandés |
| `E` / `N` / `?` | Marquer un CVE (Exploité / Non applicable / Incertain) |
| `/` | Filtrer par mot-clé |
| `S` | Trier (CVSS / Sévérité / ID) |
| `X` | Exporter les CVEs marquées en JSON |
| `Q` / `Esc` | Remonter d'un niveau |

```bash
python3 chocoscan.py -x scan.xml --interactive --lhost 10.10.14.5
```

---

### Interface web (FastAPI + React)
Dashboard web complet avec visualisation des CVE, filtres interactifs,
tri par score, export des rapports. Accessible sur `http://localhost:8000`.

```bash
python3 chocoscan.py -x scan.xml --web
```

---

## Base de données CVE

| Script | Fonction |
|---|---|
| `update_db.py` | Mise à jour complète (NVD + CISA KEV + exploits) |
| `update_db_critical.py` | CVE critiques uniquement (plus rapide) |
| `update_exploits.py` | Références exploit (ExploitDB, Metasploit) |
| `update_db_ctf.py` | Machines HTB/THM liées à chaque CVE |
| `update_db_tags.py` | Tags sémantiques (rce, auth-bypass, kev-listed…) |
| `update_db_cpe.py` | Résolution CPE pour le matching de versions |

---

## Résumé des flags CLI

```
Entrée
  -x / --xml FILE          Fichier Nmap XML (ou Masscan/Nessus)
  --scan TARGET            Scanner directement avec nmap intégré
  --ssh-scan TARGET        Scan SSH authentifié
  --diff AVANT APRES       Comparer deux scans

Filtrage
  --min-cvss FLOAT         CVSS minimum (défaut: 0.0)
  --severity LEVELS        CRITICAL,HIGH,MEDIUM,LOW
  --after-year AAAA        CVE publiés après cette année
  --top-cves N             Nombre de CVE par service (défaut: 5)

Modules offensifs — Web
  --web-payloads [SVC]     Payloads LFI/SSTI/SQLi/SSRF/XXE/XSS
  --enum-web               Énumération web (fuzzing, technos)
  --vhost [DOMAIN]         Virtual host discovery

Modules offensifs — Réseau
  --revshell [SVC]         Reverse shells adaptés
  --all-shells             Tous les shells disponibles
  --pivot [LHOST]          Guide pivoting (Ligolo/Chisel/SSH)
  --upgrade-shell          Upgrade shell basique → TTY
  --lhost IP               IP attaquant (pour les shells/callbacks)
  --lport PORT             Port d'écoute (défaut: 4444)

Modules offensifs — Credentials
  --brute                  Commandes brute force par service
  --default-creds          Credentials par défaut
  --hashcrack [HASH]       Hash cracker (hashcat/john)
  --wordlist [FILE]        Wordlist ciblée depuis le scan
  --custom-words W1 W2     Mots supplémentaires pour la wordlist
  --cipher TEXT            Identifier/décoder un encodage

Modules offensifs — SMB & AD
  --smb                    Énumération SMB + Impacket
  --ad-enum                Énumération Active Directory
  --ad-auto                Exécuter automatiquement les commandes AD
  --bloodhound FILE        Analyser des données BloodHound
  --lateral                Mouvement latéral post-compromise
  --tokens [PRIVS]         Token privileges Windows

Modules offensifs — Privesc
  --privesc                Checklist privilege escalation
  --gtfobins               GTFOBins (SUID/sudo/caps)
  --misconfig              Détection de misconfigurations

Modules offensifs — Container & Cloud
  --container [MODE]       Container escape (all | quick)
  --cloud                  Énumération AWS/Azure/GCP

Modules utilitaires
  --loot                   Collecte de fichiers sensibles (SSH)
  --msf                    Modules Metasploit associés
  --msf-script             Générer un script RC Metasploit
  --kill-chain             Kill chain MITRE ATT&CK

Export & Reporting
  --export-html            Générer un rapport HTML
  --export-json            Générer un rapport JSON
  --output-dir DIR         Dossier de sortie (défaut: output/)

Interface
  --interactive / -i       Mode TUI interactif
  --web                    Interface web FastAPI + React

Configuration
  config init              Créer ~/.chocoscan.conf
  config show              Afficher la configuration active
  --no-api                 Désactiver le fallback NVD
  --no-scoring             Désactiver le scoring contextuel
  --no-ad                  Désactiver la détection AD
  --no-chains              Désactiver l'analyse kill chain
  --ignore-file FILE       Fichier .chocoscanignore personnalisé
  --no-ignore              Désactiver le fichier ignore
  --verbose / -v           Mode verbeux
```
