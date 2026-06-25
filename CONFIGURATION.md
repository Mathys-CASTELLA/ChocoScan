# Configuration — ChocoScan

ChocoScan lit automatiquement un fichier de configuration TOML pour éviter de
répéter les mêmes arguments à chaque commande. Ce fichier est facultatif —
ChocoScan fonctionne parfaitement sans lui.

---

## Priorité de résolution

Quand une option est définie à plusieurs endroits, la règle est :

```
1. Argument CLI explicite          --min-cvss 9.0
2. Variable d'environnement        CHOCOSCAN_MIN_CVSS=9.0
3. Fichier ~/.chocoscan.conf       min_cvss = 9.0
4. Valeur par défaut argparse
```

L'argument CLI a toujours la priorité absolue.

---

## Emplacements du fichier de config

ChocoScan cherche le fichier dans cet ordre :

| Priorité | Chemin |
|---|---|
| 1 | Variable `$CHOCOSCAN_CONFIG` (chemin personnalisé) |
| 2 | `~/.chocoscan.conf` |
| 3 | `~/.config/chocoscan/config.toml` |
| 4 | `./.chocoscan.conf` (répertoire courant) |

```bash
# Forcer un chemin spécifique
export CHOCOSCAN_CONFIG=/opt/chocoscan/mon_profil.toml
python3 chocoscan.py -x scan.xml

# Initialiser le fichier dans ~/.chocoscan.conf
python3 chocoscan.py config init

# Afficher la configuration active (sources + valeurs)
python3 chocoscan.py config show

# Réinitialiser
python3 chocoscan.py config init --force
```

---

## Référence de toutes les clés

### Section racine (options globales)

| Clé TOML | CLI équivalent | Type | Défaut | Description |
|---|---|---|---|---|
| `min_cvss` | `--min-cvss` | float | `0.0` | CVSS minimum pour afficher un CVE |
| `severity` | `--severity` | string | `""` | Filtre de sévérité (`CRITICAL,HIGH,MEDIUM,LOW`) |
| `after_year` | `--after-year` | int | `null` | N'afficher que les CVE publiés après cette année |
| `top_cves` | `--top-cves` | int | `5` | Nombre de CVE affichés par service |
| `exploits` | `--exploits` | bool | `false` | Afficher les informations d'exploitation |
| `no_api` | `--no-api` | bool | `false` | Désactiver le fallback vers l'API NVD |
| `no_scoring` | `--no-scoring` | bool | `false` | Désactiver le scoring contextuel |
| `no_ad` | `--no-ad` | bool | `false` | Désactiver la détection AD automatique |
| `no_chains` | `--no-chains` | bool | `false` | Désactiver l'analyse kill chain |
| `interactive` | `--interactive` / `-i` | bool | `false` | Lancer le mode interactif par défaut |
| `export_html` | `--export-html` | bool | `false` | Générer un rapport HTML automatiquement |
| `export_json` | `--export-json` | bool | `false` | Générer un rapport JSON automatiquement |
| `output_dir` | `--output-dir` | string | `"output"` | Dossier de sortie des rapports |
| `input_format` | `--input-format` | string | `"auto"` | Format d'entrée (`auto`, `nmap`, `masscan`, `nessus`) |

### Section `[scan]`

Options liées au scan Nmap intégré (`--scan`).

| Clé TOML | CLI équivalent | Type | Défaut | Description |
|---|---|---|---|---|
| `nmap_args` | `--nmap-args` | string | `""` | Arguments supplémentaires passés à nmap |

### Section `[web]`

Options liées à l'énumération web (`--enum-web`).

| Clé TOML | CLI équivalent | Type | Défaut | Description |
|---|---|---|---|---|
| `enum_web` | `--enum-web` | bool | `false` | Activer l'énumération web automatiquement |
| `enum_threads` | `--enum-threads` | int | `10` | Nombre de threads pour le fuzzing |
| `enum_delay` | `--enum-delay` | float | `0.05` | Délai entre les requêtes (en secondes) |

---

## Nommage des clés

Les clés suivent une convention cohérente :

| Format | Exemple |
|---|---|
| **Fichier TOML** | `min_cvss`, `export_html`, `top_cves` (underscore) |
| **Argument CLI** | `--min-cvss`, `--export-html`, `--top-cves` (tiret) |
| **Variable d'env** | `CHOCOSCAN_MIN_CVSS`, `CHOCOSCAN_EXPORT_HTML` (préfixe + majuscules) |

---

## Exemples de profils

### Profil CTF (HackTheBox / Root-Me)

Optimisé pour une utilisation rapide en CTF, avec les modules offensifs
et les exports activés par défaut.

```toml
# ~/.chocoscan.conf — Profil CTF
min_cvss     = 6.0
top_cves     = 10
exploits     = true
export_html  = false
output_dir   = "~/ctf/reports"
severity     = "CRITICAL,HIGH"
after_year   = 2018

[scan]
nmap_args = "-T4 --open -sV -sC"

[web]
enum_web     = false
enum_threads = 20
enum_delay   = 0.05
```

Usage avec ce profil :

```bash
# Le profil applique déjà --severity CRITICAL,HIGH --exploits top_cves=10
python3 chocoscan.py -x scan.xml --web-payloads --smb --lhost 10.10.14.5
```

---

### Profil OSCP / Exam

Optimisé pour l'examen OSCP : génération automatique de rapports,
filtre sévérité élevé, sans API externe.

```toml
# ~/.chocoscan.conf — Profil OSCP
min_cvss     = 7.0
top_cves     = 5
exploits     = true
export_html  = true
export_json  = true
output_dir   = "~/oscp_exam/reports"
severity     = "CRITICAL,HIGH"
after_year   = 2015
no_api       = true   # Pas d'accès internet pendant l'exam

[scan]
nmap_args = "-T4 --open -sV -sC -p-"

[web]
enum_web     = false
enum_threads = 10
```

---

### Profil minimal (silencieux)

Aucun rapport automatique, seulement les CVE critiques, pas d'AD ni de kill chain.

```toml
# ~/.chocoscan.conf — Profil minimal
min_cvss   = 9.0
top_cves   = 3
severity   = "CRITICAL"
no_ad      = true
no_chains  = true
no_scoring = true

[scan]
nmap_args  = "-T3 --open"
```

---

### Profil verbose (analyse approfondie)

Tous les CVE, toutes les fonctionnalités, export systématique.

```toml
# ~/.chocoscan.conf — Profil verbose
min_cvss     = 0.0
top_cves     = 20
exploits     = true
export_html  = true
export_json  = true
output_dir   = "~/pentest/reports"
severity     = ""

[scan]
nmap_args = "-T4 --open -sV -sC -A"

[web]
enum_web     = true
enum_threads = 30
enum_delay   = 0.1
```

---

## Variables d'environnement

Toutes les clés du fichier de config peuvent aussi être définies via des
variables d'environnement. Utile pour les scripts ou les pipelines CI.

```bash
# Équivalents en variables d'environnement
export CHOCOSCAN_MIN_CVSS=7.0
export CHOCOSCAN_SEVERITY="CRITICAL,HIGH"
export CHOCOSCAN_EXPLOITS=true
export CHOCOSCAN_EXPORT_HTML=true
export CHOCOSCAN_OUTPUT_DIR="/tmp/reports"
export CHOCOSCAN_TOP_CVES=10
export CHOCOSCAN_NO_API=false

# Chemin de config personnalisé
export CHOCOSCAN_CONFIG="/opt/configs/oscp_profile.toml"
```

---

## Gérer plusieurs profils

Une approche pratique pour alterner entre CTF, OSCP et usage quotidien :

```bash
# Stocker les profils dans ~/.config/chocoscan/
mkdir -p ~/.config/chocoscan
cp profil_ctf.toml    ~/.config/chocoscan/ctf.toml
cp profil_oscp.toml   ~/.config/chocoscan/oscp.toml
cp profil_minimal.toml ~/.config/chocoscan/minimal.toml

# Activer un profil pour la session courante
export CHOCOSCAN_CONFIG=~/.config/chocoscan/ctf.toml

# Ou créer des alias bash
alias choco-ctf='CHOCOSCAN_CONFIG=~/.config/chocoscan/ctf.toml python3 ~/tools/chocoscan/chocoscan.py'
alias choco-oscp='CHOCOSCAN_CONFIG=~/.config/chocoscan/oscp.toml python3 ~/tools/chocoscan/chocoscan.py'
```

---

## Notes

- Le fichier de config est facultatif. Sans lui, ChocoScan fonctionne avec les valeurs par défaut d'argparse.
- Les commentaires sont supportés dans le fichier TOML (ligne commençant par `#`).
- Les valeurs booléennes s'écrivent `true` / `false` (TOML standard).
- Les chemins peuvent contenir `~` (expansion automatique par ChocoScan).
- Une clé inconnue dans le fichier de config génère un avertissement mais n'empêche pas l'exécution.
