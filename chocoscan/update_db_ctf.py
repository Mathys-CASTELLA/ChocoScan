#!/usr/bin/env python3
"""
ChocoScan — Enrichissement CVE orienté CTF / Pentest
=====================================================

Injecte dans cve_db.json une sélection curated de CVEs classiques
rencontrées sur HackTheBox, TryHackMe et CTF en général.

Chaque entrée inclut :
  - id, cvss, severity, affected_versions
  - description / description_fr
  - exploit_available, exploit_db (ID ExploitDB), metasploit (module)
  - ctf_machines : machines HTB/THM connues pour cette vulnérabilité
  - references

Usage :
    python update_db_ctf.py                  # Injecte tout
    python update_db_ctf.py --dry-run        # Aperçu sans modifier la DB
    python update_db_ctf.py --service tomcat # Seulement un service
    python update_db_ctf.py --stats          # Stats avant/après
    python update_db_ctf.py --list-services  # Liste les services couverts
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import track
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

DATA_DIR    = Path(__file__).parent / "data"
CVE_DB_PATH = DATA_DIR / "cve_db.json"

# =============================================================================
# BASE CURATED CTF/PENTEST
# =============================================================================
# Format identique à cve_db.json :
# {
#   "id": str,
#   "cvss": float,
#   "severity": str,                    # CRITICAL / HIGH / MEDIUM / LOW
#   "affected_versions": list[str],     # contraintes compatibles version_checker
#   "description": str,
#   "description_fr": str,
#   "exploit_available": bool,
#   "exploit_db": int | None,           # ID sur exploit-db.com
#   "metasploit": str | None,           # chemin du module MSF
#   "ctf_machines": list[str],          # machines HTB/THM connues
#   "references": list[str],
# }

CTF_CVE_DATABASE: dict[str, list[dict]] = {

    # ─── OpenSSH ─────────────────────────────────────────────────────────────
    "openssh": [
        {
            "id": "CVE-2023-38408",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 9.3p2"],
            "description": "Remote code execution via PKCS#11 in ssh-agent when forwarded to an attacker-controlled system.",
            "description_fr": "Exécution de code à distance via PKCS#11 dans ssh-agent lorsqu'il est transféré vers un système contrôlé par l'attaquant.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
                "https://github.com/LucasPDiniz/CVE-2023-38408",
            ],
        },
        {
            "id": "CVE-2024-6387",
            "cvss": 8.1,
            "severity": "HIGH",
            "affected_versions": ["< 9.8p1"],
            "description": "regreSSHion: race condition in sshd signal handler allows unauthenticated RCE as root on glibc-based Linux.",
            "description_fr": "regreSSHion : race condition dans le gestionnaire de signaux de sshd permettant un RCE non authentifié en root sur Linux (glibc).",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
                "https://github.com/zgzhang/cve-2024-6387-poc",
            ],
        },
        {
            "id": "CVE-2016-6210",
            "cvss": 5.3,
            "severity": "MEDIUM",
            "affected_versions": ["< 7.3"],
            "description": "OpenSSH user enumeration via timing attack on BLOWFISH password hashing.",
            "description_fr": "Énumération d'utilisateurs via une attaque temporelle sur le hachage BLOWFISH.",
            "exploit_available": True,
            "exploit_db": 40136,
            "metasploit": "auxiliary/scanner/ssh/ssh_enumusers",
            "ctf_machines": ["Stratosphere (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2016-6210",
                "https://www.exploit-db.com/exploits/40136",
            ],
        },
        {
            "id": "CVE-2018-15473",
            "cvss": 5.3,
            "severity": "MEDIUM",
            "affected_versions": ["< 7.8"],
            "description": "OpenSSH user enumeration via malformed packet — server responds differently for valid vs invalid usernames.",
            "description_fr": "Énumération d'utilisateurs via paquet malformé — le serveur répond différemment selon que l'utilisateur existe ou non.",
            "exploit_available": True,
            "exploit_db": 45233,
            "metasploit": "auxiliary/scanner/ssh/ssh_enumusers",
            "ctf_machines": ["Nineveh (HTB)", "Valentine (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
                "https://www.exploit-db.com/exploits/45233",
            ],
        },
    ],

    # ─── Apache HTTP Server ───────────────────────────────────────────────────
    "apache": [
        {
            "id": "CVE-2021-41773",
            "cvss": 7.5,
            "severity": "HIGH",
            "affected_versions": ["= 2.4.49"],
            "description": "Path traversal and RCE in Apache 2.4.49 via URL-encoded dot-dot segments if mod_cgi is enabled.",
            "description_fr": "Traversée de chemin et RCE dans Apache 2.4.49 via des segments dot-dot encodés en URL si mod_cgi est activé.",
            "exploit_available": True,
            "exploit_db": 50383,
            "metasploit": "exploit/multi/http/apache_normalize_path_rce",
            "ctf_machines": ["Forgotten (HTB)", "Acme (THM)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                "https://www.exploit-db.com/exploits/50383",
            ],
        },
        {
            "id": "CVE-2021-42013",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["= 2.4.49", "= 2.4.50"],
            "description": "Bypass of CVE-2021-41773 fix in Apache 2.4.50 allows path traversal and RCE.",
            "description_fr": "Contournement du correctif CVE-2021-41773 dans Apache 2.4.50 permettant traversée de chemin et RCE.",
            "exploit_available": True,
            "exploit_db": 50406,
            "metasploit": "exploit/multi/http/apache_normalize_path_rce",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
                "https://www.exploit-db.com/exploits/50406",
            ],
        },
        {
            "id": "CVE-2014-6271",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["< 4.3"],
            "description": "Shellshock: bash processes trailing strings after function definitions in environment variables, enabling RCE via CGI.",
            "description_fr": "Shellshock : bash traite les chaînes après les définitions de fonctions dans les variables d'environnement, permettant RCE via CGI.",
            "exploit_available": True,
            "exploit_db": 34766,
            "metasploit": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
            "ctf_machines": ["Shocker (HTB)", "Beep (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
                "https://www.exploit-db.com/exploits/34766",
            ],
        },
        {
            "id": "CVE-2017-7679",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 2.2.33", "< 2.4.26"],
            "description": "mod_mime buffer overread can reflect an extra byte past the end of a request body.",
            "description_fr": "Dépassement de tampon dans mod_mime pouvant exposer un octet supplémentaire au-delà du corps de la requête.",
            "exploit_available": False,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7679"],
        },
    ],

    # ─── Apache Tomcat ────────────────────────────────────────────────────────
    "tomcat": [
        {
            "id": "CVE-2017-12617",
            "cvss": 8.1,
            "severity": "HIGH",
            "affected_versions": ["< 9.0.1", "< 8.5.23", "< 8.0.47", "< 7.0.82"],
            "description": "JSP upload via HTTP PUT when enabled, leading to RCE.",
            "description_fr": "Upload de JSP via HTTP PUT lorsqu'activé, menant à un RCE.",
            "exploit_available": True,
            "exploit_db": 43008,
            "metasploit": "exploit/multi/http/tomcat_jsp_upload_bypass",
            "ctf_machines": ["Jerry (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2017-12617",
                "https://www.exploit-db.com/exploits/43008",
            ],
        },
        {
            "id": "CVE-2020-1938",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 9.0.31", "< 8.5.51", "< 7.0.100"],
            "description": "Ghostcat: AJP connector allows arbitrary file read and inclusion from the web app, enabling RCE with file upload.",
            "description_fr": "Ghostcat : le connecteur AJP permet la lecture et l'inclusion arbitraire de fichiers depuis l'application web, menant à un RCE si l'upload de fichiers est possible.",
            "exploit_available": True,
            "exploit_db": 48143,
            "metasploit": "auxiliary/admin/http/tomcat_ghostcat",
            "ctf_machines": ["Tabby (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2020-1938",
                "https://www.exploit-db.com/exploits/48143",
                "https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi",
            ],
        },
        {
            "id": "CVE-2019-0232",
            "cvss": 8.1,
            "severity": "HIGH",
            "affected_versions": ["< 9.0.18", "< 8.5.39", "< 7.0.93"],
            "description": "RCE via CGI Servlet on Windows due to improper neutralization of special elements.",
            "description_fr": "RCE via CGI Servlet sur Windows en raison d'une mauvaise neutralisation des éléments spéciaux.",
            "exploit_available": True,
            "exploit_db": 47073,
            "metasploit": "exploit/windows/http/tomcat_cgi_cmdlineargs",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-0232",
                "https://www.exploit-db.com/exploits/47073",
            ],
        },
        {
            "id": "CVE-2016-4438",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 2.3.29"],
            "description": "Apache Struts REST plugin with XStream handler allows arbitrary code execution via crafted XML request.",
            "description_fr": "Le plugin REST d'Apache Struts avec le handler XStream permet l'exécution de code arbitraire via une requête XML forgée.",
            "exploit_available": True,
            "exploit_db": 41570,
            "metasploit": "exploit/multi/http/struts_dmi_rest_exec",
            "ctf_machines": [],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2016-4438"],
        },
    ],

    # ─── Apache Struts ────────────────────────────────────────────────────────
    "struts": [
        {
            "id": "CVE-2017-5638",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": [">= 2.3.5", "< 2.3.32"],
            "description": "RCE via Content-Type header in the Jakarta Multipart parser — the Equifax breach vector.",
            "description_fr": "RCE via l'en-tête Content-Type dans le parser Jakarta Multipart — vecteur de la fuite Equifax.",
            "exploit_available": True,
            "exploit_db": 41570,
            "metasploit": "exploit/multi/http/struts2_content_type_ognl",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
                "https://www.exploit-db.com/exploits/41570",
            ],
        },
        {
            "id": "CVE-2018-11776",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 2.3.35", "< 2.5.17"],
            "description": "RCE via namespace value without leading slash and actionChaining or redirect result.",
            "description_fr": "RCE via une valeur namespace sans slash initial combinée à actionChaining ou redirect.",
            "exploit_available": True,
            "exploit_db": 45260,
            "metasploit": "exploit/multi/http/struts2_namespace_ognl",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2018-11776",
                "https://www.exploit-db.com/exploits/45260",
            ],
        },
    ],

    # ─── Log4j ────────────────────────────────────────────────────────────────
    "log4j": [
        {
            "id": "CVE-2021-44228",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": [">= 2.0-beta9", "< 2.15.0"],
            "description": "Log4Shell: JNDI injection via user-controlled log data allows unauthenticated RCE.",
            "description_fr": "Log4Shell : injection JNDI via des données de log contrôlées par l'utilisateur permettant un RCE non authentifié.",
            "exploit_available": True,
            "exploit_db": 50592,
            "metasploit": None,
            "ctf_machines": ["LogForge (HTB)", "Solar (THM)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://github.com/fullhunt/log4j-scan",
                "https://www.exploit-db.com/exploits/50592",
            ],
        },
        {
            "id": "CVE-2021-45046",
            "cvss": 9.0,
            "severity": "CRITICAL",
            "affected_versions": [">= 2.0-beta9", "< 2.16.0"],
            "description": "Bypass of CVE-2021-44228 fix: RCE via Thread Context Map patterns and non-default configs.",
            "description_fr": "Contournement du correctif CVE-2021-44228 : RCE via les patterns Thread Context Map.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-45046"],
        },
    ],

    # ─── SMB / Windows ────────────────────────────────────────────────────────
    "smb": [
        {
            "id": "CVE-2017-0144",
            "cvss": 9.3,
            "severity": "CRITICAL",
            "affected_versions": ["< Windows 10 1703"],
            "description": "EternalBlue: SMBv1 buffer overflow allows unauthenticated RCE as SYSTEM — used by WannaCry and NotPetya.",
            "description_fr": "EternalBlue : dépassement de tampon dans SMBv1 permettant RCE non authentifié en SYSTEM — utilisé par WannaCry et NotPetya.",
            "exploit_available": True,
            "exploit_db": 42315,
            "metasploit": "exploit/windows/smb/ms17_010_eternalblue",
            "ctf_machines": ["Blue (HTB)", "Legacy (HTB)", "Eternal (THM)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                "https://www.exploit-db.com/exploits/42315",
            ],
        },
        {
            "id": "CVE-2008-4250",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["= Windows XP SP2", "= Windows XP SP3", "= Windows 2003"],
            "description": "MS08-067: NetAPI32 buffer overflow in Server service allows unauthenticated RCE.",
            "description_fr": "MS08-067 : dépassement de tampon dans NetAPI32 (service Server) permettant RCE non authentifié.",
            "exploit_available": True,
            "exploit_db": 6824,
            "metasploit": "exploit/windows/smb/ms08_067_netapi",
            "ctf_machines": ["Legacy (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2008-4250",
                "https://www.exploit-db.com/exploits/6824",
            ],
        },
        {
            "id": "CVE-2020-0796",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["= Windows 10 1903", "= Windows 10 1909"],
            "description": "SMBGhost: integer overflow in SMBv3 compression allows unauthenticated RCE as SYSTEM.",
            "description_fr": "SMBGhost : dépassement d'entier dans la compression SMBv3 permettant RCE non authentifié en SYSTEM.",
            "exploit_available": True,
            "exploit_db": 48537,
            "metasploit": "exploit/windows/smb/smbghost_auth_bypass",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
                "https://www.exploit-db.com/exploits/48537",
            ],
        },
    ],

    # ─── Samba ────────────────────────────────────────────────────────────────
    "samba": [
        {
            "id": "CVE-2007-2447",
            "cvss": 6.0,
            "severity": "MEDIUM",
            "affected_versions": [">= 3.0.0", "< 3.0.25"],
            "description": "Command injection via MS-RPC SamrChangePassword or username field in Samba 3.0.x.",
            "description_fr": "Injection de commandes via MS-RPC SamrChangePassword ou le champ username dans Samba 3.0.x.",
            "exploit_available": True,
            "exploit_db": 16320,
            "metasploit": "exploit/multi/samba/usermap_script",
            "ctf_machines": ["Lame (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2007-2447",
                "https://www.exploit-db.com/exploits/16320",
            ],
        },
        {
            "id": "CVE-2017-7494",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": [">= 3.5.0", "< 4.6.4"],
            "description": "SambaCry: RCE via shared library upload to a writable share and IPC$ trigger.",
            "description_fr": "SambaCry : RCE via upload d'une bibliothèque partagée dans un partage accessible en écriture et déclenchement via IPC$.",
            "exploit_available": True,
            "exploit_db": 42084,
            "metasploit": "exploit/linux/samba/is_known_pipename",
            "ctf_machines": ["SteelMountain (THM)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2017-7494",
                "https://www.exploit-db.com/exploits/42084",
            ],
        },
    ],

    # ─── FTP (vsftpd) ─────────────────────────────────────────────────────────
    "vsftpd": [
        {
            "id": "CVE-2011-2523",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["= 2.3.4"],
            "description": "Backdoor in vsftpd 2.3.4 — smiley face ':)' in username triggers a bind shell on port 6200.",
            "description_fr": "Backdoor dans vsftpd 2.3.4 — le smiley ':)' dans le nom d'utilisateur ouvre un shell sur le port 6200.",
            "exploit_available": True,
            "exploit_db": 17491,
            "metasploit": "exploit/unix/ftp/vsftpd_234_backdoor",
            "ctf_machines": ["Metasploitable2", "Devel (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
                "https://www.exploit-db.com/exploits/17491",
            ],
        },
    ],

    # ─── MySQL ────────────────────────────────────────────────────────────────
    "mysql": [
        {
            "id": "CVE-2012-2122",
            "cvss": 5.1,
            "severity": "MEDIUM",
            "affected_versions": ["< 5.1.63", "< 5.5.24", "< 5.6.6"],
            "description": "Authentication bypass by timing attack — repeated connection attempts with wrong password can grant access.",
            "description_fr": "Contournement d'authentification par attaque temporelle — des tentatives répétées avec un mauvais mot de passe peuvent accorder l'accès.",
            "exploit_available": True,
            "exploit_db": 19092,
            "metasploit": "auxiliary/scanner/mysql/mysql_authbypass_hashdump",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2012-2122",
                "https://www.exploit-db.com/exploits/19092",
            ],
        },
        {
            "id": "CVE-2016-6663",
            "cvss": 7.0,
            "severity": "HIGH",
            "affected_versions": ["< 5.5.52", "< 5.6.33", "< 5.7.15"],
            "description": "Race condition privilege escalation from mysql user to root via REPAIR TABLE.",
            "description_fr": "Escalade de privilèges par race condition de l'utilisateur mysql vers root via REPAIR TABLE.",
            "exploit_available": True,
            "exploit_db": 40360,
            "metasploit": None,
            "ctf_machines": ["Nineveh (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2016-6663",
                "https://www.exploit-db.com/exploits/40360",
            ],
        },
    ],

    # ─── Spring Framework ─────────────────────────────────────────────────────
    "spring": [
        {
            "id": "CVE-2022-22965",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": [">= 5.3.0", "< 5.3.18", ">= 5.2.0", "< 5.2.20"],
            "description": "Spring4Shell: RCE via data binding on JDK 9+ with Tomcat as WAR deployment.",
            "description_fr": "Spring4Shell : RCE via le data binding sur JDK 9+ avec Tomcat en déploiement WAR.",
            "exploit_available": True,
            "exploit_db": 50856,
            "metasploit": "exploit/multi/http/spring_framework_rce_spring4shell",
            "ctf_machines": ["Inject (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
                "https://www.exploit-db.com/exploits/50856",
            ],
        },
        {
            "id": "CVE-2022-22963",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": [">= 3.1.0", "< 3.2.3", ">= 3.0.0", "< 3.1.7"],
            "description": "RCE in Spring Cloud Function via routing expressions in the spring.cloud.function.routing-expression header.",
            "description_fr": "RCE dans Spring Cloud Function via les expressions de routage dans l'en-tête spring.cloud.function.routing-expression.",
            "exploit_available": True,
            "exploit_db": 50764,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-22963",
                "https://www.exploit-db.com/exploits/50764",
            ],
        },
    ],

    # ─── Jenkins ──────────────────────────────────────────────────────────────
    "jenkins": [
        {
            "id": "CVE-2018-1000861",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 2.138.4", "< 2.154"],
            "description": "Unauthenticated RCE via Stapler web framework's routing and Jenkins CLI.",
            "description_fr": "RCE non authentifié via le framework web Stapler et le CLI Jenkins.",
            "exploit_available": True,
            "exploit_db": 46572,
            "metasploit": "exploit/multi/http/jenkins_metaprogramming",
            "ctf_machines": ["Jeeves (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2018-1000861",
                "https://www.exploit-db.com/exploits/46572",
            ],
        },
        {
            "id": "CVE-2016-0792",
            "cvss": 9.0,
            "severity": "CRITICAL",
            "affected_versions": ["< 1.650", "< 1.642.2"],
            "description": "Unauthenticated RCE via Java deserialization in Jenkins CLI (ysoserial gadget chain).",
            "description_fr": "RCE non authentifié via désérialisation Java dans le CLI Jenkins (chaîne ysoserial).",
            "exploit_available": True,
            "exploit_db": 39320,
            "metasploit": "exploit/multi/http/jenkins_cli_deserialization",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2016-0792",
                "https://www.exploit-db.com/exploits/39320",
            ],
        },
        {
            "id": "CVE-2024-23897",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 2.442", "< 2.426.3"],
            "description": "Arbitrary file read through Jenkins CLI built-in command parser, leading to RCE via various attack paths.",
            "description_fr": "Lecture arbitraire de fichiers via le parser de commandes CLI Jenkins, menant à un RCE via différents vecteurs.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-23897",
                "https://github.com/godylockz/CVE-2024-23897",
            ],
        },
    ],

    # ─── GitLab ───────────────────────────────────────────────────────────────
    "gitlab": [
        {
            "id": "CVE-2021-22205",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["< 13.10.3"],
            "description": "Unauthenticated RCE via ExifTool image parsing in GitLab CE/EE.",
            "description_fr": "RCE non authentifié via le parsing d'images par ExifTool dans GitLab CE/EE.",
            "exploit_available": True,
            "exploit_db": 49951,
            "metasploit": None,
            "ctf_machines": ["GitLab (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-22205",
                "https://www.exploit-db.com/exploits/49951",
            ],
        },
        {
            "id": "CVE-2023-7028",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": [">= 16.1.0", "< 16.7.2"],
            "description": "Account takeover without user interaction via password reset sent to an attacker-controlled email.",
            "description_fr": "Prise de contrôle de compte sans interaction utilisateur via réinitialisation de mot de passe envoyée à un email contrôlé par l'attaquant.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-7028",
                "https://github.com/Vozec/CVE-2023-7028",
            ],
        },
    ],

    # ─── Nostromo (nhttpd) ────────────────────────────────────────────────────
    "nostromo": [
        {
            "id": "CVE-2019-16278",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["<= 1.9.6"],
            "description": "Directory traversal RCE in nostromo nhttpd via HTTP request with ..// sequence.",
            "description_fr": "RCE par traversée de répertoire dans nostromo nhttpd via une requête HTTP avec la séquence ../.",
            "exploit_available": True,
            "exploit_db": 47837,
            "metasploit": "exploit/multi/http/nostromo_code_exec",
            "ctf_machines": ["Traverxec (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-16278",
                "https://www.exploit-db.com/exploits/47837",
            ],
        },
    ],

    # ─── WebLogic ─────────────────────────────────────────────────────────────
    "weblogic": [
        {
            "id": "CVE-2019-2725",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["<= 10.3.6", "= 12.1.3"],
            "description": "Deserialization RCE via wls9_async_response application in Oracle WebLogic.",
            "description_fr": "RCE par désérialisation via l'application wls9_async_response dans Oracle WebLogic.",
            "exploit_available": True,
            "exploit_db": 46780,
            "metasploit": "exploit/multi/misc/weblogic_deserialize_asyncresponseservice",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-2725",
                "https://www.exploit-db.com/exploits/46780",
            ],
        },
        {
            "id": "CVE-2020-14882",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["<= 10.3.6", "<= 12.1.3", "<= 12.2.1.4"],
            "description": "Unauthenticated RCE via Console component in Oracle WebLogic — auth bypass + code exec.",
            "description_fr": "RCE non authentifié via le composant Console dans Oracle WebLogic — contournement d'auth + exécution de code.",
            "exploit_available": True,
            "exploit_db": 49504,
            "metasploit": "exploit/multi/http/oracle_weblogic_wls_wsat_deserialization",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2020-14882",
                "https://www.exploit-db.com/exploits/49504",
            ],
        },
    ],

    # ─── Redis ────────────────────────────────────────────────────────────────
    "redis": [
        {
            "id": "CVE-2022-0543",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["< 6.0.16", "< 6.2.6", "< 7.0.0"],
            "description": "Lua sandbox escape in Redis on Debian/Ubuntu packages allows RCE.",
            "description_fr": "Échappement du sandbox Lua dans Redis sur les paquets Debian/Ubuntu permettant un RCE.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": ["Rebound (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
                "https://github.com/aodsec/CVE-2022-0543",
            ],
        },
        {
            "id": "CVE-2015-4335",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["< 2.8.21", "< 3.0.2"],
            "description": "Redis eval sandbox escape allows arbitrary code execution via crafted Lua script.",
            "description_fr": "Échappement du sandbox eval de Redis permettant l'exécution de code arbitraire via un script Lua forgé.",
            "exploit_available": True,
            "exploit_db": 36880,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2015-4335",
                "https://www.exploit-db.com/exploits/36880",
            ],
        },
    ],

    # ─── Confluence ───────────────────────────────────────────────────────────
    "confluence": [
        {
            "id": "CVE-2022-26134",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": [">= 1.3.0", "< 7.4.17", "< 7.13.7", "< 7.14.3", "< 7.15.2", "< 7.16.4", "< 7.17.4", "< 7.18.1"],
            "description": "Unauthenticated OGNL injection RCE in Confluence Server and Data Center.",
            "description_fr": "Injection OGNL non authentifiée avec RCE dans Confluence Server et Data Center.",
            "exploit_available": True,
            "exploit_db": 50952,
            "metasploit": "exploit/multi/http/atlassian_confluence_namespace_ognl_injection",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-26134",
                "https://www.exploit-db.com/exploits/50952",
            ],
        },
        {
            "id": "CVE-2023-22527",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["< 8.5.4"],
            "description": "Template injection RCE in outdated Confluence Data Center and Server versions — no auth required.",
            "description_fr": "RCE par injection de template dans Confluence Data Center et Server — aucune authentification requise.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-22527",
                "https://github.com/cleverg0d/CVE-2023-22527",
            ],
        },
    ],

    # ─── Jira ─────────────────────────────────────────────────────────────────
    "jira": [
        {
            "id": "CVE-2019-11581",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 7.13.9", "< 8.3.2"],
            "description": "SSTI in Contact Administrators and Email Notifications forms allows unauthenticated RCE.",
            "description_fr": "SSTI dans les formulaires Contact Administrators et Email Notifications permettant un RCE non authentifié.",
            "exploit_available": True,
            "exploit_db": 47267,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-11581",
                "https://www.exploit-db.com/exploits/47267",
            ],
        },
    ],

    # ─── Webmin ───────────────────────────────────────────────────────────────
    "webmin": [
        {
            "id": "CVE-2019-15107",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["= 1.882", "= 1.890", "= 1.900", "= 1.910", "= 1.920"],
            "description": "Backdoor in Webmin 1.890 (and others) via password_change.cgi — unauthenticated RCE.",
            "description_fr": "Backdoor dans Webmin 1.890 (et autres) via password_change.cgi — RCE non authentifié.",
            "exploit_available": True,
            "exploit_db": 47230,
            "metasploit": "exploit/linux/http/webmin_backdoor",
            "ctf_machines": ["Postman (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-15107",
                "https://www.exploit-db.com/exploits/47230",
            ],
        },
        {
            "id": "CVE-2006-3392",
            "cvss": 7.5,
            "severity": "HIGH",
            "affected_versions": ["< 1.290"],
            "description": "Arbitrary file read via URL parameter — can expose /etc/shadow.",
            "description_fr": "Lecture arbitraire de fichiers via le paramètre URL — peut exposer /etc/shadow.",
            "exploit_available": True,
            "exploit_db": 2017,
            "metasploit": "auxiliary/admin/webmin/file_disclosure",
            "ctf_machines": ["Beep (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2006-3392",
                "https://www.exploit-db.com/exploits/2017",
            ],
        },
    ],

    # ─── PHP ──────────────────────────────────────────────────────────────────
    "php": [
        {
            "id": "CVE-2012-1823",
            "cvss": 7.5,
            "severity": "HIGH",
            "affected_versions": ["< 5.3.12", "< 5.4.2"],
            "description": "PHP CGI argument injection — query string parsed as command-line arguments allows RCE.",
            "description_fr": "Injection d'arguments PHP CGI — la query string est parsée comme arguments en ligne de commande, permettant RCE.",
            "exploit_available": True,
            "exploit_db": 18836,
            "metasploit": "exploit/multi/http/php_cgi_arg_injection",
            "ctf_machines": ["Nineveh (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2012-1823",
                "https://www.exploit-db.com/exploits/18836",
            ],
        },
        {
            "id": "CVE-2024-4577",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 8.1.29", "< 8.2.20", "< 8.3.8"],
            "description": "Argument injection in PHP on Windows with Apache mod_cgi — bypass of CVE-2012-1823 fix via Unicode best-fit mapping.",
            "description_fr": "Injection d'arguments dans PHP sur Windows avec Apache mod_cgi — contournement du correctif CVE-2012-1823 via le mapping best-fit Unicode.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
                "https://github.com/watchtowrlabs/CVE-2024-4577",
            ],
        },
    ],

    # ─── WordPress ────────────────────────────────────────────────────────────
    "wordpress": [
        {
            "id": "CVE-2019-8942",
            "cvss": 8.8,
            "severity": "HIGH",
            "affected_versions": ["< 5.0.1"],
            "description": "Authenticated RCE via path traversal in image metadata — requires Author role.",
            "description_fr": "RCE authentifié via traversée de chemin dans les métadonnées d'image — nécessite le rôle Auteur.",
            "exploit_available": True,
            "exploit_db": 46662,
            "metasploit": "exploit/multi/http/wp_crop_image_file_upload",
            "ctf_machines": ["Hackback (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-8942",
                "https://www.exploit-db.com/exploits/46662",
            ],
        },
    ],

    # ─── FreePBX / Asterisk ───────────────────────────────────────────────────
    "freepbx": [
        {
            "id": "CVE-2019-19006",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 13.0.188", "< 14.0.13", "< 15.0.16"],
            "description": "Admin authentication bypass in FreePBX — unauthenticated access to admin panel.",
            "description_fr": "Contournement de l'authentification admin dans FreePBX — accès non authentifié au panneau admin.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": ["Connected (HTB)"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-19006"],
        },
        {
            "id": "CVE-2021-4034",
            "cvss": 7.8,
            "severity": "HIGH",
            "affected_versions": ["< 0.121"],
            "description": "PwnKit: Local privilege escalation in pkexec (polkit) — any local user to root.",
            "description_fr": "PwnKit : élévation de privilèges locale dans pkexec (polkit) — n'importe quel utilisateur local vers root.",
            "exploit_available": True,
            "exploit_db": 50689,
            "metasploit": "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec",
            "ctf_machines": ["Connected (HTB)", "Previse (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-4034",
                "https://www.exploit-db.com/exploits/50689",
            ],
        },
    ],

    # ─── Drupal ───────────────────────────────────────────────────────────────
    "drupal": [
        {
            "id": "CVE-2018-7600",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 7.58", "< 8.3.9", "< 8.4.6", "< 8.5.1"],
            "description": "Drupalgeddon2: unauthenticated RCE via Form API AJAX requests.",
            "description_fr": "Drupalgeddon2 : RCE non authentifié via les requêtes AJAX de l'API Form.",
            "exploit_available": True,
            "exploit_db": 44449,
            "metasploit": "exploit/unix/webapp/drupal_drupalgeddon2",
            "ctf_machines": ["DC-1 (VulnHub)", "Networked (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2018-7600",
                "https://www.exploit-db.com/exploits/44449",
            ],
        },
        {
            "id": "CVE-2018-7602",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 7.59", "< 8.5.3"],
            "description": "Drupalgeddon3: authenticated RCE via AJAX API, bypassing CVE-2018-7600 fix.",
            "description_fr": "Drupalgeddon3 : RCE authentifié via l'API AJAX, contournant le correctif CVE-2018-7600.",
            "exploit_available": True,
            "exploit_db": 44557,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2018-7602",
                "https://www.exploit-db.com/exploits/44557",
            ],
        },
    ],

    # ─── Docker ───────────────────────────────────────────────────────────────
    "docker": [
        {
            "id": "CVE-2019-5736",
            "cvss": 8.6,
            "severity": "HIGH",
            "affected_versions": ["< 18.09.2"],
            "description": "runc container escape — overwrite host runc binary from inside a container.",
            "description_fr": "Évasion de conteneur runc — écrasement du binaire runc hôte depuis l'intérieur d'un conteneur.",
            "exploit_available": True,
            "exploit_db": 46359,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-5736",
                "https://www.exploit-db.com/exploits/46359",
            ],
        },
    ],

    # ─── Cacti ────────────────────────────────────────────────────────────────
    "cacti": [
        {
            "id": "CVE-2022-46169",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["<= 1.2.22"],
            "description": "Unauthenticated command injection in Cacti via X-Forwarded-For header and poller_id parameter.",
            "description_fr": "Injection de commandes non authentifiée dans Cacti via l'en-tête X-Forwarded-For et le paramètre poller_id.",
            "exploit_available": True,
            "exploit_db": 51166,
            "metasploit": None,
            "ctf_machines": ["MonitorsTwo (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-46169",
                "https://www.exploit-db.com/exploits/51166",
            ],
        },
    ],

    # ─── Grafana ──────────────────────────────────────────────────────────────
    "grafana": [
        {
            "id": "CVE-2021-43798",
            "cvss": 7.5,
            "severity": "HIGH",
            "affected_versions": [">= 8.0.0", "< 8.3.1"],
            "description": "Directory traversal allows unauthenticated arbitrary file read via /public/plugins/<plugin-id>/../.",
            "description_fr": "Traversée de répertoire permettant la lecture arbitraire de fichiers non authentifiée via /public/plugins/<plugin-id>/../.",
            "exploit_available": True,
            "exploit_db": 50581,
            "metasploit": None,
            "ctf_machines": ["Ambassador (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-43798",
                "https://www.exploit-db.com/exploits/50581",
            ],
        },
    ],

    # ─── ActiveMQ ─────────────────────────────────────────────────────────────
    "activemq": [
        {
            "id": "CVE-2023-46604",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["< 5.15.16", "< 5.16.7", "< 5.17.6", "< 5.18.3"],
            "description": "Unauthenticated RCE via ClassInfo OpenWire protocol deserialization in Apache ActiveMQ.",
            "description_fr": "RCE non authentifié via désérialisation du protocole OpenWire ClassInfo dans Apache ActiveMQ.",
            "exploit_available": True,
            "exploit_db": 51893,
            "metasploit": "exploit/multi/misc/apache_activemq_rce_cve_2023_46604",
            "ctf_machines": ["Broker (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-46604",
                "https://www.exploit-db.com/exploits/51893",
            ],
        },
    ],

    # ─── Node.js ──────────────────────────────────────────────────────────────
    "node": [
        {
            "id": "CVE-2021-21315",
            "cvss": 7.8,
            "severity": "HIGH",
            "affected_versions": ["< 5.3.1"],
            "description": "Command injection in systeminformation npm package via crafted process name.",
            "description_fr": "Injection de commandes dans le paquet npm systeminformation via un nom de processus forgé.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-21315"],
        },
    ],

    # ─── Nginx ────────────────────────────────────────────────────────────────
    "nginx": [
        {
            "id": "CVE-2013-4547",
            "cvss": 7.5,
            "severity": "HIGH",
            "affected_versions": [">= 0.8.41", "< 1.5.7"],
            "description": "Null byte injection in nginx allows bypass of access restrictions via crafted URI.",
            "description_fr": "Injection d'octet nul dans nginx permettant de contourner les restrictions d'accès via un URI forgé.",
            "exploit_available": True,
            "exploit_db": 31346,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2013-4547",
                "https://www.exploit-db.com/exploits/31346",
            ],
        },
    ],

    # ─── RDP ─────────────────────────────────────────────────────────────────
    "rdp": [
        {
            "id": "CVE-2019-0708",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["= Windows XP", "= Windows 7", "= Windows 2003", "= Windows 2008"],
            "description": "BlueKeep: unauthenticated RCE via RDP in pre-authentication phase — wormable.",
            "description_fr": "BlueKeep : RCE non authentifié via RDP dans la phase de pré-authentification — propagation automatique possible.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
                "https://github.com/robertdavidgraham/rdpscan",
            ],
        },
    ],

    # ─── VNC ─────────────────────────────────────────────────────────────────
    "vnc": [
        {
            "id": "CVE-2006-2369",
            "cvss": 7.5,
            "severity": "HIGH",
            "affected_versions": ["= 4.1.1"],
            "description": "RealVNC authentication bypass — clients can select no authentication type and connect without credentials.",
            "description_fr": "Contournement d'authentification RealVNC — les clients peuvent sélectionner aucun type d'authentification et se connecter sans identifiants.",
            "exploit_available": True,
            "exploit_db": 1791,
            "metasploit": "auxiliary/scanner/vnc/vnc_none_auth",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2006-2369",
                "https://www.exploit-db.com/exploits/1791",
            ],
        },
    ],

    # ─── Ivanti / Pulse Secure ────────────────────────────────────────────────
    "ivanti": [
        {
            "id": "CVE-2019-11510",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["< 9.0.4"],
            "description": "Unauthenticated arbitrary file read in Pulse Secure SSL VPN — /etc/passwd and session files exposed.",
            "description_fr": "Lecture arbitraire de fichiers non authentifiée dans Pulse Secure SSL VPN — /etc/passwd et fichiers de session exposés.",
            "exploit_available": True,
            "exploit_db": 47895,
            "metasploit": "auxiliary/admin/http/pulse_secure_file_read",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-11510",
                "https://www.exploit-db.com/exploits/47895",
            ],
        },
        {
            "id": "CVE-2024-21887",
            "cvss": 9.1,
            "severity": "CRITICAL",
            "affected_versions": ["< 22.7R2.1", "< 9.1R18.3"],
            "description": "Command injection in Ivanti Connect Secure and Policy Secure web components — exploited in the wild.",
            "description_fr": "Injection de commandes dans les composants web d'Ivanti Connect Secure et Policy Secure — exploitée dans la nature.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-21887",
                "https://github.com/duy-31/CVE-2023-46805_CVE-2024-21887",
            ],
        },
    ],

    # ─── Fortinet ─────────────────────────────────────────────────────────────
    "fortinet": [
        {
            "id": "CVE-2022-40684",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": [">= 7.2.0", "< 7.2.2", ">= 7.0.0", "< 7.0.7"],
            "description": "Authentication bypass via alternate path in FortiOS and FortiProxy — unauthenticated admin actions.",
            "description_fr": "Contournement d'authentification via un chemin alternatif dans FortiOS et FortiProxy — actions admin non authentifiées.",
            "exploit_available": True,
            "exploit_db": 51237,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-40684",
                "https://www.exploit-db.com/exploits/51237",
            ],
        },
        {
            "id": "CVE-2023-27997",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": ["< 6.0.17", "< 6.2.15", "< 6.4.13", "< 7.0.12", "< 7.2.5"],
            "description": "Pre-authentication heap overflow in FortiOS SSL-VPN — allows unauthenticated RCE.",
            "description_fr": "Dépassement de tas avant authentification dans le SSL-VPN FortiOS — permet un RCE non authentifié.",
            "exploit_available": False,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-27997"],
        },
    ],

    # ─── Elasticsearch ────────────────────────────────────────────────────────
    "elasticsearch": [
        {
            "id": "CVE-2014-3120",
            "cvss": 6.8,
            "severity": "MEDIUM",
            "affected_versions": ["< 1.3.8", "< 1.4.3"],
            "description": "RCE via dynamic script execution (Groovy sandbox escape) in Elasticsearch.",
            "description_fr": "RCE via l'exécution de scripts dynamiques (échappement du sandbox Groovy) dans Elasticsearch.",
            "exploit_available": True,
            "exploit_db": 34932,
            "metasploit": "exploit/multi/elasticsearch/script_mvel_rce",
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2014-3120",
                "https://www.exploit-db.com/exploits/34932",
            ],
        },
    ],

    # ─── IIS ──────────────────────────────────────────────────────────────────
    "iis": [
        {
            "id": "CVE-2017-7269",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "affected_versions": ["= 6.0"],
            "description": "Buffer overflow in WebDAV ScStoragePathFromUrl in IIS 6.0 — unauthenticated RCE.",
            "description_fr": "Dépassement de tampon dans WebDAV ScStoragePathFromUrl dans IIS 6.0 — RCE non authentifié.",
            "exploit_available": True,
            "exploit_db": 41738,
            "metasploit": "exploit/windows/iis/iis_webdav_scstoragepathfromurl",
            "ctf_machines": ["Grandpa (HTB)", "Granny (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2017-7269",
                "https://www.exploit-db.com/exploits/41738",
            ],
        },
    ],

    # ─── Roundcube ────────────────────────────────────────────────────────────
    "roundcube": [
        {
            "id": "CVE-2023-43770",
            "cvss": 6.1,
            "severity": "MEDIUM",
            "affected_versions": ["< 1.4.15", "< 1.5.6", "< 1.6.4"],
            "description": "Stored XSS via malicious link reference in plain text messages.",
            "description_fr": "XSS stocké via une référence de lien malveillante dans les messages en texte brut.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": ["Devvortex (HTB)"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-43770"],
        },
    ],

    # ─── CUPS ─────────────────────────────────────────────────────────────────
    "cups": [
        {
            "id": "CVE-2024-47176",
            "cvss": 9.9,
            "severity": "CRITICAL",
            "affected_versions": ["< 2.0.1"],
            "description": "cups-browsed binds to UDP 631 from any source — combined with CVE-2024-47076/47175 allows unauthenticated RCE.",
            "description_fr": "cups-browsed écoute sur UDP 631 depuis n'importe quelle source — combiné aux CVE-2024-47076/47175 permet un RCE non authentifié.",
            "exploit_available": True,
            "exploit_db": None,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-47176",
                "https://github.com/RickdeJager/cupshax",
            ],
        },
    ],

    # ─── Sudo (privesc locale) ────────────────────────────────────────────────
    "sudo": [
        {
            "id": "CVE-2021-3156",
            "cvss": 7.8,
            "severity": "HIGH",
            "affected_versions": [">= 1.8.2", "< 1.9.5p2"],
            "description": "Baron Samedit: heap buffer overflow in sudo via -s flag — any local user to root without auth.",
            "description_fr": "Baron Samedit : dépassement de tas dans sudo via le flag -s — n'importe quel utilisateur local vers root sans authentification.",
            "exploit_available": True,
            "exploit_db": 49521,
            "metasploit": "exploit/linux/local/sudo_baron_samedit",
            "ctf_machines": ["Knife (HTB)", "Academy (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-3156",
                "https://www.exploit-db.com/exploits/49521",
            ],
        },
        {
            "id": "CVE-2019-14287",
            "cvss": 8.8,
            "severity": "HIGH",
            "affected_versions": ["< 1.8.28"],
            "description": "sudo user ID -1 bypass — 'sudo -u#-1 /bin/bash' runs as root if user is listed in sudoers.",
            "description_fr": "Bypass user ID -1 dans sudo — 'sudo -u#-1 /bin/bash' s'exécute en root si l'utilisateur est dans sudoers.",
            "exploit_available": True,
            "exploit_db": 47502,
            "metasploit": None,
            "ctf_machines": [],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-14287",
                "https://www.exploit-db.com/exploits/47502",
            ],
        },
    ],

    # ─── Polkit (pkexec) ─────────────────────────────────────────────────────
    "polkit": [
        {
            "id": "CVE-2021-4034",
            "cvss": 7.8,
            "severity": "HIGH",
            "affected_versions": ["< 0.121"],
            "description": "PwnKit: local privilege escalation in pkexec — any local user to root via SUID binary.",
            "description_fr": "PwnKit : élévation de privilèges locale dans pkexec — n'importe quel utilisateur local vers root via le binaire SUID.",
            "exploit_available": True,
            "exploit_db": 50689,
            "metasploit": "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec",
            "ctf_machines": ["Previse (HTB)", "Meta (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-4034",
                "https://www.exploit-db.com/exploits/50689",
            ],
        },
    ],

    # ─── Dirty Cow (kernel) ───────────────────────────────────────────────────
    "kernel": [
        {
            "id": "CVE-2016-5195",
            "cvss": 7.8,
            "severity": "HIGH",
            "affected_versions": ["< 4.8.3"],
            "description": "Dirty COW: race condition in the copy-on-write implementation of the Linux kernel — local root.",
            "description_fr": "Dirty COW : race condition dans l'implémentation copy-on-write du kernel Linux — root local.",
            "exploit_available": True,
            "exploit_db": 40616,
            "metasploit": None,
            "ctf_machines": ["Dirtycow (THM)", "Bulldog (VulnHub)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2016-5195",
                "https://www.exploit-db.com/exploits/40616",
                "https://dirtycow.ninja",
            ],
        },
        {
            "id": "CVE-2022-0847",
            "cvss": 7.8,
            "severity": "HIGH",
            "affected_versions": [">= 5.8", "< 5.16.11"],
            "description": "Dirty Pipe: local privilege escalation via pipe buffer flag mishandling in Linux kernel.",
            "description_fr": "Dirty Pipe : élévation de privilèges locale via une mauvaise gestion des flags de buffer de pipe dans le kernel Linux.",
            "exploit_available": True,
            "exploit_db": 50808,
            "metasploit": None,
            "ctf_machines": ["Ophiuchi (HTB)"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-0847",
                "https://www.exploit-db.com/exploits/50808",
            ],
        },
    ],
}

# =============================================================================
# LOGIQUE D'INJECTION
# =============================================================================

def load_db() -> dict:
    if not CVE_DB_PATH.exists():
        return {}
    with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_db(db: dict):
    with open(CVE_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)


def inject_ctf_cves(db: dict, target_service: str | None = None, dry_run: bool = False) -> dict:
    """
    Injecte les CVEs CTF dans la DB existante.
    - Skipe les CVEs déjà présentes (même ID).
    - Merge les nouvelles en tête de liste (priorité d'affichage).
    - target_service : si fourni, n'injecte que ce service.
    """
    stats = defaultdict(lambda: {"injected": 0, "skipped": 0})

    services_to_process = (
        {target_service: CTF_CVE_DATABASE[target_service]}
        if target_service and target_service in CTF_CVE_DATABASE
        else CTF_CVE_DATABASE
    )

    for service, cves in services_to_process.items():
        existing = db.get(service, [])
        existing_ids = {c["id"] for c in existing}
        new_cves = []

        for cve in cves:
            if cve["id"] in existing_ids:
                stats[service]["skipped"] += 1
            else:
                new_cves.append(cve)
                stats[service]["injected"] += 1

        if not dry_run and new_cves:
            # Nouvelles CVEs en tête, puis existantes
            db[service] = new_cves + existing

    return stats


def print_stats(db_before: dict, db_after: dict, injection_stats: dict):
    total_before = sum(len(v) for v in db_before.values())
    total_after  = sum(len(v) for v in db_after.values())

    if RICH:
        console.print()
        table = Table(title="Résultat de l'injection CTF", box=box.ROUNDED, show_footer=True)
        table.add_column("Service", style="cyan", footer="TOTAL")
        table.add_column("Injectées", style="green", justify="center",
                         footer=str(sum(s["injected"] for s in injection_stats.values())))
        table.add_column("Ignorées (déjà présentes)", style="yellow", justify="center",
                         footer=str(sum(s["skipped"] for s in injection_stats.values())))

        for svc in sorted(injection_stats):
            s = injection_stats[svc]
            if s["injected"] or s["skipped"]:
                table.add_row(svc, str(s["injected"]), str(s["skipped"]))

        console.print(table)
        console.print(f"\n  CVEs avant : [bold]{total_before}[/]  →  après : [bold green]{total_after}[/]  "
                      f"(+{total_after - total_before})\n")
    else:
        print(f"\n{'Service':<20} {'Injectées':>10} {'Ignorées':>10}")
        print("-" * 44)
        for svc in sorted(injection_stats):
            s = injection_stats[svc]
            print(f"  {svc:<18} {s['injected']:>10} {s['skipped']:>10}")
        print("-" * 44)
        total_inj = sum(s["injected"] for s in injection_stats.values())
        total_skip = sum(s["skipped"] for s in injection_stats.values())
        print(f"  {'TOTAL':<18} {total_inj:>10} {total_skip:>10}")
        print(f"\nCVEs avant : {total_before}  →  après : {total_after} (+{total_after - total_before})\n")


def list_services():
    """Affiche les services couverts par la base CTF."""
    if RICH:
        table = Table(title="Services couverts par la base CTF", box=box.SIMPLE)
        table.add_column("Service", style="cyan")
        table.add_column("CVEs", justify="center", style="green")
        table.add_column("Exploitables", justify="center", style="yellow")
        table.add_column("Machines CTF", style="dim")

        for svc in sorted(CTF_CVE_DATABASE):
            cves = CTF_CVE_DATABASE[svc]
            exploitable = sum(1 for c in cves if c.get("exploit_available"))
            machines = set()
            for c in cves:
                machines.update(c.get("ctf_machines", []))
            table.add_row(svc, str(len(cves)), str(exploitable),
                          ", ".join(sorted(machines)) if machines else "—")
        console.print(table)
    else:
        print(f"\n{'Service':<20} {'CVEs':>6} {'Exploit':>8}  Machines CTF")
        print("-" * 70)
        for svc in sorted(CTF_CVE_DATABASE):
            cves = CTF_CVE_DATABASE[svc]
            exploitable = sum(1 for c in cves if c.get("exploit_available"))
            machines = set()
            for c in cves:
                machines.update(c.get("ctf_machines", []))
            print(f"  {svc:<18} {len(cves):>6} {exploitable:>8}  {', '.join(sorted(machines)) or '—'}")
        print()


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="ChocoScan — Enrichissement CVE orienté CTF/Pentest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python update_db_ctf.py
  python update_db_ctf.py --dry-run
  python update_db_ctf.py --service tomcat
  python update_db_ctf.py --list-services
  python update_db_ctf.py --stats
        """,
    )
    parser.add_argument("--dry-run",       action="store_true",  help="Aperçu sans modifier la DB")
    parser.add_argument("--service",       type=str, default=None, help="Injecter seulement ce service")
    parser.add_argument("--stats",         action="store_true",  help="Afficher les stats de la DB après injection")
    parser.add_argument("--list-services", action="store_true",  help="Lister les services disponibles et quitter")
    args = parser.parse_args()

    if args.list_services:
        list_services()
        return

    if RICH:
        console.print(Panel.fit(
            "[bold cyan]ChocoScan[/] — [yellow]Enrichissement CVE CTF/Pentest[/]",
            subtitle=f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M')}[/]"
        ))
    else:
        print(f"\n=== ChocoScan — Enrichissement CVE CTF/Pentest ===\n")

    if args.service and args.service not in CTF_CVE_DATABASE:
        available = ", ".join(sorted(CTF_CVE_DATABASE.keys()))
        print(f"[!] Service inconnu : '{args.service}'\n    Disponibles : {available}")
        sys.exit(1)

    db_before = load_db()
    db_work   = {k: list(v) for k, v in db_before.items()}  # copie

    injection_stats = inject_ctf_cves(db_work, target_service=args.service, dry_run=args.dry_run)

    if args.dry_run:
        if RICH:
            console.print("\n[bold yellow]Mode dry-run — aucune modification effectuée[/]\n")
        else:
            print("\n[DRY-RUN] Aucune modification effectuée.\n")
        print_stats(db_before, db_work, injection_stats)
        return

    save_db(db_work)
    print_stats(db_before, db_work, injection_stats)

    if args.stats:
        if RICH:
            console.print("[bold]Statistiques globales de la DB :[/]")
            table = Table(box=box.SIMPLE)
            table.add_column("Métrique", style="cyan")
            table.add_column("Valeur", justify="right", style="green")
            table.add_row("Services total", str(len(db_work)))
            table.add_row("CVEs total", str(sum(len(v) for v in db_work.values())))
            table.add_row("CVEs exploitables", str(sum(
                1 for cves in db_work.values() for c in cves if c.get("exploit_available")
            )))
            table.add_row("CVEs avec module MSF", str(sum(
                1 for cves in db_work.values() for c in cves if c.get("metasploit")
            )))
            table.add_row("CVEs avec ExploitDB", str(sum(
                1 for cves in db_work.values() for c in cves if c.get("exploit_db")
            )))
            console.print(table)
        else:
            total = sum(len(v) for v in db_work.values())
            exploit = sum(1 for cves in db_work.values() for c in cves if c.get("exploit_available"))
            msf = sum(1 for cves in db_work.values() for c in cves if c.get("metasploit"))
            print(f"  Services : {len(db_work)} | CVEs : {total} | Exploitables : {exploit} | MSF : {msf}")

    if RICH:
        console.print("[green]✓[/] Base mise à jour : [bold]data/cve_db.json[/]\n")
    else:
        print("[+] Base mise à jour : data/cve_db.json\n")


if __name__ == "__main__":
    main()
