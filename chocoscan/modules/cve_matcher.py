"""
Module de matching CVE.
Recherche dans la base locale puis fallback sur l'API NVD,
avec cache persistant pour limiter les requêtes réseau.
"""

import json
import re
import time
import hashlib
import requests
from pathlib import Path
from datetime import datetime, timedelta
from modules.version_checker import is_version_affected, check_version_affected, Confidence

try:
    from modules.config import find_config_file, load_config, load_env_overrides
    _CONFIG_AVAILABLE = True
except ImportError:
    _CONFIG_AVAILABLE = False


# ─── Clé API NVD ───────────────────────────────────────────────────────────────

_NVD_KEY_WARNED = False  # affiche le message d'astuce une seule fois par exécution


def get_nvd_api_key() -> str | None:
    """
    Résout la clé API NVD depuis (par ordre de priorité) :
      1. Variable d'environnement $CHOCOSCAN_NVD_API_KEY ou $NVD_API_KEY
      2. ~/.chocoscan.conf  →  nvd_api_key = "..."

    Une clé API NVD gratuite multiplie le rate limit par 10
    (5 req/30s sans clé → 50 req/30s avec clé).
    Demande sur : https://nvd.nist.gov/developers/request-an-api-key
    """
    import os

    # 1. Variables d'environnement (les deux noms sont acceptés)
    for env_var in ("CHOCOSCAN_NVD_API_KEY", "NVD_API_KEY"):
        val = os.environ.get(env_var, "").strip()
        if val:
            return val

    # 2. Fichier de config
    if _CONFIG_AVAILABLE:
        try:
            path = find_config_file()
            if path:
                # nvd_api_key n'est pas dans CONFIGURABLE_KEYS (sensible, on la lit à part)
                import tomllib
                with open(path, "rb") as f:
                    raw = tomllib.load(f)
                key = raw.get("nvd_api_key", "").strip()
                if key:
                    return key
        except Exception:
            pass

    return None


def _warn_no_api_key_once():
    """Affiche une seule fois par exécution un message d'astuce sur la clé NVD."""
    global _NVD_KEY_WARNED
    if _NVD_KEY_WARNED:
        return
    _NVD_KEY_WARNED = True
    try:
        from rich.console import Console
        Console(stderr=True).print(
            "[dim]💡 Astuce : sans clé API NVD, le fallback est limité à 5 requêtes/30s "
            "et peut ralentir le scan. Ajoutez nvd_api_key = \"...\" dans ~/.chocoscan.conf "
            "pour passer à 50 requêtes/30s.\n"
            "   Clé gratuite : https://nvd.nist.gov/developers/request-an-api-key[/dim]"
        )
    except ImportError:
        print(
            "[i] Astuce : sans clé API NVD, le fallback est limité à 5 req/30s.\n"
            "    Ajoutez nvd_api_key dans ~/.chocoscan.conf pour 50 req/30s.\n"
            "    Clé gratuite : https://nvd.nist.gov/developers/request-an-api-key"
        )


# Chemins
CVE_DB_PATH     = Path(__file__).parent.parent / "data" / "cve_db.json"
CVE_RECENT_PATH = Path(__file__).parent.parent / "data" / "cve_recent.json"
NVD_CACHE_PATH  = Path(__file__).parent.parent / "data" / "nvd_cache.json"

# TTL du cache NVD (24 heures)
NVD_CACHE_TTL_HOURS = 24

# Mapping service nmap -> clé dans la CVE DB
SERVICE_ALIASES = {
    "ssh": "openssh",
    "openssh": "openssh",
    "http": "apache",
    "https": "apache",
    "apache": "apache",
    "apache httpd": "apache",
    "nginx": "nginx",
    "ftp": "vsftpd",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "mysql": "mysql",
    "mariadb": "mysql",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "microsoft-ds": "smb",
    "smb": "smb",
    "netbios-ssn": "smb",
    "ms-wbt-server": "rdp",
    "rdp": "rdp",
    "iis": "iis",
    "microsoft iis": "iis",
    "http-proxy": "iis",
    "php": "php",
    "ssl": "ssl",
    "openssl": "ssl",
    "telnet": "telnet",
    "smtp": "smtp",
    "tomcat": "tomcat",
    "apache tomcat": "tomcat",
    "samba": "samba",
    "smbd": "samba",
    "vnc": "vnc",
    "redis": "redis",
    "mongodb": "mongodb",
    "elasticsearch": "elasticsearch",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "jenkins": "jenkins",
    "docker": "docker",
    "docker registry": "docker",
    "domain": "dns",
    "dns": "dns",
    "rsync": "rsync",
    "memcache": "memcached",
    "memcached": "memcached",
    "exim": "smtp",
    "exim smtpd": "smtp",
    "postfix": "smtp",
    "gitlab": "gitlab",
    "confluence": "confluence",
    "spring": "spring",
    "spring boot": "spring",
    "fortinet": "fortinet",
    "fortios": "fortinet",
    "fortigate": "fortinet",
    "vmware": "vmware",
    "vcenter": "vmware",
    "esxi": "vmware",
    "citrix": "citrix",
    "netscaler": "citrix",
    "microsoft windows rpc": "rpc",
    "msrpc": "rpc",
    "ms-rpc": "rpc",
    "snmp": "snmp",
    "snmpd": "snmp",
    "ldap": "ldap",
    "openldap": "ldap",
    "kerberos": "kerberos",
    "kerberos-sec": "kerberos",
    "ftp-data": "ftp",
    "rabbitmq": "rabbitmq",
    "amqp": "rabbitmq_amqp",
    "erlang": "erlang_ssh",
    "grafana": "grafana",
    "zabbix": "zabbix",
    "zabbix-agent": "zabbix",
    "openvpn": "openvpn",
    "git": "git",
    "git-daemon": "git",
    "kibana": "kibana",
    "couchdb": "couchdb",
    "squid": "squid",
    "squid-http": "squid",
    "haproxy": "haproxy",
    "minio": "minio",
    "zimbra": "zimbra",
    "exchange": "exchange",
    "microsoft exchange": "exchange",
    "sharepoint": "sharepoint",
    "veeam": "veeam",
    "ivanti": "ivanti",
    "pulse secure": "ivanti",
    "palo alto": "paloalto",
    "pan-os": "paloalto",
    "f5": "f5",
    "big-ip": "f5",
    "junos": "junos",
    "moodle": "moodle",
    "phpmyadmin": "phpmyadmin",
    "webmin": "webmin",
    "splunkd": "splunk",
    "splunk": "splunk",
    "sonarqube": "sonarqube",
    "activemq": "activemq",
    "openwire": "activemq",
    "node.js": "node",
    "node": "node",
    "django": "django",
    "laravel": "laravel",
    "windows rdp": "windows",
    "ms-wbt": "windows",
    "winrm": "winrm",
    "wsman": "winrm",
    "gitea": "gitea",

    # ── Ajouts web_fingerprinter ────────────────────────────────────────────
    "craft cms":       "craft_cms",
    "craftcms":        "craft_cms",
    "craft_cms":       "craft_cms",
    "x-craft-version": "craft_cms",
    "nextcloud":       "nextcloud",
    "phpmyadmin":      "phpmyadmin",
    "webmin":          "webmin",
    "concrete5":       "concrete5",
    "concrete cms":    "concrete5",
    "opencart":        "opencart",
    "ghost":           "ghost",
    "wagtail":         "wagtail",
    "laravel":         "laravel",
    "django":          "django",
    "angular":         "angular",
    "spring":          "spring",
    "spring boot":     "spring",
    "gogs": "gogs",
    "nfs": "nfs",
    "nfsd": "nfs",
    "rpcbind": "rpc",
    "h2 database": "h2_database",
    "h2": "h2_database",
    "openfire": "openfire",
    "supervisor": "supervisor",
    "supervisord": "supervisor",
    "wso2": "wso2",
    "nostromo": "nostromo",
    "nhttpd": "nostromo",
    "icecast": "icecast",
    "jboss": "jboss",
    "wildfly": "jboss",
    "weblogic": "weblogic",
    "struts": "struts",
    "log4j": "log4j",
    "xz": "openssh",
    "liblzma": "openssh",
    "ofbiz": "ofbiz",
    "apache ofbiz": "ofbiz",
    "coldfusion": "coldfusion",
    "adobe coldfusion": "coldfusion",
    "glpi": "glpi",
    "octopus": "octopus",
    "octopus deploy": "octopus",
    "cacti": "cacti",
    "roundcube": "roundcube",
    "nagios": "nagios",
    "nagios xi": "nagios",
    "cisco asa": "asa",
    "asa": "asa",
    "sharefile": "sharefile",
    "bamboo": "bamboo",
    "jira": "jira",
    "thinkphp": "thinkphp",
    "umbraco": "umbraco",
    "ghost": "ghost_cms",
    "prestashop": "prestashop",
    "magento": "magento",
    "rocket.chat": "rocketchat",
    "rocketchat": "rocketchat",
    "rstudio": "rstudio",
    "jupyter": "jupyter",
    "jupyterhub": "jupyter",
    "concrete5": "concrete5",
    "concrete cms": "concrete5",
    "typo3": "typo3",
    "owncloud": "owncloud",
    "harbor": "harbor",
    "consul": "consul",
    "vault": "vault",
    "hashicorp vault": "vault",
    "etcd": "etcd",
    "kubernetes": "kubernetes",
    "kube-apiserver": "kubernetes",
    "portainer": "portainer",
    "synapse": "matrix_synapse",
    "matrix": "matrix_synapse",
    "teamcity": "teamcity",
    "selenium": "selenium",
    "selenium grid": "selenium",
    "adminer": "adminer",
    "freepbx": "freepbx",
    "asterisk": "freepbx",
    "sip": "freepbx",
    "webdav": "webdav",
    "http webdav": "webdav",
    "jetbrains teamcity": "teamcity",
    "teamcity/": "teamcity",
    "papercut": "papercut",
    "papercut ng": "papercut",
    "papercut mf": "papercut",


    # ── OpenSSH / SSH variantes ──────────────────────────────────────────────
    "ssh-2.0": "openssh",
    "ssh-1.99": "openssh",
    "ssh-1.5": "openssh",
    "openssh_": "openssh",
    "libssh": "openssh",
    "dropbear": "openssh",
    "bitvise": "openssh",
    "ssh2": "openssh",
    "putty": "openssh",

    # ── Apache variantes ─────────────────────────────────────────────────────
    "apache/2": "apache",
    "apache/1": "apache",
    "apache-coyote": "tomcat",
    "httpd": "apache",
    "mod_ssl": "apache",
    "mod_perl": "apache",
    "mod_python": "apache",
    "mod_php": "apache",

    # ── Nginx variantes ──────────────────────────────────────────────────────
    "nginx/1": "nginx",
    "nginx/0": "nginx",
    "openresty": "nginx",
    "tengine": "nginx",

    # ── IIS variantes ────────────────────────────────────────────────────────
    "microsoft-httpapi": "iis",
    "microsoft httpapi": "iis",
    "microsoft-iis/": "iis",
    "iis/": "iis",
    "asp.net": "iis",
    "iis 10": "iis",
    "iis 8": "iis",
    "iis 7": "iis",
    "iis 6": "iis",

    # ── Tomcat variantes ─────────────────────────────────────────────────────
    "tomcat/": "tomcat",
    "catalina": "tomcat",
    "jserv": "tomcat",
    "glassfish": "tomcat",
    "jetty/": "tomcat",
    "jetty": "tomcat",
    "wildfly": "jboss",
    "jboss-eap": "jboss",
    "jbossas": "jboss",

    # ── FTP variantes ────────────────────────────────────────────────────────
    "ftpd": "vsftpd",
    "wu-ftpd": "vsftpd",
    "pure-ftpd": "proftpd",
    "filezilla": "proftpd",
    "warftpd": "proftpd",
    "serv-u": "proftpd",
    "bftpd": "vsftpd",
    "glftpd": "vsftpd",

    # ── MySQL / MariaDB variantes ────────────────────────────────────────────
    "mysql community": "mysql",
    "mysql enterprise": "mysql",
    "percona": "mysql",
    "mariadb/": "mysql",
    "mysql/": "mysql",
    "aurora": "mysql",

    # ── PostgreSQL variantes ─────────────────────────────────────────────────
    "postgres/": "postgresql",
    "postgresql/": "postgresql",
    "pgbouncer": "postgresql",
    "pgpool": "postgresql",

    # ── Redis variantes ──────────────────────────────────────────────────────
    "redis/": "redis",
    "redis server": "redis",
    "keydb": "redis",

    # ── SMB / Windows variantes ──────────────────────────────────────────────
    "cifs": "smb",
    "microsoft-ds": "smb",
    "netbios": "smb",
    "netbios-ns": "smb",
    "netbios-dgm": "smb",
    "windows rpc": "rpc",
    "msrpc": "rpc",
    "epmapper": "rpc",
    "ncacn_http": "rpc",

    # ── RDP variantes ────────────────────────────────────────────────────────
    "ms-wbt-server": "rdp",
    "remote desktop protocol": "rdp",
    "terminal services": "rdp",
    "xrdp": "rdp",
    "freerdp": "rdp",

    # ── SSL/TLS variantes ─────────────────────────────────────────────────────
    "ssl/": "ssl",
    "tls": "ssl",
    "https/": "ssl",
    "stunnel": "ssl",
    "openssl/": "ssl",

    # ── DNS variantes ────────────────────────────────────────────────────────
    "named": "dns",
    "bind": "dns",
    "bind9": "dns",
    "powerdns": "dns",
    "dnsmasq": "dns",
    "unbound": "dns",
    "domain ": "dns",
    "mdns": "dns",
    "dnssec": "dns",

    # ── SMTP variantes ───────────────────────────────────────────────────────
    "sendmail": "smtp",
    "postfix smtpd": "smtp",
    "postfix/smtp": "smtp",
    "exim4": "smtp",
    "qmail": "smtp",
    "opensmtpd": "smtp",
    "smtpd": "smtp",
    "esmtp": "smtp",
    "mailserver": "smtp",
    "helo": "smtp",
    "pop3": "smtp",
    "imap": "smtp",
    "dovecot": "smtp",
    "courier": "smtp",

    # ── Samba variantes ──────────────────────────────────────────────────────
    "samba/": "samba",
    "samba smbd": "samba",
    "nmbd": "samba",
    "winbind": "samba",

    # ── VNC variantes ────────────────────────────────────────────────────────
    "vnc-http": "vnc",
    "realvnc": "vnc",
    "tigervnc": "vnc",
    "tightvnc": "vnc",
    "ultravnc": "vnc",
    "x11vnc": "vnc",
    "libvncserver": "vnc",
    "rfb ": "vnc",

    # ── MongoDB variantes ────────────────────────────────────────────────────
    "mongod": "mongodb",
    "mongos": "mongodb",
    "mongodb/": "mongodb",

    # ── Elasticsearch variantes ──────────────────────────────────────────────
    "elastic": "elasticsearch",
    "elasticsearch/": "elasticsearch",
    "opensearch": "elasticsearch",
    "es-transport": "elasticsearch",

    # ── Kubernetes variantes ─────────────────────────────────────────────────
    "kubelet": "kubernetes",
    "kube-proxy": "kubernetes",
    "etcd/": "etcd",
    "kubectl": "kubernetes",
    "k8s": "kubernetes",
    "kubeadm": "kubernetes",

    # ── Docker variantes ─────────────────────────────────────────────────────
    "dockerd": "docker",
    "containerd": "docker",
    "docker daemon": "docker",
    "docker engine": "docker",
    "docker api": "docker",
    "container runtime": "docker",
    "runc": "docker",

    # ── Spring variantes ─────────────────────────────────────────────────────
    "spring-boot": "spring",
    "spring framework": "spring",
    "spring mvc": "spring",
    "spring security": "spring",
    "spring cloud": "spring",
    "pivotal": "spring",

    # ── PHP variantes ────────────────────────────────────────────────────────
    "php/": "php",
    "php-fpm": "php",
    "x-powered-by: php": "php",
    "hhvm": "php",

    # ── Node.js variantes ────────────────────────────────────────────────────
    "express": "nodejs",
    "expressjs": "nodejs",
    "next.js": "nodejs",
    "nuxt": "nodejs",
    "fastify": "nodejs",
    "nestjs": "nodejs",
    "node/": "nodejs",

    # ── Memcached variantes ──────────────────────────────────────────────────
    "memcache/": "memcached",

    # ── SNMP variantes ───────────────────────────────────────────────────────
    "snmp/": "snmp",
    "net-snmp": "snmp",
    "cisco snmp": "snmp",

    # ── LDAP variantes ───────────────────────────────────────────────────────
    "ldap/": "ldap",
    "active directory": "ldap",
    "ad ds": "ldap",
    "msad": "ldap",
    "ldaps": "ldap",
    "389 directory": "ldap",
    "freeipa": "ldap",

    # ── Kerberos variantes ───────────────────────────────────────────────────
    "kerberos/": "kerberos",
    "kdc": "kerberos",
    "krb5": "kerberos",
    "krb524d": "kerberos",

    # ── NFS variantes ────────────────────────────────────────────────────────
    "nfs/": "nfs",
    "mountd": "nfs",
    "rpc.mountd": "nfs",
    "nfs3": "nfs",
    "nfs4": "nfs",
    "portmapper": "rpc",
    "rpcinfo": "rpc",

    # ── Zabbix variantes ────────────────────────────────────────────────────
    "zabbix-agent2": "zabbix",
    "zabbix agent": "zabbix",
    "zabbix server": "zabbix",

    # ── Grafana variantes ───────────────────────────────────────────────────
    "grafana/": "grafana",

    # ── Splunk variantes ────────────────────────────────────────────────────
    "splunk web": "splunk",
    "splunkd web": "splunk",

    # ── GitLab variantes ────────────────────────────────────────────────────
    "gitlab-workhorse": "gitlab",
    "gitlab ce": "gitlab",
    "gitlab ee": "gitlab",

    # ── Jenkins variantes ───────────────────────────────────────────────────
    "jenkins/": "jenkins",
    "hudson": "jenkins",
    "jenkins-ci": "jenkins",

    # ── Confluence variantes ────────────────────────────────────────────────
    "atlassian confluence": "confluence",
    "confluence/": "confluence",

    # ── Jira variantes ──────────────────────────────────────────────────────
    "atlassian jira": "jira",
    "jira software": "jira",
    "jira service": "jira",

    # ── WordPress variantes ─────────────────────────────────────────────────
    "wp-login": "wordpress",
    "wp-admin": "wordpress",
    "wp-content": "wordpress",
    "wpengine": "wordpress",

    # ── Drupal variantes ────────────────────────────────────────────────────
    "drupal/": "drupal",
    "x-generator: drupal": "drupal",

    # ── ColdFusion variantes ────────────────────────────────────────────────
    "cfide": "coldfusion",
    "adobe coldfusion": "coldfusion",
    "lucee": "coldfusion",
    "railo": "coldfusion",

    # ── WebLogic variantes ──────────────────────────────────────────────────
    "weblogic/": "weblogic",
    "oracle weblogic": "weblogic",
    "wls": "weblogic",
    "t3 ": "weblogic",

    # ── Fortinet variantes ──────────────────────────────────────────────────
    "fortiweb": "fortinet",
    "fortimail": "fortinet",
    "fortiadc": "fortinet",
    "fortiddos": "fortinet",
    "fortianalyzer": "fortinet",

    # ── Cisco ASA variantes ─────────────────────────────────────────────────
    "cisco ftd": "asa",
    "cisco firepower": "asa",
    "adaptive security": "asa",

    # ── SIP / VoIP ───────────────────────────────────────────────────────────
    "sip ": "freepbx",
    "asterisk pbx": "freepbx",
    "asterisk/": "freepbx",
    "voip": "freepbx",
    "freeswitch": "freepbx",
    "kamailio": "freepbx",
    "opensips": "freepbx",

    # ── Nouveaux services ────────────────────────────────────────────────────
    "cassandra": "cassandra",
    "cassandradb": "cassandra",
    "influxdb": "influxdb",
    "influx": "influxdb",
    "prometheus": "prometheus",
    "pushgateway": "prometheus",
    "alertmanager": "prometheus",
    "netdata": "netdata",
    "opentsdb": "opentsdb",
    "mqtt": "mqtt",
    "mosquitto": "mqtt",
    "emqx": "mqtt",
    "cups": "cups",
    "ipp": "cups",
    "ipp/": "cups",
    "distcc": "distcc",
    "distccd": "distcc",
    "rsyslog": "rsyslog",
    "syslog": "rsyslog",
    "syslog-ng": "rsyslog",
    "x11": "x11",
    "x display": "x11",
    "xserver": "x11",
    "xorg": "x11",
    "postgres exporter": "postgresql",
    "pgadmin": "phpmyadmin",
    "redis exporter": "redis",
    "metabase": "metabase",
    "superset": "metabase",
    "airflow": "airflow",
    "celery": "airflow",
    "rabbitmq management": "rabbitmq",
    "rabbitmq/": "rabbitmq",
    "mattermost": "rocketchat",
    "slack-compatible": "rocketchat",
    "gitlab-pages": "gitlab",
    "minio/": "minio",
    "s3-compatible": "minio",
    "consul/": "consul",
    "hashicorp consul": "consul",
    "hashicorp nomad": "consul",
    "vault/": "vault",
    "hashicorp": "vault",
    "traefik": "traefik",
    "traefik/": "traefik",
    "envoy": "traefik",
    "istio": "traefik",
    "linkerd": "traefik",
    "neo4j": "neo4j",
    "bolt": "neo4j",
    "neo4j/": "neo4j",
    "orientdb": "neo4j",
    "arangodb": "neo4j",
    "solr": "solr",
    "apache solr": "solr",
    "lucene": "solr",
    "kafka": "kafka",
    "apache kafka": "kafka",
    "zookeeper": "kafka",
    "nats": "kafka",
    "pulsar": "kafka",
    "clickhouse": "clickhouse",
    "clickhouse/": "clickhouse",
    "hive": "hadoop",
    "hadoop": "hadoop",
    "hdfs": "hadoop",
    "hbase": "hadoop",
    "spark": "hadoop",
    "presto": "hadoop",
    "trino": "hadoop",
    "druid": "hadoop",
    "tensorflow serving": "tensorflow",
    "torchserve": "tensorflow",
    "ollama": "tensorflow",
    "triton": "tensorflow",
    "openwebui": "tensorflow",
    "langchain": "tensorflow",

    # ── Services critiques HTB ────────────────────────────────────────────────
    # Privilege escalation Linux
    "sudo":              "sudo",
    "sudoedit":          "sudo",
    "polkit":            "polkit",
    "pkexec":            "polkit",
    "policykit":         "polkit",
    "linux kernel":      "linux_kernel",
    "linux_kernel":      "linux_kernel",
    "gnu bash":          "bash",
    "gnu screen":        "screen",
    # FTP
    "vsftpd":            "vsftpd",
    "proftpd":           "proftpd",
    "pure-ftpd":         "pure_ftpd",
    "pureftpd":          "pure_ftpd",
    # Mail
    "exim":              "exim",
    "exim4":             "exim",
    "postfix":           "postfix",
    "dovecot":           "dovecot",
    "sendmail":          "sendmail",
    "zimbra":            "zimbra",
    # OpenSSL
    "openssl":           "openssl",
    "libssl":            "openssl",
    # Frameworks web
    "rails":             "rails",
    "ruby on rails":     "rails",
    "flask":             "flask",
    "werkzeug":          "flask",
    "nodejs":            "nodejs",
    "node.js":           "nodejs",
    "node":              "nodejs",
    "symfony":           "symfony",
    # Médias
    "imagemagick":       "imagemagick",
    "imagick":           "imagemagick",
    "ghostscript":       "ghostscript",
    # Réseau
    "cups":              "cups",
    "rsync":             "rsync",
    "named":             "bind",
    "openldap":          "ldap",
    "squid":             "squid",
    "haproxy":           "haproxy",
    "lighttpd":          "lighttpd",
    "tigervnc":          "vnc",
    "tightvnc":          "vnc",
    "libvncserver":      "vnc",
    # Containers
    "runc":              "runc",
    "containerd":        "containerd",
    # DB
    "couchdb":           "couchdb",
    "apache couchdb":    "couchdb",
    "memcached":         "memcached",
    "microsoft sql server": "mssql",
    "ms-sql-s":          "mssql",
    "ms-sql":            "mssql",
}

LOCAL_PRIVESC_SERVICES = [
    "shellshock", "dirtycow", "polkit", "sudo", "screen", "pkexec", "openssl_3"
]


# ─── Cache NVD ────────────────────────────────────────────────────────────────

def _load_nvd_cache() -> dict:
    if NVD_CACHE_PATH.exists():
        try:
            with open(NVD_CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_nvd_cache(cache: dict):
    try:
        with open(NVD_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
    except Exception:
        pass


def _cache_key(service: str, version: str) -> str:
    raw = f"{service.lower().strip()}|{version.lower().strip()}"
    return hashlib.md5(raw.encode()).hexdigest()


def _cache_is_valid(entry: dict) -> bool:
    try:
        ts = datetime.fromisoformat(entry.get("timestamp", ""))
        return datetime.now() - ts < timedelta(hours=NVD_CACHE_TTL_HOURS)
    except Exception:
        return False


# ─── Chargement des bases ─────────────────────────────────────────────────────

def load_local_db() -> dict:
    """Charge la base CVE locale principale."""
    with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_recent_db() -> dict:
    """Charge la base CVE récentes (cve_recent.json) si disponible."""
    if CVE_RECENT_PATH.exists():
        try:
            with open(CVE_RECENT_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


# ─── Extraction service / version ─────────────────────────────────────────────

def extract_service_key(service_name: str, banner: str = "") -> str | None:
    """
    Détermine la clé de la CVE DB depuis le nom du service et sa bannière.

    Le matching se fait par mots entiers (frontières \\b), pas par simple
    sous-chaîne : ça évite les faux positifs où un alias court apparaît
    par hasard à l'intérieur d'un autre mot. Exemples concrets corrigés :
        "digit-service"  ne matche plus "git"
        "legitimate-app" ne matche plus "git"
        "h2o-proxy"      ne matche plus "h2" (h2_database)
    """
    combined = f"{service_name} {banner}".lower().strip()
    # Trier par longueur décroissante pour que les aliases plus spécifiques
    # soient évalués en premier (ex: "apache tomcat" avant "apache")
    for alias, key in sorted(SERVICE_ALIASES.items(), key=lambda x: len(x[0]), reverse=True):
        # \b ne fonctionne correctement que sur des caractères alphanumériques :
        # un alias comme "h2" doit matcher "h2 database" mais pas "h2o-proxy".
        # re.escape gère les alias contenant des espaces ou caractères spéciaux
        # (ex: "apache tomcat", "node.js").
        pattern = r"\b" + re.escape(alias) + r"\b"
        if re.search(pattern, combined):
            return key
    return None

def extract_version_from_banner(banner: str) -> str:
    """Extrait la version depuis une bannière nmap."""
    patterns = [
        r'(\d+\.\d+[\.\d]*(?:[p\-]\d+)?)',
    ]
    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1)
    return ""


# ─── Recherche locale ─────────────────────────────────────────────────────────

def search_local_db(service_key: str, version: str) -> list:
    """
    Recherche des CVE dans les bases locales pour un service/version.
    Priorité : cve_recent.json (CVEs récentes) > cve_db.json (base principale)
    Les doublons (même CVE ID) sont dédupliqués, recent_db prioritaire.

    Chaque CVE retournée porte un champ `_confidence` (certain/likely/uncertain)
    qui reflète la fiabilité du matching de version — utilisé par le rapport HTML
    pour distinguer visuellement les CVEs confirmées des CVEs supposées.
    """
    main_db   = load_local_db()
    recent_db = load_recent_db()

    seen_ids = set()
    results  = []

    def _confidence_for(cve: dict) -> dict:
        """Calcule la confidence et enrichit la CVE avec les métadonnées de matching."""
        affected = cve.get("affected_versions", [])
        if not version:
            # Pas de version détectée par Nmap du tout → on ne peut rien confirmer
            return {
                "_confidence":   Confidence.UNCERTAIN.value,
                "_match_reason": "Version non détectée par Nmap pour ce service",
            }
        match = check_version_affected(version, "", affected)
        return {
            "_confidence":   match.confidence.value,
            "_match_reason": match.reason,
        }

    # 1. CVE récentes en priorité
    for cve in recent_db.get(service_key, []):
        if not version or is_version_affected(version, cve.get("affected_versions", [])):
            cve_id = cve.get("id", "")
            if cve_id not in seen_ids:
                seen_ids.add(cve_id)
                results.append({**cve, "source": "Local DB (récent)", **_confidence_for(cve)})

    # 2. Base principale
    for cve in main_db.get(service_key, []):
        if not version or is_version_affected(version, cve.get("affected_versions", [])):
            cve_id = cve.get("id", "")
            if cve_id not in seen_ids:
                seen_ids.add(cve_id)
                results.append({**cve, "source": "Local DB", **_confidence_for(cve)})

    return results


# ─── Traduction ───────────────────────────────────────────────────────────────

def translate_to_french(text: str) -> str:
    """Traduit un texte EN -> FR via l'API gratuite MyMemory."""
    if not text:
        return ""
    try:
        url = "https://api.mymemory.translated.net/get"
        params = {"q": text[:490], "langpair": "en|fr"}
        resp = requests.get(url, params=params, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        translated = data.get("responseData", {}).get("translatedText", "")
        if translated and "MYMEMORY WARNING" not in translated.upper():
            return translated
    except Exception:
        pass
    return ""


# ─── API NVD avec cache ───────────────────────────────────────────────────────

def search_nvd_api(service: str, version: str, max_results: int = 5, cpe: str | None = None) -> list:
    """
    Interroge l'API NVD comme fallback, avec cache persistant 24h.
    Retourne une liste de CVE simplifiées.

    Si `cpe` est fourni (CPE 2.3 résolu via modules.cpe_resolver), la requête
    utilise `cpeName` plutôt que `keywordSearch` — bien plus précis, réduit
    nettement les faux positifs/négatifs liés à l'ambiguïté des noms en
    texte libre (ex: "git" qui matche aussi "gitlab", "digit", etc. en
    keywordSearch, alors qu'un CPE cible précisément le bon produit).

    Utilise automatiquement une clé API NVD si configurée (voir get_nvd_api_key())
    pour passer de 5 req/30s à 50 req/30s — réduit considérablement le temps
    de scan sur les services non couverts par la base locale.
    """
    cache = _load_nvd_cache()
    # Le cache est clé sur (service, version) indépendamment du mode de
    # requête utilisé : le résultat attendu pour un même service/version
    # est le même, que la résolution sous-jacente soit passée par CPE ou
    # par mot-clé.
    key   = _cache_key(service, version)

    # Retour depuis le cache si valide
    if key in cache and _cache_is_valid(cache[key]):
        return cache[key]["data"]

    api_key = get_nvd_api_key()
    if not api_key:
        _warn_no_api_key_once()

    url     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": api_key} if api_key else {}

    if cpe:
        # Requête précise par CPE. On laisse le composant version du CPE
        # tel que résolu (souvent "*" pour la base enrichie, ou une version
        # précise si fournie par l'appelant) — NVD filtre alors sur ce CPE.
        params = {"cpeName": cpe, "resultsPerPage": max_results}
    else:
        query  = f"{service} {version}".strip()
        params = {"keywordSearch": query, "resultsPerPage": max_results}

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=10)

        # ── Gestion fine des erreurs HTTP avant raise_for_status ──────────────
        if resp.status_code == 403:
            try:
                from rich.console import Console
                Console(stderr=True).print(
                    "[yellow][!] NVD API : accès refusé (403). "
                    "Votre clé API est peut-être invalide ou expirée.[/yellow]"
                )
            except ImportError:
                print("[!] NVD API : accès refusé (403). Clé API invalide ou expirée ?")
            return [{"id": "API_ERROR", "description": "NVD API : 403 Forbidden (clé invalide ?)",
                     "cvss": "N/A", "severity": "N/A"}]

        if resp.status_code == 429:
            try:
                from rich.console import Console
                hint = ("Ajoutez une clé API NVD pour un quota plus large."
                        if not api_key else
                        "Quota dépassé malgré la clé API — réessayez dans quelques secondes.")
                Console(stderr=True).print(
                    f"[yellow][!] NVD API : rate limit atteint (429). {hint}\n"
                    f"    https://nvd.nist.gov/developers/request-an-api-key[/yellow]"
                )
            except ImportError:
                print(f"[!] NVD API : rate limit atteint (429).")
            return [{"id": "API_ERROR", "description": "NVD API : rate limit dépassé (429)",
                     "cvss": "N/A", "severity": "N/A"}]

        # Un CPE mal formé ou inconnu de NVD renvoie un 404 / 400 selon les cas.
        # On retente alors automatiquement en keywordSearch plutôt que de
        # remonter une erreur sèche à l'utilisateur.
        if cpe and resp.status_code in (400, 404):
            return search_nvd_api(service, version, max_results=max_results, cpe=None)

        resp.raise_for_status()
        data    = resp.json()
        results = []

        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "N/A")

            descriptions = cve_data.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available")

            score    = "N/A"
            severity = "UNKNOWN"
            metrics  = cve_data.get("metrics", {})

            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                score     = cvss_data.get("baseScore", "N/A")
                severity  = cvss_data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                score     = cvss_data.get("baseScore", "N/A")
                severity  = "N/A (CVSSv2)"

            desc_short = desc[:200] + "..." if len(desc) > 200 else desc
            results.append({
                "id":             cve_id,
                "description":    desc_short,
                "description_fr": translate_to_french(desc_short),
                "cvss":           score,
                "severity":       severity,
                "source":         "NVD API (CPE)" if cpe else "NVD API",
            })

        # Si une requête CPE n'a rien retourné, on retente en keywordSearch
        # plutôt que de renvoyer une liste vide (le CPE résolu peut être trop
        # restrictif, ex: mauvaise version exacte) — comportement de repli
        # cohérent avec le 400/404 ci-dessus.
        if cpe and not results:
            return search_nvd_api(service, version, max_results=max_results, cpe=None)

        # Mise en cache
        cache[key] = {"timestamp": datetime.now().isoformat(), "data": results}
        _save_nvd_cache(cache)

        # Rate limiting adaptatif : 50 req/30s avec clé API, 5 req/30s sans
        # (NVD recommande de rester sous la limite officielle avec une marge)
        time.sleep(0.6 / 10 if api_key else 0.6)
        return results

    except requests.exceptions.Timeout:
        return [{"id": "API_ERROR", "description": "NVD API timeout", "cvss": "N/A", "severity": "N/A"}]
    except Exception as e:
        return [{"id": "API_ERROR", "description": f"NVD API error: {str(e)}", "cvss": "N/A", "severity": "N/A"}]


# ─── Point d'entrée principal ─────────────────────────────────────────────────

def filter_cves(
    cves: list,
    min_cvss: float,
    severity_filter: set | None,
    after_year: int | None = None,
) -> list:
    """
    Applique les filtres CVSS minimum, sévérité et année sur une liste de CVEs.
    Les filtres sont combinés en AND logique.
    Désormais dans cve_matcher pour être importable par web/pipeline.py.
    """
    import re as _re
    result = []
    for c in cves:
        if min_cvss > 0:
            try:
                score = float(str(c.get("cvss", 0)).replace("N/A", "0") or 0)
                if score < min_cvss:
                    continue
            except (ValueError, TypeError):
                continue

        if severity_filter:
            sev = str(c.get("severity", "UNKNOWN")).upper()
            if sev not in severity_filter:
                continue

        if after_year:
            cve_id = c.get("id", "")
            m = _re.match(r"CVE-(\d{4})-", cve_id, _re.IGNORECASE)
            if not m or int(m.group(1)) < after_year:
                continue

        result.append(c)
    return result


def get_cves_for_service(service_name: str, banner: str, use_api_fallback: bool = True) -> list:
    """
    Point d'entrée principal.
    1. Essaie la base locale (recent + main)
    2. Fallback API NVD avec cache si rien trouvé
       — utilise une requête par CPE (cpeName) si un CPE est résolu pour ce
         service, plus précise que keywordSearch ; retombe automatiquement
         sur keywordSearch si la résolution CPE échoue ou ne donne rien.
    """
    version     = extract_version_from_banner(banner)
    service_key = extract_service_key(service_name, banner)

    local_results = []
    if service_key:
        local_results = search_local_db(service_key, version)

    if local_results:
        return local_results

    # Fallback API NVD (avec cache)
    if use_api_fallback and (service_name or banner):
        cpe = None
        if service_key:
            try:
                from modules.cpe_resolver import resolve_cpe
                cpe = resolve_cpe(service_key, product_name=service_key, version=version,
                                   use_api_fallback=False)  # statique uniquement ici, pas de double appel réseau
            except ImportError:
                cpe = None
        return search_nvd_api(service_name if service_name else "", version, cpe=cpe)

    return []
