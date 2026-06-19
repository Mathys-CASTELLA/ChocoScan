"""
ChocoScan — Module d'énumération web intelligente.

Détecte la stack web depuis les services Nmap et lance une énumération
ciblée avec des wordlists embarquées adaptées à chaque technologie.

Fonctionne sans dépendance externe obligatoire :
  - Mode natif  : requêtes HTTP Python (requests) — toujours disponible
  - Mode gobuster/feroxbuster : si l'outil est présent sur la machine

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

import re
import time
import socket
import subprocess
import shutil
import tempfile
import os
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
    from rich.rule import Rule
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None


# ─────────────────────────────────────────────────────────────────────────────
# Wordlists embarquées par stack / technologie
# ─────────────────────────────────────────────────────────────────────────────

WORDLISTS: dict[str, list[str]] = {

    # ── Générique (tout service HTTP) ─────────────────────────────────────────
    "generic": [
        "/", "/index.html", "/index.php", "/index.asp", "/index.aspx",
        "/robots.txt", "/sitemap.xml", "/.htaccess", "/.htpasswd",
        "/admin", "/admin/", "/administrator", "/administrator/",
        "/login", "/login.php", "/login.html", "/signin",
        "/dashboard", "/panel", "/cpanel", "/webadmin",
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
        "/config", "/config.php", "/config.yml", "/config.json",
        "/db", "/database", "/sql", "/dump.sql",
        "/upload", "/uploads", "/files", "/static", "/assets",
        "/images", "/img", "/js", "/css", "/fonts",
        "/test", "/testing", "/dev", "/development",
        "/old", "/bak", "/temp", "/tmp",
        "/.git", "/.git/HEAD", "/.git/config",
        "/.env", "/.env.bak", "/.env.local", "/.env.production",
        "/web.config", "/web.xml", "/server.xml",
        "/README.md", "/README", "/CHANGELOG",
        "/phpinfo.php", "/info.php", "/test.php",
        "/shell.php", "/cmd.php", "/webshell.php",
        "/crossdomain.xml", "/security.txt", "/.well-known/security.txt",
        "/error", "/404.html", "/500.html",
        "/console", "/debug", "/trace",
        "/health", "/status", "/ping", "/version",
        "/metrics", "/actuator",
    ],

    # ── Apache ────────────────────────────────────────────────────────────────
    "apache": [
        "/server-status", "/server-info", "/server-status?auto",
        "/.htaccess", "/.htpasswd", "/.htgroups",
        "/cgi-bin/", "/cgi-bin/test.cgi", "/cgi-bin/printenv.pl",
        "/cgi-bin/env.pl", "/cgi-bin/status",
        "/icons/", "/manual/", "/manual/en/",
        "/error/", "/error/403.html",
        "/apache2/", "/apache/",
        "/.svn/", "/.svn/entries",
        "/phpmyadmin", "/phpmyadmin/", "/pma/", "/PMA/",
        "/adminer", "/adminer.php",
        "/mod_status", "/mod_info",
        "/.DS_Store",
        "/WEB-INF/web.xml",
    ],

    # ── Nginx ─────────────────────────────────────────────────────────────────
    "nginx": [
        "/nginx_status", "/stub_status",
        "/.well-known/", "/favicon.ico",
        "/default", "/50x.html",
        "/proxy", "/proxy/",
        "/api/", "/api/health",
        "/internal/", "/_internal/",
        "/.nginx/", "/conf/",
        "/__nginx_status",
    ],

    # ── IIS ───────────────────────────────────────────────────────────────────
    "iis": [
        "/iisstart.htm", "/welcome.png",
        "/_vti_bin/", "/_vti_bin/shtml.dll",
        "/_vti_inf.html", "/_vti_pvt/",
        "/aspnet_client/", "/aspnet_client/system_web/",
        "/trace.axd", "/elmah.axd", "/ScriptResource.axd",
        "/WebResource.axd", "/default.aspx",
        "/admin.aspx", "/login.aspx", "/logout.aspx",
        "/.git/", "/web.config", "/global.asax",
        "/App_Data/", "/bin/", "/App_Code/",
        "/uploadedfiles/", "/uploads/",
        "/%2e%2e/", "/%2f/",
    ],

    # ── Tomcat ────────────────────────────────────────────────────────────────
    "tomcat": [
        "/manager/", "/manager/html", "/manager/text",
        "/manager/status", "/manager/jmxproxy",
        "/host-manager/", "/host-manager/html",
        "/admin/", "/admin/index.jsp",
        "/examples/", "/examples/jsp/",
        "/examples/servlets/", "/examples/websocket/",
        "/docs/", "/WEB-INF/", "/WEB-INF/web.xml",
        "/META-INF/", "/META-INF/MANIFEST.MF",
        "/index.jsp", "/default.jsp",
        "/status", "/status/",
        "/servlet/", "/servlet/default",
        "/struts/", "/spring/",
        "/axis/", "/axis/services/",
        "/axis2/", "/axis2/services/",
        "/jmx-console/", "/web-console/",
        "/invoker/JMXInvokerServlet",
        "/invoker/EJBInvokerServlet",
    ],

    # ── WordPress ─────────────────────────────────────────────────────────────
    "wordpress": [
        "/wp-login.php", "/wp-admin/", "/wp-admin/admin-ajax.php",
        "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
        "/wp-content/", "/wp-content/uploads/",
        "/wp-content/plugins/", "/wp-content/themes/",
        "/wp-includes/", "/wp-includes/version.php",
        "/wp-json/", "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts", "/wp-json/oembed/1.0/embed",
        "/xmlrpc.php", "/?feed=rss2", "/?author=1",
        "/wp-cron.php", "/wp-mail.php",
        "/wp-signup.php", "/wp-activate.php",
        "/?p=1", "/?page_id=2",
        "/wp-content/debug.log",
        "/wp-content/uploads/wpforms/",
        "/.wp-cli/", "/wp-cli.yml",
        "/wp-admin/install.php",
        "/wp-admin/upgrade.php",
        "/wp-trackback.php",
    ],

    # ── Drupal ────────────────────────────────────────────────────────────────
    "drupal": [
        "/user/login", "/user/register", "/user/password",
        "/admin/", "/admin/config", "/admin/people",
        "/node/1", "/node/add",
        "/?q=node/1", "/?q=admin",
        "/CHANGELOG.txt", "/INSTALL.txt", "/README.txt",
        "/core/CHANGELOG.txt", "/core/INSTALL.txt",
        "/sites/default/settings.php",
        "/sites/default/files/",
        "/modules/", "/themes/", "/profiles/",
        "/core/", "/vendor/",
        "/.drush/", "/drush/",
        "/web.config", "/update.php",
        "/cron.php", "/authorize.php",
        "/xmlrpc.php",
        "/admin/reports/status",
        "/admin/modules",
    ],

    # ── Joomla ────────────────────────────────────────────────────────────────
    "joomla": [
        "/administrator/", "/administrator/index.php",
        "/administrator/manifests/files/joomla.xml",
        "/configuration.php", "/configuration.php.bak",
        "/components/", "/modules/", "/plugins/",
        "/templates/", "/images/", "/media/",
        "/cache/", "/logs/", "/tmp/",
        "/api/index.php", "/api/",
        "/index.php?option=com_users&view=login",
        "/index.php?option=com_config",
        "/joomla.xml", "/htaccess.txt",
        "/web.config.txt", "/README.txt",
        "/CHANGELOG", "/LICENSE",
        "/includes/", "/libraries/",
        "/language/", "/layouts/",
    ],

    # ── PHP ───────────────────────────────────────────────────────────────────
    "php": [
        "/phpinfo.php", "/info.php", "/php.php",
        "/test.php", "/1.php", "/a.php",
        "/shell.php", "/cmd.php", "/webshell.php",
        "/upload.php", "/file.php", "/down.php",
        "/config.php", "/settings.php", "/database.php",
        "/db.php", "/conn.php", "/connect.php",
        "/admin.php", "/login.php", "/register.php",
        "/index.php", "/main.php", "/home.php",
        "/api.php", "/ajax.php", "/process.php",
        "/include/", "/includes/", "/inc/",
        "/lib/", "/libs/", "/library/",
        "/class/", "/classes/", "/model/",
        "/template/", "/templates/", "/view/",
        "/.env", "/.env.php",
        "/composer.json", "/composer.lock",
        "/vendor/", "/vendor/autoload.php",
    ],

    # ── Django ────────────────────────────────────────────────────────────────
    "django": [
        "/admin/", "/admin/login/",
        "/accounts/login/", "/accounts/logout/",
        "/accounts/register/", "/accounts/profile/",
        "/api/", "/api/v1/", "/api/v2/",
        "/api/auth/", "/api/token/",
        "/static/", "/media/",
        "/debug/", "/__debug__/",
        "/django-admin/",
        "/?format=json", "/?format=api",
        "/manage/", "/.well-known/",
        "/robots.txt", "/sitemap.xml",
        "/health/", "/healthcheck/",
    ],

    # ── Laravel ───────────────────────────────────────────────────────────────
    "laravel": [
        "/.env", "/.env.example", "/.env.bak",
        "/artisan", "/composer.json", "/composer.lock",
        "/storage/logs/laravel.log",
        "/storage/app/", "/storage/framework/",
        "/public/", "/public/index.php",
        "/app/", "/config/", "/database/",
        "/routes/web.php", "/routes/api.php",
        "/vendor/", "/vendor/autoload.php",
        "/telescope", "/telescope/requests",
        "/horizon", "/horizon/dashboard",
        "/api/", "/api/user",
        "/login", "/logout", "/register",
        "/forgot-password", "/reset-password",
        "/_debugbar/", "/debugbar/",
        "/phpinfo.php",
    ],

    # ── Spring Boot ───────────────────────────────────────────────────────────
    "spring": [
        "/actuator", "/actuator/health", "/actuator/info",
        "/actuator/env", "/actuator/beans", "/actuator/mappings",
        "/actuator/heapdump", "/actuator/threaddump",
        "/actuator/metrics", "/actuator/loggers",
        "/actuator/shutdown", "/actuator/refresh",
        "/actuator/httptrace", "/actuator/auditevents",
        "/actuator/conditions", "/actuator/configprops",
        "/actuator/flyway", "/actuator/liquibase",
        "/actuator/scheduledtasks", "/actuator/sessions",
        "/swagger-ui.html", "/swagger-ui/",
        "/v2/api-docs", "/v3/api-docs",
        "/api-docs", "/swagger.json",
        "/webjars/swagger-ui/",
        "/api/", "/api/v1/", "/graphql",
        "/jolokia/", "/jolokia/exec/",
        "/console/", "/h2-console/",
        "/spring/", "/management/",
    ],

    # ── Node.js / Express ────────────────────────────────────────────────────
    "nodejs": [
        "/api/", "/api/v1/", "/api/v2/",
        "/api/users", "/api/auth", "/api/login",
        "/graphql", "/graphiql",
        "/.env", "/package.json", "/package-lock.json",
        "/node_modules/", "/.npmrc",
        "/public/", "/static/", "/dist/", "/build/",
        "/health", "/healthz", "/ready", "/live",
        "/metrics", "/status",
        "/socket.io/", "/ws/",
        "/dashboard", "/admin",
        "/login", "/logout", "/register",
        "/__proto__", "/constructor",
        "/debug", "/?debug=true",
    ],

    # ── Jenkins ───────────────────────────────────────────────────────────────
    "jenkins": [
        "/", "/login", "/logout",
        "/asynchPeople/", "/people/",
        "/systemInfo", "/system/", "/configure",
        "/script", "/scriptText",
        "/computer/", "/credentials/",
        "/job/", "/view/",
        "/cli", "/jnlpJars/jenkins-cli.jar",
        "/api/json", "/api/xml",
        "/whoAmI/", "/me/",
        "/securityRealm/", "/administrativeMonitor/",
        "/pluginManager/", "/updateCenter/",
        "/descriptorByName/", "/log/",
        "/git/notifyCommit", "/svn/notifyCommit",
        "/subversion/", "/github-webhook/",
        "/queue/api/json",
        "/overallLoad/api/json",
        "/manage", "/safeExit",
    ],

    # ── GitLab ────────────────────────────────────────────────────────────────
    "gitlab": [
        "/users/sign_in", "/users/sign_up",
        "/explore", "/explore/projects",
        "/admin/", "/admin/users", "/admin/groups",
        "/-/health", "/-/readiness", "/-/liveness",
        "/-/metrics", "/-/debug/rails/",
        "/api/v4/users", "/api/v4/projects",
        "/api/v4/version", "/api/v4/settings",
        "/-/graphql-explorer",
        "/help/", "/-/profile",
        "/-/ide/", "/uploads/",
        "/assets/", "/-/jwks",
        "/oauth/authorize", "/oauth/token",
    ],

    # ── phpMyAdmin ────────────────────────────────────────────────────────────
    "phpmyadmin": [
        "/phpmyadmin/", "/phpmyadmin/index.php",
        "/phpMyAdmin/", "/phpMyAdmin/index.php",
        "/pma/", "/pma/index.php",
        "/PMA/", "/mysql/", "/mysqladmin/",
        "/db/", "/dbadmin/",
        "/phpMyAdmin-latest-all-languages/",
        "/phpmyadmin2/", "/phpmyadmin3/",
        "/sql/", "/myadmin/",
    ],

    # ── Kibana ────────────────────────────────────────────────────────────────
    "kibana": [
        "/", "/app/home", "/app/kibana",
        "/api/status", "/api/features",
        "/api/saved_objects/",
        "/s/default/app/",
        "/login", "/logout",
        "/app/management", "/app/monitoring",
        "/app/apm", "/app/logs",
        "/api/console/proxy", "/api/console/api_server",
        "/bundles/", "/ui/fonts/",
        "/.kibana/", "/_cat/indices",
        "/elasticsearch/", "/api/elasticsearch/",
    ],

    # ── Grafana ───────────────────────────────────────────────────────────────
    "grafana": [
        "/login", "/logout",
        "/api/health", "/api/org",
        "/api/users", "/api/user",
        "/api/datasources", "/api/dashboards/home",
        "/api/search", "/api/annotations",
        "/api/admin/users", "/api/admin/settings",
        "/api/frontend/settings",
        "/d/", "/dashboard/",
        "/explore", "/alerting/",
        "/plugins/", "/public/",
        "/?orgId=1",
        "/render/", "/avatar/",
    ],

    # ── Webmin ────────────────────────────────────────────────────────────────
    "webmin": [
        "/", "/session_login.cgi",
        "/unauthenticated/", "/images/",
        "/fastrpc.cgi", "/miniserv.pl",
        "/proc/net/tcp", "/etc/passwd",
        "/file/show.cgi", "/file/",
        "/shell/index.cgi", "/shell/",
        "/net/index.cgi", "/system-status/",
        "/package-updates/", "/webmin/",
        "/usermin/", "/virtualmin/",
        "/cgi-bin/", "/virtual-server/",
    ],

    # ── Tomcat Manager ───────────────────────────────────────────────────────
    "tomcat_manager": [
        "/manager/html", "/manager/text", "/manager/status",
        "/host-manager/html", "/host-manager/text",
        "/manager/html/list", "/manager/html/deploy",
        "/manager/html/undeploy",
    ],

    # ── API REST générique ───────────────────────────────────────────────────
    "api": [
        "/api", "/api/", "/api/v1", "/api/v1/",
        "/api/v2", "/api/v2/", "/api/v3",
        "/api/health", "/api/status", "/api/ping",
        "/api/version", "/api/info",
        "/api/users", "/api/user", "/api/me",
        "/api/admin", "/api/config",
        "/api/login", "/api/auth", "/api/token",
        "/api/refresh", "/api/logout",
        "/api/docs", "/api/swagger",
        "/api/graphql", "/api/schema",
        "/graphql", "/graphiql",
        "/swagger", "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/redoc", "/docs",
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/oauth2/authorize", "/oauth2/token",
        "/connect/token", "/connect/authorize",
    ],

    # ── Sonarqube ─────────────────────────────────────────────────────────────
    "sonarqube": [
        "/", "/sessions/new", "/admin/",
        "/api/system/status", "/api/system/info",
        "/api/users/search", "/api/projects/search",
        "/api/settings/values", "/api/authentication/login",
        "/web_api/", "/api/issues/search",
        "/dashboard", "/projects",
        "/account/", "/account/security",
        "/admin/users", "/admin/groups",
    ],

    # ── ColdFusion ────────────────────────────────────────────────────────────
    "coldfusion": [
        "/CFIDE/", "/CFIDE/administrator/",
        "/CFIDE/adminapi/", "/CFIDE/componentutils/",
        "/CFIDE/debug/", "/CFIDE/scripts/",
        "/CFIDE/administrator/index.cfm",
        "/CFIDE/administrator/login.cfm",
        "/cfusion/", "/lucee/",
        "/railo/", "/railo-context/",
        "/WEB-INF/", "/WEB-INF/web.xml",
        "/index.cfm", "/default.cfm",
        "/admin.cfm", "/login.cfm",
        "/Application.cfc", "/Application.cfm",
    ],

    # ── Splunk ────────────────────────────────────────────────────────────────
    "splunk": [
        "/", "/en-US/account/login",
        "/services/", "/services/authentication/",
        "/services/auth/login", "/services/properties/",
        "/en-US/app/", "/en-US/manager/",
        "/api/", "/api/v1/",
        "/services/server/info",
        "/services/server/settings/",
        "/services/configs/",
        "/services/saved/searches",
        "/en-US/debug/refresh",
        "/robots.txt",
    ],

    # ── GLPI ──────────────────────────────────────────────────────────────────
    "glpi": [
        "/", "/index.php", "/front/",
        "/login.php", "/logout.php",
        "/apirest.php", "/api.php",
        "/install/", "/install/install.php",
        "/config/", "/files/", "/pics/",
        "/plugins/", "/lib/", "/inc/",
        "/locales/", "/ajax/",
        "/front/central.php",
        "/front/helpdesk.public.php",
        "/front/tracking.injector.php",
    ],

    # ── OFBiz ─────────────────────────────────────────────────────────────────
    "ofbiz": [
        "/accounting/", "/catalog/",
        "/ordermgr/", "/partymgr/",
        "/webtools/", "/webtools/control/main",
        "/webtools/control/ViewHandlerExt",
        "/main?USERNAME=&PASSWORD=&requirePasswordChange=Y",
        "/accounting/control/main",
        "/webtools/control/ProgramExport",
        "/webtools/control/xmlrpc;jsessionid=",
        "/content/control/main",
        "/ecommerce/control/main",
        "/webtools/control/LookupInvoice",
    ],

    # ── Moodle ────────────────────────────────────────────────────────────────
    "moodle": [
        "/login/", "/login/index.php",
        "/admin/", "/admin/index.php",
        "/course/", "/user/",
        "/mod/", "/lib/", "/theme/",
        "/blocks/", "/filter/",
        "/webservice/", "/webservice/rest/server.php",
        "/webservice/soap/server.php",
        "/config.php", "/version.php",
        "/local/", "/auth/",
        "/enrol/", "/grade/",
        "/report/", "/question/",
        "/?redirect=0",
    ],

    # ── Cacti ─────────────────────────────────────────────────────────────────
    "cacti": [
        "/", "/index.php", "/graph_view.php",
        "/login.php", "/logout.php",
        "/remote_agent.php",
        "/api_device.php", "/api_graph.php",
        "/settings.php", "/utilities.php",
        "/host.php", "/graph.php",
        "/scripts/", "/plugins/",
        "/include/", "/lib/",
        "/log/", "/cache/",
        "/images/", "/formats/",
        "/mibs/", "/resource/",
    ],

    # ── Roundcube ─────────────────────────────────────────────────────────────
    "roundcube": [
        "/", "/index.php", "/?_task=login",
        "/installer/", "/installer/index.php",
        "/config/", "/logs/", "/temp/",
        "/plugins/", "/skins/", "/vendor/",
        "/program/", "/program/include/",
        "/.htaccess", "/composer.json",
        "/config/config.inc.php",
        "/config/defaults.inc.php",
        "/?_task=settings",
        "/?_task=logout",
    ],

}


# ─────────────────────────────────────────────────────────────────────────────
# Correspondances service Nmap → stacks wordlist
# ─────────────────────────────────────────────────────────────────────────────

# Chaque entrée : (pattern_regex, [stacks_à_utiliser])
# Les patterns sont comparés au banner/product Nmap (insensible à la casse)
STACK_DETECTION_RULES: list[tuple[str, list[str]]] = [

    # Serveurs web
    (r"apache",                 ["generic", "apache", "php"]),
    (r"nginx",                  ["generic", "nginx"]),
    (r"iis|internet information", ["generic", "iis"]),
    (r"lighttpd",               ["generic", "php"]),
    (r"litespeed",              ["generic", "php"]),
    (r"caddy",                  ["generic"]),
    (r"openresty",              ["generic", "nginx"]),

    # Application servers
    (r"tomcat|apache.tomcat|apache-coyote", ["generic", "tomcat", "tomcat_manager"]),
    (r"jboss|wildfly",          ["generic", "tomcat"]),
    (r"weblogic",               ["generic", "tomcat"]),
    (r"websphere",              ["generic", "tomcat"]),
    (r"glassfish",              ["generic", "tomcat"]),
    (r"jetty",                  ["generic", "spring"]),

    # CMS
    (r"wordpress|wp-",          ["generic", "wordpress", "php"]),
    (r"drupal",                 ["generic", "drupal", "php"]),
    (r"joomla",                 ["generic", "joomla", "php"]),
    (r"moodle",                 ["generic", "moodle", "php"]),

    # Frameworks / langages
    (r"php",                    ["generic", "php"]),
    (r"django",                 ["generic", "django"]),
    (r"laravel",                ["generic", "laravel", "php"]),
    (r"flask",                  ["generic", "api"]),
    (r"rails|ruby",             ["generic", "api"]),
    (r"spring|springboot",      ["generic", "spring"]),
    (r"node|express|next\.?js", ["generic", "nodejs"]),

    # DevOps / monitoring
    (r"jenkins",                ["generic", "jenkins"]),
    (r"gitlab",                 ["generic", "gitlab"]),
    (r"grafana",                ["generic", "grafana"]),
    (r"kibana",                 ["generic", "kibana"]),
    (r"sonarqube|sonar",        ["generic", "sonarqube"]),
    (r"splunk",                 ["generic", "splunk"]),

    # Admin / BDD
    (r"phpmyadmin|pma",         ["generic", "phpmyadmin"]),
    (r"adminer",                ["generic", "phpmyadmin"]),
    (r"webmin",                 ["generic", "webmin"]),
    (r"coldfusion|lucee|railo", ["generic", "coldfusion"]),

    # ITSM / CMDB
    (r"glpi",                   ["generic", "glpi"]),
    (r"cacti",                  ["generic", "cacti"]),
    (r"roundcube",              ["generic", "roundcube"]),
    (r"ofbiz",                  ["generic", "ofbiz"]),
    (r"moodle",                 ["generic", "moodle"]),

    # Ports typiques sans banner identifié
]

# Ports web courants : port → stacks par défaut si aucune banner reconnue
PORT_DEFAULTS: dict[int, list[str]] = {
    80:   ["generic"],
    443:  ["generic"],
    8080: ["generic", "tomcat"],
    8443: ["generic", "spring"],
    8000: ["generic", "django"],
    8001: ["generic"],
    8008: ["generic"],
    8009: ["generic", "tomcat"],
    8081: ["generic"],
    8082: ["generic"],
    8888: ["generic", "nodejs", "jupyter"],
    8983: ["generic"],           # Solr
    9000: ["generic"],           # SonarQube
    9090: ["generic"],           # Prometheus
    9200: ["generic"],           # Elasticsearch
    3000: ["generic", "grafana", "nodejs"],
    4848: ["generic"],           # GlassFish
    5000: ["generic", "api"],
    5601: ["generic", "kibana"],
    7474: ["generic"],           # Neo4j
    10000: ["generic", "webmin"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Structures de données
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WebTarget:
    """Représente une cible HTTP à énumérer."""
    host: str
    port: int
    scheme: str           # "http" ou "https"
    service_name: str
    banner: str
    detected_stacks: list[str] = field(default_factory=list)

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass
class EnumResult:
    """Résultat d'une requête d'énumération."""
    url: str
    status_code: int
    content_length: int
    title: str
    redirect: str
    interesting: bool     # heuristique : vaut le coup d'être regardé


# ─────────────────────────────────────────────────────────────────────────────
# Détection de stack
# ─────────────────────────────────────────────────────────────────────────────

def detect_stacks(service_name: str, banner: str, port: int) -> list[str]:
    """
    Détecte les stacks applicatives depuis le service Nmap.
    Retourne une liste dédupliquée de clés wordlist.
    """
    combined = f"{service_name} {banner}".lower()
    stacks = []

    for pattern, stack_keys in STACK_DETECTION_RULES:
        if re.search(pattern, combined, re.IGNORECASE):
            for k in stack_keys:
                if k not in stacks:
                    stacks.append(k)

    # Fallback sur le port si aucune stack détectée
    if not stacks and port in PORT_DEFAULTS:
        stacks = PORT_DEFAULTS[port].copy()

    # Toujours inclure generic en premier
    if "generic" not in stacks:
        stacks.insert(0, "generic")

    return stacks


def build_wordlist(stacks: list[str]) -> list[str]:
    """
    Construit la wordlist finale en fusionnant les stacks détectées,
    en dédupliquant et en préservant l'ordre.
    """
    seen = set()
    paths = []
    for stack in stacks:
        for path in WORDLISTS.get(stack, []):
            if path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


# ─────────────────────────────────────────────────────────────────────────────
# Détection HTTP/HTTPS
# ─────────────────────────────────────────────────────────────────────────────

def detect_scheme(host: str, port: int) -> str:
    """Détermine si le port utilise HTTP ou HTTPS."""
    # Ports HTTPS classiques
    https_ports = {443, 8443, 4443, 9443, 8843}
    if port in https_ports:
        return "https"
    if not REQUESTS_AVAILABLE:
        return "http"
    # Test HTTPS d'abord
    try:
        r = requests.get(
            f"https://{host}:{port}/",
            timeout=4, verify=False,
            allow_redirects=False
        )
        return "https"
    except Exception:
        pass
    return "http"


def extract_title(html: str) -> str:
    """Extrait le titre HTML d'une page."""
    m = re.search(r"<title[^>]*>([^<]{1,120})</title>", html, re.IGNORECASE)
    if m:
        return m.group(1).strip()[:80]
    return ""


def is_interesting(status: int, length: int, title: str, path: str) -> bool:
    """
    Heuristique pour identifier les résultats méritant attention.
    """
    # Codes intéressants
    if status in (200, 201, 301, 302, 307, 308, 401, 403):
        # Exclure les pages vides
        if status == 200 and length < 10:
            return False
        return True
    # 500 sur des paths sensibles = potentiellement intéressant
    if status == 500 and any(kw in path for kw in
                             ["/admin", "/config", "/api", "/manager", "/actuator"]):
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Énumération native (requests Python)
# ─────────────────────────────────────────────────────────────────────────────

def enumerate_native(
    target: WebTarget,
    paths: list[str],
    threads: int = 10,
    delay: float = 0.05,
) -> list[EnumResult]:
    """
    Énumération HTTP via requests Python — aucune dépendance externe.
    Utilise un pool de threads simple pour la parallélisation.
    """
    if not REQUESTS_AVAILABLE:
        return []

    import concurrent.futures

    results: list[EnumResult] = []
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (ChocoScan WebEnum)",
        "Accept": "text/html,application/json,*/*",
    })

    def probe(path: str) -> Optional[EnumResult]:
        url = f"{target.base_url}{path}"
        try:
            r = session.get(
                url, timeout=5, verify=False,
                allow_redirects=False,
                stream=False,
            )
            length = len(r.content)
            title  = extract_title(r.text[:4096]) if "html" in r.headers.get("content-type", "") else ""
            redir  = r.headers.get("Location", "")
            interesting = is_interesting(r.status_code, length, title, path)
            time.sleep(delay)
            return EnumResult(
                url=url,
                status_code=r.status_code,
                content_length=length,
                title=title,
                redirect=redir,
                interesting=interesting,
            )
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe, p): p for p in paths}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res and res.status_code not in (404, 400):
                results.append(res)

    return sorted(results, key=lambda x: (x.status_code, -x.content_length))


# ─────────────────────────────────────────────────────────────────────────────
# Point d'entrée principal
# ─────────────────────────────────────────────────────────────────────────────

def run_web_enum(
    services: list,          # liste de NmapService
    threads: int = 10,
    delay: float = 0.05,
    output_dir: str = "output",
) -> list[dict]:
    """
    Lance l'énumération web sur tous les services HTTP/HTTPS détectés.

    Args:
        services   : liste de NmapService issus du parser Nmap
        threads    : nombre de threads par cible
        delay      : délai entre requêtes (secondes)
        output_dir : dossier pour les fichiers wordlist temporaires

    Returns:
        Liste de dicts {target, stacks, wordlist_size, results}
    """
    if not REQUESTS_AVAILABLE:
        if console:
            console.print("[red][!] Module 'requests' manquant — énumération web impossible.[/red]")
        return []

    # Identifier les services web
    web_services = []
    web_ports    = set(PORT_DEFAULTS.keys()) | {80, 443, 8080, 8443}
    web_keywords = {"http", "https", "web", "www", "ssl", "tls"}

    for svc in services:
        is_web = (
            svc.port in web_ports or
            any(kw in svc.service_name.lower() for kw in web_keywords) or
            any(kw in svc.banner.lower() for kw in web_keywords)
        )
        if is_web:
            web_services.append(svc)

    if not web_services:
        if console:
            console.print("[yellow][!] Aucun service web détecté pour l'énumération.[/yellow]")
        return []

    if console:
        console.print()
        console.print(f"[bold cyan][*] Énumération web — {len(web_services)} service(s) web détecté(s)[/bold cyan]")

    all_enum_results = []

    for svc in web_services:
        scheme = detect_scheme(svc.host, svc.port)
        stacks = detect_stacks(svc.service_name, svc.banner, svc.port)
        paths  = build_wordlist(stacks)

        target = WebTarget(
            host=svc.host,
            port=svc.port,
            scheme=scheme,
            service_name=svc.service_name,
            banner=svc.banner,
            detected_stacks=stacks,
        )

        if console:
            console.print()
            console.print(f"[bold]→ {target.base_url}[/bold] — {svc.banner or svc.service_name}")
            stacks_display = ", ".join(s for s in stacks if s != "generic")
            console.print(f"  Stacks détectées : [cyan]{stacks_display or 'générique'}[/cyan]")
            console.print(f"  Wordlist : [cyan]{len(paths)} chemins[/cyan]")

        # Énumération avec barre de progression
        results: list[EnumResult] = []

        if console:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(
                    f"  [cyan]Énumération {target.base_url}...[/cyan]",
                    total=len(paths)
                )

                # Traitement par batch pour mettre à jour la progression
                import concurrent.futures
                session = requests.Session()
                session.headers.update({"User-Agent": "Mozilla/5.0 (ChocoScan WebEnum)"})

                def probe(path):
                    url = f"{target.base_url}{path}"
                    try:
                        r = session.get(url, timeout=5, verify=False,
                                       allow_redirects=False)
                        length = len(r.content)
                        title  = extract_title(r.text[:4096]) if "html" in r.headers.get("content-type","") else ""
                        redir  = r.headers.get("Location", "")
                        inter  = is_interesting(r.status_code, length, title, path)
                        time.sleep(delay)
                        return EnumResult(url, r.status_code, length, title, redir, inter)
                    except Exception:
                        return None

                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
                    futures = {ex.submit(probe, p): p for p in paths}
                    for fut in concurrent.futures.as_completed(futures):
                        progress.advance(task)
                        res = fut.result()
                        if res and res.status_code not in (404, 400, 405):
                            results.append(res)

        else:
            results = enumerate_native(target, paths, threads, delay)

        results.sort(key=lambda x: (x.status_code, -x.content_length))

        # Affichage des résultats
        if console:
            display_enum_results(target, results)

        all_enum_results.append({
            "target": target.base_url,
            "host": svc.host,
            "port": svc.port,
            "stacks": stacks,
            "wordlist_size": len(paths),
            "results": [
                {
                    "url": r.url,
                    "status": r.status_code,
                    "length": r.content_length,
                    "title": r.title,
                    "redirect": r.redirect,
                    "interesting": r.interesting,
                }
                for r in results
            ],
        })

    return all_enum_results


# ─────────────────────────────────────────────────────────────────────────────
# Affichage terminal
# ─────────────────────────────────────────────────────────────────────────────

# Couleurs par code HTTP
STATUS_COLORS = {
    200: "bold green",
    201: "green",
    204: "green",
    301: "cyan",
    302: "cyan",
    307: "cyan",
    308: "cyan",
    401: "yellow",
    403: "yellow",
    405: "dim",
    500: "bold red",
    503: "red",
}


def status_color(code: int) -> str:
    return STATUS_COLORS.get(code, "white")


def display_enum_results(target: WebTarget, results: list[EnumResult]):
    """Affiche les résultats d'énumération dans un tableau Rich."""
    if not console or not results:
        if console:
            console.print("  [dim]Aucun résultat notable.[/dim]")
        return

    interesting = [r for r in results if r.interesting]
    others      = [r for r in results if not r.interesting]

    console.print(f"\n  [bold]Résultats — {len(results)} réponses[/bold] "
                  f"([green]{len(interesting)} intéressants[/green])")

    if not results:
        console.print("  [dim]Aucun chemin accessible trouvé.[/dim]")
        return

    table = Table(
        box=box.SIMPLE_HEAVY, show_header=True,
        header_style="bold", expand=True
    )
    table.add_column("Code", justify="center", width=6)
    table.add_column("URL", no_wrap=False)
    table.add_column("Taille", justify="right", width=8)
    table.add_column("Titre / Redirect", no_wrap=False)

    # Intéressants d'abord
    for r in interesting[:40]:
        color = status_color(r.status_code)
        extra = r.redirect if r.redirect else r.title
        table.add_row(
            f"[{color}]{r.status_code}[/{color}]",
            f"[{color}]{r.url}[/{color}]",
            str(r.content_length),
            f"[dim]{extra[:60]}[/dim]" if extra else "",
        )

    # Séparateur si on a aussi des non-intéressants
    if others and interesting:
        table.add_row("[dim]---[/dim]", "[dim]autres[/dim]", "", "")

    for r in others[:15]:
        color = status_color(r.status_code)
        extra = r.redirect if r.redirect else r.title
        table.add_row(
            f"[dim]{r.status_code}[/dim]",
            f"[dim]{r.url}[/dim]",
            f"[dim]{r.content_length}[/dim]",
            f"[dim]{extra[:60]}[/dim]" if extra else "",
        )

    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# Export pour rapport HTML/JSON
# ─────────────────────────────────────────────────────────────────────────────

def enum_results_to_html_section(enum_results: list[dict]) -> str:
    """Génère une section HTML pour le rapport ChocoScan."""
    if not enum_results:
        return ""

    html = """
<div class="section enum-section">
  <h2>🌐 Énumération Web</h2>
"""
    for target_data in enum_results:
        results = target_data.get("results", [])
        stacks  = [s for s in target_data.get("stacks", []) if s != "generic"]
        interesting = [r for r in results if r.get("interesting")]

        html += f"""
  <div class="enum-target">
    <h3>{target_data['target']}</h3>
    <p class="enum-meta">
      Stacks détectées : <strong>{', '.join(stacks) or 'générique'}</strong> —
      Chemins testés : <strong>{target_data['wordlist_size']}</strong> —
      Résultats : <strong>{len(results)}</strong>
      (dont <strong class="interesting-count">{len(interesting)}</strong> intéressants)
    </p>
    <table class="enum-table">
      <thead>
        <tr><th>Code</th><th>URL</th><th>Taille</th><th>Titre / Redirect</th></tr>
      </thead>
      <tbody>
"""
        for r in sorted(results, key=lambda x: (not x.get("interesting"), x.get("status", 999))):
            code    = r.get("status", 0)
            url     = r.get("url", "")
            length  = r.get("length", 0)
            title   = r.get("title") or r.get("redirect") or ""
            inter   = r.get("interesting", False)
            css     = "interesting" if inter else ""
            color   = {
                200: "#4caf50", 201: "#4caf50",
                301: "#2196f3", 302: "#2196f3", 307: "#2196f3",
                401: "#ff9800", 403: "#ff9800",
                500: "#f44336",
            }.get(code, "#9e9e9e")

            html += f"""
        <tr class="{css}">
          <td style="color:{color};font-weight:bold">{code}</td>
          <td><a href="{url}" target="_blank">{url}</a></td>
          <td>{length}</td>
          <td>{title[:80]}</td>
        </tr>"""

        html += """
      </tbody>
    </table>
  </div>
"""

    html += "</div>\n"
    return html
