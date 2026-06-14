"""
Convertit une image (logo ChocoScan) en art ANSI affichable dans un terminal
via rich, en utilisant des blocs colorés (half-block rendering pour doubler
la résolution verticale).
"""

from PIL import Image


def image_to_rich_art(path: str, width: int = 50) -> str:
    """
    Convertit une image en chaîne rich markup utilisant des demi-blocs (▀)
    pour afficher deux pixels par caractère (haut/bas) avec couleurs truecolor.
    """
    img = Image.open(path).convert("RGB")

    # Calcul de la hauteur en conservant le ratio (x2 car demi-blocs)
    ratio = img.height / img.width
    height = int(width * ratio)
    if height % 2 != 0:
        height += 1

    img = img.resize((width, height), Image.LANCZOS)

    lines = []
    for y in range(0, height, 2):
        line = ""
        for x in range(width):
            top = img.getpixel((x, y))
            bottom = img.getpixel((x, y + 1)) if y + 1 < height else top
            tr, tg, tb = top
            br, bg, bb = bottom
            # Caractère demi-bloc haut, couleur fg=haut, bg=bas
            line += f"[rgb({tr},{tg},{tb}) on rgb({br},{bg},{bb})]▀[/]"
        lines.append(line)

    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    from rich.console import Console
    console = Console()
    path = sys.argv[1] if len(sys.argv) > 1 else "assets/chocowake.png"
    width = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    art = image_to_rich_art(path, width)
    console.print(art)
