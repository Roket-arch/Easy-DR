"""Identité visuelle : palette et icônes générées (aucun fichier image à embarquer)."""
from PIL import Image, ImageDraw

BG = "#0B1220"
SIDEBAR = "#080E1A"
CARD = "#131D31"
CARD2 = "#1A2742"
LINE = "#23324F"
TEXT = "#E8EEF9"
MUTED = "#8DA0BF"
BLUE = "#2F6BFF"
BLUE_H = "#4A82FF"
GREEN = "#22C55E"
RED = "#EF4444"
AMBER = "#F59E0B"
GRAY = "#64748B"

STATE_COLOR = {"ok": GREEN, "warn": RED, "off": GRAY, "info": BLUE}

_SHIELD = [(0.5, 0.04), (0.88, 0.17), (0.88, 0.50), (0.81, 0.68), (0.66, 0.84), (0.5, 0.96),
           (0.34, 0.84), (0.19, 0.68), (0.12, 0.50), (0.12, 0.17)]


def shield(state="ok", size=128) -> Image.Image:
    S = size * 4
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    col = STATE_COLOR.get(state, BLUE)
    d.polygon([(x * S, y * S) for x, y in _SHIELD], fill=col)
    inner = [(0.5 * S + (x * S - 0.5 * S) * 0.82, 0.5 * S + (y * S - 0.5 * S) * 0.82) for x, y in _SHIELD]
    d.polygon(inner, outline=(255, 255, 255, 70), width=max(2, S // 60))
    w = max(6, S // 13)
    white = (255, 255, 255, 255)
    if state in ("ok", "info"):
        pts = [(0.33 * S, 0.50 * S), (0.45 * S, 0.63 * S), (0.69 * S, 0.37 * S)]
        d.line(pts, fill=white, width=w, joint="curve")
        for p in (pts[0], pts[-1]):
            d.ellipse([p[0] - w / 2, p[1] - w / 2, p[0] + w / 2, p[1] + w / 2], fill=white)
    elif state == "warn":
        d.line([(0.5 * S, 0.30 * S), (0.5 * S, 0.58 * S)], fill=white, width=w)
        d.ellipse([0.5 * S - w * 0.7, 0.67 * S - w * 0.7, 0.5 * S + w * 0.7, 0.67 * S + w * 0.7], fill=white)
    else:
        d.line([(0.36 * S, 0.5 * S), (0.64 * S, 0.5 * S)], fill=white, width=w)
    return im.resize((size, size), Image.LANCZOS)
