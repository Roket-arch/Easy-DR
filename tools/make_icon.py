"""Génère assets/easydr.ico depuis le même dessin de bouclier que l'application."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from easydr.branding import shield

out = ROOT / "assets"; out.mkdir(exist_ok=True)
shield("info", 256).save(out / "easydr.ico", sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)])
print("icône générée :", out / "easydr.ico")
