"""Construit dist/EasyDR/ (PyInstaller, mode dossier : démarrage rapide, peu de faux positifs antivirus)."""
import sys, subprocess
from pathlib import Path
import PyInstaller.__main__ as pyi

ROOT = Path(__file__).resolve().parent.parent
subprocess.check_call([sys.executable, str(ROOT / "tools" / "make_icon.py")])
args = [
    str(ROOT / "run_easydr.py"),
    "--name", "EasyDR", "--onedir", "--noconfirm", "--clean",
    "--noconsole", "--icon", str(ROOT / "assets" / "easydr.ico"),
    "--distpath", str(ROOT / "dist"), "--workpath", str(ROOT / "build"), "--specpath", str(ROOT / "build"),
    "--collect-data", "customtkinter",
    "--collect-submodules", "watchdog.observers",
    "--hidden-import", "yara",
    "--exclude-module", "matplotlib", "--exclude-module", "numpy", "--exclude-module", "scipy",
    "--exclude-module", "pandas", "--exclude-module", "IPython", "--exclude-module", "pytest",
]
if sys.platform == "win32":
    args += ["--hidden-import", "pystray._win32"]
pyi.run(args)
print("OK ->", ROOT / "dist" / "EasyDR")
