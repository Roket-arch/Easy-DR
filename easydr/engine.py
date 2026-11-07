"""Moteur de détection : hash IOC (GitHub) + règles YARA (GitHub) + heuristiques légères."""
import os, hashlib, zlib, time
from dataclasses import dataclass, field
from pathlib import Path
from . import config as C

try:
    import yara
except ImportError:
    yara = None

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
ARCHIVES = {".zip", ".rar", ".7z", ".iso", ".img"}
SCAN_EXT = {".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx", ".msi", ".bat", ".cmd", ".ps1",
            ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".py",
            ".sh", ".elf", ".apk", ".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlsb", ".ppt",
            ".pptm", ".rtf", ".pdf", ".chm", ".reg", ".url", ".xll", ".one", ".php", ".jsp", ".aspx",
            ".txt"} | ARCHIVES
PE_OK = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".mui", ".efi", ".drv"}
EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".lnk", ".jar"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "jpeg", "png", "gif", "zip", "rar", "mp3", "mp4"}
RISKY = ("\\temp\\", "/tmp/", "\\appdata\\", "\\downloads\\", "/downloads/", "\\public\\", "\\programdata\\")
MAX_SIZE = 200 * 1024 * 1024
YARA_MAX = 32 * 1024 * 1024
CRITICAL, SUSPECT = 80, 50


@dataclass
class Verdict:
    level: str = None            # None | 'suspect' | 'critical'
    score: int = 0
    reasons: list = field(default_factory=list)
    sha256: str = None
    title: str = ""
    skipped: bool = False


def _magic(head: bytes) -> bool:
    return head[:2] == b"MZ" or head[:4] == b"\x7fELF"


def interesting(path: str) -> bool:
    """Filtre ultra-léger : faut-il même regarder ce fichier ?"""
    ext = os.path.splitext(path)[1].lower()
    if ext in SCAN_EXT:
        return True
    try:
        with open(path, "rb") as f:
            return _magic(f.read(4))
    except OSError:
        return False


class Engine:
    def __init__(self, db):
        self.db = db
        self._rules = None
        self._rules_mtime = 0
        self.rv = ""   # version des règles (invalide le cache de scan)

    def reload_if_needed(self):
        self.rv = C.get_meta(self.db, "sig_version", "none")
        if yara and C.RULES_BIN.exists():
            m = C.RULES_BIN.stat().st_mtime
            if m != self._rules_mtime:
                try:
                    self._rules = yara.load(str(C.RULES_BIN)); self._rules_mtime = m
                except Exception:
                    self._rules = None

    def _hash(self, path):
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        head = b""
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                if not head:
                    head = chunk[:1 << 20]
                md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), head

    def scan(self, path: str) -> Verdict:
        v = Verdict()
        try:
            st = os.stat(path)
            if st.st_size == 0 or st.st_size > MAX_SIZE:
                v.skipped = True; return v
            md5, sha1, sha256, head = self._hash(path)
        except OSError:
            v.skipped = True; return v
        v.sha256 = sha256
        if self.db.execute("SELECT 1 FROM whitelist WHERE sha256=?", (sha256,)).fetchone():
            return v

        score, reasons = 0, []
        row = self.db.execute("SELECT name FROM ioc_hashes WHERE hash IN (?,?,?)", (md5, sha1, sha256)).fetchone()
        if row:
            score = 100; reasons.append(f"Hash malveillant connu ({row[0]})")
        if EICAR in head[:4096]:
            score = 100; reasons.append("Fichier de test antivirus EICAR")

        p = path.lower()
        ext = os.path.splitext(p)[1]
        parts = os.path.basename(p).split(".")
        if len(parts) > 2 and ext in EXEC_EXT and parts[-2] in DOC_EXT:
            score += 50; reasons.append("Double extension trompeuse")
        if head[:2] == b"MZ" and ext not in PE_OK and ext not in (".tmp", ".bin", ".dat", ".exe_"):
            score += 50; reasons.append("Exécutable déguisé en autre type de fichier")
        if ext in EXEC_EXT and any(k in p for k in RISKY) and len(head) > 20000:
            if len(zlib.compress(head[:262144], 1)) / min(len(head), 262144) > 0.96:
                score += 25; reasons.append("Contenu compressé/chiffré (packer) dans un dossier à risque")

        if self._rules is not None and ext not in ARCHIVES and st.st_size <= YARA_MAX:
            try:
                ext_vars = dict(filename=os.path.basename(path), filepath=path,
                                extension=ext, filetype="", md5=md5, owner="")
                best = 0
                for m in self._rules.match(path, externals=ext_vars, timeout=30):
                    s = int(m.meta.get("score", 60) or 60)
                    best = max(best, s)
                    reasons.append(f"Règle YARA {m.rule} (score {s})")
                score = max(score, best) if best >= SUSPECT else score
            except Exception:
                pass

        v.score, v.reasons = score, reasons
        v.level = "critical" if score >= CRITICAL else "suspect" if score >= SUSPECT else None
        v.title = reasons[0] if reasons else ""
        return v
