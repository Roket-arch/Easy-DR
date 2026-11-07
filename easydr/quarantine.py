"""Neutralisation : arrêt des processus, mise en quarantaine chiffrée (XOR) et restauration."""
import os, time, uuid
from pathlib import Path
from . import config as C

_KEY = 0x5A
_TABLE = bytes(b ^ _KEY for b in range(256))


def _xor_copy(src, dst):
    with open(src, "rb") as f, open(dst, "wb") as g:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            g.write(chunk.translate(_TABLE))


def kill_processes_of(path):
    """Termine tous les processus lancés depuis ce fichier. Renvoie le nombre tué."""
    try:
        import psutil
    except ImportError:
        return 0
    n, target = 0, os.path.normcase(os.path.abspath(path))
    me = os.getpid()
    for p in psutil.process_iter(["pid", "exe"]):
        try:
            if p.pid != me and p.info["exe"] and os.path.normcase(p.info["exe"]) == target:
                p.kill(); n += 1
        except Exception:
            pass
    return n


def kill_pid(pid):
    try:
        import psutil
        p = psutil.Process(pid)
        for ch in p.children(recursive=True):
            try: ch.kill()
            except Exception: pass
        p.kill()
        return True
    except Exception:
        return False


def quarantine_file(db, path, reason, sha256=None) -> str:
    kill_processes_of(path)
    qid = uuid.uuid4().hex
    dst = C.QUAR_DIR / f"{qid}.q"
    _xor_copy(path, dst)
    try:
        os.remove(path)
    except OSError:
        os.remove(dst)
        raise
    db.execute("INSERT INTO quarantine VALUES(?,?,?,?,?)", (qid, path, time.time(), reason, sha256))
    return qid


def restore(db, qid):
    r = db.execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
    if not r:
        return
    dst = Path(r["orig"])
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst = dst.with_name(dst.stem + "_restaure" + dst.suffix)
    _xor_copy(C.QUAR_DIR / f"{qid}.q", dst)
    delete(db, qid)
    return str(dst)


def delete(db, qid):
    try:
        (C.QUAR_DIR / f"{qid}.q").unlink()
    except OSError:
        pass
    db.execute("DELETE FROM quarantine WHERE id=?", (qid,))
