"""Mise à jour des signatures depuis GitHub (processus court, libère la RAM en quittant)."""
import io, os, re, json, time, shutil, hashlib, zipfile, tempfile, urllib.request
from pathlib import Path
from . import config as C

UA = {"User-Agent": "EasyDR/1.0"}
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def _get(url, headers=None, timeout=60):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    return urllib.request.urlopen(req, timeout=timeout)


def _parse_hashes(text):
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        h, _, name = line.partition(";")
        h = h.strip()
        if HASH_RE.match(h):
            rows.append((h.lower(), (name.strip() or "IOC")[:120]))
    return rows


def _compile_all(files):
    import yara
    ns = {Path(f).stem: str(f) for f in files}
    try:
        return yara.compile(filepaths=ns, externals=C.YARA_EXTERNALS), []
    except yara.SyntaxError:
        good, bad = {}, []
        for k, f in ns.items():          # on isole les fichiers défectueux au lieu d'échouer
            try:
                yara.compile(filepath=f, externals=C.YARA_EXTERNALS); good[k] = f
            except Exception:
                bad.append(k)
        return yara.compile(filepaths=good, externals=C.YARA_EXTERNALS), bad


def update(force=False) -> str:
    c = C.connect()
    tmp = Path(tempfile.mkdtemp(prefix="easydr_"))
    try:
        yara_files, hashes, versions, shas, zips = [], [], [], {}, {}
        for name, repo, branch in C.SIGNATURE_SOURCES:   # codeload n'a pas de limite de débit comme l'API
            with _get(f"https://codeload.github.com/{repo}/zip/refs/heads/{branch}", timeout=120) as r:
                data = r.read()
            zips[name] = data
            with zipfile.ZipFile(io.BytesIO(data)) as z:   # le commentaire du zip GitHub = SHA du commit
                commit = z.comment.decode("ascii", "ignore").strip() or hashlib.sha256(data).hexdigest()
            shas[name] = commit
            versions.append(f"{name}@{commit[:7]}")
        if all(C.get_meta(c, f"sig_{n}") == v for n, v in shas.items()) and not force and C.RULES_BIN.exists():
            C.set_meta(c, "sig_checked", time.time())
            return "déjà à jour"
        for name, data in zips.items():
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for n in z.namelist():
                    rel = n.split("/", 1)[1] if "/" in n else n
                    if re.fullmatch(r"yara/[^/]+\.(yar|yara)", rel):
                        dst = tmp / f"{name}__{Path(rel).name}"
                        dst.write_bytes(z.read(n)); yara_files.append(dst)
                    elif rel == "iocs/hash-iocs.txt":
                        hashes += _parse_hashes(z.read(n).decode("utf-8", "ignore"))
        if not yara_files and not hashes:
            C.set_meta(c, "sig_checked", time.time())
            return "déjà à jour"
        msg = []
        if hashes:
            c.execute("BEGIN")
            c.execute("DELETE FROM ioc_hashes")
            c.executemany("INSERT OR REPLACE INTO ioc_hashes VALUES(?,?)", hashes)
            c.execute("COMMIT")
            msg.append(f"{len(hashes)} hash")
        if yara_files:
            rules, bad = _compile_all(yara_files)
            out = C.RULES_BIN.with_suffix(".tmp")
            rules.save(str(out)); os.replace(out, C.RULES_BIN)
            msg.append(f"{len(yara_files) - len(bad)} fichiers de règles")
        for name, sha in shas.items():
            C.set_meta(c, f"sig_{name}", sha)
        C.set_meta(c, "sig_version", " ".join(versions))
        C.set_meta(c, "sig_checked", time.time())
        C.log_event(c, "info", "update", "Signatures mises à jour", ", ".join(msg))
        return "mis à jour : " + ", ".join(msg)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        c.close()


def main(force=False):
    lock = C.singleton(C.PORT_UPDATER)
    if not lock:
        return
    C.lower_priority()
    C.init_db()
    c = C.connect()
    force = force or C.get_meta(c, "sig_force") == "1"
    C.set_meta(c, "sig_force", 0); C.set_meta(c, "sig_running", 1)
    try:
        C.set_meta(c, "sig_error", "")
        update(force)
    except Exception as e:
        C.set_meta(c, "sig_error", str(e)[:200])
        hrs = C.get_setting(c, "update_hours")
        C.set_meta(c, "sig_checked", time.time() - hrs * 3600 + 900)   # nouvel essai dans 15 min
    finally:
        C.set_meta(c, "sig_running", 0)
        c.close()
