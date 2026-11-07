"""Chemins, constantes, base SQLite partagée (daemon / worker / UI)."""
import os, sys, json, time, socket, sqlite3, subprocess
from pathlib import Path

IS_WIN = os.name == "nt"
FROZEN = getattr(sys, "frozen", False)


def _data_dir() -> Path:
    if os.environ.get("EASYDR_HOME"):
        p = Path(os.environ["EASYDR_HOME"])
    elif IS_WIN:
        p = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "EasyDR"
    else:
        p = Path.home() / ".local/share/EasyDR"
    p.mkdir(parents=True, exist_ok=True)
    return p


DATA = _data_dir()
DB_PATH = DATA / "easydr.db"
QUAR_DIR = DATA / "quarantine"
RULES_BIN = DATA / "rules.bin"
QUAR_DIR.mkdir(parents=True, exist_ok=True)

PORT_DAEMON, PORT_WORKER, PORT_UPDATER, PORT_UI = 47653, 47654, 47655, 47656

SIGNATURE_SOURCES = [
    # (nom, repo GitHub, branche)   -> licences : voir README
    ("signature-base", "Neo23x0/signature-base", "master"),
]
YARA_EXTERNALS = dict(filename="", filepath="", extension="", filetype="", md5="", owner="")

DEFAULTS = {
    "protection": True,          # surveillance temps réel
    "auto_neutralize": True,     # quarantaine auto des menaces critiques
    "auto_kill_behavior": True,  # stoppe les comportements ransomware évidents
    "notify": True,
    "webhook_url": "",           # Discord / Slack / générique
    "update_hours": 24,
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, level TEXT, kind TEXT, title TEXT,
  detail TEXT, path TEXT, sha256 TEXT, pid INTEGER, action TEXT DEFAULT 'none', notified INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS ioc_hashes(hash TEXT PRIMARY KEY, name TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS scan_queue(
  id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT, kind TEXT, source TEXT, ts REAL, state INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS scan_cache(path TEXT PRIMARY KEY, mtime REAL, size INTEGER, rv TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS quarantine(
  id TEXT PRIMARY KEY, orig TEXT, ts REAL, reason TEXT, sha256 TEXT);
CREATE TABLE IF NOT EXISTS whitelist(sha256 TEXT PRIMARY KEY, path TEXT, ts REAL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS commands(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, cmd TEXT, arg TEXT, state INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS stats(day TEXT PRIMARY KEY, scanned INTEGER DEFAULT 0, threats INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
"""


def connect() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, timeout=20, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def init_db():
    c = connect()
    c.executescript(SCHEMA)
    c.close()


def get_setting(c, key):
    r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return json.loads(r[0]) if r else DEFAULTS[key]


def set_setting(c, key, value):
    c.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, json.dumps(value)))


def get_meta(c, key, default=None):
    r = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return r[0] if r else default


def set_meta(c, key, value):
    c.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, str(value)))


def log_event(c, level, kind, title, detail="", path=None, sha256=None, pid=None, action="none"):
    cur = c.execute(
        "INSERT INTO events(ts,level,kind,title,detail,path,sha256,pid,action) VALUES(?,?,?,?,?,?,?,?,?)",
        (time.time(), level, kind, title, detail, path, sha256, pid, action))
    return cur.lastrowid


def add_stats(c, scanned=0, threats=0):
    day = time.strftime("%Y-%m-%d")
    c.execute("INSERT OR IGNORE INTO stats(day) VALUES(?)", (day,))
    c.execute("UPDATE stats SET scanned=scanned+?, threats=threats+? WHERE day=?", (scanned, threats, day))


def singleton(port):
    """Verrou inter-processus via un port loopback. Renvoie le socket, ou None si déjà pris."""
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port)); s.listen(1)
        return s
    except OSError:
        s.close(); return None


def is_alive(port) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def spawn(flag, low=True):
    """Relance ce même programme dans un mode (--daemon, --scan-worker, --update, --ui)."""
    cmd = [sys.executable, flag] if FROZEN else [sys.executable, "-m", "easydr", flag]
    kw = {}
    if IS_WIN:
        kw["creationflags"] = (0x08000000 | 0x00004000) if low else 0  # NO_WINDOW | BELOW_NORMAL
    else:
        kw["start_new_session"] = True
    return subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, **kw)


def lower_priority(io=True):
    try:
        import psutil
        p = psutil.Process()
        if IS_WIN:
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            if io:
                p.ionice(psutil.IOPRIO_VERYLOW)
        else:
            p.nice(10)
    except Exception:
        pass


def watch_dirs():
    """Dossiers surveillés en temps réel (là où arrivent les fichiers venant de l'extérieur)."""
    if os.environ.get("EASYDR_WATCH"):
        return [d for d in os.environ["EASYDR_WATCH"].split(os.pathsep) if os.path.isdir(d)]
    import tempfile
    h = Path.home()
    c = [h / "Downloads", h / "Desktop", Path(tempfile.gettempdir()), Path(r"C:\Users\Public")]
    if IS_WIN:
        c.append(Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup")
    return [str(d) for d in c if str(d) and d.is_dir()]


def quick_dirs():
    d = watch_dirs()
    h = Path.home()
    extra = [h / "Documents"]
    if IS_WIN:
        extra += [Path(os.environ.get("APPDATA", "")), Path(os.environ.get("LOCALAPPDATA", "")) / "Temp",
                  Path(r"C:\Windows\Temp"), Path(r"C:\ProgramData")]
    return list(dict.fromkeys(d + [str(e) for e in extra if str(e) and e.is_dir()]))


def full_roots():
    try:
        import psutil
        roots = [p.mountpoint for p in psutil.disk_partitions(all=False)
                 if "cdrom" not in p.opts and p.fstype and (not IS_WIN or "fixed" in p.opts)]
        if roots:
            return roots if IS_WIN else [str(Path.home())]
    except Exception:
        pass
    return ["C:\\"] if IS_WIN else [str(Path.home())]


def enqueue(c, path, kind="file", source="realtime"):
    if kind == "file" and c.execute("SELECT 1 FROM scan_queue WHERE path=? AND state=0", (path,)).fetchone():
        return
    c.execute("INSERT INTO scan_queue(path,kind,source,ts) VALUES(?,?,?,?)", (path, kind, source, time.time()))


def log_exc(where=""):
    """Journal d'erreurs (DATA/easydr.log, tronqué à ~1 Mo) : plus aucune erreur n'est avalée en silence."""
    import traceback
    try:
        f = DATA / "easydr.log"
        if f.exists() and f.stat().st_size > 1_000_000:
            f.write_text("")
        with open(f, "a", encoding="utf-8") as h:
            h.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {where}\n{traceback.format_exc()}\n")
    except Exception:
        pass


def in_data(path) -> bool:
    """Vrai si path est dans le dossier de données d'Easy DR (comparaison de chemins, pas de préfixe texte)."""
    try:
        return Path(os.path.abspath(path)).is_relative_to(DATA)
    except Exception:
        return False
