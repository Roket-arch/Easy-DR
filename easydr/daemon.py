"""Daemon d'arrière-plan : léger (surveillance + tray + alertes). Les analyses lourdes sont déléguées
au worker, qui n'existe en mémoire que quand il y a du travail."""
import os, re, sys, json, time, threading, urllib.request
from pathlib import Path
from . import config as C
from . import quarantine as Q
from .engine import interesting

try:
    import psutil
except ImportError:
    psutil = None
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer, FileSystemEventHandler = None, object

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
          "rundll32.exe", "regsvr32.exe"}
# (regex, titre, niveau, arrêt automatique du processus)
CMD_RULES = [
    (r"vssadmin(\.exe)?\s+delete\s+shadows", "Suppression des copies cliché (typique ransomware)", "critical", True),
    (r"wmic.*shadowcopy\s+delete", "Suppression des copies cliché (typique ransomware)", "critical", True),
    (r"bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", "Sabotage de la récupération Windows", "critical", True),
    (r"wbadmin\s+delete\s+(catalog|backup)", "Suppression des sauvegardes Windows", "critical", True),
    (r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{60,}", "PowerShell encodé (obfusqué)", "suspect", False),
    (r"certutil.*-urlcache.*http", "Téléchargement via certutil", "suspect", False),
    (r"mshta(\.exe)?\s+https?://", "mshta exécute un script distant", "suspect", False),
    (r"(curl|wget)[^|]*\|\s*(ba)?sh", "Exécution directe d'un script téléchargé", "suspect", False),
]


class Daemon:
    @property
    def db(self):
        """Une connexion SQLite par thread (SQLite l'exige ; tray, watchdog et boucles sont des threads distincts)."""
        c = getattr(self._tl, "c", None)
        if c is None:
            c = self._tl.c = C.connect()
        return c

    def __init__(self):
        self._tl = threading.local()
        self.stop = threading.Event()
        self.pend = {}
        self.protection = True
        self.icon = None
        self.observer = None

    # ───────── temps réel : fichiers
    def start_watchers(self):
        if not Observer:
            C.log_exc("watchdog indisponible"); return
        outer = self

        class H(FileSystemEventHandler):
            def _add(self, p):
                if p and outer.protection and not C.in_data(p):
                    outer.pend[p] = time.time()
            def on_created(self, e): not e.is_directory and self._add(e.src_path)
            def on_modified(self, e): not e.is_directory and self._add(e.src_path)
            def on_moved(self, e): not e.is_directory and self._add(e.dest_path)

        try:
            self.observer = Observer()
        except Exception:
            C.log_exc("observer"); return
        h = H()
        for d in C.watch_dirs():
            try:
                self.observer.schedule(h, d, recursive=True)
            except Exception:
                C.log_exc(f"watch {d}")
        self.observer.daemon = True
        self.observer.start()

    def flush_pending(self):
        now = time.time()
        for p, t in list(self.pend.items()):
            if now - t > 1.5:                       # on attend que l'écriture soit terminée
                self.pend.pop(p, None)
                if os.path.isfile(p) and interesting(p):
                    C.enqueue(self.db, p, "file", "realtime")

    # ───────── temps réel : comportements
    def behavior_loop(self):
        if not psutil:
            return
        known = set(psutil.pids())
        while not self.stop.wait(2):
            cur = set(psutil.pids())
            new, known = cur - known, cur
            if not self.protection:
                continue
            for pid in new:
                try:
                    self.analyse(pid)
                except Exception as e:
                    if not isinstance(e, psutil.Error):
                        C.log_exc("analyse")

    def analyse(self, pid):
        p = psutil.Process(pid)
        name = (p.name() or "").lower()
        try:
            cmd = " ".join(p.cmdline())
        except Exception:
            cmd = ""
        try:
            exe = p.exe()
        except Exception:
            exe = ""
        try:
            parent = (p.parent().name() or "").lower() if p.parent() else ""
        except Exception:
            parent = ""
        for rx, title, level, kill in CMD_RULES:
            if re.search(rx, cmd, re.I):
                if parent in OFFICE and level == "suspect":
                    level = "critical"
                self._behavior(pid, title, level, kill, cmd, exe)
                return
        if parent in OFFICE and name in SHELLS:
            self._behavior(pid, f"{parent} a lancé {name}", "suspect", False, cmd, exe)
        low = exe.lower()
        if exe and any(k in low for k in ("\\temp\\", "/tmp/", "\\appdata\\local\\temp", "\\downloads\\")) \
                and not C.in_data(exe):
            C.enqueue(self.db, exe, "file", "process")       # le worker (avec cache) tranchera

    def _behavior(self, pid, title, level, kill, cmd, exe):
        action = "none"
        if kill and C.get_setting(self.db, "auto_kill_behavior") and Q.kill_pid(pid):
            action = "killed"
        C.log_event(self.db, level, "behavior", title, cmd[:300], exe or None, None, pid, action)
        C.add_stats(self.db, 0, 1)

    # ───────── alertes (notification + webhook)
    def notifier(self):
        rows = self.db.execute("SELECT * FROM events WHERE notified=0 AND level IN ('critical','suspect') "
                               "ORDER BY id LIMIT 10").fetchall()
        for r in rows:
            self.db.execute("UPDATE events SET notified=1 WHERE id=?", (r["id"],))
            if not C.get_setting(self.db, "notify"):
                continue
            done = r["action"] in ("quarantined", "killed")
            head = ("Menace neutralisée" if done else
                    "Menace détectée" if r["level"] == "critical" else "Activité suspecte")
            name = os.path.basename(r["path"]) if r["path"] else ""
            body = f"{r['title']}" + (f"\n{name}" if name else "")
            if self.icon:
                try:
                    self.icon.notify(body, head)
                except Exception:
                    pass
            url = C.get_setting(self.db, "webhook_url")
            if url:
                threading.Thread(target=self._webhook, args=(url, f"🛡️ Easy DR — {head}\n{body}"), daemon=True).start()

    @staticmethod
    def _webhook(url, text):
        try:
            req = urllib.request.Request(url, json.dumps({"content": text, "text": text}).encode(),
                                         {"Content-Type": "application/json", "User-Agent": "EasyDR"})
            urllib.request.urlopen(req, timeout=8).read()
        except Exception:
            pass

    # ───────── commandes envoyées par l'interface (qui, elle, ne tourne pas en admin)
    def commands(self):
        for r in self.db.execute("SELECT * FROM commands WHERE state=0 ORDER BY id").fetchall():
            self.db.execute("UPDATE commands SET state=1 WHERE id=?", (r["id"],))
            try:
                self.run_command(r["cmd"], r["arg"])
            except Exception as e:
                C.log_event(self.db, "info", "error", "Commande échouée", f"{r['cmd']} : {e}")

    def run_command(self, cmd, arg):
        db = self.db
        if cmd == "update_sigs":
            C.set_meta(db, "sig_force", 1)
            if not C.is_alive(C.PORT_UPDATER):
                C.spawn("--update")
        elif cmd == "restore":
            dst = Q.restore(db, arg)
            C.log_event(db, "info", "quarantine", "Fichier restauré", dst or "")
        elif cmd == "delete_q":
            Q.delete(db, arg)
        elif cmd == "neutralize":
            ev = db.execute("SELECT * FROM events WHERE id=?", (int(arg),)).fetchone()
            if not ev:
                return
            did = False
            if ev["pid"] and Q.kill_pid(ev["pid"]):
                did = True
            if ev["path"] and os.path.isfile(ev["path"]):
                Q.quarantine_file(db, ev["path"], ev["title"], ev["sha256"]); did = True
            if did:
                db.execute("UPDATE events SET action=? WHERE id=?",
                           ("quarantined" if ev["path"] else "killed", ev["id"]))
        elif cmd == "trust":
            ev = db.execute("SELECT * FROM events WHERE id=?", (int(arg),)).fetchone()
            if ev and ev["sha256"]:
                db.execute("INSERT OR REPLACE INTO whitelist VALUES(?,?,?)", (ev["sha256"], ev["path"], time.time()))
                q = db.execute("SELECT id FROM quarantine WHERE sha256=?", (ev["sha256"],)).fetchone()
                if q:
                    Q.restore(db, q["id"])
                db.execute("UPDATE events SET action='trusted' WHERE id=?", (ev["id"],))
        elif cmd == "stop":
            self.shutdown()

    # ───────── supervision
    def supervise(self):
        db = self.db
        if db.execute("SELECT 1 FROM scan_queue WHERE state=0 LIMIT 1").fetchone() and not C.is_alive(C.PORT_WORKER):
            C.spawn("--scan-worker")
        hours = C.get_setting(db, "update_hours")
        last = float(C.get_meta(db, "sig_checked", 0) or 0)
        if (not C.RULES_BIN.exists() or time.time() - last > hours * 3600) and not C.is_alive(C.PORT_UPDATER):
            C.set_meta(db, "sig_checked", time.time() - hours * 3600 + 900)   # anti-boucle, 15 min
            C.spawn("--update")

    def housekeeping(self):
        self.db.execute("DELETE FROM events WHERE ts<?", (time.time() - 180 * 86400,))
        self.db.execute("DELETE FROM scan_queue WHERE state=1")
        rv = C.get_meta(self.db, "sig_version", "none")
        self.db.execute("DELETE FROM scan_cache WHERE rv<>?", (rv,))

    def main_loop(self):
        tick = 0
        while not self.stop.wait(1):
            try:
                self.protection = bool(C.get_setting(self.db, "protection"))
                self.flush_pending()
                self.commands()
                self.notifier()
                if tick % 2 == 0:
                    self.supervise()
                if tick % 3600 == 0:
                    self.housekeeping()
                self.update_icon()
            except Exception:
                C.log_exc("main_loop")
            tick += 1

    # ───────── tray
    def update_icon(self):
        if not self.icon:
            return
        state = "ok" if self.protection else "off"
        if state != getattr(self, "_state", None):
            from .branding import shield
            self._state = state
            self.icon.icon = shield(state, 64)
            self.icon.title = "Easy DR — protégé" if self.protection else "Easy DR — protection en pause"

    def shutdown(self, *_):
        self.stop.set()
        if self.observer:
            try: self.observer.stop()
            except Exception: pass
        if self.icon:
            try: self.icon.stop()
            except Exception: pass

    def build_tray(self):
        try:
            import pystray
            from .branding import shield
        except Exception:
            return None
        def toggle(icon, item):
            C.set_setting(self.db, "protection", not C.get_setting(self.db, "protection"))

        def quick(icon, item):
            C.enqueue(self.db, "|".join(C.quick_dirs()), "dir", "quick")

        menu = pystray.Menu(
            pystray.MenuItem("Ouvrir Easy DR", lambda i, it: C.spawn("--ui", low=False), default=True),
            pystray.MenuItem("Analyse rapide", quick),
            pystray.MenuItem("Protection en temps réel", toggle, checked=lambda it: C.get_setting(self.db, "protection")),
            pystray.MenuItem("Mettre à jour les signatures", lambda i, it: self.run_command("update_sigs", "")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quitter Easy DR", lambda i, it: self.shutdown()),
        )
        return pystray.Icon("EasyDR", shield("ok", 64), "Easy DR — protégé", menu)

    def run(self):
        C.log_event(self.db, "info", "service", "Easy DR est actif", "Protection en temps réel démarrée")
        self.start_watchers()
        threading.Thread(target=self.behavior_loop, daemon=True).start()
        self.icon = self.build_tray() if os.environ.get("EASYDR_NO_TRAY") != "1" else None
        if self.icon:
            threading.Thread(target=self.main_loop, daemon=True).start()
            try:
                self.icon.run()               # bloque jusqu'à « Quitter »
            except Exception:
                self.icon = None
                self.main_loop()
        else:
            self.main_loop()


def main():
    lock = C.singleton(C.PORT_DAEMON)
    if not lock:
        return
    C.lower_priority(io=False)
    C.init_db()
    Daemon().run()
