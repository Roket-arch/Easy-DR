"""Worker d'analyse : démarré à la demande par le daemon, s'arrête seul après 90 s d'inactivité."""
import os, time, json
from . import config as C
from .engine import Engine, interesting
from . import quarantine as Q

IDLE_EXIT = 90
SKIP_DIRS = {"$recycle.bin", "system volume information", "winsxs", "servicing", "node_modules", ".git",
             "proc", "sys", "dev", "run"}


def walk(root):
    for dp, dn, fn in os.walk(root, onerror=lambda e: None):
        dn[:] = [d for d in dn if d.lower() not in SKIP_DIRS and not C.in_data(os.path.join(dp, d))]
        for f in fn:
            yield os.path.join(dp, f)


class Worker:
    def __init__(self):
        self.db = C.connect()
        self.eng = Engine(self.db)
        self.scanned = self.threats = 0

    def settings(self):
        return C.get_setting(self.db, "auto_neutralize")

    def check(self, path, source):
        try:
            st = os.stat(path)
        except OSError:
            return
        row = self.db.execute("SELECT mtime,size,rv FROM scan_cache WHERE path=?", (path,)).fetchone()
        if row and row[0] == st.st_mtime and row[1] == st.st_size and row[2] == self.eng.rv:
            return
        if not interesting(path):
            return
        v = self.eng.scan(path)
        if v.skipped:
            return
        self.scanned += 1
        if not v.level:
            self.db.execute("INSERT OR REPLACE INTO scan_cache VALUES(?,?,?,?)",
                            (path, st.st_mtime, st.st_size, self.eng.rv))
            return
        dup = self.db.execute("SELECT 1 FROM events WHERE path=? AND sha256=? AND ts>? AND kind='file'",
                              (path, v.sha256, time.time() - 3600)).fetchone()
        if dup:
            return
        self.threats += 1
        action, extra = "none", ""
        if v.level == "critical" and self.settings():
            try:
                Q.quarantine_file(self.db, path, "; ".join(v.reasons), v.sha256)
                action = "quarantined"
            except Exception as e:
                extra = f" (échec de la quarantaine : {e})"
        C.log_event(self.db, v.level, "file", v.title, "; ".join(v.reasons) + extra,
                    path, v.sha256, None, action)

    def flush_stats(self):
        if self.scanned or self.threats:
            C.add_stats(self.db, self.scanned, self.threats)
            self.scanned = self.threats = 0

    def next_job(self, only_files=False):
        q = "SELECT * FROM scan_queue WHERE state=0" + (" AND kind='file'" if only_files else "")
        r = self.db.execute(q + " ORDER BY CASE kind WHEN 'file' THEN 0 ELSE 1 END, id LIMIT 1").fetchone()
        if r:
            self.db.execute("UPDATE scan_queue SET state=1 WHERE id=?", (r["id"],))
        return r

    def drain_files(self):
        while True:
            j = self.next_job(only_files=True)
            if not j:
                return
            self.check(j["path"], j["source"])
            self.db.execute("DELETE FROM scan_queue WHERE id=?", (j["id"],))

    def status(self, **kw):
        C.set_meta(self.db, "scan_status", json.dumps(kw))

    def run_dirs(self, job):
        roots = [p for p in job["path"].split("|") if p and os.path.exists(p)]
        t0, n, bad0 = time.time(), 0, self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        C.set_meta(self.db, "scan_cancel", 0)
        cancelled = False
        for root in roots:
            for fp in walk(root):
                n += 1
                if n % 25 == 0:
                    if C.get_meta(self.db, "scan_cancel") == "1":
                        cancelled = True; break
                    self.status(running=1, kind=job["source"], count=n, current=fp, started=t0,
                                threats=self.threats)
                    self.drain_files(); self.flush_stats()
                self.check(fp, job["source"])
            if cancelled:
                break
        found = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] - bad0
        self.flush_stats()
        self.status(running=0, kind=job["source"], count=n, current="", started=t0, ended=time.time(),
                    cancelled=int(cancelled), threats=found)
        C.set_meta(self.db, "last_scan", time.time())
        C.set_meta(self.db, "scan_cancel", 0)

    def loop(self):
        idle = time.time()
        while time.time() - idle < IDLE_EXIT:
            self.eng.reload_if_needed()
            job = self.next_job()
            if not job:
                self.flush_stats(); time.sleep(1); continue
            idle = time.time()
            try:
                if job["kind"] == "dir":
                    self.run_dirs(job)
                else:
                    self.check(job["path"], job["source"])
            except Exception as e:
                C.log_event(self.db, "info", "error", "Erreur d'analyse", f"{job['path']} : {e}")
            self.db.execute("DELETE FROM scan_queue WHERE id=?", (job["id"],))
            self.flush_stats()
            if job["kind"] == "dir":
                idle = time.time()


def main():
    lock = C.singleton(C.PORT_WORKER)
    if not lock:
        return
    C.lower_priority()
    C.init_db()
    Worker().loop()
