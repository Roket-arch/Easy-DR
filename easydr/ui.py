"""Interface Easy DR (customtkinter). Elle ne fait que lire/écrire la base : le daemon agit."""
import os, csv, json, time
from tkinter import ttk, filedialog, messagebox
import customtkinter as ctk
from . import config as C, __version__
from .branding import *

LEVEL = {"critical": ("Critique", RED), "suspect": ("Suspect", AMBER), "info": ("Info", MUTED)}
ACTION = {"quarantined": "Neutralisé", "killed": "Processus arrêté", "trusted": "Approuvé"}


def F(size=13, weight="normal"):
    return ctk.CTkFont(family="Segoe UI", size=size, weight=weight)


def ago(ts):
    if not ts:
        return "jamais"
    d = time.time() - float(ts)
    if d < 90: return "à l'instant"
    if d < 3600: return f"il y a {int(d // 60)} min"
    if d < 86400: return f"il y a {int(d // 3600)} h"
    return f"il y a {int(d // 86400)} j"


def when(ts):
    return time.strftime("%d/%m %H:%M", time.localtime(ts))


def card(parent, **kw):
    return ctk.CTkFrame(parent, fg_color=CARD, corner_radius=16, border_width=1, border_color=LINE, **kw)


def button(parent, text, cmd, primary=False, danger=False, **kw):
    if primary:
        kw.setdefault("height", 44)
        return ctk.CTkButton(parent, text=text, command=cmd, fg_color=BLUE, hover_color=BLUE_H,
                             font=F(14, "bold"), corner_radius=10, **kw)
    kw.setdefault("height", 38)
    return ctk.CTkButton(parent, text=text, command=cmd, fg_color="transparent" if not danger else RED,
                         hover_color=CARD2, border_width=1, border_color=LINE if not danger else RED,
                         text_color=TEXT, font=F(13), corner_radius=10, **kw)


def img(state, size):
    im = shield(state, size * 2)
    return ctk.CTkImage(light_image=im, dark_image=im, size=(size, size))


class Table(ttk.Treeview):
    def __init__(self, parent, cols, widths, **kw):
        super().__init__(parent, columns=[c for c, _ in cols], show="headings", selectmode="browse", **kw)
        for (c, label), w in zip(cols, widths):
            self.heading(c, text=label, anchor="w")
            self.column(c, width=w, minwidth=50, anchor="w", stretch=(w >= 240))
        for k, col in (("critical", RED), ("suspect", AMBER), ("info", MUTED)):
            self.tag_configure(k, foreground=col)
        self._sig = None

    def fill(self, rows):
        """rows: [(iid, values, tag)] – ne reconstruit que si les données ont changé (pas de scintillement)."""
        sig = repr(rows)
        if sig == self._sig:
            return
        self._sig = sig
        sel = self.selection()
        self.delete(*self.get_children())
        for iid, vals, tag in rows:
            self.insert("", "end", iid=str(iid), values=vals, tags=(tag,))
        if sel and self.exists(sel[0]):
            self.selection_set(sel[0])


class Page(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app.content, fg_color="transparent")
        self.app, self.db = app, app.db

    def refresh(self):
        pass

    def header(self, title, sub=""):
        ctk.CTkLabel(self, text=title, font=F(26, "bold"), text_color=TEXT, anchor="w").pack(fill="x", pady=(0, 0 if sub else 14))
        if sub:
            ctk.CTkLabel(self, text=sub, font=F(13), text_color=MUTED, anchor="w").pack(fill="x", pady=(2, 14))


# ───────────────────────────── Tableau de bord ─────────────────────────────
class Dashboard(Page):
    def __init__(self, app):
        super().__init__(app)
        hero = card(self); hero.pack(fill="x", pady=(0, 14))
        self.shield = ctk.CTkLabel(hero, text="", image=img("ok", 120))
        self.shield.pack(side="left", padx=30, pady=26)
        box = ctk.CTkFrame(hero, fg_color="transparent"); box.pack(side="left", fill="both", expand=True, pady=26)
        self.title = ctk.CTkLabel(box, text="", font=F(30, "bold"), text_color=TEXT, anchor="w")
        self.title.pack(fill="x")
        self.sub = ctk.CTkLabel(box, text="", font=F(13), text_color=MUTED, anchor="w", justify="left")
        self.sub.pack(fill="x", pady=(4, 16))
        row = ctk.CTkFrame(box, fg_color="transparent"); row.pack(anchor="w")
        button(row, "Analyser maintenant", lambda: app.start_scan("quick"), primary=True, width=200).pack(side="left")
        button(row, "Analyse complète", lambda: app.start_scan("full"), width=170).pack(side="left", padx=10)

        tiles = ctk.CTkFrame(self, fg_color="transparent"); tiles.pack(fill="x", pady=(0, 14))
        self.t = []
        for i, name in enumerate(("Fichiers analysés aujourd'hui", "Menaces détectées (7 jours)", "À examiner")):
            c = card(tiles); c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 7, 0 if i == 2 else 7))
            tiles.grid_columnconfigure(i, weight=1)
            v = ctk.CTkLabel(c, text="0", font=F(30, "bold"), text_color=TEXT, anchor="w"); v.pack(fill="x", padx=20, pady=(16, 0))
            ctk.CTkLabel(c, text=name, font=F(12), text_color=MUTED, anchor="w").pack(fill="x", padx=20, pady=(0, 16))
            self.t.append(v)

        sig = card(self); sig.pack(fill="x", pady=(0, 14))
        self.sig = ctk.CTkLabel(sig, text="", font=F(12), text_color=MUTED, anchor="w", justify="left")
        self.sig.pack(side="left", padx=20, pady=14)
        button(sig, "Mettre à jour", lambda: app.cmd("update_sigs"), width=130, height=32).pack(side="right", padx=16)

        ctk.CTkLabel(self, text="Activité récente", font=F(15, "bold"), text_color=TEXT, anchor="w").pack(fill="x", pady=(2, 6))
        self.feed = card(self); self.feed.pack(fill="both", expand=True)
        self.rows = []

    def refresh(self):
        db, now = self.db, time.time()
        day = time.strftime("%Y-%m-%d")
        r = db.execute("SELECT scanned FROM stats WHERE day=?", (day,)).fetchone()
        threats = db.execute("SELECT COUNT(*) FROM events WHERE level IN ('critical','suspect') AND ts>?",
                             (now - 7 * 86400,)).fetchone()[0]
        todo = db.execute("SELECT COUNT(*) FROM events WHERE level IN ('critical','suspect') AND action='none' "
                          "AND ts>?", (now - 30 * 86400,)).fetchone()[0]
        for w, v in zip(self.t, (r[0] if r else 0, threats, todo)):
            w.configure(text=f"{v:,}".replace(",", " "))
        alive, prot = C.is_alive(C.PORT_DAEMON), C.get_setting(db, "protection")
        if not alive:
            st, t, s = "off", "Service arrêté", "Le service d'arrière-plan ne répond pas. Il redémarre à l'ouverture de session."
        elif not prot:
            st, t, s = "off", "Protection en pause", "La surveillance en temps réel est désactivée (Paramètres)."
        elif todo:
            st, t, s = "warn", f"{todo} élément(s) à examiner", "Ouvrez l'historique pour neutraliser ou approuver ces alertes."
        else:
            st, t, s = "ok", "Vous êtes protégé", "Surveillance en temps réel active. Aucune menace en attente."
        if st != getattr(self, "_st", None):
            self._st = st; self.shield.configure(image=img(st, 120))
        self.title.configure(text=t); self.sub.configure(text=s)
        ver = C.get_meta(db, "sig_version", "aucune")
        n = db.execute("SELECT COUNT(*) FROM ioc_hashes").fetchone()[0]
        err = C.get_meta(db, "sig_error")
        self.sig.configure(text=f"Signatures : {ver} · {n:,} hash".replace(",", " ") +
                           f" · vérifiées {ago(C.get_meta(db, 'sig_checked'))}" +
                           (f"\n⚠ Dernière mise à jour impossible : {err}" if err else ""))
        for w in self.rows:
            w.destroy()
        self.rows = []
        ev = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 6").fetchall()
        if not ev:
            ev = []
        for e in ev:
            lab, col = LEVEL[e["level"]]
            line = ctk.CTkFrame(self.feed, fg_color="transparent"); line.pack(fill="x", padx=16, pady=5)
            ctk.CTkLabel(line, text="●", text_color=col, font=F(12), width=18).pack(side="left")
            ctk.CTkLabel(line, text=e["title"][:70], font=F(13), text_color=TEXT, anchor="w").pack(side="left", padx=4)
            tag = ACTION.get(e["action"]) or ""
            ctk.CTkLabel(line, text=when(e["ts"]), font=F(12), text_color=MUTED).pack(side="right")
            if tag:
                ctk.CTkLabel(line, text=tag, font=F(11, "bold"), text_color=GREEN).pack(side="right", padx=12)
            self.rows.append(line)


# ───────────────────────────── Analyse ─────────────────────────────
class Scan(Page):
    def __init__(self, app):
        super().__init__(app)
        self.header("Analyse", "Choisissez le niveau d'analyse. Elle tourne en arrière-plan sans ralentir le PC.")
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x")
        for i, (k, name, desc) in enumerate((
                ("quick", "Analyse rapide", "Téléchargements, Bureau, Documents, AppData, Temp, Démarrage. ≈ 1 à 3 min."),
                ("full", "Analyse complète", "Tous les disques. Peut durer longtemps, priorité basse."),
                ("custom", "Analyse personnalisée", "Un dossier de votre choix."))):
            c = card(row); c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 7, 0 if i == 2 else 7))
            row.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(c, text=name, font=F(16, "bold"), text_color=TEXT, anchor="w").pack(fill="x", padx=18, pady=(16, 2))
            ctk.CTkLabel(c, text=desc, font=F(12), text_color=MUTED, anchor="w", justify="left", wraplength=230).pack(fill="x", padx=18)
            button(c, "Lancer", lambda k=k: app.start_scan(k), primary=(k == "quick")).pack(padx=18, pady=16, fill="x")
        self.box = card(self); self.box.pack(fill="x", pady=14)
        self.state = ctk.CTkLabel(self.box, text="Aucune analyse en cours", font=F(16, "bold"), text_color=TEXT, anchor="w")
        self.state.pack(fill="x", padx=20, pady=(18, 4))
        self.bar = ctk.CTkProgressBar(self.box, height=8, progress_color=BLUE, fg_color=CARD2)
        self.bar.pack(fill="x", padx=20, pady=6); self.bar.set(0)
        self.cur = ctk.CTkLabel(self.box, text="", font=F(12), text_color=MUTED, anchor="w")
        self.cur.pack(fill="x", padx=20, pady=(0, 6))
        self.cancel = button(self.box, "Annuler l'analyse", self.do_cancel, width=170, height=34)
        self.running = False

    def do_cancel(self):
        C.set_meta(self.db, "scan_cancel", 1)

    def refresh(self):
        raw = C.get_meta(self.db, "scan_status")
        s = json.loads(raw) if raw else {}
        queued = self.db.execute("SELECT 1 FROM scan_queue WHERE kind='dir' AND state=0").fetchone()
        if s.get("running"):
            if not self.running:
                self.bar.configure(mode="indeterminate"); self.bar.start(); self.running = True
                self.cancel.pack(anchor="w", padx=20, pady=(0, 18))
            self.state.configure(text=f"Analyse en cours · {s.get('count', 0):,} fichiers · {s.get('threats', 0)} menace(s)".replace(",", " "))
            self.cur.configure(text=s.get("current", "")[-95:])
        elif queued:
            self.state.configure(text="Analyse en file d'attente…"); self.cur.configure(text="Démarrage du moteur")
        else:
            if self.running:
                self.bar.stop(); self.bar.configure(mode="determinate"); self.running = False; self.cancel.pack_forget()
            if s.get("ended"):
                self.bar.set(1)
                end = "annulée" if s.get("cancelled") else "terminée"
                self.state.configure(text=f"Analyse {end} · {s['count']:,} fichiers · {s.get('threats', 0)} menace(s)".replace(",", " "))
                self.cur.configure(text=f"Fin {ago(s['ended'])}")


# ───────────────────────────── Historique ─────────────────────────────
class History(Page):
    def __init__(self, app):
        super().__init__(app)
        self.header("Historique", "Toutes les détections et actions. Sélectionnez une ligne pour agir.")
        bar = ctk.CTkFrame(self, fg_color="transparent"); bar.pack(fill="x", pady=(0, 8))
        self.seg = ctk.CTkSegmentedButton(bar, values=["Tout", "Critiques", "Suspects", "Système"], command=lambda v: self.refresh(),
                                          selected_color=BLUE, selected_hover_color=BLUE_H, unselected_color=CARD2, fg_color=CARD2,
                                          height=34, font=F(12), text_color=TEXT)
        self.seg.set("Tout"); self.seg.pack(side="left")
        button(bar, "Exporter CSV", self.export, width=120, height=32).pack(side="right")
        button(bar, "Faire confiance", lambda: self.act("trust"), width=130, height=32).pack(side="right", padx=8)
        button(bar, "Neutraliser", lambda: self.act("neutralize"), width=120, height=32, danger=True).pack(side="right")
        self.tab = Table(self, (("ts", "Date"), ("lvl", "Niveau"), ("what", "Détection"), ("path", "Élément"), ("act", "Statut")),
                         (96, 66, 250, 240, 100))
        self.tab.pack(fill="both", expand=True)

    def rows(self):
        f = {"Critiques": "level='critical'", "Suspects": "level='suspect'", "Système": "level='info'"}.get(self.seg.get(), "1")
        return self.db.execute(f"SELECT * FROM events WHERE {f} ORDER BY id DESC LIMIT 500").fetchall()

    def refresh(self):
        out = []
        for e in self.rows():
            act = ACTION.get(e["action"]) or ("À examiner" if e["level"] != "info" else "—")
            out.append((e["id"], (when(e["ts"]), LEVEL[e["level"]][0], e["title"], e["path"] or e["detail"] or "", act), e["level"]))
        self.tab.fill(out)

    def act(self, cmd):
        s = self.tab.selection()
        if not s:
            return messagebox.showinfo("Easy DR", "Sélectionnez d'abord une ligne.")
        if cmd == "neutralize" and not messagebox.askyesno("Neutraliser", "Mettre en quarantaine / arrêter cet élément ?"):
            return
        self.app.cmd(cmd, s[0])

    def export(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="easydr_historique.csv")
        if p:
            with open(p, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";"); w.writerow(["date", "niveau", "type", "titre", "détail", "chemin", "sha256", "action"])
                for e in self.rows():
                    w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"])), e["level"], e["kind"],
                                e["title"], e["detail"], e["path"], e["sha256"], e["action"]])


# ───────────────────────────── Quarantaine ─────────────────────────────
class Quarantine(Page):
    def __init__(self, app):
        super().__init__(app)
        self.header("Quarantaine", "Les fichiers neutralisés sont chiffrés et inoffensifs. Vous pouvez les restaurer.")
        bar = ctk.CTkFrame(self, fg_color="transparent"); bar.pack(fill="x", pady=(0, 8))
        button(bar, "Supprimer définitivement", self.delete, width=190, height=32, danger=True).pack(side="right")
        button(bar, "Restaurer", self.restore, width=120, height=32).pack(side="right", padx=8)
        self.tab = Table(self, (("ts", "Date"), ("orig", "Emplacement d'origine"), ("why", "Raison")), (96, 400, 260))
        self.tab.pack(fill="both", expand=True)

    def refresh(self):
        rows = self.db.execute("SELECT * FROM quarantine ORDER BY ts DESC").fetchall()
        self.tab.fill([(r["id"], (when(r["ts"]), r["orig"], (r["reason"] or "")[:120]), "info") for r in rows])

    def restore(self):
        s = self.tab.selection()
        if s and messagebox.askyesno("Restaurer", "Ce fichier a été jugé dangereux. Le restaurer quand même ?"):
            self.app.cmd("restore", s[0])

    def delete(self):
        s = self.tab.selection()
        if s and messagebox.askyesno("Supprimer", "Supprimer définitivement ce fichier ?"):
            self.app.cmd("delete_q", s[0])


# ───────────────────────────── Paramètres ─────────────────────────────
class Settings(Page):
    def __init__(self, app):
        super().__init__(app)
        self.header("Paramètres")
        c = card(self); c.pack(fill="x")
        self.vars = {}
        for key, label, desc in (
                ("protection", "Protection en temps réel", "Surveille Téléchargements, Bureau, Temp, Démarrage et les nouveaux processus."),
                ("auto_neutralize", "Neutraliser automatiquement les menaces critiques", "Mise en quarantaine immédiate (restaurable)."),
                ("auto_kill_behavior", "Stopper les comportements de ransomware", "Ex. suppression des copies cliché Windows."),
                ("notify", "Notifications", "Alerte dans la zone de notification à chaque détection.")):
            row = ctk.CTkFrame(c, fg_color="transparent"); row.pack(fill="x", padx=20, pady=10)
            t = ctk.CTkFrame(row, fg_color="transparent"); t.pack(side="left")
            ctk.CTkLabel(t, text=label, font=F(14, "bold"), text_color=TEXT, anchor="w").pack(fill="x")
            ctk.CTkLabel(t, text=desc, font=F(12), text_color=MUTED, anchor="w").pack(fill="x")
            v = ctk.BooleanVar(value=C.get_setting(self.db, key)); self.vars[key] = v
            ctk.CTkSwitch(row, text="", variable=v, progress_color=BLUE, width=48,
                          command=lambda k=key, v=v: C.set_setting(self.db, k, bool(v.get()))).pack(side="right")
        w = card(self); w.pack(fill="x", pady=14)
        ctk.CTkLabel(w, text="Alertes à distance (Discord / Slack / webhook)", font=F(14, "bold"), text_color=TEXT, anchor="w").pack(fill="x", padx=20, pady=(14, 0))
        ctk.CTkLabel(w, text="Collez l'URL d'un webhook pour recevoir chaque alerte sur votre téléphone.", font=F(12), text_color=MUTED, anchor="w").pack(fill="x", padx=20)
        r = ctk.CTkFrame(w, fg_color="transparent"); r.pack(fill="x", padx=20, pady=14)
        self.hook = ctk.CTkEntry(r, placeholder_text="https://discord.com/api/webhooks/…", height=36, fg_color=CARD2, border_color=LINE)
        self.hook.pack(side="left", fill="x", expand=True)
        self.hook.insert(0, C.get_setting(self.db, "webhook_url"))
        button(r, "Enregistrer", self.save_hook, width=110, height=36).pack(side="left", padx=(10, 0))
        a = card(self); a.pack(fill="x")
        ctk.CTkLabel(a, text=f"Easy DR {__version__}", font=F(14, "bold"), text_color=TEXT, anchor="w").pack(fill="x", padx=20, pady=(14, 0))
        ctk.CTkLabel(a, text="Règles YARA et IOC : Neo23x0/signature-base (licence DRL 1.1), mises à jour automatiquement depuis GitHub.\n"
                             f"Données : {C.DATA}", font=F(12), text_color=MUTED, anchor="w", justify="left").pack(fill="x", padx=20, pady=(0, 14))

    def save_hook(self):
        C.set_setting(self.db, "webhook_url", self.hook.get().strip())
        messagebox.showinfo("Easy DR", "Webhook enregistré.")


# ───────────────────────────── Fenêtre ─────────────────────────────
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        self.title("Easy DR"); self.geometry("1040x700"); self.minsize(940, 620)
        self.configure(fg_color=BG)
        self.db = C.connect()
        side = ctk.CTkFrame(self, fg_color=SIDEBAR, width=220, corner_radius=0); side.pack(side="left", fill="y")
        side.pack_propagate(False)
        logo = ctk.CTkFrame(side, fg_color="transparent"); logo.pack(fill="x", padx=20, pady=(26, 22))
        ctk.CTkLabel(logo, text="", image=img("info", 34)).pack(side="left")
        ctk.CTkLabel(logo, text=" Easy DR", font=F(20, "bold"), text_color=TEXT).pack(side="left")
        self.content = ctk.CTkFrame(self, fg_color="transparent"); self.content.pack(side="left", fill="both", expand=True, padx=28, pady=24)
        self.pages, self.nav = {}, {}
        for name, cls in (("Tableau de bord", Dashboard), ("Analyse", Scan), ("Historique", History),
                          ("Quarantaine", Quarantine), ("Paramètres", Settings)):
            self.pages[name] = cls(self)
            b = ctk.CTkButton(side, text="   " + name, anchor="w", height=42, corner_radius=10, fg_color="transparent",
                              hover_color=CARD2, text_color=TEXT, font=F(14), command=lambda n=name: self.show(n))
            b.pack(fill="x", padx=14, pady=2); self.nav[name] = b
        ctk.CTkLabel(side, text="Protection par signatures GitHub\n+ analyse comportementale", font=F(11), text_color=MUTED,
                     justify="left").pack(side="bottom", padx=20, pady=20, anchor="w")
        st = ttk.Style(self); st.theme_use("clam")
        st.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT, rowheight=34, borderwidth=0, font=("Segoe UI", 10))
        st.configure("Treeview.Heading", background=CARD2, foreground=MUTED, relief="flat", font=("Segoe UI", 9, "bold"), padding=8)
        st.configure("Treeview", bordercolor=CARD, lightcolor=CARD, darkcolor=CARD)
        st.map("Treeview", background=[("selected", BLUE)], foreground=[("selected", "white")])
        st.map("Treeview.Heading", background=[("active", CARD2)])
        self.current = None
        self.show("Tableau de bord")
        if not C.is_alive(C.PORT_DAEMON):
            C.spawn("--daemon")
        self.tick()

    def show(self, name):
        if self.current:
            self.pages[self.current].pack_forget()
            self.nav[self.current].configure(fg_color="transparent")
        self.current = name
        self.nav[name].configure(fg_color=CARD2)
        self.pages[name].pack(fill="both", expand=True)
        self.pages[name].refresh()

    def tick(self):
        try:
            self.pages[self.current].refresh()
        except Exception:
            pass
        self.after(1500, self.tick)

    def cmd(self, cmd, arg=""):
        self.db.execute("INSERT INTO commands(ts,cmd,arg) VALUES(?,?,?)", (time.time(), cmd, str(arg)))

    def start_scan(self, kind):
        if kind == "custom":
            path = filedialog.askdirectory()
            if not path:
                return
        else:
            path = "|".join(C.quick_dirs() if kind == "quick" else C.full_roots())
        C.set_meta(self.db, "scan_status", "")
        C.enqueue(self.db, path, "dir", kind)
        self.show("Analyse")


def main():
    lock = C.singleton(C.PORT_UI)
    if not lock:
        return
    C.init_db()
    App().mainloop()
