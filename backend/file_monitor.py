"""
ThreatSense — Download Monitor
================================
Watches the user's Downloads folder for new files.
When a file finishes downloading, shows a popup asking
whether to scan it. If yes, shows an animated progress
window while uploading to the ThreatSense backend.

Usage:
    python file_monitor.py
    python file_monitor.py --folder "D:\\MyDownloads"
    python file_monitor.py --backend http://192.168.1.50:8000
"""

import os
import sys
import time
import queue
import sqlite3
import socket
import shutil
import argparse
import threading
import webbrowser
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─── Configuration ────────────────────────────────────────────────────────────
DEFAULT_DOWNLOADS = str(Path.home() / "Downloads")
DEFAULT_BACKEND   = "http://localhost:8000"
FRONTEND_URL      = "http://localhost:3000"

TEMP_EXTENSIONS = {
    ".crdownload", ".part", ".download", ".tmp", ".partial", ".opdownload",
}
MIN_FILE_SIZE = 1
STABLE_CHECK_INTERVAL = 0.5
STABLE_CHECK_ROUNDS   = 4

# ─── Theme (matching frontend ThreatSenseV2.jsx) ─────────────────────────────
C = {
    "bg":       "#0f0f11",
    "surface":  "#141418",
    "card":     "#1a1a1f",
    "border":   "#2a2a30",
    "text":     "#e4e4e7",
    "dim":      "#a1a1aa",
    "muted":    "#71717a",
    "green":    "#22c55e",
    "blue":     "#3b82f6",
    "red":      "#ef4444",
    "orange":   "#f97316",
    "amber":    "#f59e0b",
}

SEV = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#22c55e",
    "BENIGN":   "#3b82f6",
    "UNKNOWN":  "#71717a",
}

STEPS = [
    "Hashing file",
    "Running static analysis",
    "Querying VirusTotal",
    "Correlating IOCs",
    "Generating AI report",
]


# ─── Safe window management ──────────────────────────────────────────────────

def _safe_destroy(root):
    """Destroy a customtkinter window, suppressing animation cleanup errors."""
    try:
        # Cancel ALL pending after callbacks to prevent 'invalid command' errors
        for after_id in root.tk.eval("after info").split():
            try:
                root.after_cancel(after_id)
            except Exception:
                pass
    except Exception:
        pass
    try:
        root.destroy()
    except Exception:
        pass


def _center(win, w, h):
    x = (win.winfo_screenwidth() - w) // 2
    y = (win.winfo_screenheight() - h) // 2
    win.geometry(f"{w}x{h}+{x}+{y}")


def _mk_root(title, w, h):
    import customtkinter as ctk
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    root = ctk.CTk()
    root.title(title)
    root.configure(fg_color=C["bg"])
    root.resizable(False, False)
    root.attributes("-topmost", True)
    _center(root, w, h)
    return root


def _topbar(root, right_text="", right_color=None):
    import customtkinter as ctk
    top = ctk.CTkFrame(root, fg_color=C["surface"], height=46, corner_radius=0)
    top.pack(fill="x")
    top.pack_propagate(False)
    ctk.CTkLabel(top, text="  ThreatSense",
                 font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
                 text_color=C["text"]).pack(side="left", padx=14)
    if right_text:
        ctk.CTkLabel(top, text=f"{right_text}  ",
                     font=ctk.CTkFont(family="Consolas", size=11),
                     text_color=right_color or C["muted"]).pack(side="right", padx=14)
    ctk.CTkFrame(root, fg_color=C["border"], height=1).pack(fill="x")
    return top


# ─── Chrome download source lookup ───────────────────────────────────────────

def _get_download_source(filepath: str) -> dict:
    """
    Read Chrome's History SQLite DB to find where a file was downloaded from.
    Returns {url, domain, ip} or empty dict if not found.
    """
    chrome_history = os.path.join(
        os.environ.get("LOCALAPPDATA", ""),
        "Google", "Chrome", "User Data", "Default", "History"
    )
    if not os.path.exists(chrome_history):
        return {}

    # Chrome locks the file — copy to temp
    tmp = os.path.join(tempfile.gettempdir(), f"ts_chrome_{os.getpid()}.db")
    try:
        shutil.copy2(chrome_history, tmp)
    except Exception:
        return {}

    try:
        conn = sqlite3.connect(tmp)
        cursor = conn.cursor()

        # Normalise path for matching
        norm = os.path.normpath(filepath).replace("/", "\\")

        # Try matching by target_path (Chrome stores full path)
        cursor.execute(
            "SELECT tab_url, site_url FROM downloads WHERE target_path = ? ORDER BY id DESC LIMIT 1",
            (norm,)
        )
        row = cursor.fetchone()

        # Fallback: match by filename suffix
        if not row:
            fn = os.path.basename(filepath)
            cursor.execute(
                "SELECT tab_url, site_url FROM downloads WHERE target_path LIKE ? ORDER BY id DESC LIMIT 1",
                (f"%{fn}",)
            )
            row = cursor.fetchone()

        conn.close()
    except Exception:
        return {}
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

    if not row:
        return {}

    url = row[0] or row[1] or ""
    if not url or not url.startswith("http"):
        return {}

    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
    except Exception:
        return {"url": url}

    # Strip localhost / 127.0.0.1 — those are our own backend
    if domain in ("localhost", "127.0.0.1", "0.0.0.0", ""):
        return {}

    # Resolve domain → IP
    ip = ""
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        pass

    return {"url": url, "domain": domain, "ip": ip}




# ─── Scan popup ───────────────────────────────────────────────────────────────

def _show_scan_popup(filepath: str, source: dict = None) -> bool:
    import customtkinter as ctk
    result = {"v": False}

    root = _mk_root("ThreatSense", 450, 270)

    fn = os.path.basename(filepath)
    sz = os.path.getsize(filepath)
    sz_s = f"{sz/1024:.1f} KB" if sz < 1048576 else f"{sz/1048576:.1f} MB"
    ext = os.path.splitext(fn)[1].lower() or "file"

    def yes():
        result["v"] = True
        _safe_destroy(root)
    def no():
        _safe_destroy(root)

    root.protocol("WM_DELETE_WINDOW", no)

    _topbar(root, "new download", C["blue"])

    body = ctk.CTkFrame(root, fg_color=C["bg"])
    body.pack(fill="both", expand=True, padx=22, pady=14)

    ctk.CTkLabel(body, text="New download detected",
                 font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
                 text_color=C["text"]).pack(anchor="w")
    ctk.CTkLabel(body, text="Scan this file for threats?",
                 font=ctk.CTkFont(size=12), text_color=C["dim"]).pack(anchor="w", pady=(2, 12))

    # File card
    card = ctk.CTkFrame(body, fg_color=C["surface"], corner_radius=8,
                         border_width=1, border_color=C["border"])
    card.pack(fill="x")
    ci = ctk.CTkFrame(card, fg_color="transparent")
    ci.pack(padx=14, pady=10, fill="x")
    ctk.CTkLabel(ci, text=fn[:42] + ("..." if len(fn) > 42 else ""),
                 font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                 text_color=C["text"]).pack(anchor="w")

    meta_text = f"{sz_s}  ·  {ext}  ·  Downloads"
    if source and source.get("domain"):
        meta_text += f"  ·  {source['domain']}"
    ctk.CTkLabel(ci, text=meta_text,
                 font=ctk.CTkFont(family="Consolas", size=10),
                 text_color=C["muted"]).pack(anchor="w", pady=(3, 0))

    # Buttons
    bf = ctk.CTkFrame(root, fg_color=C["bg"])
    bf.pack(fill="x", padx=22, pady=(0, 14))
    ctk.CTkButton(bf, text="Scan File", font=ctk.CTkFont(size=13, weight="bold"),
                  fg_color=C["text"], hover_color="#d4d4d8",
                  text_color="#09090b", corner_radius=6, height=34, width=110,
                  command=yes).pack(side="right", padx=(8, 0))
    ctk.CTkButton(bf, text="Skip", font=ctk.CTkFont(size=13),
                  fg_color=C["border"], hover_color="#3a3a40",
                  text_color=C["dim"], corner_radius=6, height=34, width=70,
                  command=no).pack(side="right")

    root.mainloop()
    return result["v"]


# ─── Progress window (animated pipeline steps) ───────────────────────────────

def _show_progress_and_scan(filepath: str, backend_url: str, source: dict = None) -> dict:
    import customtkinter as ctk

    fn = os.path.basename(filepath)
    sz = os.path.getsize(filepath)
    sz_s = f"{sz/1024:.0f} KB" if sz < 1048576 else f"{sz/1048576:.1f} MB"

    state = {"result": None, "error": None, "done": False}

    root = _mk_root("ThreatSense", 470, 400)
    root.protocol("WM_DELETE_WINDOW", lambda: None)

    _topbar(root, "analyzing", C["blue"])

    body = ctk.CTkFrame(root, fg_color=C["bg"])
    body.pack(fill="both", expand=True, padx=22, pady=14)

    # File row
    fr = ctk.CTkFrame(body, fg_color=C["surface"], corner_radius=8,
                       border_width=1, border_color=C["border"])
    fr.pack(fill="x", pady=(0, 16))
    fri = ctk.CTkFrame(fr, fg_color="transparent")
    fri.pack(padx=14, pady=9, fill="x")
    ctk.CTkLabel(fri, text=fn[:38] + ("..." if len(fn) > 38 else ""),
                 font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                 text_color=C["text"]).pack(anchor="w")
    meta = sz_s
    if source and source.get("domain"):
        meta += f"  ·  {source['domain']}"
    ctk.CTkLabel(fri, text=meta, font=ctk.CTkFont(family="Consolas", size=10),
                 text_color=C["muted"]).pack(anchor="w", pady=(2, 0))

    # Progress
    pf = ctk.CTkFrame(body, fg_color="transparent")
    pf.pack(fill="x", pady=(0, 4))
    plbl = ctk.CTkLabel(pf, text="Analyzing...", font=ctk.CTkFont(size=12),
                        text_color=C["muted"])
    plbl.pack(side="left")
    pctlbl = ctk.CTkLabel(pf, text="0%", font=ctk.CTkFont(family="Consolas", size=12),
                          text_color=C["text"])
    pctlbl.pack(side="right")

    pbar = ctk.CTkProgressBar(body, progress_color=C["blue"], fg_color=C["border"],
                               height=3, corner_radius=1)
    pbar.pack(fill="x", pady=(0, 16))
    pbar.set(0)

    # Steps
    sframe = ctk.CTkFrame(body, fg_color="transparent")
    sframe.pack(fill="x")

    dots, labels, statuses = [], [], []
    for i, txt in enumerate(STEPS):
        row = ctk.CTkFrame(sframe, fg_color="transparent", height=34)
        row.pack(fill="x")
        row.pack_propagate(False)
        d = ctk.CTkLabel(row, text=f" {i+1:02d} ",
                         font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=C["muted"], width=30)
        d.pack(side="left")
        l = ctk.CTkLabel(row, text=txt, font=ctk.CTkFont(size=13),
                         text_color=C["muted"])
        l.pack(side="left", padx=(4, 0))
        s = ctk.CTkLabel(row, text="", font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=C["muted"])
        s.pack(side="right", padx=(0, 4))
        dots.append(d); labels.append(l); statuses.append(s)
        if i < len(STEPS) - 1:
            ctk.CTkFrame(sframe, fg_color=C["border"], height=1).pack(fill="x")

    cur = {"step": 0}

    def paint(idx):
        pct = min(int(idx / len(STEPS) * 100), 100)
        pctlbl.configure(text=f"{pct}%")
        pbar.set(idx / len(STEPS))
        for i in range(len(STEPS)):
            if i < idx:
                dots[i].configure(text_color=C["green"])
                labels[i].configure(text_color=C["dim"])
                statuses[i].configure(text="done", text_color=C["green"])
            elif i == idx and idx < len(STEPS):
                dots[i].configure(text_color=C["text"])
                labels[i].configure(text_color=C["text"],
                                     font=ctk.CTkFont(size=13, weight="bold"))
                statuses[i].configure(text="running", text_color=C["blue"])
            else:
                dots[i].configure(text_color=C["muted"])
                labels[i].configure(text_color=C["muted"],
                                     font=ctk.CTkFont(size=13))
                statuses[i].configure(text="")

    def advance():
        if state["done"]:
            return
        s = cur["step"]
        if s < len(STEPS) - 1:
            cur["step"] = s + 1
            paint(cur["step"])
            delay = 1500 if s < 2 else 4000
            root.after(delay, advance)

    def poll():
        if state["done"]:
            if state["error"]:
                plbl.configure(text="Error", text_color=C["red"])
                pbar.configure(progress_color=C["red"])
                root.after(2000, lambda: _safe_destroy(root))
            else:
                paint(len(STEPS))
                pctlbl.configure(text="100%")
                pbar.set(1.0)
                plbl.configure(text="Complete", text_color=C["green"])
                for i in range(len(STEPS)):
                    dots[i].configure(text_color=C["green"])
                    labels[i].configure(text_color=C["dim"])
                    statuses[i].configure(text="done", text_color=C["green"])
                root.after(1000, lambda: _safe_destroy(root))
            return
        root.after(300, poll)

    def bg():
        try:
            state["result"] = _upload_file(filepath, backend_url, source)
        except Exception as e:
            state["error"] = str(e)
        state["done"] = True

    paint(0)
    root.after(1200, advance)
    root.after(300, poll)
    threading.Thread(target=bg, daemon=True).start()

    root.mainloop()

    if state["error"]:
        raise RuntimeError(state["error"])
    return state["result"]


# ─── Result popup (with Delete File + View Report) ───────────────────────────

def _show_result_popup(filename: str, filepath: str, result: dict, backend_url: str):
    import customtkinter as ctk

    llm = result.get("llm_report", {})
    sev     = llm.get("severity", "UNKNOWN")
    threat  = llm.get("threat_classification", "Unknown")
    conf    = llm.get("confidence", 0)
    summary = llm.get("executive_summary", "No summary available.")
    iid     = result.get("incident_id", "?")
    sc      = SEV.get(sev, C["muted"])

    action = {"deleted": False}

    root = _mk_root("ThreatSense", 490, 460)
    root.protocol("WM_DELETE_WINDOW", lambda: _safe_destroy(root))

    _topbar(root, f"#{iid}", C["muted"])

    # Severity accent bar
    ctk.CTkFrame(root, fg_color=sc, height=3, corner_radius=0).pack(fill="x")

    # Scrollable body
    body = ctk.CTkFrame(root, fg_color=C["bg"])
    body.pack(fill="both", expand=True, padx=22, pady=14)

    # Badge row
    br = ctk.CTkFrame(body, fg_color="transparent")
    br.pack(anchor="w", pady=(0, 4))
    ctk.CTkLabel(br, text=f" {sev} ",
                 font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                 text_color=sc, fg_color=C["surface"], corner_radius=4).pack(side="left")
    ctk.CTkLabel(br, text=f"  {threat}",
                 font=ctk.CTkFont(family="Consolas", size=11),
                 text_color=C["muted"]).pack(side="left", padx=(6, 0))

    ctk.CTkLabel(body, text=filename,
                 font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
                 text_color=C["text"]).pack(anchor="w")
    ctk.CTkLabel(body, text=f"Confidence {conf}%  ·  Incident #{iid}",
                 font=ctk.CTkFont(family="Consolas", size=10),
                 text_color=C["muted"]).pack(anchor="w", pady=(2, 12))

    # Summary
    sc_f = ctk.CTkFrame(body, fg_color=C["surface"], corner_radius=8,
                          border_width=1, border_color=C["border"])
    sc_f.pack(fill="x", pady=(0, 8))
    ctk.CTkLabel(sc_f, text="EXECUTIVE SUMMARY",
                 font=ctk.CTkFont(family="Consolas", size=9),
                 text_color=C["muted"]).pack(anchor="w", padx=14, pady=(10, 4))
    ctk.CTkLabel(sc_f, text=summary[:250] + ("..." if len(summary) > 250 else ""),
                 font=ctk.CTkFont(size=12), text_color=C["dim"],
                 wraplength=430, justify="left").pack(anchor="w", padx=14, pady=(0, 12))

    # IOCs
    iocs = llm.get("ioc_highlights", [])
    if iocs:
        ic = ctk.CTkFrame(body, fg_color=C["surface"], corner_radius=8,
                           border_width=1, border_color=C["border"])
        ic.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(ic, text="IOCs", font=ctk.CTkFont(family="Consolas", size=9),
                     text_color=C["muted"]).pack(anchor="w", padx=14, pady=(10, 4))
        for ioc in iocs[:4]:
            ctk.CTkLabel(ic, text=f"  {ioc}",
                         font=ctk.CTkFont(family="Consolas", size=11),
                         text_color=sc).pack(anchor="w", padx=14)
        ctk.CTkLabel(ic, text="", height=4).pack()

    # ── Action Buttons ──
    btn_area = ctk.CTkFrame(root, fg_color=C["bg"])
    btn_area.pack(fill="x", padx=22, pady=(0, 14))

    # Status label (for delete confirmation)
    status_msg = ctk.CTkLabel(btn_area, text="", font=ctk.CTkFont(size=11),
                               text_color=C["green"])
    status_msg.pack(side="top", pady=(0, 6))

    btn_row = ctk.CTkFrame(btn_area, fg_color="transparent")
    btn_row.pack(fill="x")

    def do_delete():
        """Delete the downloaded file."""
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                action["deleted"] = True
                status_msg.configure(text=f"Deleted: {filename}", text_color=C["green"])
                del_btn.configure(state="disabled", text="Deleted",
                                   fg_color=C["border"], text_color=C["muted"])
            else:
                status_msg.configure(text="File already removed", text_color=C["amber"])
        except Exception as e:
            status_msg.configure(text=f"Delete failed: {e}", text_color=C["red"])

    def do_view_report():
        """Download the PDF report and open it."""
        try:
            pdf_url = f"{backend_url}/incidents/{iid}/pdf"
            resp = requests.get(pdf_url, timeout=30)
            resp.raise_for_status()

            # Save to temp file and open
            tmp = os.path.join(tempfile.gettempdir(),
                               f"ThreatSense_Report_{iid}_{filename}.pdf")
            with open(tmp, "wb") as f:
                f.write(resp.content)

            # Open with default PDF viewer
            os.startfile(tmp)
            status_msg.configure(text="Report opened", text_color=C["green"])
        except Exception as e:
            status_msg.configure(text=f"Failed: {e}", text_color=C["red"])

    # Delete button (red accent for dangerous files)
    del_color = C["red"] if sev in ("CRITICAL", "HIGH", "MEDIUM") else C["border"]
    del_text_c = "#ffffff" if sev in ("CRITICAL", "HIGH", "MEDIUM") else C["dim"]
    del_btn = ctk.CTkButton(
        btn_row, text="Delete File", font=ctk.CTkFont(size=12),
        fg_color=del_color, hover_color="#cc3333" if sev in ("CRITICAL", "HIGH", "MEDIUM") else "#3a3a40",
        text_color=del_text_c, corner_radius=6, height=34, width=110,
        command=do_delete,
    )
    del_btn.pack(side="left")

    # View Report button
    ctk.CTkButton(
        btn_row, text="View Report", font=ctk.CTkFont(size=12),
        fg_color=C["border"], hover_color="#3a3a40",
        text_color=C["dim"], corner_radius=6, height=34, width=110,
        command=do_view_report,
    ).pack(side="left", padx=(8, 0))

    # Close / dismiss
    ctk.CTkButton(
        btn_row, text="Done", font=ctk.CTkFont(size=13, weight="bold"),
        fg_color=C["text"], hover_color="#d4d4d8",
        text_color="#09090b", corner_radius=6, height=34, width=80,
        command=lambda: _safe_destroy(root),
    ).pack(side="right")

    root.mainloop()
    return action["deleted"]


# ─── Error popup ──────────────────────────────────────────────────────────────

def _show_error_popup(filename: str, error: str):
    import customtkinter as ctk

    root = _mk_root("ThreatSense", 430, 190)
    root.protocol("WM_DELETE_WINDOW", lambda: _safe_destroy(root))

    _topbar(root)
    ctk.CTkFrame(root, fg_color=C["red"], height=3, corner_radius=0).pack(fill="x")

    body = ctk.CTkFrame(root, fg_color=C["bg"])
    body.pack(fill="both", expand=True, padx=22, pady=12)
    ctk.CTkLabel(body, text=f"Failed to scan: {filename}",
                 font=ctk.CTkFont(size=13, weight="bold"),
                 text_color=C["text"]).pack(anchor="w")
    ctk.CTkLabel(body, text=error[:200],
                 font=ctk.CTkFont(family="Consolas", size=10),
                 text_color=C["dim"], wraplength=370, justify="left").pack(anchor="w", pady=(6, 0))

    ctk.CTkButton(root, text="OK", font=ctk.CTkFont(size=13),
                  fg_color=C["border"], hover_color="#3a3a40",
                  text_color=C["dim"], corner_radius=6, height=30, width=60,
                  command=lambda: _safe_destroy(root)).pack(pady=(0, 12))

    root.mainloop()


# ─── File utilities ───────────────────────────────────────────────────────────

def _is_temp_file(fp):
    return os.path.splitext(fp)[1].lower() in TEMP_EXTENSIONS


def _wait_for_stable(fp, timeout=30.0):
    start = time.time()
    prev, stable = -1, 0
    while time.time() - start < timeout:
        try:
            if not os.path.exists(fp):
                return False
            cur = os.path.getsize(fp)
        except OSError:
            return False
        if cur == prev and cur > 0:
            stable += 1
            if stable >= STABLE_CHECK_ROUNDS:
                return True
        else:
            stable = 0
        prev = cur
        time.sleep(STABLE_CHECK_INTERVAL)
    return False


def _upload_file(fp, backend_url, source=None):
    fn = os.path.basename(fp)
    data = {}
    if source:
        data["source_domain"] = source.get("domain", "")
        data["source_ip"] = source.get("ip", "")
    with open(fp, "rb") as f:
        resp = requests.post(f"{backend_url}/analyze", files={"file": (fn, f)}, data=data, timeout=180)
    resp.raise_for_status()
    return resp.json()


# ─── Watchdog handler ─────────────────────────────────────────────────────────

class DownloadHandler(FileSystemEventHandler):
    def __init__(self, q):
        super().__init__()
        self.q = q
        self._seen = set()
        self._lock = threading.Lock()

    def on_created(self, event):
        if event.is_directory:
            return
        fp = event.src_path
        if _is_temp_file(fp):
            return
        with self._lock:
            if fp in self._seen:
                return
            self._seen.add(fp)
        self.q.put(fp)

    def on_moved(self, event):
        if event.is_directory:
            return
        dest = event.dest_path
        if _is_temp_file(event.src_path) and not _is_temp_file(dest):
            with self._lock:
                if dest in self._seen:
                    return
                self._seen.add(dest)
            self.q.put(dest)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ThreatSense Download Monitor")
    parser.add_argument("--folder", "-f", default=DEFAULT_DOWNLOADS)
    parser.add_argument("--backend", "-b", default=DEFAULT_BACKEND)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    watch = os.path.abspath(args.folder)
    backend = args.backend.rstrip("/")
    browser = not args.no_browser

    if not os.path.isdir(watch):
        print(f"[!] Folder not found: {watch}")
        sys.exit(1)

    print(f"[*] Checking backend at {backend}...")
    try:
        r = requests.get(f"{backend}/", timeout=5)
        if r.ok:
            print(f"[+] Backend online")
    except Exception:
        print(f"[!] Backend not reachable — start it before downloading files")

    fq = queue.Queue()
    obs = Observer()
    obs.schedule(DownloadHandler(fq), watch, recursive=False)
    obs.start()

    print(f"\n{'='*55}")
    print(f"  ThreatSense Download Monitor")
    print(f"{'='*55}")
    print(f"  Watching:  {watch}")
    print(f"  Backend:   {backend}")
    print(f"  Status:    ACTIVE")
    print(f"{'='*55}\n")
    print("  Press Ctrl+C to stop.\n")

    try:
        while True:
            try:
                fp = fq.get(timeout=1.0)
            except queue.Empty:
                continue

            fn = os.path.basename(fp)
            print(f"[>] {fn}")

            if not _wait_for_stable(fp):
                print(f"[!] Disappeared: {fn}")
                continue

            sz = os.path.getsize(fp)
            if sz < MIN_FILE_SIZE:
                continue

            sz_s = f"{sz/1024:.1f} KB" if sz < 1048576 else f"{sz/1048576:.1f} MB"
            print(f"[+] Ready ({sz_s})")

            # ── Source lookup ──
            source = _get_download_source(fp)
            if source and source.get("domain"):
                print(f"[📡] Source: {source['domain']}" + (f" ({source['ip']})" if source.get('ip') else ""))

            if not _show_scan_popup(fp, source):
                print(f"[-] Skipped\n")
                continue

            print(f"[*] Scanning...")
            try:
                result = _show_progress_and_scan(fp, backend, source)
                sev = result.get("llm_report", {}).get("severity", "?")
                iid = result.get("incident_id", "?")
                print(f"[+] {sev} — #{iid}")

                deleted = _show_result_popup(fn, fp, result, backend)

                if deleted:
                    print(f"[x] File deleted: {fn}")

                if browser:
                    webbrowser.open(FRONTEND_URL)

            except Exception as e:
                print(f"[!] {e}")
                _show_error_popup(fn, str(e))
            print()

    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        obs.stop()

    obs.join()
    print("[*] Stopped.")


if __name__ == "__main__":
    main()
