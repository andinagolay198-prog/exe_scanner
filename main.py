"""
EXE Scanner — GUI chính
Giao diện tkinter với terminal real-time, bảng kết quả, và log viewer
"""
import os
import sys
import threading
import queue
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font as tkfont

# Thêm root vào sys.path
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.pe_parser import PEParser
from core.scanner import ThreatScorer, load_yara_rules, scan_yara, YaraMatch
from core.logger import ScanLogger, LOGS_DIR
from core.report_html import generate_report
from core.virustotal  import VTClient
try:
    from core.virustotal import VTClient
    VT_AVAILABLE = True
except Exception:
    VT_AVAILABLE = False
    VTClient = None

# ─────────────────────────────────────────────────────────────
#  THEME
# ─────────────────────────────────────────────────────────────
BG       = "#0d1117"
BG2      = "#161b22"
BG3      = "#21262d"
BORDER   = "#30363d"
FG       = "#c9d1d9"
FG2      = "#8b949e"
FG_TERM  = "#e6edf3"
ACC      = "#58a6ff"
GREEN    = "#3fb950"
YELLOW   = "#d29922"
ORANGE   = "#f0883e"
RED      = "#f85149"
PURPLE   = "#bc8cff"
PINK     = "#ff7b72"

LEVEL_COLORS = {
    "INFO":     FG2,
    "OK":       GREEN,
    "SECTION":  ACC,
    "WARN":     YELLOW,
    "HIGH":     ORANGE,
    "CRITICAL": RED,
}

VERDICT_COLORS = {
    "CLEAN":               GREEN,
    "POTENTIALLY_UNWANTED": YELLOW,
    "SUSPICIOUS":          ORANGE,
    "MALICIOUS":           RED,
    "CRITICAL_THREAT":     PURPLE,
}


# ─────────────────────────────────────────────────────────────
#  SCAN WORKER
# ─────────────────────────────────────────────────────────────
class ScanWorker(threading.Thread):
    def __init__(self, paths, yara_rules, msg_queue, vt_client=None):
        super().__init__(daemon=True)
        self.paths = paths
        self.yara_rules = yara_rules
        self.msg_queue = msg_queue
        self.vt_client = vt_client
        self.parser = PEParser()
        self.scorer = ThreatScorer()

    def run(self):
        self.msg_queue.put(("SESSION_START", None))
        total = len(self.paths)
        for i, path in enumerate(self.paths):
            self.msg_queue.put(("PROGRESS", (i + 1, total, path)))
            try:
                self._scan_one(path)
            except Exception as e:
                self.msg_queue.put(("LOG", (f"Lỗi quét {path}: {e}", "CRITICAL")))
        self.msg_queue.put(("DONE", total))

    def _scan_one(self, path: str):
        fname = os.path.basename(path)
        self.msg_queue.put(("LOG", (f"{'─'*60}", "SECTION")))
        self.msg_queue.put(("LOG", (f"Bắt đầu quét: {fname}", "SECTION")))
        self.msg_queue.put(("LOG", (f"Path: {path}", "INFO")))

        pe_result = self.parser.analyze(path)

        if not pe_result.is_valid_pe:
            self.msg_queue.put(("LOG", (f"Không phải PE hợp lệ: {pe_result.error}", "WARN")))
            self.msg_queue.put(("LOG", (f"MD5   : {pe_result.md5}", "INFO")))
            self.msg_queue.put(("LOG", (f"SHA256: {pe_result.sha256}", "INFO")))
        else:
            self.msg_queue.put(("LOG", (f"[PE OK] {pe_result.machine_type} | {pe_result.subsystem}", "OK")))
            self.msg_queue.put(("LOG", (f"Compiled: {pe_result.timestamp_str}", "INFO")))
            self.msg_queue.put(("LOG", (f"MD5   : {pe_result.md5}", "INFO")))
            self.msg_queue.put(("LOG", (f"SHA256: {pe_result.sha256}", "INFO")))
            self.msg_queue.put(("LOG", (f"EP: 0x{pe_result.entry_point:08X}  in_code={pe_result.ep_in_code_section}", "INFO")))

            # Sections
            self.msg_queue.put(("LOG", ("  [SECTIONS]", "SECTION")))
            for s in pe_result.sections:
                tag = "SUSPICIOUS" if s.is_suspicious else "OK"
                level = "WARN" if s.is_suspicious else "INFO"
                self.msg_queue.put(("LOG", (
                    f"  {s.name:<12} entr={s.entropy:.3f}  virt={s.virtual_size:<7,}  raw={s.raw_size:<7,}  [{tag}]",
                    level
                )))
                for reason in s.suspicion_reasons:
                    self.msg_queue.put(("LOG", (f"    => {reason}", "HIGH")))

            # Suspicious imports
            if pe_result.suspicious_imports:
                self.msg_queue.put(("LOG", ("  [SUSPICIOUS IMPORTS]", "SECTION")))
                for si in pe_result.suspicious_imports[:20]:
                    lvl = si["level"]
                    col = "CRITICAL" if lvl == "CRITICAL" else ("HIGH" if lvl == "HIGH" else "WARN")
                    self.msg_queue.put(("LOG", (
                        f"  [{lvl:<8}] {si['api']:<30} — {si['reason']}", col
                    )))

            # Strings
            strs = pe_result.suspicious_strings
            for key, vals in strs.items():
                if vals:
                    self.msg_queue.put(("LOG", (f"  [STRINGS: {key.upper()}]", "SECTION")))
                    for v in vals[:6]:
                        self.msg_queue.put(("LOG", (f"    {v}", "WARN")))

        # YARA
        yara_matches = []
        self.msg_queue.put(("LOG", ("  [YARA SCAN]", "SECTION")))
        if self.yara_rules:
            yara_matches = scan_yara(path, self.yara_rules)
            if yara_matches:
                for m in yara_matches:
                    lvl = "CRITICAL" if m.severity == "CRITICAL" else (
                          "HIGH" if m.severity == "HIGH" else "WARN")
                    self.msg_queue.put(("LOG", (
                        f"  MATCH [{m.severity:<8}] {m.rule_name} — {m.description}", lvl
                    )))
            else:
                self.msg_queue.put(("LOG", ("  Không có YARA match", "OK")))
        else:
            self.msg_queue.put(("LOG", ("  YARA không khả dụng (pip install yara-python)", "WARN")))

        # VirusTotal lookup
        vt_report = None
        if self.vt_client and pe_result.sha256:
            self.msg_queue.put(("LOG", ("  [VIRUSTOTAL]", "SECTION")))
            try:
                vt_report = self.vt_client.lookup_hash(pe_result.sha256)
                if vt_report.error:
                    self.msg_queue.put(("LOG", (f"  VT: {vt_report.error}", "WARN")))
                elif not vt_report.found:
                    self.msg_queue.put(("LOG", ("  VT: Hash chua co trong database", "WARN")))
                else:
                    mal = vt_report.malicious
                    tot = vt_report.total_engines
                    det = vt_report.detection_rate
                    cached = " (cached)" if vt_report.cached else ""
                    lvl = "CRITICAL" if mal >= 10 else ("HIGH" if mal >= 3 else ("WARN" if mal >= 1 else "OK"))
                    self.msg_queue.put(("LOG", (
                        f"  VT{cached}: {mal}/{tot} engines ({det:.1f}%)"
                        + (f" | {vt_report.threat_label}" if vt_report.threat_label else ""),
                        lvl
                    )))
                    if vt_report.names:
                        self.msg_queue.put(("LOG", (f"  VT names: {', '.join(vt_report.names[:5])}", "HIGH")))
            except Exception as e:
                self.msg_queue.put(("LOG", (f"  VT error: {e}", "WARN")))

        # Score
        report = self.scorer.score(pe_result, yara_matches, vt_report)
        self.msg_queue.put(("LOG", (
            f"  SCORE: {report.score}/100  |  VERDICT: {report.verdict}", "SECTION"
        )))
        for f in report.findings[:8]:
            lvl = f["level"]
            col = "CRITICAL" if lvl == "CRITICAL" else ("HIGH" if lvl == "HIGH" else "WARN")
            self.msg_queue.put(("LOG", (
                f"    [{lvl:<8}] +{f['points']:>2} — {f['description']}", col
            )))

        self.msg_queue.put(("RESULT", report))


# ─────────────────────────────────────────────────────────────
#  MAIN APP
# ─────────────────────────────────────────────────────────────
class EXEScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("EXE Scanner — Malware & Botnet Detector")
        self.root.geometry("1280x820")
        self.root.configure(bg=BG)
        self.root.minsize(900, 600)

        self.yara_rules = None
        self.scan_results = []
        self.msg_queue = queue.Queue()
        self.logger: ScanLogger | None = None
        self._scanning = False
        self._vt_api_key: str = ""
        self._vt_client = None
        self._vt_upload = False
        self._vt_client_obj = None

        self._load_yara_async()
        self._build_ui()
        self._poll_queue()

    # ─── YARA loading ─────────────────────────────────────────

    def _load_yara_async(self):
        def _load():
            rules = load_yara_rules()
            self.msg_queue.put(("YARA_LOADED", rules))
        threading.Thread(target=_load, daemon=True).start()

    # ─── UI Construction ──────────────────────────────────────

    def _build_ui(self):
        self._apply_ttk_style()

        # ── Top bar ──
        topbar = tk.Frame(self.root, bg=BG2, height=52, bd=0)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        title_lbl = tk.Label(topbar, text="EXE Scanner",
                             bg=BG2, fg=ACC,
                             font=("Consolas", 16, "bold"))
        title_lbl.pack(side="left", padx=16, pady=10)

        sub_lbl = tk.Label(topbar,
                           text="Malware · Botnet · Virus PE Detector",
                           bg=BG2, fg=FG2, font=("Consolas", 10))
        sub_lbl.pack(side="left", pady=14)

        self.yara_status = tk.Label(topbar, text="YARA: loading...",
                                    bg=BG2, fg=YELLOW, font=("Consolas", 9))
        self.yara_status.pack(side="right", padx=14)

        # ── Toolbar ──
        toolbar = tk.Frame(self.root, bg=BG3, height=44, bd=0)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        self.btn_files = self._btn(toolbar, "  Chọn File(s)", self._pick_files)
        self.btn_files.pack(side="left", padx=(10, 4), pady=7)

        self.btn_folder = self._btn(toolbar, "  Chọn Folder", self._pick_folder)
        self.btn_folder.pack(side="left", padx=4, pady=7)

        self.btn_scan = self._btn(toolbar, "  QUÉT NGAY", self._start_scan,
                                  bg="#1f6feb", hover="#388bfd")
        self.btn_scan.pack(side="left", padx=(10, 4), pady=7)

        self.btn_clear = self._btn(toolbar, "  Xóa", self._clear_all,
                                   bg=BG3, hover=BG2)
        self.btn_clear.pack(side="left", padx=4, pady=7)

        self.btn_report = self._btn(toolbar, "  Xuất HTML", self._export_html,
                                    bg="#1a3a1a", hover="#2a5a2a")
        self.btn_report.pack(side="right", padx=4, pady=7)

        self.btn_vt = self._btn(toolbar, "  VT API Key", self._set_vt_key,
                                bg=BG3, hover=BG2)
        self.btn_vt.pack(side="right", padx=4, pady=7)

        self.btn_logs = self._btn(toolbar, "  Mở Logs", self._open_logs_dir,
                                  bg=BG3, hover=BG2)
        self.btn_logs.pack(side="right", padx=10, pady=7)

        # ── Progress bar ──
        prog_frame = tk.Frame(self.root, bg=BG, height=24)
        prog_frame.pack(fill="x")
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(prog_frame, variable=self.progress_var,
                                             maximum=100, style="scan.Horizontal.TProgressbar")
        self.progress_bar.pack(fill="x", padx=2, pady=1)
        self.status_lbl = tk.Label(prog_frame, text="Sẵn sàng",
                                   bg=BG, fg=FG2, font=("Consolas", 9))
        self.status_lbl.pack(side="left", padx=8)

        # ── File list ──
        self.file_list: List[str] = []

        # ── Main pane ──
        paned = tk.PanedWindow(self.root, orient="horizontal",
                               bg=BORDER, sashwidth=4, sashrelief="flat",
                               handlesize=0)
        paned.pack(fill="both", expand=True, padx=0, pady=0)

        # Left: results table
        left = tk.Frame(paned, bg=BG)
        paned.add(left, minsize=320, width=400)
        self._build_results_panel(left)

        # Right: notebook (terminal + details + logs)
        right = tk.Frame(paned, bg=BG)
        paned.add(right, minsize=400)
        self._build_right_panel(right)

    def _build_results_panel(self, parent):
        hdr = tk.Label(parent, text="Kết quả quét", bg=BG2,
                       fg=ACC, font=("Consolas", 11, "bold"), anchor="w",
                       padx=10, pady=6)
        hdr.pack(fill="x")

        frame = tk.Frame(parent, bg=BG)
        frame.pack(fill="both", expand=True)

        cols = ("file", "score", "verdict")
        self.results_tree = ttk.Treeview(
            frame, columns=cols, show="headings",
            style="dark.Treeview", selectmode="browse"
        )
        self.results_tree.heading("file",    text="File",    anchor="w")
        self.results_tree.heading("score",   text="Score",   anchor="center")
        self.results_tree.heading("verdict", text="Verdict", anchor="center")
        self.results_tree.column("file",    width=180, stretch=True,  anchor="w")
        self.results_tree.column("score",   width=52,  stretch=False, anchor="center")
        self.results_tree.column("verdict", width=140, stretch=False, anchor="center")

        sb = ttk.Scrollbar(frame, orient="vertical",
                           command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=sb.set)
        self.results_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.results_tree.bind("<<TreeviewSelect>>", self._on_result_select)

        # Tag colors per verdict
        for verdict, color in VERDICT_COLORS.items():
            self.results_tree.tag_configure(verdict, foreground=color)

    def _build_right_panel(self, parent):
        nb = ttk.Notebook(parent, style="dark.TNotebook")
        nb.pack(fill="both", expand=True)
        self.notebook = nb

        # Tab 1: Terminal
        t1 = tk.Frame(nb, bg=BG)
        nb.add(t1, text="  Terminal  ")
        self._build_terminal(t1)

        # Tab 2: Detail
        t2 = tk.Frame(nb, bg=BG)
        nb.add(t2, text="  Chi tiết  ")
        self._build_detail_panel(t2)

        # Tab 3: Logs
        t3 = tk.Frame(nb, bg=BG)
        nb.add(t3, text="  Logs  ")
        self._build_logs_panel(t3)

    def _build_terminal(self, parent):
        ctrl = tk.Frame(parent, bg=BG2, height=30)
        ctrl.pack(fill="x")
        ctrl.pack_propagate(False)
        tk.Label(ctrl, text="Real-time output", bg=BG2, fg=FG2,
                 font=("Consolas", 9)).pack(side="left", padx=8, pady=5)
        self._btn(ctrl, "Clear terminal", self._clear_terminal,
                  bg=BG2, hover=BG3, h=22).pack(side="right", padx=8, pady=4)

        frame = tk.Frame(parent, bg=BG)
        frame.pack(fill="both", expand=True)

        self.terminal = tk.Text(
            frame, bg="#010409", fg=FG_TERM,
            font=("Consolas", 9), wrap="none",
            insertbackground=ACC, state="disabled",
            borderwidth=0, relief="flat",
        )
        vsb = ttk.Scrollbar(frame, orient="vertical",   command=self.terminal.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.terminal.xview)
        self.terminal.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        for level, color in LEVEL_COLORS.items():
            self.terminal.tag_configure(level, foreground=color)
        self.terminal.tag_configure("SECTION",
                                    foreground=ACC,
                                    font=("Consolas", 9, "bold"))

        hsb.pack(side="bottom", fill="x")
        vsb.pack(side="right",  fill="y")
        self.terminal.pack(side="left", fill="both", expand=True)

    def _build_detail_panel(self, parent):
        self.detail_text = tk.Text(
            parent, bg=BG2, fg=FG,
            font=("Consolas", 9), wrap="word",
            state="disabled", borderwidth=0,
        )
        vsb = ttk.Scrollbar(parent, orient="vertical",
                             command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.detail_text.pack(fill="both", expand=True)

        for level, color in LEVEL_COLORS.items():
            self.detail_text.tag_configure(level, foreground=color)
        self.detail_text.tag_configure("SECTION",
                                       foreground=ACC,
                                       font=("Consolas", 9, "bold"))
        self.detail_text.tag_configure("VERDICT_OK",   foreground=GREEN)
        self.detail_text.tag_configure("VERDICT_WARN",  foreground=YELLOW)
        self.detail_text.tag_configure("VERDICT_HIGH",  foreground=ORANGE)
        self.detail_text.tag_configure("VERDICT_CRIT",  foreground=RED)
        self.detail_text.tag_configure("VERDICT_DEAD",  foreground=PURPLE)
        self.detail_text.tag_configure("HEADER",
                                       foreground=ACC,
                                       font=("Consolas", 10, "bold"))

    def _build_logs_panel(self, parent):
        ctrl = tk.Frame(parent, bg=BG2, height=30)
        ctrl.pack(fill="x")
        ctrl.pack_propagate(False)
        tk.Label(ctrl, text="File logs", bg=BG2, fg=FG2,
                 font=("Consolas", 9)).pack(side="left", padx=8, pady=5)
        self._btn(ctrl, "Làm mới", self._refresh_logs,
                  bg=BG2, hover=BG3, h=22).pack(side="right", padx=8, pady=4)

        frame = tk.Frame(parent, bg=BG)
        frame.pack(fill="both", expand=True)

        self.logs_list = tk.Listbox(
            frame, bg=BG2, fg=FG, font=("Consolas", 9),
            selectbackground=ACC, selectforeground="#fff",
            borderwidth=0, relief="flat",
            activestyle="none",
        )
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.logs_list.yview)
        self.logs_list.configure(yscrollcommand=sb.set)
        self.logs_list.bind("<Double-Button-1>", self._open_log_file)
        self.logs_list.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self._refresh_logs()

    # ─── Helpers ──────────────────────────────────────────────

    def _btn(self, parent, text, cmd, bg="#21262d", hover="#30363d", h=30):
        btn = tk.Label(parent, text=text, bg=bg, fg=FG,
                       font=("Consolas", 9), cursor="hand2",
                       padx=10, pady=2, height=1)
        btn.bind("<Button-1>", lambda e: cmd())
        btn.bind("<Enter>", lambda e: btn.configure(bg=hover))
        btn.bind("<Leave>", lambda e: btn.configure(bg=bg))
        return btn

    def _apply_ttk_style(self):
        style = ttk.Style()
        style.theme_use("default")

        style.configure("dark.Treeview",
                        background=BG2, foreground=FG,
                        fieldbackground=BG2,
                        rowheight=22, borderwidth=0,
                        font=("Consolas", 9))
        style.configure("dark.Treeview.Heading",
                        background=BG3, foreground=FG2,
                        borderwidth=0, font=("Consolas", 9, "bold"))
        style.map("dark.Treeview",
                  background=[("selected", ACC)],
                  foreground=[("selected", "#fff")])

        style.configure("dark.TNotebook",
                        background=BG, borderwidth=0, tabmargins=[0, 0, 0, 0])
        style.configure("dark.TNotebook.Tab",
                        background=BG3, foreground=FG2,
                        font=("Consolas", 9), padding=[10, 4],
                        borderwidth=0)
        style.map("dark.TNotebook.Tab",
                  background=[("selected", BG2)],
                  foreground=[("selected", ACC)])

        style.configure("scan.Horizontal.TProgressbar",
                        troughcolor=BG3, background=ACC,
                        thickness=4, borderwidth=0)

        style.configure("TScrollbar",
                        troughcolor=BG2, background=BG3,
                        borderwidth=0, arrowcolor=FG2)

    # ─── File picking ──────────────────────────────────────────

    def _pick_files(self):
        paths = filedialog.askopenfilenames(
            title="Chọn file EXE để quét",
            filetypes=[("Executable files", "*.exe *.dll *.sys *.scr"),
                       ("All files", "*.*")]
        )
        if paths:
            self.file_list = list(paths)
            self._set_status(f"{len(paths)} file(s) đã chọn")
            self._term_log(f"Đã chọn {len(paths)} file(s) để quét", "INFO")

    def _pick_folder(self):
        folder = filedialog.askdirectory(title="Chọn thư mục quét")
        if folder:
            exts = {".exe", ".dll", ".sys", ".scr"}
            files = []
            for root_, dirs, fnames in os.walk(folder):
                # Skip obviously safe dirs
                dirs[:] = [d for d in dirs if d.lower() not in
                           {"windows", "system32", "syswow64"}]
                for f in fnames:
                    if os.path.splitext(f)[1].lower() in exts:
                        files.append(os.path.join(root_, f))
            self.file_list = files
            self._set_status(f"Tìm thấy {len(files)} file(s) trong folder")
            self._term_log(f"Folder scan: {len(files)} file(s) tìm thấy trong {folder}", "INFO")

    # ─── Scan ─────────────────────────────────────────────────

    def _start_scan(self):
        if self._scanning:
            messagebox.showwarning("Đang quét", "Vui lòng chờ scan hiện tại hoàn thành.")
            return
        if not self.file_list:
            messagebox.showinfo("Chưa chọn file",
                                "Hãy chọn file hoặc folder trước khi quét.")
            return

        self._scanning = True
        self.btn_scan.configure(fg=FG2)

        # Init logger
        self.logger = ScanLogger()
        self.logger.new_session("scan")

        worker = ScanWorker(self.file_list.copy(), self.yara_rules, self.msg_queue, self._vt_client_obj)
        worker.start()

    # ─── Queue polling ────────────────────────────────────────

    def _poll_queue(self):
        try:
            while True:
                msg_type, payload = self.msg_queue.get_nowait()
                self._handle_msg(msg_type, payload)
        except queue.Empty:
            pass
        self.root.after(40, self._poll_queue)

    def _handle_msg(self, msg_type: str, payload):
        if msg_type == "YARA_LOADED":
            self.yara_rules = payload
            if payload:
                self.yara_status.configure(text="YARA: OK", fg=GREEN)
                self._term_log("YARA rules loaded OK", "OK")
            else:
                self.yara_status.configure(text="YARA: không khả dụng", fg=YELLOW)
                self._term_log("YARA không khả dụng (install: pip install yara-python)", "WARN")

        elif msg_type == "SESSION_START":
            self._term_log("="*60, "SECTION")
            self._term_log(f"SESSION BẮT ĐẦU: {datetime.datetime.now().strftime('%H:%M:%S')}", "SECTION")
            self.notebook.select(0)

        elif msg_type == "PROGRESS":
            i, total, path = payload
            pct = (i / total) * 100
            self.progress_var.set(pct)
            self._set_status(f"Đang quét {i}/{total}: {os.path.basename(path)}")

        elif msg_type == "LOG":
            msg, level = payload
            self._term_log(msg, level)
            if self.logger:
                getattr(self.logger, level.lower(), self.logger.info)(msg)

        elif msg_type == "RESULT":
            report = payload
            self._add_result(report)
            if self.logger:
                self.logger.log_report(report)

        elif msg_type == "DONE":
            total = payload
            self._scanning = False
            self.btn_scan.configure(fg=FG)
            self.progress_var.set(100)
            self._set_status(f"Hoàn thành — {total} file(s) đã quét")
            self._term_log("="*60, "SECTION")
            self._term_log(f"SCAN HOÀN THÀNH — {total} file(s)", "OK")
            self._refresh_logs()

    # ─── Terminal output ───────────────────────────────────────

    def _term_log(self, msg: str, level: str = "INFO"):
        self.terminal.configure(state="normal")
        prefix_map = {
            "SECTION":  ">>> ",
            "CRITICAL": "[!!!] ",
            "HIGH":     "[!!]  ",
            "WARN":     "[!]   ",
            "OK":       "[OK]  ",
            "INFO":     "      ",
        }
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        prefix = prefix_map.get(level, "      ")
        line = f"{ts} {prefix}{msg}\n"
        self.terminal.insert("end", line, level)
        self.terminal.see("end")
        self.terminal.configure(state="disabled")

    def _clear_terminal(self):
        self.terminal.configure(state="normal")
        self.terminal.delete("1.0", "end")
        self.terminal.configure(state="disabled")

    # ─── Results table ────────────────────────────────────────

    def _add_result(self, report):
        self.scan_results.append(report)
        fname = os.path.basename(report.filepath)
        score = report.score
        verdict = report.verdict
        tag = verdict

        self.results_tree.insert(
            "", "end",
            iid=str(len(self.scan_results) - 1),
            values=(fname, score, verdict),
            tags=(tag,),
        )

    def _on_result_select(self, event):
        sel = self.results_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if idx < len(self.scan_results):
            report = self.scan_results[idx]
            self._show_detail(report)
            self.notebook.select(1)

    def _show_detail(self, report):
        pe = report.pe_result
        dt = self.detail_text

        dt.configure(state="normal")
        dt.delete("1.0", "end")

        def w(text, tag=""):
            dt.insert("end", text, tag)

        # Header
        w(f"{'═'*60}\n", "HEADER")
        w(f"  {os.path.basename(report.filepath)}\n", "HEADER")
        w(f"{'═'*60}\n", "HEADER")

        # Verdict block
        vc = {"CLEAN": "VERDICT_OK", "POTENTIALLY_UNWANTED": "VERDICT_WARN",
              "SUSPICIOUS": "VERDICT_HIGH", "MALICIOUS": "VERDICT_CRIT",
              "CRITICAL_THREAT": "VERDICT_DEAD"}
        vtag = vc.get(report.verdict, "VERDICT_WARN")
        w(f"\n  SCORE   : {report.score}/100\n", vtag)
        w(f"  VERDICT : {report.verdict}\n\n", vtag)

        # File info
        w("  [FILE INFO]\n", "SECTION")
        w(f"  Path   : {pe.filepath}\n")
        w(f"  Size   : {pe.file_size:,} bytes\n")
        w(f"  MD5    : {pe.md5}\n")
        w(f"  SHA1   : {pe.sha1}\n")
        w(f"  SHA256 : {pe.sha256}\n")

        if pe.is_valid_pe:
            w("\n  [PE HEADER]\n", "SECTION")
            w(f"  Machine  : {pe.machine} ({pe.machine_type})\n")
            w(f"  Compiled : {pe.timestamp_str}\n")
            w(f"  EP       : 0x{pe.entry_point:08X}  in_code={pe.ep_in_code_section}\n")
            w(f"  ImageBase: 0x{pe.image_base:08X}\n")
            w(f"  Subsystem: {pe.subsystem}\n")
            w(f"  64-bit   : {pe.is_64bit}  |  DLL: {pe.is_dll}\n")
            w(f"  Has TLS  : {pe.has_tls}  |  Has Sig: {pe.has_signature}\n")
            if pe.imphash:
                w(f"  ImpHash  : {pe.imphash}\n", "INFO")
            if pe.compiler_guess:
                col_ = "WARN" if "no rich" in pe.compiler_guess.lower() else "INFO"
                w(f"  Compiler : {pe.compiler_guess}\n", col_)
            if pe.has_overlay:
                w(f"  Overlay  : {pe.overlay_size:,} bytes @ 0x{pe.overlay_offset:X} "
                  f"(entropy={pe.overlay_entropy:.2f})\n",
                  "HIGH" if pe.overlay_entropy > 7.0 else "WARN")

            if pe.exports:
                w(f"\n  [EXPORTS] {len(pe.exports)} function(s)"
                  + (f" — DLL: {pe.export_dll_name}" if pe.export_dll_name else "") + "\n", "SECTION")
                for exp in pe.exports[:15]:
                    tag_ = "HIGH" if exp.is_suspicious else "INFO"
                    w(f"  {'[!] ' if exp.is_suspicious else '    '}{exp.name} (ord {exp.ordinal})"
                      + (f" — {exp.suspicion_reason}" if exp.suspicion_reason else "") + "\n", tag_)
            if pe.compiler_hint:
                w(f"  Compiler : {pe.compiler_hint}\n", "SECTION")
            if pe.imphash:
                w(f"  ImpHash  : {pe.imphash}\n", "INFO")
            if pe.has_overlay:
                ovc = "CRITICAL" if pe.overlay_entropy > 7.0 else "HIGH"
                w(f"  Overlay  : {pe.overlay_size:,} bytes @ 0x{pe.overlay_offset:X}  entropy={pe.overlay_entropy:.2f}\n", ovc)
            if not pe.checksum_valid and pe.checksum_stored != 0:
                w(f"  Checksum : MISMATCH stored=0x{pe.checksum_stored:08X} actual=0x{pe.checksum_actual:08X}\n", "WARN")

            w("\n  [SECTIONS]\n", "SECTION")
            for s in pe.sections:
                tag_ = "HIGH" if s.is_suspicious else "INFO"
                w(f"  {s.name:<12} entropy={s.entropy:.3f}  "
                  f"virt={s.virtual_size:>8,}  raw={s.raw_size:>8,}\n", tag_)
                for r in s.suspicion_reasons:
                    w(f"    => {r}\n", "CRITICAL")

            if pe.suspicious_imports:
                w("\n  [SUSPICIOUS IMPORTS]\n", "SECTION")
                for si in pe.suspicious_imports:
                    tag_ = "CRITICAL" if si["level"] == "CRITICAL" else (
                           "HIGH" if si["level"] == "HIGH" else "WARN")
                    w(f"  [{si['level']:<8}] {si['api']:<30} {si['reason']}\n", tag_)

        if getattr(pe, "suspicious_exports", None):
            w("\n  [SUSPICIOUS EXPORTS]\n", "SECTION")
            for exp in pe.suspicious_exports:
                name = exp.name or f"ord#{exp.ordinal}"
                w(f"  [MEDIUM  ] {name:<30} {exp.reason}\n", "WARN")

        if report.yara_matches:
            w("\n  [YARA MATCHES]\n", "SECTION")
            for m in report.yara_matches:
                tag_ = "CRITICAL" if m.severity == "CRITICAL" else (
                       "HIGH" if m.severity == "HIGH" else "WARN")
                w(f"  [{m.severity:<8}] {m.rule_name}\n", tag_)
                if m.description:
                    w(f"              {m.description}\n", "INFO")
                if m.family:
                    w(f"              Family: {m.family}\n", "WARN")

        # Strings
        strs = pe.suspicious_strings
        IMPORTANT_KEYS = ("c2_indicators","irc_commands","base64_decoded","mutexes","ips","urls","registry","file_paths")
        for key in list(IMPORTANT_KEYS) + [k for k in strs if k not in IMPORTANT_KEYS]:
            vals = strs.get(key, [])
            if vals:
                tag_ = "CRITICAL" if key in ("c2_indicators","irc_commands") else ("HIGH" if key == "base64_decoded" else "WARN")
                w(f"\n  [STRINGS: {key.upper()}]\n", "SECTION")
                for v in vals[:10]:
                    w(f"    {v}\n", tag_)

        if getattr(pe, "rich_header", None):
            w("\n  [RICH HEADER - Compiler fingerprint]\n", "SECTION")
            for rh in pe.rich_header[:8]:
                w(f"    {rh.product:<30} {rh.description}\n", "INFO")

        # VT block
        if report.vt_report and report.vt_report.found:
            vt = report.vt_report
            vt_col = "CRITICAL" if vt.malicious >= 5 else ("HIGH" if vt.malicious >= 2 else "WARN")
            w("\n  [VIRUSTOTAL]\n", "SECTION")
            w(f"  Detections : {vt.malicious}/{vt.total_engines} ({vt.detection_rate:.1f}%)\n", vt_col)
            if vt.threat_label:
                w(f"  Threat     : {vt.threat_label}\n", "CRITICAL")
            if vt.names:
                w(f"  Names      : {', '.join(vt.names[:5])}\n", "WARN")
            if vt.first_seen:
                w(f"  First seen : {vt.first_seen}\n", "INFO")
            if vt.last_seen:
                w(f"  Last seen  : {vt.last_seen}\n", "INFO")
            if vt.cached:
                w(f"  (kết quả từ cache)\n", "INFO")

        w("\n  [TOP FINDINGS]\n", "SECTION")
        for f in report.findings[:15]:
            tag_ = "CRITICAL" if f["level"] == "CRITICAL" else (
                   "HIGH" if f["level"] == "HIGH" else "WARN")
            w(f"  [{f['level']:<8}] +{f['points']:>2} — {f['description']}\n", tag_)

        dt.configure(state="disabled")

    # ─── Logs panel ───────────────────────────────────────────

    def _refresh_logs(self):
        self.logs_list.delete(0, "end")
        try:
            files = sorted(os.listdir(LOGS_DIR), reverse=True)
            for f in files:
                self.logs_list.insert("end", f)
        except Exception:
            pass

    def _open_log_file(self, event):
        sel = self.logs_list.curselection()
        if not sel:
            return
        fname = self.logs_list.get(sel[0])
        fpath = os.path.join(LOGS_DIR, fname)
        self._show_log_content(fpath)

    def _show_log_content(self, fpath: str):
        win = tk.Toplevel(self.root)
        win.title(f"Log — {os.path.basename(fpath)}")
        win.geometry("900x600")
        win.configure(bg=BG)

        txt = tk.Text(win, bg="#010409", fg=FG_TERM,
                      font=("Consolas", 9), wrap="none")
        vsb = ttk.Scrollbar(win, orient="vertical",   command=txt.yview)
        hsb = ttk.Scrollbar(win, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        for level, color in LEVEL_COLORS.items():
            txt.tag_configure(level, foreground=color)

        hsb.pack(side="bottom", fill="x")
        vsb.pack(side="right",  fill="y")
        txt.pack(fill="both", expand=True)

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    tag = "INFO"
                    for lvl in ("CRITICAL", "HIGH", "WARN", "OK", "SECTION"):
                        if f"[{lvl}" in line:
                            tag = lvl
                            break
                    txt.insert("end", line, tag)
            txt.configure(state="disabled")
        except Exception as e:
            txt.insert("end", f"Không đọc được file: {e}")

    def _open_logs_dir(self):
        import subprocess
        if sys.platform == "win32":
            os.startfile(LOGS_DIR)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", LOGS_DIR])
        else:
            subprocess.Popen(["xdg-open", LOGS_DIR])

    # ─── Misc ─────────────────────────────────────────────────

    def _export_html(self):
        if not self.scan_results:
            messagebox.showinfo("Không có dữ liệu", "Hãy quét ít nhất 1 file trước.")
            return
        import datetime
        ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out = filedialog.asksaveasfilename(
            title="Lưu báo cáo HTML",
            defaultextension=".html",
            filetypes=[("HTML", "*.html"), ("All", "*.*")],
            initialfile=f"report_{ts}.html",
        )
        if not out:
            return
        try:
            vt_d = {}
            for r in self.scan_results:
                if r.vt_report and r.pe_result and r.vt_report.found:
                    v = r.vt_report
                    vt_d[r.pe_result.sha256.lower()] = {
                        "found": v.found, "error": v.error,
                        "malicious": v.malicious, "suspicious": v.suspicious,
                        "undetected": v.undetected, "harmless": v.harmless,
                        "total_engines": v.total_engines,
                        "detection_rate": v.detection_rate,
                        "names": v.names, "cached": v.cached,
                        "file_type": v.file_type,
                        "first_seen": v.first_seen,
                        "last_seen": v.last_seen,
                        "threat_label": v.threat_label,
                        "engines": [{"engine_name": e.engine_name, "category": e.category, "result": e.result} for e in v.engines[:50]],
                    }
            path = generate_report(self.scan_results, vt_results=vt_d or None, output_path=out)
            self._term_log(f"Báo cáo HTML đã lưu: {path}", "OK")
            if messagebox.askyesno("Đã xuất báo cáo",
                                   f"Báo cáo đã lưu tại:\n{path}\n\nMở ngay?"):
                import webbrowser
                webbrowser.open(f"file://{path}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể tạo báo cáo: {e}")

    def _set_vt_key(self):
        win = tk.Toplevel(self.root)
        win.title("VirusTotal API Key")
        win.geometry("500x180")
        win.configure(bg=BG2)
        win.resizable(False, False)

        tk.Label(win, text="VirusTotal API Key",
                 bg=BG2, fg=ACC, font=("Consolas", 11, "bold")).pack(pady=(16, 4))
        tk.Label(win,
                 text="Nhập API key để tra hash trên VirusTotal (free tier: 4 req/min)",
                 bg=BG2, fg=FG2, font=("Consolas", 9)).pack(pady=(0, 10))

        entry_var = tk.StringVar(value=self._vt_api_key)
        entry = tk.Entry(win, textvariable=entry_var, show="*",
                         bg=BG3, fg=FG, insertbackground=ACC,
                         font=("Consolas", 10), bd=0, relief="flat",
                         width=50)
        entry.pack(padx=20, ipady=6)

        upload_var = tk.BooleanVar(value=False)
        tk.Checkbutton(win, text="Auto-upload nếu hash không có trên VT (tốn quota)",
                       variable=upload_var, bg=BG2, fg=FG2,
                       selectcolor=BG3, activebackground=BG2,
                       font=("Consolas", 9)).pack(pady=(6,0))

        def _save():
            self._vt_api_key = entry_var.get().strip()
            self._vt_upload  = upload_var.get()
            if self._vt_api_key:
                self._vt_client = VTClient(self._vt_api_key)
                self._term_log("VirusTotal API key đã lưu" + (" (upload mode ON)" if self._vt_upload else ""), "OK")
            else:
                self._vt_client = None
            win.destroy()

        btn_frame = tk.Frame(win, bg=BG2)
        btn_frame.pack(pady=14)
        self._btn(btn_frame, "  Lưu", _save, bg=ACC, hover="#388bfd").pack(side="left", padx=6)
        self._btn(btn_frame, "  Hủy", win.destroy, bg=BG3, hover=BG).pack(side="left", padx=6)

    def _clear_all(self):
        self.results_tree.delete(*self.results_tree.get_children())
        self.scan_results.clear()
        self._clear_terminal()
        self.progress_var.set(0)
        self._set_status("Sẵn sàng")
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.configure(state="disabled")

    def _set_status(self, text: str):
        self.status_lbl.configure(text=text)


# ─────────────────────────────────────────────────────────────
#  ENTRY
# ─────────────────────────────────────────────────────────────
def main():
    root = tk.Tk()
    root.withdraw()

    # Splash screen nhỏ
    splash = tk.Toplevel()
    splash.overrideredirect(True)
    splash.geometry("420x120+400+300")
    splash.configure(bg=BG2)
    tk.Label(splash, text="EXE Scanner", bg=BG2, fg=ACC,
             font=("Consolas", 20, "bold")).pack(pady=(20, 4))
    tk.Label(splash, text="Đang khởi động...", bg=BG2, fg=FG2,
             font=("Consolas", 10)).pack()

    def _launch():
        splash.destroy()
        root.deiconify()
        EXEScannerApp(root)
        root.mainloop()

    root.after(1200, _launch)
    root.mainloop()


if __name__ == "__main__":
    main()
