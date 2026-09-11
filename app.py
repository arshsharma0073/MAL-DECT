
"""MAL-DECT — a safe, hackathon-friendly Windows file risk scanner.

This program performs static checks only. It never opens or runs scanned files.
"""

from __future__ import annotations

import hashlib
import os
import queue
import re
import threading
from datetime import datetime, timedelta
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


SUSPICIOUS_EXTENSIONS = {
    ".exe": 20, ".msi": 20, ".dll": 15, ".scr": 25, ".bat": 20,
    ".cmd": 20, ".ps1": 25, ".vbs": 25, ".js": 15, ".jar": 15,
}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".js"}
SUSPICIOUS_PATTERNS = {
    rb"powershell\s+.*(-enc|-encodedcommand)": (35, "Encoded PowerShell command"),
    rb"invoke-webrequest|wget\s+http|curl\s+http": (25, "Downloads content from the internet"),
    rb"frombase64string|base64": (15, "Uses Base64 encoding"),
    rb"rundll32|regsvr32|mshta": (25, "Uses a Windows living-off-the-land tool"),
    rb"startup|currentversion\\run": (20, "May create persistence at startup"),
    rb"encrypt.*(file|folder)|ransom": (35, "Possible file-encryption behavior"),
    rb"getasynckeystate|keylog": (45, "Potential keylogging behavior"),
    rb"copy.*(removable|usb)|autorun\.inf": (40, "Potential removable-drive propagation"),
}
MAX_FILES = 5000
MAX_SCRIPT_BYTES = 256 * 1024


def assistant_reply(question: str) -> str:
    """Give safe, offline device-protection guidance based on common questions."""
    text = question.lower()
    if any(word in text for word in ("high risk", "flagged", "malware found", "infected")):
        return ("Stay calm—being flagged is not proof of malware. Do not open the file. "
                "Note its location, scan it with Windows Security, and quarantine or delete it only if Windows Security confirms a threat.")
    if any(word in text for word in ("scan", "use", "work", "result")):
        return ("Choose a folder with Browse, then select Scan folder. MAL-DECT checks file types, recent changes, and suspicious script patterns. "
                "The result is a risk indicator, so always review the reason shown before taking action.")
    if any(word in text for word in ("password", "account", "phishing", "email", "link")):
        return ("Never enter passwords after following an unexpected link. Check the sender and website address carefully, use a unique password for each account, and enable two-factor authentication.")
    if any(word in text for word in ("protect", "safe", "security", "prevent", "tips")):
        return ("Keep Windows, browsers, and apps updated; leave Windows Security enabled; install software only from trusted sources; back up important files; and avoid unexpected attachments, cracked software, and USB drives you do not trust.")
    if any(word in text for word in ("virus", "ransomware", "download", "popup")):
        return ("Do not click suspicious pop-ups or download unknown files. Disconnect from the internet if you think an active infection is spreading, then run a full scan with Windows Security and ask a trusted IT professional for help if needed.")
    return ("I can help with safe device protection. Ask me how to use MAL-DECT, what to do with a flagged file, how to spot phishing, or how to keep Windows secure.")


def scan_file(path: Path) -> tuple[int, list[str], str]:
    """Return risk score, explanations, and a short SHA-256 fingerprint."""
    score = 0
    reasons: list[str] = []
    ext = path.suffix.lower()
    if ext in SUSPICIOUS_EXTENSIONS:
        points = SUSPICIOUS_EXTENSIONS[ext]
        score += points
        reasons.append(f"Executable or script file ({ext})")

    try:
        modified = datetime.fromtimestamp(path.stat().st_mtime)
        if ext in SUSPICIOUS_EXTENSIONS and modified > datetime.now() - timedelta(days=7):
            score += 10
            reasons.append("Created or modified in the last 7 days")

        digest = hashlib.sha256()
        with path.open("rb") as file:
            data = file.read(MAX_SCRIPT_BYTES)
            digest.update(data)
        fingerprint = digest.hexdigest()[:12]

        if ext in SCRIPT_EXTENSIONS:
            for pattern, (points, explanation) in SUSPICIOUS_PATTERNS.items():
                if re.search(pattern, data, re.IGNORECASE):
                    score += points
                    reasons.append(explanation)
    except (OSError, PermissionError):
        return 0, [], "unavailable"

    return min(score, 100), reasons, fingerprint


def risk_label(score: int) -> str:
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def malware_category(path: Path, reasons: list[str]) -> str:
    """Return a cautious malware-family estimate, not a malware diagnosis."""
    details = " ".join(reasons).lower()
    ext = path.suffix.lower()
    if "keylogging" in details:
        return "Potential spyware / keylogger"
    if "file-encryption" in details:
        return "Potential ransomware"
    if "removable-drive propagation" in details:
        return "Potential worm"
    if "downloads content" in details:
        return "Potential Trojan / downloader"
    if "encoded powershell" in details:
        return "Potential Trojan (obfuscated script)"
    if "persistence" in details:
        return "Potential Trojan / persistence"
    if ext in {".ps1", ".bat", ".cmd"}:
        return "Potential Trojan"
    if ext in {".vbs", ".js"}:
        return "Potential Trojan"
    if ext in {".exe", ".msi", ".scr", ".jar"}:
        return "Potential Trojan / virus"
    if ext == ".dll":
        return "Potential Trojan / DLL payload"
    return "Unknown malware category"


class SentinelScan(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("MAL-DECT | Visionary Coders")
        self.geometry("1100x700")
        self.minsize(900, 560)
        self.events: queue.Queue[tuple] = queue.Queue()
        self.scanning = False
        self.chat_window: tk.Toplevel | None = None
        self.folder = tk.StringVar(value=str(Path.home() / "Downloads"))
        self.status = tk.StringVar(value="Choose a folder and click Scan.")
        self._build_ui()
        self.after(100, self._read_events)

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        self.configure(background="#F4F7FB")
        style.configure("App.TFrame", background="#F4F7FB")
        style.configure("Card.TFrame", background="#FFFFFF")
        style.configure("Path.TEntry", fieldbackground="#F8FAFC", padding=9)
        style.configure("Browse.TButton", font=("Segoe UI", 10, "bold"), padding=(15, 10))
        style.configure("Scan.TButton", font=("Segoe UI", 10, "bold"), foreground="#FFFFFF", background="#2563EB", padding=(19, 10))
        style.map("Scan.TButton", background=[("active", "#1D4ED8"), ("disabled", "#94A3B8")])
        style.configure("Treeview", font=("Segoe UI", 10), rowheight=38, background="#FFFFFF", fieldbackground="#FFFFFF", foreground="#25324A")
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#E8EEF8", foreground="#40516B", relief="flat")
        style.map("Treeview", background=[("selected", "#DBEAFE")], foreground=[("selected", "#1E3A8A")])

        header = tk.Frame(self, bg="#0F172A", height=118)
        header.pack(fill="x")
        header.pack_propagate(False)
        brand = tk.Frame(header, bg="#0F172A")
        brand.pack(side="left", padx=30, pady=23)
        tk.Label(brand, text="◈  MAL-DECT", font=("Segoe UI", 22, "bold"), fg="#F8FAFC", bg="#0F172A").pack(anchor="w")
        tk.Label(brand, text="by Visionary Coders  •  Windows malware-risk analysis", font=("Segoe UI", 10), fg="#94A3B8", bg="#0F172A").pack(anchor="w", pady=(4, 0))
        header_actions = tk.Frame(header, bg="#0F172A")
        header_actions.pack(side="right", padx=30)
        tk.Button(header_actions, text="Safety Assistant  ✦", command=self.open_assistant, font=("Segoe UI", 10, "bold"), fg="#0F172A", bg="#BFDBFE", activebackground="#DBEAFE", relief="flat", padx=14, pady=8, cursor="hand2").pack(side="left", padx=(0, 16))
        tk.Label(header_actions, text="●  PROTECTED", font=("Segoe UI", 10, "bold"), fg="#86EFAC", bg="#0F172A").pack(side="left")

        body = ttk.Frame(self, style="App.TFrame", padding=(28, 24, 28, 18))
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Quick scan", font=("Segoe UI", 16, "bold"), background="#F4F7FB", foreground="#172554").pack(anchor="w")
        ttk.Label(body, text="Select a folder to check for suspicious scripts and executable files.", font=("Segoe UI", 10), background="#F4F7FB", foreground="#64748B").pack(anchor="w", pady=(2, 12))

        chooser_card = ttk.Frame(body, style="Card.TFrame", padding=14)
        chooser_card.pack(fill="x")
        chooser = ttk.Frame(chooser_card, style="Card.TFrame")
        chooser.pack(fill="x")
        ttk.Entry(chooser, textvariable=self.folder, style="Path.TEntry").pack(side="left", fill="x", expand=True)
        ttk.Button(chooser, text="Browse", style="Browse.TButton", command=self.pick_folder).pack(side="left", padx=(10, 8))
        self.scan_button = ttk.Button(chooser, text="Scan folder  →", style="Scan.TButton", command=self.start_scan)
        self.scan_button.pack(side="left")

        summary = ttk.Frame(body, style="App.TFrame")
        summary.pack(fill="x", pady=18)
        self.summary = ttk.Label(summary, text="READY TO SCAN", font=("Segoe UI", 11, "bold"), background="#F4F7FB", foreground="#2563EB")
        self.summary.pack(side="left")
        ttk.Label(summary, textvariable=self.status, font=("Segoe UI", 10), background="#F4F7FB", foreground="#64748B").pack(side="right")

        columns = ("risk", "score", "type", "file", "reasons", "fingerprint")
        results_card = ttk.Frame(body, style="Card.TFrame", padding=1)
        results_card.pack(fill="both", expand=True)
        self.table = ttk.Treeview(results_card, columns=columns, show="headings", height=18)
        headings = {"risk": "Risk", "score": "Score", "type": "Potential malware category", "file": "File", "reasons": "Why it was flagged", "fingerprint": "SHA-256 (short)"}
        widths = {"risk": 80, "score": 65, "type": 190, "file": 260, "reasons": 330, "fingerprint": 115}
        for column in columns:
            self.table.heading(column, text=headings[column])
            self.table.column(column, width=widths[column], anchor="w")
        scrollbar = ttk.Scrollbar(results_card, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.table.tag_configure("HIGH", foreground="#DC2626")
        self.table.tag_configure("MEDIUM", foreground="#B45309")
        self.table.tag_configure("LOW", foreground="#059669")
        ttk.Label(body, text="ⓘ  Malware categories are heuristic estimates, not confirmed malware. Review flagged files before taking action.", font=("Segoe UI", 9), background="#F4F7FB", foreground="#64748B").pack(anchor="w", pady=(13, 0))

    def open_assistant(self) -> None:
        """Open the built-in, offline device-safety chat window."""
        if self.chat_window and self.chat_window.winfo_exists():
            self.chat_window.lift()
            self.chat_window.focus_force()
            return

        window = tk.Toplevel(self)
        self.chat_window = window
        window.title("MAL-DECT Safety Assistant | Visionary Coders")
        window.geometry("510x610")
        window.minsize(430, 500)
        window.configure(bg="#F4F7FB")

        header = tk.Frame(window, bg="#0F172A", height=105)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="✦  DEVICE SAFETY ASSISTANT", font=("Segoe UI", 15, "bold"), fg="#F8FAFC", bg="#0F172A").pack(anchor="w", padx=22, pady=(21, 3))
        tk.Label(header, text="Private, offline guidance by MAL-DECT", font=("Segoe UI", 10), fg="#94A3B8", bg="#0F172A").pack(anchor="w", padx=22)

        chat = tk.Text(window, height=21, wrap="word", font=("Segoe UI", 10), bg="#FFFFFF", fg="#1E293B", relief="flat", padx=16, pady=14, state="disabled")
        chat.pack(fill="both", expand=True, padx=16, pady=(16, 10))
        chat.tag_configure("bot", foreground="#1D4ED8", font=("Segoe UI", 10, "bold"))
        chat.tag_configure("user", foreground="#475569", font=("Segoe UI", 10, "bold"))

        def add_message(speaker: str, message: str, tag: str) -> None:
            chat.configure(state="normal")
            chat.insert("end", speaker + "\n", tag)
            chat.insert("end", message + "\n\n")
            chat.configure(state="disabled")
            chat.see("end")

        add_message("MAL-DECT Assistant", "Hi! I can explain scan results and share simple steps to protect your Windows device. How can I help?", "bot")

        shortcuts = tk.Frame(window, bg="#F4F7FB")
        shortcuts.pack(fill="x", padx=16)
        compose = tk.Frame(window, bg="#F4F7FB")
        entry = tk.Entry(compose, font=("Segoe UI", 10), relief="solid", bd=1)

        def send_message(event: object | None = None) -> None:
            question = entry.get().strip()
            if not question:
                return
            entry.delete(0, "end")
            add_message("You", question, "user")
            add_message("MAL-DECT Assistant", assistant_reply(question), "bot")

        for label, question in (("How do I stay safe?", "How do I protect my device?"), ("A file was flagged", "What should I do with a flagged file?"), ("How does scanning work?", "How does MAL-DECT scan files?")):
            tk.Button(shortcuts, text=label, command=lambda q=question: (entry.delete(0, "end"), entry.insert(0, q), send_message()), font=("Segoe UI", 9), fg="#1D4ED8", bg="#E0E7FF", activebackground="#C7D2FE", relief="flat", padx=8, pady=6, cursor="hand2").pack(side="left", padx=(0, 7), pady=(0, 10))

        compose.pack(fill="x", padx=16, pady=(0, 18))
        entry.pack(side="left", fill="x", expand=True, ipady=8)
        tk.Button(compose, text="Send", command=send_message, font=("Segoe UI", 10, "bold"), fg="#FFFFFF", bg="#2563EB", activebackground="#1D4ED8", relief="flat", padx=16, pady=8, cursor="hand2").pack(side="left", padx=(8, 0))
        entry.bind("<Return>", send_message)
        entry.focus_set()

    def pick_folder(self) -> None:
        selected = filedialog.askdirectory(initialdir=self.folder.get())
        if selected:
            self.folder.set(selected)

    def start_scan(self) -> None:
        root = Path(self.folder.get())
        if not root.is_dir():
            messagebox.showerror("Folder not found", "Please choose an existing folder.")
            return
        if self.scanning:
            return
        self.scanning = True
        self.scan_button.configure(state="disabled")
        self.summary.configure(text="Scanning…")
        self.status.set("Looking for suspicious files…")
        for item in self.table.get_children():
            self.table.delete(item)
        threading.Thread(target=self._scan_worker, args=(root,), daemon=True).start()

    def _scan_worker(self, root: Path) -> None:
        findings: list[tuple[int, str, str, str]] = []
        files_seen = 0
        try:
            for directory, _, filenames in os.walk(root, onerror=lambda _: None):
                for name in filenames:
                    files_seen += 1
                    if files_seen > MAX_FILES:
                        self.events.put(("limit", files_seen))
                        break
                    path = Path(directory) / name
                    score, reasons, fingerprint = scan_file(path)
                    if reasons:
                        findings.append((score, str(path), "; ".join(reasons), fingerprint))
                if files_seen > MAX_FILES:
                    break
            findings.sort(key=lambda row: row[0], reverse=True)
            self.events.put(("done", findings, files_seen))
        except Exception as error:
            self.events.put(("error", str(error)))

    def _read_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "limit":
                    self.status.set(f"Safety limit reached: scanned first {MAX_FILES:,} files.")
                elif event[0] == "done":
                    _, findings, files_seen = event
                    for score, path, reasons, fingerprint in findings:
                        risk = risk_label(score)
                        category = malware_category(Path(path), reasons.split("; "))
                        self.table.insert("", "end", values=(risk, score, category, path, reasons, fingerprint), tags=(risk,))
                    high = sum(score >= 50 for score, *_ in findings)
                    medium = sum(25 <= score < 50 for score, *_ in findings)
                    self.summary.configure(text=f"{len(findings)} flagged | {high} high risk | {medium} medium risk")
                    self.status.set(f"Finished: {files_seen:,} files checked.")
                    self.scanning = False
                    self.scan_button.configure(state="normal")
                elif event[0] == "error":
                    self.status.set("Scan could not finish: " + event[1])
                    self.scanning = False
                    self.scan_button.configure(state="normal")
        except queue.Empty:
            pass
        self.after(100, self._read_events)


if __name__ == "__main__":
    SentinelScan().mainloop()
