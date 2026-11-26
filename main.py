import ctypes
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "usb_sentinel.db"
REPORT_DIR = APP_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".ps1", ".vbs", ".js",
    ".jse", ".wsf", ".hta", ".msi", ".jar", ".lnk"
}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta"}
MAX_REPORT_ITEMS = 1000


def get_removable_drives():
    """Return Windows removable-drive roots such as E:\\."""
    if os.name != "nt":
        return []
    drives = []
    get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if os.path.exists(root) and get_drive_type(ctypes.c_wchar_p(root)) == 2:
            drives.append(root)
    return drives


def get_volume_info(root):
    """Return volume label and filesystem for a Windows drive."""
    if os.name != "nt":
        return {"label": "Unknown", "filesystem": "Unknown"}
    label = ctypes.create_unicode_buffer(261)
    filesystem = ctypes.create_unicode_buffer(261)
    serial = ctypes.c_ulong()
    max_component = ctypes.c_ulong()
    flags = ctypes.c_ulong()
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root), label, len(label),
        ctypes.byref(serial), ctypes.byref(max_component),
        ctypes.byref(flags), filesystem, len(filesystem)
    )
    if ok:
        return {"label": label.value or "(No label)", "filesystem": filesystem.value or "Unknown"}
    return {"label": "(Unavailable)", "filesystem": "Unknown"}


def get_drive_info(root):
    usage = shutil.disk_usage(root)
    volume = get_volume_info(root)
    return {
        "drive": root,
        "label": volume["label"],
        "filesystem": volume["filesystem"],
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
    }


def format_bytes(value):
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or unit == "TB":
            return f"{amount:.1f} {unit}"
        amount /= 1024


def find_defender_cli():
    candidates = []
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    platform_dir = Path(program_data) / "Microsoft" / "Windows Defender" / "Platform"
    if platform_dir.exists():
        for folder in sorted(platform_dir.glob("*"), reverse=True):
            candidates.append(folder / "MpCmdRun.exe")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    candidates.append(Path(program_files) / "Windows Defender" / "MpCmdRun.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def run_defender_scan(drive):
    """Run a Microsoft Defender custom scan. Exit code alone is not a clean bill of health."""
    cli = find_defender_cli()
    if cli:
        return subprocess.run(
            [cli, "-Scan", "-ScanType", "3", "-File", drive],
            capture_output=True, text=True
        )
    escaped = drive.replace("'", "''")
    command = f"Start-MpScan -ScanType CustomScan -ScanPath '{escaped}'"
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True
    )


def is_hidden_windows(path):
    """Check Windows hidden attribute; also treat dot-prefixed names as hidden."""
    if path.name.startswith("."):
        return True
    if os.name != "nt":
        return False
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        return attrs != -1 and bool(attrs & 0x2)  # FILE_ATTRIBUTE_HIDDEN
    except Exception:
        return False


def sha256_file(path, chunk_size=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_usb(drive, progress_callback=None):
    """Collect file metadata, SHA-256 hashes and heuristic warnings. Does not execute files."""
    findings = []
    hashes = []
    file_count = 0
    hashed_count = 0
    inaccessible = 0
    autorun_files = []
    scanned_files = []

    for root, dirs, filenames in os.walk(drive):
        dirs[:] = [d for d in dirs if d not in {"System Volume Information", "$RECYCLE.BIN"}]
        for filename in filenames:
            path = Path(root) / filename
            file_count += 1
            try:
                suffix = path.suffix.lower()
                lower_name = filename.lower()
                warnings = []

                if is_hidden_windows(path):
                    warnings.append("Hidden file")

                # Example: invoice.pdf.exe or photo.jpg.scr
                parts = path.name.lower().split(".")
                if len(parts) >= 3 and any(f".{p}" in SUSPICIOUS_EXTENSIONS for p in parts[1:-1]):
                    warnings.append("Double extension")

                if suffix in SUSPICIOUS_EXTENSIONS:
                    warnings.append(f"Executable/script-like extension ({suffix})")

                if suffix == ".lnk":
                    warnings.append("Shortcut file - inspect target before opening")

                if lower_name == "autorun.inf":
                    warnings.append("autorun.inf configuration file")
                    autorun_files.append(str(path))

                try:
                    file_hash = sha256_file(path)
                    hashed_count += 1
                    hashes.append({"path": str(path), "sha256": file_hash})
                except (OSError, PermissionError):
                    file_hash = None
                    inaccessible += 1

                if warnings:
                    findings.append({
                        "path": str(path),
                        "warnings": warnings,
                        "sha256": file_hash
                    })

                scanned_files.append({"path": str(path), "sha256": file_hash})
                if progress_callback and file_count % 25 == 0:
                    progress_callback(file_count, hashed_count)
            except (OSError, PermissionError):
                inaccessible += 1

    return {
        "files_seen": file_count,
        "files_hashed": hashed_count,
        "inaccessible_items_count": inaccessible,
        "findings": findings[:MAX_REPORT_ITEMS],
        "finding_count": len(findings),
        "autorun_files": autorun_files[:MAX_REPORT_ITEMS],
        "hashes": hashes[:MAX_REPORT_ITEMS],
        "hashes_truncated": len(hashes) > MAX_REPORT_ITEMS,
    }


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                drive TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                scan_status TEXT NOT NULL,
                suspicious_files INTEGER NOT NULL DEFAULT 0,
                report_path TEXT NOT NULL
            )
        """)
        # Lightweight migration for databases created by the original MVP.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        additions = {
            "files_seen": "INTEGER NOT NULL DEFAULT 0",
            "files_hashed": "INTEGER NOT NULL DEFAULT 0",
            "defender_return_code": "INTEGER",
            "device_label": "TEXT",
            "filesystem": "TEXT",
            "total_bytes": "INTEGER",
            "free_bytes": "INTEGER",
        }
        for name, sql_type in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {sql_type}")


def save_pdf_report(report, output_path):
    """Create a readable PDF report using ReportLab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    except ImportError:
        raise RuntimeError("PDF support needs ReportLab. Run: pip install -r requirements.txt")

    doc = SimpleDocTemplate(str(output_path), pagesize=A4,
                            rightMargin=16*mm, leftMargin=16*mm,
                            topMargin=16*mm, bottomMargin=16*mm)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("USB Sentinel - Scan Report", styles["Title"]),
        Spacer(1, 8),
        Paragraph("Generated: " + report.get("generated_at", ""), styles["Normal"]),
        Spacer(1, 10),
    ]
    device = report.get("device", {})
    summary_rows = [
        ["Drive", device.get("drive", "—")],
        ["Volume label", device.get("label", "—")],
        ["Filesystem", device.get("filesystem", "—")],
        ["Capacity", format_bytes(device.get("total_bytes", 0))],
        ["Free space", format_bytes(device.get("free_bytes", 0))],
        ["Scan status", report.get("scan_status", "—")],
        ["Files examined", str(report.get("analysis", {}).get("files_seen", 0))],
        ["Files SHA-256 hashed", str(report.get("analysis", {}).get("files_hashed", 0))],
        ["Heuristic warnings", str(report.get("analysis", {}).get("finding_count", 0))],
        ["Microsoft Defender return code", str(report.get("defender_return_code", "Unavailable"))],
    ]
    table = Table(summary_rows, colWidths=[55*mm, 115*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#EAF0F7")),
        ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#B8C4D1")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("PADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Suspicious-file review (heuristics, not confirmed malware)", styles["Heading2"]))
    findings = report.get("analysis", {}).get("findings", [])
    if findings:
        rows = [["File path", "Warnings", "SHA-256"]]
        for item in findings[:80]:
            rows.append([
                Paragraph(item.get("path", "")[:180], styles["BodyText"]),
                Paragraph(", ".join(item.get("warnings", [])), styles["BodyText"]),
                Paragraph((item.get("sha256") or "Unavailable")[:24] + "...", styles["BodyText"])
            ])
        ft = Table(rows, colWidths=[75*mm, 50*mm, 45*mm], repeatRows=1)
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#DCE8F5")),
            ("GRID", (0,0), (-1,-1), 0.3, colors.grey),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("PADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(ft)
    else:
        story.append(Paragraph("No heuristic file warnings were found.", styles["Normal"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Important: Microsoft Defender is the antivirus engine. A successful scan command "
        "does not guarantee that a drive is clean. Review Windows Security > Protection history "
        "for actual detections. File heuristics may flag legitimate files.",
        ParagraphStyle("note", parent=styles["BodyText"], textColor=colors.HexColor("#7A3E00"))
    ))
    doc.build(story)


class USBScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Sentinel - USB Security Scanner")
        self.root.geometry("1050x760")
        self.root.minsize(900, 650)
        self.selected_drive = tk.StringVar()
        self.status = tk.StringVar(value="Ready. Connect a USB drive and click Refresh.")
        self.current_device_info = None
        self.last_report = None
        init_db()
        self.build_ui()
        self.refresh_drives()
        self.load_history()
        self.refresh_stats()
        self.root.after(4000, self.auto_refresh)

    def build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Label(header, text="USB SENTINEL", font=("Segoe UI", 23, "bold")).pack(side="left")
        ttk.Label(header, text="USB Malware Detection & Security Management",
                  font=("Segoe UI", 10)).pack(side="left", padx=18, pady=(9, 0))

        stats = ttk.Frame(outer)
        stats.pack(fill="x", pady=14)
        self.stat_scans = self.make_stat_card(stats, "TOTAL SCANS")
        self.stat_warnings = self.make_stat_card(stats, "FILE WARNINGS")
        self.stat_clean = self.make_stat_card(stats, "SCANS COMPLETED")
        self.stat_files = self.make_stat_card(stats, "FILES HASHED")

        device_frame = ttk.LabelFrame(outer, text="USB device information", padding=12)
        device_frame.pack(fill="x")
        top = ttk.Frame(device_frame)
        top.pack(fill="x")
        self.drive_combo = ttk.Combobox(top, textvariable=self.selected_drive,
                                        state="readonly", width=22)
        self.drive_combo.pack(side="left", padx=(0, 8))
        self.drive_combo.bind("<<ComboboxSelected>>", lambda e: self.update_device_info())
        ttk.Button(top, text="Refresh devices", command=self.refresh_drives).pack(side="left")
        self.scan_button = ttk.Button(top, text="Start USB scan", command=self.start_scan)
        self.scan_button.pack(side="right")
        self.device_info_label = ttk.Label(device_frame, text="No USB selected",
                                           foreground="#555", justify="left")
        self.device_info_label.pack(anchor="w", pady=(10, 0))

        scan_frame = ttk.LabelFrame(outer, text="Scan activity", padding=12)
        scan_frame.pack(fill="x", pady=12)
        self.progress = ttk.Progressbar(scan_frame, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 8))
        ttk.Label(scan_frame, textvariable=self.status, wraplength=950).pack(anchor="w")
        ttk.Label(
            scan_frame,
            text="The app does not execute or automatically delete files. File checks are heuristic; "
                 "Microsoft Defender provides antivirus scanning.",
            foreground="#7A3E00", wraplength=950
        ).pack(anchor="w", pady=(7, 0))

        history_frame = ttk.LabelFrame(outer, text="Scan history (double-click a row for details)", padding=10)
        history_frame.pack(fill="both", expand=True)
        cols = ("id", "date", "drive", "status", "files", "warnings")
        self.history = ttk.Treeview(history_frame, columns=cols, show="headings", height=10)
        headings = {"id":"ID", "date":"Date", "drive":"Drive", "status":"Status",
                    "files":"Files", "warnings":"Warnings"}
        widths = {"id":45, "date":165, "drive":65, "status":350, "files":75, "warnings":85}
        for col in cols:
            self.history.heading(col, text=headings[col])
            self.history.column(col, width=widths[col], anchor="w")
        self.history.pack(fill="both", expand=True)
        self.history.bind("<Double-1>", self.open_selected_history)

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=(9, 0))
        ttk.Button(actions, text="View selected scan details", command=self.open_selected_history).pack(side="left")
        ttk.Button(actions, text="Open reports folder", command=lambda: os.startfile(REPORT_DIR)).pack(side="left", padx=8)
        ttk.Button(actions, text="Export latest PDF", command=self.export_latest_pdf).pack(side="right")

    def make_stat_card(self, parent, title):
        card = ttk.LabelFrame(parent, text=title, padding=10)
        card.pack(side="left", fill="x", expand=True, padx=(0, 8))
        value = ttk.Label(card, text="0", font=("Segoe UI", 19, "bold"))
        value.pack(anchor="w")
        return value

    def refresh_stats(self):
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("""
                SELECT COUNT(*), COALESCE(SUM(suspicious_files),0),
                       COALESCE(SUM(CASE WHEN scan_status LIKE 'Defender scan command completed%' THEN 1 ELSE 0 END),0),
                       COALESCE(SUM(files_hashed),0)
                FROM scans
            """).fetchone()
        self.stat_scans.config(text=str(row[0]))
        self.stat_warnings.config(text=str(row[1]))
        self.stat_clean.config(text=str(row[2]))
        self.stat_files.config(text=str(row[3]))

    def refresh_drives(self):
        drives = get_removable_drives()
        self.drive_combo["values"] = drives
        if drives:
            if self.selected_drive.get() not in drives:
                self.selected_drive.set(drives[0])
            self.update_device_info()
            self.status.set(f"Found {len(drives)} removable drive(s).")
        else:
            self.selected_drive.set("")
            self.device_info_label.config(text="No removable USB drive detected.")
            self.status.set("No removable USB drive detected. Connect one and refresh.")

    def update_device_info(self):
        drive = self.selected_drive.get()
        if not drive:
            return
        try:
            info = get_drive_info(drive)
            self.current_device_info = info
            self.device_info_label.config(
                text=f"Drive: {info['drive']}    Label: {info['label']}    "
                     f"Filesystem: {info['filesystem']}    "
                     f"Capacity: {format_bytes(info['total_bytes'])}    "
                     f"Used: {format_bytes(info['used_bytes'])}    "
                     f"Free: {format_bytes(info['free_bytes'])}"
            )
        except Exception as exc:
            self.device_info_label.config(text=f"Could not read device information: {exc}")

    def auto_refresh(self):
        self.refresh_drives()
        self.root.after(5000, self.auto_refresh)

    def start_scan(self):
        drive = self.selected_drive.get()
        if not drive:
            messagebox.showwarning("No USB selected", "Connect a USB drive and select it first.")
            return
        if not messagebox.askyesno(
            "Confirm scan",
            f"Analyze files and run Microsoft Defender custom scan on {drive}?\n\n"
            "SHA-256 hashing may take time on large drives. Keep the drive connected."
        ):
            return
        self.scan_button.config(state="disabled")
        self.progress.start(12)
        self.status.set(f"Analyzing files and starting Defender scan on {drive}...")
        threading.Thread(target=self.scan_worker, args=(drive,), daemon=True).start()

    def scan_worker(self, drive):
        started = datetime.now().isoformat(timespec="seconds")
        try:
            device = get_drive_info(drive)
            analysis = analyze_usb(drive)
            process = run_defender_scan(drive)
            finished = datetime.now().isoformat(timespec="seconds")
            scan_status = ("Defender scan command completed" if process.returncode == 0
                           else f"Defender scan returned code {process.returncode}")
            report = {
                "application": "USB Sentinel MVP v2",
                "generated_at": finished,
                "started_at": started,
                "finished_at": finished,
                "device": device,
                "scan_engine": "Microsoft Defender",
                "scan_status": scan_status,
                "defender_return_code": process.returncode,
                "defender_stdout": (process.stdout or "")[-4000:],
                "defender_stderr": (process.stderr or "")[-2000:],
                "analysis": analysis,
                "note": "Heuristic warnings are not confirmed malware. Review Windows Security Protection History."
            }
        except Exception as exc:
            finished = datetime.now().isoformat(timespec="seconds")
            report = {
                "application": "USB Sentinel MVP v2",
                "generated_at": finished,
                "started_at": started,
                "finished_at": finished,
                "device": {"drive": drive},
                "scan_engine": "Microsoft Defender",
                "scan_status": "Scan failed",
                "error": str(exc),
                "analysis": {"files_seen": 0, "files_hashed": 0, "finding_count": 0,
                             "findings": [], "inaccessible_items_count": 0}
            }

        stem = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        json_path = REPORT_DIR / f"{stem}.json"
        pdf_path = REPORT_DIR / f"{stem}.pdf"
        report["json_report_path"] = str(json_path)
        report["pdf_report_path"] = str(pdf_path)
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        try:
            save_pdf_report(report, pdf_path)
            report["pdf_generated"] = True
        except Exception as exc:
            report["pdf_generated"] = False
            report["pdf_error"] = str(exc)
            json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        analysis = report.get("analysis", {})
        device = report.get("device", {})
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO scans
                (drive, started_at, finished_at, scan_status, suspicious_files, report_path,
                 files_seen, files_hashed, defender_return_code, device_label, filesystem,
                 total_bytes, free_bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                drive, started, finished, report["scan_status"],
                analysis.get("finding_count", 0), str(json_path),
                analysis.get("files_seen", 0), analysis.get("files_hashed", 0),
                report.get("defender_return_code"), device.get("label"),
                device.get("filesystem"), device.get("total_bytes"), device.get("free_bytes")
            ))
        self.root.after(0, self.scan_finished, report)

    def scan_finished(self, report):
        self.progress.stop()
        self.scan_button.config(state="normal")
        analysis = report.get("analysis", {})
        self.status.set(
            f"{report['scan_status']} | Files: {analysis.get('files_seen',0)} | "
            f"SHA-256 hashes: {analysis.get('files_hashed',0)} | "
            f"Warnings: {analysis.get('finding_count',0)}"
        )
        self.load_history()
        self.refresh_stats()
        self.last_report = report
        msg = (
            f"Status: {report['scan_status']}\n"
            f"Files examined: {analysis.get('files_seen',0)}\n"
            f"Files hashed: {analysis.get('files_hashed',0)}\n"
            f"Heuristic warnings: {analysis.get('finding_count',0)}\n\n"
            f"JSON report: {report.get('json_report_path')}\n"
            f"PDF report: {'Created' if report.get('pdf_generated') else 'Not created - install ReportLab'}\n\n"
            "For actual malware detections, review Windows Security > Protection history."
        )
        messagebox.showinfo("Scan completed", msg)

    def load_history(self):
        for item in self.history.get_children():
            self.history.delete(item)
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("""
                SELECT id, started_at, drive, scan_status, files_seen, suspicious_files
                FROM scans ORDER BY id DESC LIMIT 50
            """).fetchall()
        for row in rows:
            self.history.insert("", "end", values=row)

    def open_selected_history(self, event=None):
        selected = self.history.selection()
        if not selected:
            messagebox.showinfo("Select scan", "Select a scan-history row first.")
            return
        values = self.history.item(selected[0], "values")
        scan_id = int(values[0])
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT report_path FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row or not Path(row[0]).exists():
            messagebox.showerror("Report missing", "The JSON report for this scan could not be found.")
            return
        report_path = Path(row[0])
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception as exc:
            messagebox.showerror("Cannot read report", str(exc))
            return
        self.show_report_details(report, report_path)

    def show_report_details(self, report, report_path):
        win = tk.Toplevel(self.root)
        win.title("USB Sentinel - Scan Details")
        win.geometry("850x620")
        frame = ttk.Frame(win, padding=14)
        frame.pack(fill="both", expand=True)
        device = report.get("device", {})
        analysis = report.get("analysis", {})
        summary = (
            f"Drive: {device.get('drive','—')} | Label: {device.get('label','—')} | "
            f"Filesystem: {device.get('filesystem','—')}\n"
            f"Status: {report.get('scan_status','—')} | "
            f"Files: {analysis.get('files_seen',0)} | Hashed: {analysis.get('files_hashed',0)} | "
            f"Warnings: {analysis.get('finding_count',0)}\n"
            f"JSON: {report_path}"
        )
        ttk.Label(frame, text=summary, wraplength=800, justify="left").pack(anchor="w", pady=(0, 10))
        cols = ("path", "warnings", "hash")
        tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col, title, width in [
            ("path", "File path", 390), ("warnings", "Warnings", 230), ("hash", "SHA-256", 190)
        ]:
            tree.heading(col, text=title)
            tree.column(col, width=width)
        tree.pack(fill="both", expand=True)
        for item in analysis.get("findings", []):
            tree.insert("", "end", values=(
                item.get("path", ""), "; ".join(item.get("warnings", [])),
                item.get("sha256") or "Unavailable"
            ))
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(buttons, text="Open JSON report",
                   command=lambda: os.startfile(str(report_path))).pack(side="left")
        pdf_path = report.get("pdf_report_path")
        if pdf_path and Path(pdf_path).exists():
            ttk.Button(buttons, text="Open PDF report",
                       command=lambda: os.startfile(pdf_path)).pack(side="left", padx=8)

    def export_latest_pdf(self):
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT report_path FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            messagebox.showinfo("No scans", "Run a scan before exporting a report.")
            return
        try:
            report = json.loads(Path(row[0]).read_text(encoding="utf-8"))
            default_name = Path(report.get("pdf_report_path", "usb_sentinel_report.pdf")).name
            destination = filedialog.asksaveasfilename(
                defaultextension=".pdf", initialfile=default_name,
                filetypes=[("PDF files", "*.pdf")]
            )
            if not destination:
                return
            save_pdf_report(report, destination)
            messagebox.showinfo("Export complete", f"PDF saved to:\n{destination}")
        except Exception as exc:
            messagebox.showerror("PDF export failed", str(exc))


if __name__ == "__main__":
    if os.name != "nt":
        print("USB Sentinel currently requires Windows.")
    else:
        root = tk.Tk()
        app = USBScannerApp(root)
        root.mainloop()
