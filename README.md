# USB Sentinel MVP v2

Hybrid USB security project — upgraded Windows desktop MVP.

## Added in v2
- USB device information: drive letter, volume label, filesystem, capacity, used and free space.
- File analysis: hidden-file checks, suspicious double extensions, executable/script-like extensions, `.lnk` shortcut warnings and `autorun.inf` detection.
- SHA-256 hashing for examined files (hashes are included in JSON reports; findings are shown in the details window).
- Dashboard statistics: total scans, heuristic warnings, Defender scan commands completed, and files hashed.
- PDF scan report generation and PDF export.
- Detailed scan history: double-click a history row to view findings and open JSON/PDF reports.
- Automatic SQLite schema migration from the original MVP database; existing scan history is retained.

## Preserved from original MVP
- Automatic removable USB drive detection and refresh.
- Microsoft Defender custom scan integration.
- Local SQLite scan history.
- JSON report generation.
- Tkinter desktop application.

## Requirements
- Windows 10 or Windows 11
- Python 3.10 or newer
- Microsoft Defender Antivirus enabled
- ReportLab for PDF generation

## Setup
1. Extract `USB_Sentinel_MVP_v2.zip`.
2. Open the extracted folder in VS Code.
3. Open the VS Code terminal in that folder.
4. (Recommended) Create a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\activate
   ```

5. Install dependencies:

   ```powershell
   py -m pip install -r requirements.txt
   ```

6. Run:

   ```powershell
   py main.py
   ```

## How to test
1. Insert a USB drive you own and are authorized to scan.
2. Click **Refresh devices**.
3. Select the USB drive and review its device information.
4. Click **Start USB scan** and keep the drive connected.
5. Review dashboard statistics and scan history.
6. Double-click a history row to inspect warnings and hashes.
7. Open the `reports` folder for JSON and PDF reports.

## Safety and accuracy notes
- The app does not execute, delete, or automatically quarantine files.
- Microsoft Defender is the antivirus engine. A successful scan command is not proof that a drive is clean; check Windows Security > Virus & threat protection > Protection history for actual detections and remediation.
- Hidden files, double extensions, shortcuts, autorun files and executable-like extensions are heuristic indicators. They can be legitimate and are not confirmed malware.
- SHA-256 identifies file contents; a hash alone does not say whether a file is malicious.
- Hashing every file can take time on large USB drives. Keep the drive connected until the scan completes.
- The JSON report stores up to 1,000 individual hash entries and 1,000 heuristic findings to keep report sizes manageable; aggregate counts cover all files examined.

## Project limitations / next phases
This is the local desktop MVP, not yet the complete cloud hybrid system. Azure SQL, Blob Storage, FastAPI cloud synchronization, web dashboard, Power BI and cloud authentication are not implemented in this version.
