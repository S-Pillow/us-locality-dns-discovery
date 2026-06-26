#!/usr/bin/env python3
"""US Locality DNS Discovery Tool — desktop GUI entry point."""

from __future__ import annotations

import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from scanner.export_service import export_results
from scanner.models import ScanInput, ScanOptions, ScanRunResult
from scanner.scan_engine import run_scan, validate_domain_file, validate_wordlist_file

APP_TITLE = ".US Locality DNS Discovery Tool"
PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "output"
WORDLISTS_DIR = PROJECT_ROOT / "wordlists"


class DiscoveryApp(tk.Tk):
    """Main Tkinter window for the discovery tool."""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(720, 640)
        self.geometry("920x720")

        self.domain_file_var = tk.StringVar()
        self.wordlist_file_var = tk.StringVar()

        self.rfc_locality_var = tk.BooleanVar(value=True)
        self.dns_common_var = tk.BooleanVar(value=True)
        self.civic_departments_var = tk.BooleanVar(value=True)
        self.public_services_var = tk.BooleanVar(value=False)
        self.schools_libraries_var = tk.BooleanVar(value=False)
        self.delegated_manager_var = tk.BooleanVar(value=False)
        self.include_custom_var = tk.BooleanVar(value=False)

        self.axfr_var = tk.BooleanVar(value=False)
        self.auth_ns_var = tk.BooleanVar(value=True)

        self._scan_thread: threading.Thread | None = None
        self._last_scan_result: ScanRunResult | None = None

        self.wordlist_file_var.trace_add("write", self._on_wordlist_path_changed)

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        self._build_ui()
        self._on_wordlist_path_changed()
        self._log("Ready. Select a domain list and click Run Scan to begin DNS discovery.")

    def _build_ui(self) -> None:
        main = ttk.Frame(self, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        files_frame = ttk.LabelFrame(main, text="Input Files", padding=10)
        files_frame.pack(fill=tk.X, pady=(0, 10))

        self._add_file_row(
            files_frame,
            row=0,
            label="Domain list:",
            variable=self.domain_file_var,
            command=self._browse_domain_file,
        )
        self._add_file_row(
            files_frame,
            row=1,
            label="Custom wordlist (optional):",
            variable=self.wordlist_file_var,
            command=self._browse_wordlist_file,
        )

        wordlist_frame = ttk.LabelFrame(main, text="Wordlist Sources", padding=10)
        wordlist_frame.pack(fill=tk.X, pady=(0, 10))

        wordlist_rows = [
            ("RFC/locality baseline", self.rfc_locality_var),
            ("Common DNS/web labels", self.dns_common_var),
            ("Civic departments", self.civic_departments_var),
            ("Public services / portals", self.public_services_var),
            ("Schools / libraries", self.schools_libraries_var),
            ("Delegated-manager clues", self.delegated_manager_var),
        ]
        for index, (text, variable) in enumerate(wordlist_rows):
            ttk.Checkbutton(wordlist_frame, text=text, variable=variable).grid(
                row=index // 2,
                column=index % 2,
                sticky=tk.W,
                padx=(0, 24),
                pady=2,
            )

        self.custom_wordlist_check = ttk.Checkbutton(
            wordlist_frame,
            text="Include custom wordlist (when file selected)",
            variable=self.include_custom_var,
        )
        self.custom_wordlist_check.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(6, 0))

        options_frame = ttk.LabelFrame(main, text="Scan Options", padding=10)
        options_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Checkbutton(options_frame, text="Attempt AXFR", variable=self.axfr_var).grid(
            row=0, column=0, sticky=tk.W, padx=(0, 24), pady=2
        )
        ttk.Checkbutton(
            options_frame,
            text="Query authoritative nameservers directly",
            variable=self.auth_ns_var,
        ).grid(row=0, column=1, sticky=tk.W, pady=2)

        actions_frame = ttk.Frame(main)
        actions_frame.pack(fill=tk.X, pady=(0, 10))

        self.run_button = ttk.Button(actions_frame, text="Run Scan", command=self._on_run_scan)
        self.run_button.pack(side=tk.LEFT, padx=(0, 8))

        self.export_button = ttk.Button(
            actions_frame,
            text="Export Results",
            command=self._on_export_results,
            state=tk.DISABLED,
        )
        self.export_button.pack(side=tk.LEFT)

        log_frame = ttk.LabelFrame(main, text="Status / Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            height=18,
            state=tk.DISABLED,
            font=("Consolas", 10),
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _add_file_row(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        variable: tk.StringVar,
        command,
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky=tk.W, pady=4)
        entry = ttk.Entry(parent, textvariable=variable, width=70)
        entry.grid(row=row, column=1, sticky=tk.EW, padx=(8, 8), pady=4)
        ttk.Button(parent, text="Browse…", command=command).grid(row=row, column=2, pady=4)
        parent.columnconfigure(1, weight=1)

    def _browse_domain_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select domain list file",
            filetypes=[
                ("Text / CSV", "*.txt *.csv"),
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.domain_file_var.set(path)
            self._log(f"Selected domain file: {path}")

    def _browse_wordlist_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select custom wordlist file",
            filetypes=[
                ("Text / CSV", "*.txt *.csv"),
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.wordlist_file_var.set(path)
            self._log(f"Selected custom wordlist: {path}")

    def _on_wordlist_path_changed(self, *_args) -> None:
        has_file = bool(self.wordlist_file_var.get().strip())
        if has_file:
            self.custom_wordlist_check.configure(state=tk.NORMAL)
            if not self.include_custom_var.get():
                self.include_custom_var.set(True)
        else:
            self.include_custom_var.set(False)
            self.custom_wordlist_check.configure(state=tk.DISABLED)

    def _log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _validate_selected_files(self) -> tuple[bool, Path | None, Path | None]:
        domain_path_str = self.domain_file_var.get().strip()
        if not domain_path_str:
            self._log("Validation failed: no domain list file selected.")
            messagebox.showwarning("Missing file", "Please select a domain list file.")
            return False, None, None

        domain_path = Path(domain_path_str)
        ok, message = validate_domain_file(domain_path)
        self._log(message)
        if not ok:
            messagebox.showerror("Invalid domain file", message)
            return False, None, None

        wordlist_path: Path | None = None
        wordlist_path_str = self.wordlist_file_var.get().strip()
        if wordlist_path_str:
            wordlist_path = Path(wordlist_path_str)
            ok, message = validate_wordlist_file(wordlist_path)
            self._log(message)
            if not ok:
                messagebox.showerror("Invalid wordlist file", message)
                return False, None, None

        return True, domain_path, wordlist_path

    def _collect_scan_options(self, wordlist_path: Path | None) -> ScanOptions:
        include_custom = bool(wordlist_path) and self.include_custom_var.get()
        return ScanOptions(
            include_rfc_locality_baseline=self.rfc_locality_var.get(),
            include_dns_common=self.dns_common_var.get(),
            include_civic_departments=self.civic_departments_var.get(),
            include_public_services=self.public_services_var.get(),
            include_schools_libraries=self.schools_libraries_var.get(),
            include_delegated_manager_clues=self.delegated_manager_var.get(),
            include_custom_wordlist=include_custom,
            custom_wordlist_path=wordlist_path if include_custom else None,
            attempt_axfr=self.axfr_var.get(),
            query_authoritative_ns=self.auth_ns_var.get(),
        )

    def _log_scan_options(self, options: ScanOptions) -> None:
        self._log("Scan options:")
        self._log(f"  RFC/locality baseline: {options.include_rfc_locality_baseline}")
        self._log(f"  Common DNS/web labels: {options.include_dns_common}")
        self._log(f"  Civic departments: {options.include_civic_departments}")
        self._log(f"  Public services / portals: {options.include_public_services}")
        self._log(f"  Schools / libraries: {options.include_schools_libraries}")
        self._log(f"  Delegated-manager clues: {options.include_delegated_manager_clues}")
        if options.custom_wordlist_path and options.include_custom_wordlist:
            self._log(f"  Custom wordlist included: {options.custom_wordlist_path}")
        elif options.custom_wordlist_path:
            self._log(f"  Custom wordlist file selected but excluded: {options.custom_wordlist_path}")
        else:
            self._log("  Custom wordlist: not selected")

        self._log(f"  Attempt AXFR: {options.attempt_axfr}")
        self._log(f"  Query authoritative NS: {options.query_authoritative_ns}")

    def _set_scan_running(self, running: bool) -> None:
        self.run_button.configure(state=tk.DISABLED if running else tk.NORMAL)
        if running:
            self.export_button.configure(state=tk.DISABLED)

    def _set_export_enabled(self, enabled: bool) -> None:
        self.export_button.configure(state=tk.NORMAL if enabled else tk.DISABLED)

    def _on_run_scan(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            self._log("Scan already in progress.")
            return

        self._log("Run Scan requested.")
        valid, domain_path, wordlist_path = self._validate_selected_files()
        if not valid or domain_path is None:
            return

        options = self._collect_scan_options(wordlist_path)
        self._log_scan_options(options)

        scan_input = ScanInput(
            domain_file_path=domain_path,
            options=options,
            output_dir=OUTPUT_DIR,
            wordlists_dir=WORDLISTS_DIR,
        )

        self._set_scan_running(True)

        def progress(message: str) -> None:
            self.after(0, lambda m=message: self._log(m))

        def worker() -> None:
            try:
                result = run_scan(scan_input, progress_callback=progress)
                self.after(0, lambda: self._on_scan_complete(result))
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda: self._on_scan_error(exc))

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()

    def _on_scan_complete(self, result: ScanRunResult) -> None:
        self._last_scan_result = result
        self._set_scan_running(False)
        if result.domain_results:
            self._set_export_enabled(True)
            self._log("Scan complete. Export Results is now available.")
        else:
            self._set_export_enabled(False)
            self._log("Scan finished with no domain results to export.")

    def _on_scan_error(self, exc: Exception) -> None:
        self._set_scan_running(False)
        self._log(f"Scan failed: {exc.__class__.__name__}: {exc}")
        messagebox.showerror("Scan error", f"The scan encountered an error:\n{exc}")

    def _prompt_export_format(self) -> str | None:
        dialog = tk.Toplevel(self)
        dialog.title("Export Results")
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)

        choice: dict[str, str | None] = {"value": None}

        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Choose export format:").pack(anchor=tk.W, pady=(0, 10))

        def select(value: str) -> None:
            choice["value"] = value
            dialog.destroy()

        ttk.Button(
            frame,
            text="XLSX workbook (recommended)",
            command=lambda: select("xlsx"),
        ).pack(fill=tk.X, pady=2)
        ttk.Button(frame, text="Findings CSV", command=lambda: select("csv")).pack(fill=tk.X, pady=2)
        ttk.Button(frame, text="JSON", command=lambda: select("json")).pack(fill=tk.X, pady=2)
        ttk.Button(frame, text="All formats", command=lambda: select("all")).pack(fill=tk.X, pady=2)
        ttk.Button(frame, text="Cancel", command=dialog.destroy).pack(fill=tk.X, pady=(8, 0))

        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.update_idletasks()
        dialog.geometry(f"+{self.winfo_rootx() + 80}+{self.winfo_rooty() + 80}")
        self.wait_window(dialog)
        return choice["value"]

    def _on_export_results(self) -> None:
        if not self._last_scan_result or not self._last_scan_result.domain_results:
            messagebox.showwarning("Nothing to export", "Run a scan before exporting results.")
            return

        export_format = self._prompt_export_format()
        if not export_format:
            self._log("Export cancelled.")
            return

        try:
            outcome = export_results(self._last_scan_result, OUTPUT_DIR, export_format)
        except OSError as exc:
            self._log(f"Export failed: {exc}")
            messagebox.showerror("Export failed", f"Could not write export files:\n{exc}")
            return
        except Exception as exc:  # noqa: BLE001
            self._log(f"Export failed: {exc.__class__.__name__}: {exc}")
            messagebox.showerror("Export failed", f"An unexpected export error occurred:\n{exc}")
            return

        self._log("Export complete:")
        if outcome.xlsx_path:
            self._log(f"  XLSX: {outcome.xlsx_path}")
        if outcome.csv_path:
            self._log(f"  CSV: {outcome.csv_path}")
        if outcome.summary_csv_path:
            self._log(f"  Summary CSV: {outcome.summary_csv_path}")
        if outcome.json_path:
            self._log(f"  JSON: {outcome.json_path}")
        self._log(f"  Rows exported: {outcome.row_count}")
        self._log(f"  Domains scanned: {outcome.domain_count}")


def main() -> None:
    app = DiscoveryApp()
    app.mainloop()


if __name__ == "__main__":
    main()
