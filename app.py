#!/usr/bin/env python3
"""US Locality DNS Discovery Tool — desktop GUI entry point."""

from __future__ import annotations

import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from scanner.models import ScanInput, ScanOptions
from scanner.scan_engine import run_scan, validate_domain_file, validate_wordlist_file

APP_TITLE = ".US Locality DNS Discovery Tool"
PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "output"
WORDLISTS_DIR = PROJECT_ROOT / "wordlists"

ACCEPTED_EXTENSIONS = {".txt", ".csv"}


class DiscoveryApp(tk.Tk):
    """Main Tkinter window for the discovery tool prototype."""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(720, 560)
        self.geometry("900x640")

        self.domain_file_var = tk.StringVar()
        self.wordlist_file_var = tk.StringVar()

        self.use_builtin_var = tk.BooleanVar(value=True)
        self.rfc1480_var = tk.BooleanVar(value=True)
        self.civic_var = tk.BooleanVar(value=True)
        self.dns_common_var = tk.BooleanVar(value=True)
        self.axfr_var = tk.BooleanVar(value=False)
        self.auth_ns_var = tk.BooleanVar(value=True)

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        self._build_ui()
        self._log("Ready. This prototype validates inputs only; no DNS lookups are performed.")

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

        options_frame = ttk.LabelFrame(main, text="Scan Options (placeholder)", padding=10)
        options_frame.pack(fill=tk.X, pady=(0, 10))

        option_rows = [
            ("Use built-in wordlist", self.use_builtin_var),
            ("Include RFC 1480-style locality patterns", self.rfc1480_var),
            ("Include common civic labels", self.civic_var),
            ("Include common DNS labels", self.dns_common_var),
            ("Attempt AXFR", self.axfr_var),
            ("Query authoritative nameservers directly", self.auth_ns_var),
        ]
        for index, (text, variable) in enumerate(option_rows):
            ttk.Checkbutton(options_frame, text=text, variable=variable).grid(
                row=index // 2,
                column=index % 2,
                sticky=tk.W,
                padx=(0, 24),
                pady=2,
            )

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
        return ScanOptions(
            use_builtin_wordlist=self.use_builtin_var.get(),
            include_rfc1480_patterns=self.rfc1480_var.get(),
            include_civic_labels=self.civic_var.get(),
            include_dns_common_labels=self.dns_common_var.get(),
            attempt_axfr=self.axfr_var.get(),
            query_authoritative_ns=self.auth_ns_var.get(),
            custom_wordlist_path=wordlist_path,
        )

    def _log_scan_options(self, options: ScanOptions) -> None:
        self._log("Scan options:")
        self._log(f"  Use built-in wordlist: {options.use_builtin_wordlist}")
        self._log(f"  RFC 1480-style patterns: {options.include_rfc1480_patterns}")
        self._log(f"  Common civic labels: {options.include_civic_labels}")
        self._log(f"  Common DNS labels: {options.include_dns_common_labels}")
        self._log(f"  Attempt AXFR: {options.attempt_axfr}")
        self._log(f"  Query authoritative NS: {options.query_authoritative_ns}")
        if options.custom_wordlist_path:
            self._log(f"  Custom wordlist: {options.custom_wordlist_path}")
        else:
            self._log("  Custom wordlist: (none)")

        if options.use_builtin_wordlist:
            for name in ("rfc1480.txt", "civic.txt", "dns_common.txt"):
                path = WORDLISTS_DIR / name
                status = "found" if path.is_file() else "missing"
                self._log(f"  Built-in wordlist {name}: {status}")

    def _on_run_scan(self) -> None:
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
        )

        result = run_scan(scan_input)
        for message in result.status_messages:
            self._log(message)

        self._log("No DNS queries or external network calls were made.")
        self._log("Export is not available until a future ticket implements results output.")

    def _on_export_results(self) -> None:
        messagebox.showinfo(
            "Export not available",
            "Export Results is not implemented in this ticket.",
        )


def main() -> None:
    app = DiscoveryApp()
    app.mainloop()


if __name__ == "__main__":
    main()
