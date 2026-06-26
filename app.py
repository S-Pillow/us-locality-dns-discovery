#!/usr/bin/env python3
"""US Locality DNS Discovery Tool — desktop GUI entry point."""

from __future__ import annotations

import os
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from scanner.export_service import export_results
from scanner.models import CancellationToken, ScanInput, ScanOptions, ScanProfile, ScanProgressUpdate, ScanRunResult
from scanner.paths import ensure_output_dir, get_default_output_dir, get_wordlists_dir
from scanner.input_loader import (
    PREFERRED_INPUT_FORMAT_NOTE,
    RECOMMENDED_INPUT_COLUMNS_CSV,
    load_domain_inputs,
)
from scanner.scan_engine import (
    apply_scan_profile,
    axfr_preflight_warning,
    build_preflight_summary,
    preflight_scan_guidance,
    profile_guidance,
    run_scan,
    validate_domain_input,
    validate_domain_file,
    validate_wordlist_file,
)

APP_TITLE = ".US Locality DNS Discovery Tool"
DEFAULT_OUTPUT_DIR = get_default_output_dir()
WORDLISTS_DIR = get_wordlists_dir()


class DiscoveryApp(tk.Tk):
    """Main Tkinter window for the discovery tool."""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(900, 600)
        self.geometry("960x720")

        self.domain_file_var = tk.StringVar()
        self.wordlist_file_var = tk.StringVar()
        self.output_folder_var = tk.StringVar(value=str(DEFAULT_OUTPUT_DIR.resolve()))
        self.scan_profile_var = tk.StringVar(value=ScanProfile.LIGHT.value)

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
        self._cancel_token: CancellationToken | None = None
        self._scan_started_at: datetime | None = None
        self._latest_progress: ScanProgressUpdate | None = None
        self._cancel_requested: bool = False
        self._heartbeat_after_id: str | None = None
        self._progress_indeterminate: bool = False

        self.wordlist_file_var.trace_add("write", self._on_wordlist_path_changed)

        ok, message = ensure_output_dir(DEFAULT_OUTPUT_DIR)
        if not ok:
            messagebox.showwarning("Output folder", message)

        self._build_ui()
        self._bind_preflight_refresh()
        self._on_wordlist_path_changed()
        self._refresh_preflight()
        self._log("Ready. Select known 3rd-level domains and run a child domain discovery scan.")
        self._log(f"Output folder: {self.output_folder_var.get()}")

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        canvas = tk.Canvas(self, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=canvas.yview)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        main = ttk.Frame(canvas, padding=12)
        canvas_window = canvas.create_window((0, 0), window=main, anchor="nw")

        def _on_frame_configure(_event=None) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_configure(event) -> None:
            canvas.itemconfigure(canvas_window, width=event.width)

        main.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        def _on_mousewheel(event) -> None:
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

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
        self._add_output_folder_row(files_frame, row=2)

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
        self.wordlist_checkbuttons: list[ttk.Checkbutton] = []
        for index, (text, variable) in enumerate(wordlist_rows):
            check = ttk.Checkbutton(wordlist_frame, text=text, variable=variable)
            check.grid(
                row=index // 2,
                column=index % 2,
                sticky=tk.W,
                padx=(0, 24),
                pady=2,
            )
            self.wordlist_checkbuttons.append(check)

        self.custom_wordlist_check = ttk.Checkbutton(
            wordlist_frame,
            text="Include custom wordlist (when file selected)",
            variable=self.include_custom_var,
        )
        self.custom_wordlist_check.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(6, 0))

        options_frame = ttk.LabelFrame(main, text="Scan Profile", padding=10)
        options_frame.pack(fill=tk.X, pady=(0, 10))

        profile_rows = [
            ("Light Evidence (10–25 domains)", ScanProfile.LIGHT.value),
            ("Normal Evidence (3–10 domains)", ScanProfile.NORMAL.value),
            ("Deep Targeted (1–3 domains)", ScanProfile.DEEP.value),
        ]
        for index, (label, value) in enumerate(profile_rows):
            ttk.Radiobutton(
                options_frame,
                text=label,
                variable=self.scan_profile_var,
                value=value,
                command=self._on_scan_profile_changed,
            ).grid(row=0, column=index, sticky=tk.W, padx=(0, 18), pady=2)

        scan_options_frame = ttk.LabelFrame(main, text="Scan Options", padding=10)
        scan_options_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Checkbutton(scan_options_frame, text="Attempt AXFR", variable=self.axfr_var).grid(
            row=0, column=0, sticky=tk.W, padx=(0, 24), pady=2
        )
        ttk.Checkbutton(
            scan_options_frame,
            text="Query authoritative nameservers directly",
            variable=self.auth_ns_var,
        ).grid(row=0, column=1, sticky=tk.W, pady=2)

        self.wordlist_frame = wordlist_frame

        preflight_frame = ttk.LabelFrame(main, text="Preflight Summary", padding=10)
        preflight_frame.pack(fill=tk.X, pady=(0, 10))
        self.preflight_var = tk.StringVar(
            value=(
                "Select a domain list to view preflight estimate.\n"
                f"Recommended enriched CSV columns:\n  {RECOMMENDED_INPUT_COLUMNS_CSV}"
            )
        )
        ttk.Label(
            preflight_frame,
            textvariable=self.preflight_var,
            justify=tk.LEFT,
            wraplength=860,
        ).pack(anchor=tk.W)

        progress_frame = ttk.LabelFrame(main, text="Scan Progress", padding=10)
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            mode="determinate",
        )
        self.progress_bar.pack(fill=tk.X, pady=(0, 6))
        self.progress_text_var = tk.StringVar(value="Scan not running.")
        ttk.Label(
            progress_frame,
            textvariable=self.progress_text_var,
            justify=tk.LEFT,
            wraplength=860,
        ).pack(anchor=tk.W)

        actions_frame = ttk.Frame(self, padding=(12, 8))
        actions_frame.grid(row=1, column=0, columnspan=2, sticky="ew")

        self.run_button = ttk.Button(actions_frame, text="Run Scan", command=self._on_run_scan)
        self.run_button.pack(side=tk.LEFT, padx=(0, 8))

        self.cancel_button = ttk.Button(
            actions_frame,
            text="Cancel Scan",
            command=self._on_cancel_scan,
            state=tk.DISABLED,
        )
        self.cancel_button.pack(side=tk.LEFT, padx=(0, 8))

        self.export_button = ttk.Button(
            actions_frame,
            text="Export Results",
            command=self._on_export_results,
            state=tk.DISABLED,
        )
        self.export_button.pack(side=tk.LEFT)

        log_frame = ttk.LabelFrame(main, text="Status / Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            height=12,
            state=tk.DISABLED,
            font=("Consolas", 10),
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self._on_scan_profile_changed()

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

    def _add_output_folder_row(self, parent: ttk.Frame, row: int) -> None:
        ttk.Label(parent, text="Output folder:").grid(row=row, column=0, sticky=tk.W, pady=4)
        entry = ttk.Entry(parent, textvariable=self.output_folder_var, width=70)
        entry.grid(row=row, column=1, sticky=tk.EW, padx=(8, 8), pady=4)
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=row, column=2, pady=4)
        ttk.Button(button_frame, text="Browse…", command=self._browse_output_folder).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Open Folder", command=self._open_output_folder).pack(
            side=tk.LEFT, padx=(6, 0)
        )
        parent.columnconfigure(1, weight=1)

    def _browse_output_folder(self) -> None:
        initial = self.output_folder_var.get().strip() or str(DEFAULT_OUTPUT_DIR.resolve())
        path = filedialog.askdirectory(
            title="Select output folder for reports",
            initialdir=initial if Path(initial).is_dir() else str(DEFAULT_OUTPUT_DIR.resolve()),
        )
        if path:
            self.output_folder_var.set(path)
            ok, message = ensure_output_dir(Path(path))
            self._log(message)
            if not ok:
                messagebox.showerror("Output folder", message)
            self._refresh_preflight()

    def _open_output_folder(self) -> None:
        ok, output_dir = self._resolve_output_folder(show_error=True)
        if not ok or output_dir is None:
            return
        try:
            os.startfile(output_dir)  # noqa: S606 — Windows folder open for operator convenience
        except OSError as exc:
            self._log(f"Could not open output folder: {exc}")
            messagebox.showerror("Open folder", f"Could not open output folder:\n{exc}")

    def _resolve_output_folder(self, *, show_error: bool = False) -> tuple[bool, Path | None]:
        folder_text = self.output_folder_var.get().strip()
        if not folder_text:
            message = "No output folder selected."
            if show_error:
                self._log(message)
                messagebox.showerror("Output folder", message)
            return False, None

        output_dir = Path(folder_text)
        ok, message = ensure_output_dir(output_dir)
        if show_error:
            self._log(message)
            if not ok:
                messagebox.showerror("Output folder", message)
        if not ok:
            return False, None
        return True, output_dir.resolve()

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
            self._refresh_preflight()

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
        self._refresh_preflight()

    def _on_scan_profile_changed(self) -> None:
        profile = ScanProfile(self.scan_profile_var.get())
        deep_mode = profile == ScanProfile.DEEP
        for check in self.wordlist_checkbuttons:
            check.configure(state=tk.NORMAL if deep_mode else tk.DISABLED)
        self.custom_wordlist_check.configure(
            state=tk.NORMAL if deep_mode and self.wordlist_file_var.get().strip() else tk.DISABLED
        )

        if profile == ScanProfile.LIGHT:
            self.axfr_var.set(False)
            self.auth_ns_var.set(True)
            self.rfc_locality_var.set(False)
            self.dns_common_var.set(False)
            self.civic_departments_var.set(False)
            self.public_services_var.set(False)
            self.schools_libraries_var.set(False)
            self.delegated_manager_var.set(False)
        elif profile == ScanProfile.NORMAL:
            self.rfc_locality_var.set(True)
            self.dns_common_var.set(True)
            self.civic_departments_var.set(True)
            self.public_services_var.set(False)
            self.schools_libraries_var.set(False)
            self.delegated_manager_var.set(False)
        self._refresh_preflight()

    def _bind_preflight_refresh(self) -> None:
        self.scan_profile_var.trace_add("write", lambda *_args: self._refresh_preflight())
        for variable in (
            self.rfc_locality_var,
            self.dns_common_var,
            self.civic_departments_var,
            self.public_services_var,
            self.schools_libraries_var,
            self.delegated_manager_var,
            self.include_custom_var,
            self.axfr_var,
            self.auth_ns_var,
        ):
            variable.trace_add("write", lambda *_args: self._refresh_preflight())
        self.domain_file_var.trace_add("write", lambda *_args: self._refresh_preflight())
        self.output_folder_var.trace_add("write", lambda *_args: self._refresh_preflight())

    def _build_scan_input(
        self,
        domain_path: Path,
        wordlist_path: Path | None,
        *,
        validate_output: bool = False,
    ) -> ScanInput:
        ok, output_dir = self._resolve_output_folder(show_error=validate_output)
        if not ok or output_dir is None:
            raise OSError("Output folder is not available.")

        return ScanInput(
            domain_file_path=domain_path,
            options=self._collect_scan_options(wordlist_path),
            output_dir=output_dir,
            wordlists_dir=WORDLISTS_DIR,
        )

    def _refresh_preflight(self) -> None:
        output_line = f"  Output folder: {self.output_folder_var.get() or DEFAULT_OUTPUT_DIR}\n"

        domain_path_str = self.domain_file_var.get().strip()
        if not domain_path_str:
            self.preflight_var.set(
                "Select a domain list to view preflight estimate.\n" + output_line.rstrip()
            )
            return

        domain_path = Path(domain_path_str)
        ok, _message = validate_domain_file(domain_path)
        if not ok:
            self.preflight_var.set("Preflight unavailable: invalid or missing domain list file.")
            return

        loaded = load_domain_inputs(domain_path)
        if loaded.error:
            self.preflight_var.set(f"Preflight unavailable: {loaded.error}")
            return
        if not loaded.domains:
            self.preflight_var.set("Preflight unavailable: no domains found in input file.")
            return

        wordlist_path_str = self.wordlist_file_var.get().strip()
        wordlist_path = Path(wordlist_path_str) if wordlist_path_str else None
        if wordlist_path:
            ok, _message = validate_wordlist_file(wordlist_path)
            if not ok:
                self.preflight_var.set("Preflight unavailable: invalid custom wordlist file.")
                return

        summary = build_preflight_summary(
            self._build_scan_input(domain_path, wordlist_path, validate_output=False)
        )
        if summary is None:
            self.preflight_var.set(
                "Preflight unavailable: could not read domain list or output folder.\n"
                + output_line.rstrip()
            )
            return

        sources = ", ".join(summary.wordlist_sources.keys()) if summary.wordlist_sources else "(none)"
        metadata_line = ""
        if summary.metadata_columns_detected:
            metadata_line = (
                f"  Metadata columns: {', '.join(summary.metadata_columns_detected)}\n"
            )
        duplicate_line = ""
        if summary.duplicate_domains_removed:
            duplicate_line = (
                f"  Duplicate domains removed: {summary.duplicate_domains_removed}\n"
            )
        size_level, size_guidance = preflight_scan_guidance(summary.estimated_total_candidates)
        profile = ScanProfile(summary.scan_profile)
        warning_lines = ""
        if summary.input_warnings:
            warning_lines = "\n".join(f"  {warning}" for warning in summary.input_warnings) + "\n"
        sample_line = ""
        if summary.sample_domains_preview:
            sample_line = f"  First domains: {', '.join(summary.sample_domains_preview)}\n"
        domain_column_line = ""
        if summary.selected_domain_column:
            domain_column_line = f"  Selected domain column: {summary.selected_domain_column}\n"
        preferred_line = ""
        if summary.preferred_input_format_detected:
            preferred_line = "  Preferred input format detected.\n"
        elif summary.input_file_type == "enriched_csv":
            preferred_line = (
                "  Recommended CSV columns: "
                f"{RECOMMENDED_INPUT_COLUMNS_CSV}\n"
            )

        axfr_state = "ON" if summary.axfr_enabled else "OFF"
        axfr_warning_line = ""
        axfr_warning = axfr_preflight_warning(profile, summary.axfr_enabled)
        if axfr_warning:
            axfr_warning_line = f"  Warning: {axfr_warning}\n"

        self.preflight_var.set(
            "Preflight estimate — unknown child domain discovery:\n"
            f"  Goal: find child DNS names not already known in the system input.\n"
            f"{preferred_line}"
            f"  Scan profile: {profile.value}\n"
            f"  Profile guidance: {profile_guidance(profile)}\n"
            f"  Domains loaded: {summary.domain_count}\n"
            f"  Input type: {summary.input_file_type}\n"
            f"{domain_column_line}"
            f"{sample_line}"
            f"{metadata_line}"
            f"{duplicate_line}"
            f"{warning_lines}"
            f"{output_line}"
            f"  Wordlist sources: {sources}\n"
            f"  Total unique candidate labels: {summary.total_unique_labels}\n"
            f"  Estimated candidate names per domain: {summary.estimated_candidates_per_domain}\n"
            f"  Estimated total candidate names: {summary.estimated_total_candidates:,}\n"
            f"  Scan size: {size_level}\n"
            f"  Guidance: {size_guidance}\n"
            f"  Review focus: Evidence Review sheet — strong/moderate evidence_value rows.\n"
            f"  AXFR: {axfr_state}\n"
            f"{axfr_warning_line}"
            f"  Authoritative NS querying enabled: {'yes' if summary.auth_ns_enabled else 'no'}"
        )

    def _confirm_scan_start(self, total_candidates: int) -> bool:
        if total_candidates >= 50_000:
            return messagebox.askyesno(
                "Very Large Scan",
                "This is a very large scan and may take a long time. "
                "Consider using fewer wordlist sources or testing a smaller subset first.\n\n"
                f"Estimated candidate names: {total_candidates:,}\n\nContinue?",
            )
        if total_candidates >= 10_000:
            return messagebox.askyesno(
                "Large Scan",
                "This scan may take a long time.\n\n"
                f"Estimated candidate names: {total_candidates:,}\n\nContinue?",
            )
        return True

    def _set_progress_bar_indeterminate(self, indeterminate: bool) -> None:
        if indeterminate == self._progress_indeterminate:
            if indeterminate:
                try:
                    self.progress_bar.start(12)
                except tk.TclError:
                    pass
            return
        self._progress_indeterminate = indeterminate
        if indeterminate:
            self.progress_bar.configure(mode="indeterminate")
            try:
                self.progress_bar.start(12)
            except tk.TclError:
                pass
        else:
            try:
                self.progress_bar.stop()
            except tk.TclError:
                pass
            self.progress_bar.configure(mode="determinate")

    def _format_progress_text(
        self,
        update: ScanProgressUpdate | None,
        *,
        elapsed_seconds: float,
        cancel_requested: bool = False,
    ) -> str:
        elapsed_minutes, elapsed_seconds_part = divmod(int(elapsed_seconds), 60)
        if update is None:
            return (
                "Phase: Starting scan\n"
                "Preparing scan...\n"
                "Candidate testing not started yet\n"
                f"Elapsed: {elapsed_minutes}m {elapsed_seconds_part}s"
            )

        if update.candidates_started and update.candidates_total > 0:
            candidate_line = (
                f"Candidates tested: {update.candidates_tested} / {update.candidates_total}"
            )
        elif update.candidates_total > 0:
            candidate_line = (
                f"Candidate testing not started yet (estimated {update.candidates_total})"
            )
        else:
            candidate_line = "Candidate testing not started yet"

        phase_line = update.phase or "Working"
        if update.domain_total and update.current_domain:
            domain_line = (
                f"Scanning domain {update.domain_index} of {update.domain_total}: "
                f"{update.current_domain}"
            )
        else:
            domain_line = update.message or "Preparing scan"

        lines: list[str] = []
        if cancel_requested:
            lines.append("Cancel requested. The scan will stop at the next safe checkpoint.")
        lines.extend(
            [
                f"Phase: {phase_line}",
                domain_line,
                candidate_line,
                f"Completed domains: {update.domains_completed} / {update.domain_total}",
                f"Elapsed: {elapsed_minutes}m {elapsed_seconds_part}s",
            ]
        )
        return "\n".join(lines)

    def _apply_progress_display(
        self,
        update: ScanProgressUpdate | None,
        *,
        elapsed_seconds: float | None = None,
    ) -> None:
        elapsed = elapsed_seconds
        if elapsed is None:
            elapsed = update.elapsed_seconds if update is not None else 0.0

        indeterminate = True
        if update is not None:
            indeterminate = update.progress_indeterminate
        self._set_progress_bar_indeterminate(indeterminate)

        if not indeterminate and update is not None and update.domain_total > 0:
            completed_fraction = update.domains_completed / update.domain_total
            current_domain_fraction = 0.0
            if update.candidates_started and update.candidates_total > 0:
                current_domain_fraction = (
                    update.candidates_tested / update.candidates_total
                ) / update.domain_total
            self.progress_var.set(min((completed_fraction + current_domain_fraction) * 100, 100))
        elif not indeterminate:
            self.progress_var.set(0)

        self.progress_text_var.set(
            self._format_progress_text(
                update,
                elapsed_seconds=elapsed,
                cancel_requested=self._cancel_requested,
            )
        )

    def _start_progress_heartbeat(self) -> None:
        self._stop_progress_heartbeat()
        self._scan_started_at = datetime.now()
        self._latest_progress = None
        self._cancel_requested = False
        self._set_progress_bar_indeterminate(True)
        self._tick_progress_heartbeat()

    def _tick_progress_heartbeat(self) -> None:
        if self._scan_started_at is None:
            return
        if self._scan_thread is None or not self._scan_thread.is_alive():
            self._stop_progress_heartbeat()
            return

        elapsed = (datetime.now() - self._scan_started_at).total_seconds()
        self._apply_progress_display(self._latest_progress, elapsed_seconds=elapsed)
        self._heartbeat_after_id = self.after(1000, self._tick_progress_heartbeat)

    def _stop_progress_heartbeat(self) -> None:
        if self._heartbeat_after_id is not None:
            try:
                self.after_cancel(self._heartbeat_after_id)
            except tk.TclError:
                pass
            self._heartbeat_after_id = None
        self._scan_started_at = None
        self._latest_progress = None
        self._set_progress_bar_indeterminate(False)

    def _update_progress(self, update: ScanProgressUpdate) -> None:
        self._latest_progress = update
        elapsed = update.elapsed_seconds
        if self._scan_started_at is not None:
            elapsed = (datetime.now() - self._scan_started_at).total_seconds()
        self._apply_progress_display(update, elapsed_seconds=elapsed)

    def _reset_progress_ui(self, message: str = "Scan not running.") -> None:
        self._stop_progress_heartbeat()
        self._cancel_requested = False
        self.progress_var.set(0)
        self.progress_text_var.set(message)
        self.cancel_button.configure(state=tk.DISABLED)

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
        ok, message = validate_domain_input(domain_path)
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
        profile = ScanProfile(self.scan_profile_var.get())
        return ScanOptions(
            scan_profile=profile,
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
        resolved = apply_scan_profile(options)
        self._log("Scan options:")
        self._log(f"  Scan profile: {options.scan_profile.value}")
        self._log(f"  RFC/locality baseline: {resolved.include_rfc_locality_baseline}")
        self._log(f"  Common DNS/web labels: {resolved.include_dns_common}")
        self._log(f"  Civic departments: {resolved.include_civic_departments}")
        self._log(f"  Light Evidence labels: {resolved.include_light_evidence}")
        self._log(f"  Public services / portals: {resolved.include_public_services}")
        self._log(f"  Schools / libraries: {resolved.include_schools_libraries}")
        self._log(f"  Delegated-manager clues: {resolved.include_delegated_manager_clues}")
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
            self.cancel_button.configure(state=tk.NORMAL)
        else:
            self.cancel_button.configure(state=tk.DISABLED)

    def _set_export_enabled(self, enabled: bool) -> None:
        self.export_button.configure(state=tk.NORMAL if enabled else tk.DISABLED)

    def _on_cancel_scan(self) -> None:
        if self._cancel_token is not None:
            self._cancel_token.cancel()
            self._cancel_requested = True
            self._log(
                "Cancel requested. The scan will stop at the next safe checkpoint."
            )
            self.cancel_button.configure(state=tk.DISABLED)
            if self._scan_started_at is not None:
                elapsed = (datetime.now() - self._scan_started_at).total_seconds()
                self._apply_progress_display(self._latest_progress, elapsed_seconds=elapsed)

    def _on_run_scan(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            self._log("Scan already in progress.")
            return

        self._log("Run Scan requested.")
        valid, domain_path, wordlist_path = self._validate_selected_files()
        if not valid or domain_path is None:
            return

        try:
            scan_input = self._build_scan_input(domain_path, wordlist_path, validate_output=True)
        except OSError as exc:
            self._log(str(exc))
            messagebox.showerror("Output folder", str(exc))
            return

        self._log(f"Output folder: {scan_input.output_dir}")
        self._log_scan_options(scan_input.options)

        preflight = build_preflight_summary(scan_input)
        if preflight is None:
            messagebox.showerror("Preflight failed", "Could not build preflight estimate from the domain list.")
            return

        self._refresh_preflight()
        if not self._confirm_scan_start(preflight.estimated_total_candidates):
            self._log("Scan start cancelled by operator.")
            return

        self._cancel_token = CancellationToken()
        self._set_scan_running(True)
        self.progress_var.set(0)
        self.progress_text_var.set("Starting scan...")
        self._start_progress_heartbeat()

        def progress(message: str) -> None:
            self.after(0, lambda m=message: self._log(m))

        def progress_update(update: ScanProgressUpdate) -> None:
            self.after(0, lambda u=update: self._update_progress(u))

        def worker() -> None:
            try:
                result = run_scan(
                    scan_input,
                    progress_callback=progress,
                    progress_update=progress_update,
                    cancel_token=self._cancel_token,
                )
                self.after(0, lambda: self._on_scan_complete(result))
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda: self._on_scan_error(exc))

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()

    def _on_scan_complete(self, result: ScanRunResult) -> None:
        self._last_scan_result = result
        self._set_scan_running(False)
        self._cancel_token = None
        self._stop_progress_heartbeat()
        self._cancel_requested = False

        if result.cancelled:
            self.progress_var.set(
                (len(result.domain_results) / result.domains_total * 100) if result.domains_total else 0
            )
            self.progress_text_var.set(
                f"Scan cancelled. Completed {len(result.domain_results)} of {result.domains_total} domains."
            )
            self._log("Scan was cancelled. Results are partial.")
        elif result.domain_results:
            self.progress_var.set(100)
            elapsed = result.elapsed_seconds or 0.0
            self.progress_text_var.set(
                f"Scan complete. {len(result.domain_results)} domains scanned in {elapsed:.1f}s."
            )

        if result.domain_results:
            self._set_export_enabled(True)
            if result.partial:
                self._log("Partial results are available for export.")
            else:
                self._log("Scan complete. Export Results is now available.")
        else:
            self._set_export_enabled(False)
            self._reset_progress_ui("Scan finished with no domain results to export.")
            self._log("Scan finished with no domain results to export.")

    def _on_scan_error(self, exc: Exception) -> None:
        self._set_scan_running(False)
        self._cancel_token = None
        self._stop_progress_heartbeat()
        self._cancel_requested = False
        self._reset_progress_ui("Scan failed.")
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

        ok, output_dir = self._resolve_output_folder(show_error=True)
        if not ok or output_dir is None:
            return

        try:
            outcome = export_results(self._last_scan_result, output_dir, export_format)
        except OSError as exc:
            self._log(f"Export failed: {exc}")
            messagebox.showerror("Export failed", f"Could not write export files:\n{exc}")
            return
        except Exception as exc:  # noqa: BLE001
            self._log(f"Export failed: {exc.__class__.__name__}: {exc}")
            messagebox.showerror("Export failed", f"An unexpected export error occurred:\n{exc}")
            return

        self._log("Export complete:")
        self._log(f"  Output folder: {output_dir}")
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
