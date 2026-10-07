"""Tkinter desktop interface for the local code sanitizer."""

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .file_io import read_text_file, save_sanitized_file
from .leak_checker import LeakCandidate, scan_for_leaks
from .sanitizer import MaskRule, ReplacementRule, sanitize_text
from .settings import AppSettings, load_settings, save_settings


class CodeSanitizerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Code Sanitizer")
        self.root.geometry("1180x900")
        self.root.minsize(900, 700)

        self.source_path: Path | None = None
        self.source_text = ""
        self.sanitized_text: str | None = None
        self.file_path_var = tk.StringVar(value="ファイルが選択されていません")
        self.count_var = tk.StringVar(value="置換: 0件    行マスク: 0件")
        self.status_var = tk.StringVar(value="")
        self.last_directory: str | None = None
        self.settings_error: str | None = None
        try:
            settings = load_settings()
        except (OSError, ValueError) as error:
            settings = AppSettings()
            self.settings_error = str(error)
        self.replacement_rules = list(settings.replacement_rules)
        self.mask_rules = list(settings.mask_rules)
        self.last_directory = settings.last_directory
        self.ignored_identifier_words: set[str] = set()
        self.findings_by_iid: dict[str, LeakCandidate] = {}

        self._build_ui()
        for rule in self.replacement_rules:
            self.replacement_tree.insert(
                "", tk.END, values=(rule.search, rule.replacement)
            )
        for rule in self.mask_rules:
            self.mask_tree.insert("", tk.END, values=(rule.search,))
        if self.settings_error is not None:
            self.root.after_idle(self._show_settings_load_error)

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root, padding=10)
        container.pack(fill=tk.BOTH, expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(4, weight=1)

        file_frame = ttk.Frame(container)
        file_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        file_frame.columnconfigure(1, weight=1)
        ttk.Button(file_frame, text="ファイルを選択", command=self._select_file).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Label(file_frame, textvariable=self.file_path_var).grid(
            row=0, column=1, sticky="ew"
        )
        ttk.Label(file_frame, text="ルールはローカルに自動保存").grid(
            row=0, column=2, padx=(8, 0)
        )

        rules_frame = ttk.Frame(container)
        rules_frame.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        rules_frame.columnconfigure(0, weight=1)
        rules_frame.columnconfigure(1, weight=1)
        self._build_replacement_rules(rules_frame)
        self._build_mask_rules(rules_frame)

        controls = ttk.Frame(container)
        controls.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        ttk.Button(controls, text="匿名化を実行", command=self._sanitize).pack(
            side=tk.LEFT
        )
        ttk.Label(controls, textvariable=self.count_var).pack(
            side=tk.LEFT, padx=12
        )
        ttk.Button(controls, text="結果を保存", command=self._save_result).pack(
            side=tk.RIGHT
        )
        ttk.Button(controls, text="結果をコピー", command=self._copy_result).pack(
            side=tk.RIGHT, padx=(0, 8)
        )

        self._build_leak_check(container)

        preview = ttk.Panedwindow(container, orient=tk.HORIZONTAL)
        preview.grid(row=4, column=0, sticky="nsew")
        self.original_text_widget = self._make_text_pane(preview, "元コード")
        self.result_text_widget = self._make_text_pane(preview, "匿名化後コード")

        ttk.Label(container, textvariable=self.status_var).grid(
            row=5, column=0, sticky="ew", pady=(6, 0)
        )

    def _build_leak_check(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(
            parent,
            text="匿名化漏れチェック（候補の確認用）",
            padding=8,
        )
        frame.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        frame.columnconfigure(0, weight=3)
        frame.columnconfigure(1, weight=0)

        ttk.Label(
            frame,
            text="機械的な候補検出です。検出なしでも機密情報がないことは保証されません。",
            wraplength=1000,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 5))

        self.findings_tree = ttk.Treeview(
            frame,
            columns=("risk", "category", "value", "count", "lines"),
            show="headings",
            height=5,
            selectmode="browse",
        )
        for column, heading, width in (
            ("risk", "優先度", 65),
            ("category", "種類", 120),
            ("value", "候補", 220),
            ("count", "件数", 65),
            ("lines", "行", 170),
        ):
            self.findings_tree.heading(column, text=heading)
            self.findings_tree.column(column, width=width, stretch=column == "value")
        self.findings_tree.grid(
            row=1, column=0, rowspan=2, sticky="nsew", padx=(0, 8)
        )
        findings_scrollbar = ttk.Scrollbar(
            frame, orient=tk.VERTICAL, command=self.findings_tree.yview
        )
        findings_scrollbar.grid(row=1, column=1, rowspan=2, sticky="nse")
        self.findings_tree.configure(yscrollcommand=findings_scrollbar.set)
        self.findings_tree.bind(
            "<<TreeviewSelect>>", self._show_selected_finding
        )

        detail_frame = ttk.Frame(frame)
        detail_frame.grid(row=1, column=2, sticky="nsew")
        detail_frame.columnconfigure(0, weight=1)
        ttk.Label(detail_frame, text="選択した候補の詳細").grid(
            row=0, column=0, sticky="w"
        )
        self.finding_details = tk.Text(
            detail_frame, height=4, wrap=tk.WORD, state=tk.DISABLED
        )
        self.finding_details.grid(row=1, column=0, sticky="nsew", pady=(3, 5))
        ttk.Button(
            detail_frame,
            text="匿名化ルールに追加",
            command=self._add_selected_identifier_rule,
        ).grid(row=2, column=0, sticky="w")
        ttk.Button(
            detail_frame,
            text="固有名称候補を無視",
            command=self._ignore_selected_identifier,
        ).grid(row=2, column=0, sticky="e")
        frame.columnconfigure(2, weight=2)

    def _make_text_pane(
        self, parent: ttk.Panedwindow, title: str
    ) -> tk.Text:
        frame = ttk.Frame(parent)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text=title).grid(row=0, column=0, sticky="w", pady=(0, 4))
        text_widget = tk.Text(frame, wrap=tk.NONE, undo=False)
        text_widget.grid(row=1, column=0, sticky="nsew")
        y_scrollbar = ttk.Scrollbar(
            frame, orient=tk.VERTICAL, command=text_widget.yview
        )
        y_scrollbar.grid(row=1, column=1, sticky="ns")
        x_scrollbar = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=text_widget.xview)
        x_scrollbar.grid(row=2, column=0, sticky="ew")
        text_widget.configure(
            yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set
        )
        text_widget.configure(state=tk.DISABLED)
        parent.add(frame, weight=1)
        return text_widget

    def _build_replacement_rules(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(
            parent, text="通常置換ルール（大文字小文字を区別）", padding=8
        )
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self.replacement_tree = ttk.Treeview(
            frame, columns=("search", "replacement"), show="headings", height=4
        )
        self.replacement_tree.heading("search", text="検索文字列")
        self.replacement_tree.heading("replacement", text="置換文字列")
        self.replacement_tree.column("search", width=150)
        self.replacement_tree.column("replacement", width=150)
        self.replacement_tree.grid(row=0, column=0, columnspan=3, sticky="ew")
        ttk.Label(frame, text="検索").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Label(frame, text="置換").grid(row=1, column=1, sticky="w", pady=(6, 0))
        self.replacement_search_entry = ttk.Entry(frame)
        self.replacement_value_entry = ttk.Entry(frame)
        self.replacement_search_entry.grid(row=2, column=0, sticky="ew", padx=(0, 4))
        self.replacement_value_entry.grid(row=2, column=1, sticky="ew", padx=(0, 4))
        ttk.Button(frame, text="追加", command=self._add_replacement_rule).grid(
            row=2, column=2
        )
        ttk.Button(
            frame, text="選択を削除", command=self._remove_replacement_rule
        ).grid(row=3, column=0, sticky="w", pady=(4, 0))

    def _build_mask_rules(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="行マスクルール", padding=8)
        frame.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self.mask_tree = ttk.Treeview(
            frame, columns=("search",), show="headings", height=4
        )
        self.mask_tree.heading("search", text="この文字列を含む行をマスク")
        self.mask_tree.column("search", width=300)
        self.mask_tree.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Label(frame, text="検索文字列").grid(
            row=1, column=0, sticky="w", pady=(6, 0)
        )
        self.mask_search_entry = ttk.Entry(frame)
        self.mask_search_entry.grid(row=2, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(frame, text="追加", command=self._add_mask_rule).grid(
            row=2, column=1
        )
        ttk.Button(frame, text="選択を削除", command=self._remove_mask_rule).grid(
            row=3, column=0, sticky="w", pady=(4, 0)
        )

    def _select_file(self) -> None:
        selected_path = filedialog.askopenfilename(
            title="匿名化するテキストファイルを選択",
            initialdir=self.last_directory or str(Path.home()),
        )
        if not selected_path:
            return

        try:
            content = read_text_file(selected_path)
        except (OSError, UnicodeError) as error:
            messagebox.showerror(
                "読み込みエラー", f"ファイルを読み込めませんでした。\n{error}"
            )
            return

        self.source_path = Path(selected_path)
        self.source_text = content
        self.last_directory = str(self.source_path.parent)
        self.ignored_identifier_words.clear()
        self.file_path_var.set(str(self.source_path))
        self._set_text(self.original_text_widget, content)
        self._persist_settings()
        self._sanitize()

    def _add_replacement_rule(self) -> None:
        search = self.replacement_search_entry.get()
        if not search:
            messagebox.showwarning("入力エラー", "検索文字列を入力してください。")
            return

        if not self._register_replacement_rule(
            search, self.replacement_value_entry.get()
        ):
            return
        self.replacement_search_entry.delete(0, tk.END)
        self.replacement_value_entry.delete(0, tk.END)

    def _register_replacement_rule(self, search: str, replacement: str) -> bool:
        if not search:
            messagebox.showwarning("入力エラー", "検索文字列を入力してください。")
            return False

        rule = ReplacementRule(search, replacement)
        self.replacement_rules.append(rule)
        self.replacement_tree.insert(
            "", tk.END, values=(rule.search, rule.replacement)
        )
        self._persist_settings()
        self._sanitize_if_loaded()
        return True

    def _remove_replacement_rule(self) -> None:
        selection = self.replacement_tree.selection()
        if not selection:
            return
        index = self.replacement_tree.index(selection[0])
        self.replacement_tree.delete(selection[0])
        del self.replacement_rules[index]
        self._persist_settings()
        self._sanitize_if_loaded()

    def _add_mask_rule(self) -> None:
        search = self.mask_search_entry.get()
        if not search:
            messagebox.showwarning("入力エラー", "検索文字列を入力してください。")
            return

        rule = MaskRule(search)
        self.mask_rules.append(rule)
        self.mask_tree.insert("", tk.END, values=(rule.search,))
        self.mask_search_entry.delete(0, tk.END)
        self._persist_settings()
        self._sanitize_if_loaded()

    def _remove_mask_rule(self) -> None:
        selection = self.mask_tree.selection()
        if not selection:
            return
        index = self.mask_tree.index(selection[0])
        self.mask_tree.delete(selection[0])
        del self.mask_rules[index]
        self._persist_settings()
        self._sanitize_if_loaded()

    def _persist_settings(self) -> None:
        settings = AppSettings(
            replacement_rules=tuple(self.replacement_rules),
            mask_rules=tuple(self.mask_rules),
            last_directory=self.last_directory,
        )
        try:
            save_settings(settings)
        except OSError as error:
            messagebox.showerror(
                "設定保存エラー",
                f"設定をローカルに保存できませんでした。\n{error}",
            )

    def _show_settings_load_error(self) -> None:
        if self.settings_error is None:
            return
        messagebox.showerror(
            "設定読み込みエラー",
            "保存済み設定を読み込めませんでした。"
            "設定を初期状態で起動しました。\n"
            f"{self.settings_error}",
        )

    def _sanitize_if_loaded(self) -> None:
        if self.source_path is not None:
            self._sanitize()

    def _sanitize(self) -> None:
        if self.source_path is None:
            messagebox.showinfo("ファイル未選択", "先にファイルを選択してください。")
            return

        result = sanitize_text(
            self.source_text, self.replacement_rules, self.mask_rules
        )
        self.sanitized_text = result.text
        self._set_text(self.result_text_widget, result.text)
        self.count_var.set(
            f"置換: {result.replacement_count}件    "
            f"行マスク: {result.masked_line_count}件"
        )
        self._refresh_leak_findings(result.text)
        self.status_var.set("")

    def _refresh_leak_findings(self, text: str) -> None:
        result = scan_for_leaks(text, self.ignored_identifier_words)
        self.findings_tree.delete(*self.findings_tree.get_children())
        self.findings_by_iid.clear()

        category_labels = {
            "email": "Email",
            "ipv4": "IPv4",
            "url": "URL",
            "windows_path": "Windowsパス",
            "unix_path": "Unixパス",
            "credential": "認証情報候補",
            "identifier": "固有名称候補",
        }
        risk_labels = {"high": "高", "medium": "中", "low": "低"}

        for check in result.pattern_checks:
            matches = [
                candidate
                for candidate in result.pattern_candidates
                if candidate.category == check.category
            ]
            if not matches:
                self.findings_tree.insert(
                    "",
                    tk.END,
                    values=("-", check.label, "検出なし", "検出なし", "-"),
                    tags=("not_found",),
                )
                continue
            for candidate in matches:
                self._insert_finding(candidate, category_labels, risk_labels)

        for candidate in result.identifier_candidates:
            self._insert_finding(candidate, category_labels, risk_labels)

        self.findings_tree.tag_configure("not_found", foreground="#555555")
        self._set_finding_details(
            "一覧から候補を選択すると、出現回数と行番号を確認できます。"
        )

    def _insert_finding(
        self,
        candidate: LeakCandidate,
        category_labels: dict[str, str],
        risk_labels: dict[str, str],
    ) -> None:
        lines = ", ".join(str(line) for line in candidate.lines)
        iid = self.findings_tree.insert(
            "",
            tk.END,
            values=(
                risk_labels.get(candidate.risk, candidate.risk),
                category_labels.get(candidate.category, candidate.category),
                candidate.value,
                f"{candidate.count}件",
                lines,
            ),
        )
        self.findings_by_iid[iid] = candidate

    def _show_selected_finding(self, event: tk.Event) -> None:
        if event.widget is not self.findings_tree:
            return
        selection = self.findings_tree.selection()
        if not selection:
            return

        candidate = self.findings_by_iid.get(selection[0])
        if candidate is None:
            values = self.findings_tree.item(selection[0], "values")
            self._set_finding_details(f"{values[1]}: 検出なし")
            return

        line_list = ", ".join(str(line) for line in candidate.lines)
        detail = (
            f"対象文字列: {candidate.value}\n"
            f"出現回数: {candidate.count}\n"
            f"行: {line_list or '—'}"
        )
        self._set_finding_details(detail)

    def _set_finding_details(self, text: str) -> None:
        self.finding_details.configure(state=tk.NORMAL)
        self.finding_details.delete("1.0", tk.END)
        self.finding_details.insert("1.0", text)
        self.finding_details.configure(state=tk.DISABLED)

    def _selected_identifier_candidate(self) -> LeakCandidate | None:
        selection = self.findings_tree.selection()
        if not selection:
            return None
        candidate = self.findings_by_iid.get(selection[0])
        if candidate is None or candidate.category != "identifier":
            return None
        return candidate

    def _add_selected_identifier_rule(self) -> None:
        candidate = self._selected_identifier_candidate()
        if candidate is None:
            messagebox.showinfo(
                "候補を選択してください",
                "匿名化ルールに追加する固有名称候補を選択してください。",
            )
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("匿名化ルールに追加")
        dialog.transient(self.root)
        dialog.resizable(False, False)
        dialog.columnconfigure(1, weight=1)
        ttk.Label(dialog, text="検索文字列").grid(
            row=0, column=0, padx=10, pady=(10, 4), sticky="w"
        )
        search_entry = ttk.Entry(dialog, width=36)
        search_entry.grid(row=0, column=1, padx=(0, 10), pady=(10, 4), sticky="ew")
        search_entry.insert(0, candidate.value)
        ttk.Label(dialog, text="置換文字列").grid(
            row=1, column=0, padx=10, pady=4, sticky="w"
        )
        replacement_entry = ttk.Entry(dialog, width=36)
        replacement_entry.grid(
            row=1, column=1, padx=(0, 10), pady=4, sticky="ew"
        )

        buttons = ttk.Frame(dialog)
        buttons.grid(row=2, column=0, columnspan=2, padx=10, pady=(6, 10), sticky="e")

        def add_rule() -> None:
            if self._register_replacement_rule(
                search_entry.get(), replacement_entry.get()
            ):
                dialog.destroy()

        ttk.Button(buttons, text="追加", command=add_rule).pack(
            side=tk.RIGHT, padx=(6, 0)
        )
        ttk.Button(buttons, text="キャンセル", command=dialog.destroy).pack(
            side=tk.RIGHT
        )
        dialog.grab_set()
        search_entry.focus_set()

    def _ignore_selected_identifier(self) -> None:
        candidate = self._selected_identifier_candidate()
        if candidate is None:
            messagebox.showinfo(
                "候補を選択してください",
                "無視する固有名称候補を選択してください。",
            )
            return

        self.ignored_identifier_words.add(candidate.value.casefold())
        if self.sanitized_text is not None:
            self._refresh_leak_findings(self.sanitized_text)
        self.status_var.set(f"候補「{candidate.value}」をこのファイルで無視しました。")

    @staticmethod
    def _set_text(widget: tk.Text, content: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", content)
        widget.configure(state=tk.DISABLED)

    def _save_result(self) -> None:
        if self.source_path is None or self.sanitized_text is None:
            messagebox.showinfo("結果なし", "先に匿名化を実行してください。")
            return

        default_name = (
            f"{self.source_path.stem}_sanitized{self.source_path.suffix}"
        )
        destination = filedialog.asksaveasfilename(
            title="匿名化結果を保存",
            initialdir=str(self.source_path.parent),
            initialfile=default_name,
            defaultextension=self.source_path.suffix,
            filetypes=[("すべてのファイル", "*")],
        )
        if not destination:
            return

        try:
            save_sanitized_file(self.source_path, destination, self.sanitized_text)
        except (OSError, ValueError) as error:
            messagebox.showerror(
                "保存エラー", f"ファイルを保存できませんでした。\n{error}"
            )
            return
        self.status_var.set(f"保存しました: {destination}")

    def _copy_result(self) -> None:
        if self.sanitized_text is None:
            messagebox.showinfo("結果なし", "先に匿名化を実行してください。")
            return

        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.sanitized_text)
        except tk.TclError as error:
            messagebox.showerror(
                "コピーエラー", f"クリップボードへコピーできませんでした。\n{error}"
            )
            return
        self.status_var.set("匿名化結果をクリップボードにコピーしました。")


def main() -> None:
    root = tk.Tk()
    CodeSanitizerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
