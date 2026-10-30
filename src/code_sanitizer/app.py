"""Tkinter desktop interface for the local code sanitizer."""

from collections.abc import Callable
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from tkinterdnd2 import DND_FILES

from .drag_drop import parse_dropped_files
from .file_io import (
    read_text_file,
    save_restorable_outputs,
    save_restored_file,
    save_sanitized_file,
)
from .leak_checker import LeakCandidate, scan_for_leaks
from .restoration import (
    RestorationResult,
    load_restoration_data,
    restore_text,
)
from .sanitizer import (
    DATE_MASK_LABEL,
    MaskRule,
    ReplacementRule,
    sanitize_text,
    sanitize_text_for_restoration,
)
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
        self.restoration_result: RestorationResult | None = None
        self.restored_text: str | None = None
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
        self.mode_tabs = ttk.Notebook(self.root)
        self.mode_tabs.pack(fill=tk.BOTH, expand=True)
        self.sanitize_tab = ttk.Frame(self.mode_tabs, padding=10)
        self.restore_tab = ttk.Frame(self.mode_tabs, padding=10)
        self.mode_tabs.add(self.sanitize_tab, text="匿名化モード")
        self.mode_tabs.add(self.restore_tab, text="復元モード")

        container = self.sanitize_tab
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
        drop_hint = ttk.Label(file_frame, text="またはここへファイルをドロップ")
        drop_hint.grid(row=1, column=0, columnspan=3, sticky="w")
        self._bind_file_drop(file_frame, self._drop_source_file)
        self._bind_file_drop(drop_hint, self._drop_source_file)
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
        ttk.Button(
            controls,
            text="復元可能な匿名化を作成",
            command=self._create_restorable_sanitized_file,
        ).pack(side=tk.LEFT, padx=(8, 0))
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
        self._build_restoration_ui()

        preview = ttk.Panedwindow(container, orient=tk.HORIZONTAL)
        preview.grid(row=4, column=0, sticky="nsew")
        self.original_text_widget = self._make_text_pane(preview, "元コード")
        self.result_text_widget = self._make_text_pane(preview, "匿名化後コード")

        ttk.Label(container, textvariable=self.status_var).grid(
            row=5, column=0, sticky="ew", pady=(6, 0)
        )

    def _build_restoration_ui(self) -> None:
        container = self.restore_tab
        container.columnconfigure(0, weight=1)
        container.rowconfigure(4, weight=1)

        ttk.Label(
            container,
            text=(
                "匿名化に使った元コード・修正後コード・復元情報を指定してください。"
                "復元情報には元の機密文字列が含まれます。"
            ),
            wraplength=1050,
        ).grid(row=0, column=0, sticky="ew", pady=(0, 8))

        inputs = ttk.Frame(container)
        inputs.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        inputs.columnconfigure(1, weight=1)
        self.restore_original_path = tk.StringVar()
        self.restore_edited_path = tk.StringVar()
        self.restore_data_path = tk.StringVar()
        self._add_restore_file_selector(
            inputs,
            row=0,
            label="匿名化時コード（元コードまたは匿名化済みコード）",
            variable=self.restore_original_path,
            command=self._select_restore_original,
        )
        self._add_restore_file_selector(
            inputs,
            row=1,
            label="AI修正後コード",
            variable=self.restore_edited_path,
            command=self._select_restore_edited,
        )
        self._add_restore_file_selector(
            inputs,
            row=2,
            label="復元情報",
            variable=self.restore_data_path,
            command=self._select_restore_data,
        )

        controls = ttk.Frame(container)
        controls.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        ttk.Button(
            controls, text="復元を実行", command=self._run_restoration
        ).pack(side=tk.LEFT)
        ttk.Button(
            controls, text="復元結果をコピー", command=self._copy_restored_result
        ).pack(side=tk.RIGHT)
        ttk.Button(
            controls, text="復元結果を保存", command=self._save_restored_result
        ).pack(side=tk.RIGHT, padx=(0, 8))

        self.restore_summary = tk.Text(
            container, height=9, wrap=tk.WORD, state=tk.DISABLED
        )
        self.restore_summary.grid(row=3, column=0, sticky="ew", pady=(0, 6))

        preview = ttk.Panedwindow(container, orient=tk.HORIZONTAL)
        preview.grid(row=4, column=0, sticky="nsew")
        self.restored_text_widget = self._make_text_pane(
            preview, "復元結果（確認用）"
        )
        self.restore_status_var = tk.StringVar(value="")
        ttk.Label(container, textvariable=self.restore_status_var).grid(
            row=5, column=0, sticky="ew", pady=(6, 0)
        )

    def _add_restore_file_selector(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        variable: tk.StringVar,
        command: Callable[[], None],
    ) -> None:
        ttk.Label(parent, text=label).grid(
            row=row, column=0, sticky="w", padx=(0, 8), pady=3
        )
        path_entry = ttk.Entry(parent, textvariable=variable, state="readonly")
        path_entry.grid(
            row=row, column=1, sticky="ew", pady=3
        )
        self._bind_file_drop(
            path_entry,
            lambda event, target=variable: self._drop_restore_file(event, target),
        )
        drop_hint = ttk.Label(parent, text="ここへドロップ")
        drop_hint.grid(
            row=row, column=3, padx=(6, 0), pady=3
        )
        self._bind_file_drop(
            drop_hint,
            lambda event, target=variable: self._drop_restore_file(event, target),
        )
        ttk.Button(parent, text="選択", command=command).grid(
            row=row, column=2, padx=(8, 0), pady=3
        )

    def _bind_file_drop(
        self, widget: tk.Misc, handler: Callable[[tk.Event], str]
    ) -> None:
        widget.drop_target_register(DND_FILES)
        widget.dnd_bind("<<Drop>>", handler)

    def _drop_source_file(self, event: tk.Event) -> str:
        try:
            paths = parse_dropped_files(self.root.tk, event.data)
        except ValueError as error:
            messagebox.showerror("ドロップエラー", str(error))
            return "break"
        if len(paths) != 1:
            messagebox.showwarning(
                "ファイル数を確認してください",
                "匿名化モードにはファイルを1つだけドロップしてください。",
            )
            return "break"
        self._load_source_file(paths[0])
        return "break"

    def _drop_restore_file(self, event: tk.Event, variable: tk.StringVar) -> str:
        try:
            paths = parse_dropped_files(self.root.tk, event.data)
        except ValueError as error:
            messagebox.showerror("ドロップエラー", str(error))
            return "break"
        if len(paths) != 1:
            messagebox.showwarning(
                "ファイル数を確認してください",
                "各入力欄にはファイルを1つずつドロップしてください。",
            )
            return "break"
        self._set_restore_file(variable, paths[0])
        return "break"

    def _select_restore_original(self) -> None:
        self._select_restore_file(
            self.restore_original_path,
            "元コードを選択",
            (("テキストファイル", "*"),),
        )

    def _select_restore_edited(self) -> None:
        self._select_restore_file(
            self.restore_edited_path,
            "AI修正後コードを選択",
            (("テキストファイル", "*"),),
        )

    def _select_restore_data(self) -> None:
        self._select_restore_file(
            self.restore_data_path,
            "復元情報を選択",
            (("JSONファイル", "*.json"),),
        )

    def _select_restore_file(
        self,
        variable: tk.StringVar,
        title: str,
        filetypes: tuple[tuple[str, str], ...],
    ) -> None:
        selected_path = filedialog.askopenfilename(
            title=title,
            initialdir=self.last_directory or str(Path.home()),
            filetypes=filetypes,
        )
        if not selected_path:
            return
        self._set_restore_file(variable, selected_path)

    def _set_restore_file(
        self, variable: tk.StringVar, selected_path: str
    ) -> None:
        if (
            variable is self.restore_data_path
            and Path(selected_path).suffix.lower() != ".json"
        ):
            messagebox.showerror(
                "ファイル選択エラー",
                "復元情報にはJSONファイル（.json）を指定してください。",
            )
            return
        if not Path(selected_path).is_file():
            messagebox.showerror(
                "ファイル選択エラー",
                f"選択したパスはファイルではありません。\n{selected_path}",
            )
            return
        variable.set(selected_path)
        self._remember_directory(Path(selected_path).parent)

    def _remember_directory(self, directory: Path) -> None:
        self.last_directory = str(directory)
        self._persist_settings()

    def _create_restorable_sanitized_file(self) -> None:
        if self.source_path is None:
            messagebox.showinfo("ファイル未選択", "先にファイルを選択してください。")
            return

        result = sanitize_text_for_restoration(
            self.source_text, self.replacement_rules, self.mask_rules
        )
        default_name = (
            f"{self.source_path.stem}_restorable_sanitized"
            f"{self.source_path.suffix}"
        )
        sanitized_path = filedialog.asksaveasfilename(
            title="復元可能な匿名化コードを保存",
            initialdir=str(self.source_path.parent),
            initialfile=default_name,
            defaultextension=self.source_path.suffix,
        )
        if not sanitized_path:
            return

        restoration_name = (
            f"{Path(sanitized_path).name}.restoration.json"
        )
        restoration_path = filedialog.asksaveasfilename(
            title="機密情報を含む復元情報を保存",
            initialdir=str(Path(sanitized_path).parent),
            initialfile=restoration_name,
            defaultextension=".restoration.json",
            filetypes=[
                ("復元情報", "*.restoration.json"),
                ("すべてのファイル", "*"),
            ],
        )
        if not restoration_path:
            return

        try:
            save_restorable_outputs(
                self.source_path,
                sanitized_path,
                restoration_path,
                result.text,
                result.restoration_data,
            )
        except (OSError, ValueError) as error:
            messagebox.showerror(
                "復元可能匿名化の保存エラー",
                "ファイルを保存できませんでした。既存ファイルは上書きしません。\n"
                f"{error}",
            )
            return

        self._remember_directory(Path(sanitized_path).parent)
        self.status_var.set(
            "復元可能な匿名化コードと復元情報を保存しました。"
            "復元情報は機密情報を含むため、ローカルで安全に管理してください。"
        )
        messagebox.showinfo(
            "保存しました",
            f"匿名化コード:\n{sanitized_path}\n\n"
            f"復元情報:\n{restoration_path}\n\n"
            "復元情報には元の機密文字列が含まれます。"
            "共有・送信・Gitへの追加を避けてください。",
        )

    def _run_restoration(self) -> None:
        paths = (
            self.restore_original_path.get(),
            self.restore_edited_path.get(),
            self.restore_data_path.get(),
        )
        if not all(paths):
            messagebox.showinfo(
                "入力が不足しています",
                "元コード、AI修正後コード、復元情報をすべて選択してください。",
            )
            return

        try:
            original_text = read_text_file(paths[0])
            edited_text = read_text_file(paths[1])
            restoration_data = load_restoration_data(paths[2])
            result = restore_text(original_text, edited_text, restoration_data)
        except (OSError, UnicodeError, ValueError) as error:
            messagebox.showerror(
                "復元エラー", f"復元処理を完了できませんでした。\n{error}"
            )
            return

        self.restoration_result = result
        self.restored_text = result.text
        self._set_text(self.restored_text_widget, result.text)
        self._set_restore_summary(result)
        self.restore_status_var.set(
            "復元状態: 人間による確認が必要"
            if not result.fully_restored
            else "復元状態: ID整合性を確認（出力内容の確認を推奨）"
        )

    def _set_restore_summary(self, result: RestorationResult) -> None:
        status = (
            "人間による確認が必要"
            if not result.fully_restored
            else "未解決IDなし（出力内容の目視確認を推奨）"
        )
        lines = [
            f"復元状態: {status}",
            f"復元成功件数: {result.restored_count}",
            f"未復元件数: {result.unresolved_count}",
            f"消失したREDACTED: {', '.join(result.missing_tokens) or 'なし'}",
            f"不正なREDACTED: {', '.join(result.invalid_tokens) or 'なし'}",
            f"未知のREDACTED: {', '.join(result.unknown_tokens) or 'なし'}",
            f"重複したREDACTED: {', '.join(result.duplicated_tokens) or 'なし'}",
        ]
        if result.source_mismatch:
            lines.append(
                "警告: 元コードまたは復元情報の対応データが作成時と一致しません。"
                "復元していません。"
            )
        elif result.source_reconstructed:
            lines.append(
                "復元情報と匿名化時コードから未匿名化元コードを再構成し、"
                "SHA-256を照合しました。"
            )
        if result.review_required:
            lines.append(
                "行マスクIDは元の行全体を復元するため人間の確認が必要です。"
                "行内にAI編集があるIDは自動復元していません: "
                + ", ".join(result.review_required)
            )
        self.restore_summary.configure(state=tk.NORMAL)
        self.restore_summary.delete("1.0", tk.END)
        self.restore_summary.insert("1.0", "\n".join(lines))
        self.restore_summary.configure(state=tk.DISABLED)

    def _save_restored_result(self) -> None:
        if self.restored_text is None or self.restoration_result is None:
            messagebox.showinfo("結果なし", "先に復元を実行してください。")
            return

        original_path = Path(self.restore_original_path.get())
        destination = filedialog.asksaveasfilename(
            title="復元結果を保存",
            initialdir=self.last_directory or str(original_path.parent),
            initialfile=f"{original_path.stem}_restored{original_path.suffix}",
            defaultextension=original_path.suffix,
        )
        if not destination:
            return

        protected_paths = (
            self.restore_original_path.get(),
            self.restore_edited_path.get(),
            self.restore_data_path.get(),
        )
        try:
            save_restored_file(destination, self.restored_text, protected_paths)
        except (OSError, ValueError) as error:
            messagebox.showerror(
                "復元結果の保存エラー",
                f"ファイルを保存できませんでした。\n{error}",
            )
            return
        self._remember_directory(Path(destination).parent)
        self.restore_status_var.set(f"復元結果を保存しました: {destination}")

    def _copy_restored_result(self) -> None:
        if self.restored_text is None:
            messagebox.showinfo("結果なし", "先に復元を実行してください。")
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.restored_text)
        except tk.TclError as error:
            messagebox.showerror(
                "コピーエラー", f"復元結果をコピーできませんでした。\n{error}"
            )
            return
        self.restore_status_var.set("復元結果をクリップボードにコピーしました。")

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
        self.mask_tree.heading("search", text="この条件を含む行をマスク")
        self.mask_tree.column("search", width=300)
        self.mask_tree.grid(row=0, column=0, columnspan=3, sticky="ew")
        ttk.Label(frame, text="検索文字列").grid(
            row=1, column=0, sticky="w", pady=(6, 0)
        )
        self.mask_search_entry = ttk.Entry(frame)
        self.mask_search_entry.grid(row=2, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(frame, text="追加", command=self._add_mask_rule).grid(
            row=2, column=1, padx=(0, 4)
        )
        ttk.Button(
            frame, text="日付形式を追加", command=self._add_date_mask_rule
        ).grid(
            row=2, column=2
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

        self._load_source_file(selected_path)

    def _load_source_file(self, selected_path: str) -> None:
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

    def _add_date_mask_rule(self) -> None:
        rule = MaskRule(DATE_MASK_LABEL, match_date_formats=True)
        if rule in self.mask_rules:
            return

        self.mask_rules.append(rule)
        self.mask_tree.insert("", tk.END, values=(rule.search,))
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
    from tkinterdnd2 import TkinterDnD

    root = TkinterDnD.Tk()
    CodeSanitizerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
