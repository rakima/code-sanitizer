"""Tkinter desktop interface for the local code sanitizer."""

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .file_io import read_text_file, save_sanitized_file
from .sanitizer import MaskRule, ReplacementRule, sanitize_text


class CodeSanitizerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Code Sanitizer")
        self.root.geometry("1100x760")
        self.root.minsize(800, 560)

        self.source_path: Path | None = None
        self.source_text = ""
        self.sanitized_text: str | None = None
        self.file_path_var = tk.StringVar(value="ファイルが選択されていません")
        self.count_var = tk.StringVar(value="置換: 0件    行マスク: 0件")
        self.status_var = tk.StringVar(value="")
        self.replacement_rules: list[ReplacementRule] = []
        self.mask_rules: list[MaskRule] = []

        self._build_ui()

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root, padding=10)
        container.pack(fill=tk.BOTH, expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(3, weight=1)

        file_frame = ttk.Frame(container)
        file_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        file_frame.columnconfigure(1, weight=1)
        ttk.Button(file_frame, text="ファイルを選択", command=self._select_file).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Label(file_frame, textvariable=self.file_path_var).grid(
            row=0, column=1, sticky="ew"
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

        preview = ttk.Panedwindow(container, orient=tk.HORIZONTAL)
        preview.grid(row=3, column=0, sticky="nsew")
        self.original_text_widget = self._make_text_pane(preview, "元コード")
        self.result_text_widget = self._make_text_pane(preview, "匿名化後コード")

        ttk.Label(container, textvariable=self.status_var).grid(
            row=4, column=0, sticky="ew", pady=(6, 0)
        )

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
            title="匿名化するテキストファイルを選択"
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
        self.file_path_var.set(str(self.source_path))
        self._set_text(self.original_text_widget, content)
        self._sanitize()

    def _add_replacement_rule(self) -> None:
        search = self.replacement_search_entry.get()
        if not search:
            messagebox.showwarning("入力エラー", "検索文字列を入力してください。")
            return

        rule = ReplacementRule(search, self.replacement_value_entry.get())
        self.replacement_rules.append(rule)
        self.replacement_tree.insert(
            "", tk.END, values=(rule.search, rule.replacement)
        )
        self.replacement_search_entry.delete(0, tk.END)
        self.replacement_value_entry.delete(0, tk.END)
        self._sanitize_if_loaded()

    def _remove_replacement_rule(self) -> None:
        selection = self.replacement_tree.selection()
        if not selection:
            return
        index = self.replacement_tree.index(selection[0])
        self.replacement_tree.delete(selection[0])
        del self.replacement_rules[index]
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
        self._sanitize_if_loaded()

    def _remove_mask_rule(self) -> None:
        selection = self.mask_tree.selection()
        if not selection:
            return
        index = self.mask_tree.index(selection[0])
        self.mask_tree.delete(selection[0])
        del self.mask_rules[index]
        self._sanitize_if_loaded()

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
        self.status_var.set("")

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
