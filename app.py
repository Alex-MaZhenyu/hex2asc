import tkinter as tk
from tkinter import ttk

from converters import (
    safe_hex_to_int,
    safe_hex_to_text,
    safe_text_to_hex,
)


class App(ttk.Frame):
    def __init__(self, master: tk.Tk):
        super().__init__(master)
        self.master = master
        self.status_var = tk.StringVar(value="Ready")

        self.encoding_var = tk.StringVar(value="utf-8")
        self.uppercase_var = tk.BooleanVar(value=True)
        self.sep_var = tk.StringVar(value=" ")

        self._build_ui()

    def _build_ui(self) -> None:
        self.pack(fill="both", expand=True)

        outer = ttk.Frame(self)
        outer.pack(fill="both", expand=True, padx=14, pady=14)

        title = ttk.Label(outer, text="Hex / ASCII / Int Converter", font=("Segoe UI", 16, "bold"))
        title.pack(anchor="w")

        sub = ttk.Label(
            outer,
            text="Convert between hex strings, text (ASCII/UTF-8/GBK), and integer values.",
            font=("Segoe UI", 10),
            foreground="#444",
        )
        sub.pack(anchor="w", pady=(2, 10))

        opts = ttk.Frame(outer)
        opts.pack(fill="x", pady=(0, 10))

        ttk.Label(opts, text="Encoding:").pack(side="left")
        enc = ttk.Combobox(opts, textvariable=self.encoding_var, state="readonly", width=10)
        enc["values"] = ("utf-8", "ascii", "gbk", "latin1")
        enc.pack(side="left", padx=(6, 12))

        upper = ttk.Checkbutton(opts, text="Uppercase hex", variable=self.uppercase_var)
        upper.pack(side="left")

        ttk.Label(opts, text="Separator:").pack(side="left", padx=(12, 0))
        sep = ttk.Combobox(opts, textvariable=self.sep_var, state="readonly", width=8)
        sep["values"] = (" ", "", ":", "-")
        sep.pack(side="left", padx=(6, 0))

        nb = ttk.Notebook(outer)
        nb.pack(fill="both", expand=True)

        self.tab_hex2text = ttk.Frame(nb)
        self.tab_text2hex = ttk.Frame(nb)
        self.tab_hex2int = ttk.Frame(nb)

        nb.add(self.tab_hex2text, text="hex2asc")
        nb.add(self.tab_text2hex, text="asc2hex")
        nb.add(self.tab_hex2int, text="hex2int")

        self._build_hex2text(self.tab_hex2text)
        self._build_text2hex(self.tab_text2hex)
        self._build_hex2int(self.tab_hex2int)

        status = ttk.Frame(outer)
        status.pack(fill="x", pady=(10, 0))
        ttk.Separator(status).pack(fill="x", pady=(0, 8))
        ttk.Label(status, textvariable=self.status_var, foreground="#333").pack(anchor="w")

    def _make_text_area(self, parent: ttk.Frame, height: int) -> tk.Text:
        t = tk.Text(parent, height=height, wrap="word", undo=True, font=("Consolas", 11))
        t.configure(relief="solid", bd=1)
        return t

    def _get_text(self, t: tk.Text) -> str:
        return t.get("1.0", "end-1c")

    def _set_text(self, t: tk.Text, value: str) -> None:
        t.delete("1.0", "end")
        t.insert("1.0", value)

    def _copy_text(self, t: tk.Text) -> None:
        s = self._get_text(t)
        self.master.clipboard_clear()
        self.master.clipboard_append(s)
        self.status_var.set("Copied to clipboard")

    def _clear_pair(self, a: tk.Text, b: tk.Text) -> None:
        self._set_text(a, "")
        self._set_text(b, "")
        self.status_var.set("Cleared")

    def _build_hex2text(self, tab: ttk.Frame) -> None:
        pane = ttk.PanedWindow(tab, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=12, pady=12)

        left = ttk.Frame(pane)
        right = ttk.Frame(pane)
        pane.add(left, weight=1)
        pane.add(right, weight=1)

        ttk.Label(left, text="Hex input (e.g. 41 42 43 or 0x414243):", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.hex2text_in = self._make_text_area(left, height=12)
        self.hex2text_in.pack(fill="both", expand=True, pady=(6, 0))

        ttk.Label(right, text="Text output:", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.hex2text_out = self._make_text_area(right, height=12)
        self.hex2text_out.pack(fill="both", expand=True, pady=(6, 0))

        btns = ttk.Frame(tab)
        btns.pack(fill="x", padx=12, pady=(0, 12))

        ttk.Button(btns, text="Convert", command=self._on_hex2text).pack(side="left")
        ttk.Button(btns, text="Copy output", command=lambda: self._copy_text(self.hex2text_out)).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Clear", command=lambda: self._clear_pair(self.hex2text_in, self.hex2text_out)).pack(side="left", padx=(8, 0))

    def _build_text2hex(self, tab: ttk.Frame) -> None:
        pane = ttk.PanedWindow(tab, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=12, pady=12)

        left = ttk.Frame(pane)
        right = ttk.Frame(pane)
        pane.add(left, weight=1)
        pane.add(right, weight=1)

        ttk.Label(left, text="Text input:", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.text2hex_in = self._make_text_area(left, height=12)
        self.text2hex_in.pack(fill="both", expand=True, pady=(6, 0))

        ttk.Label(right, text="Hex output:", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.text2hex_out = self._make_text_area(right, height=12)
        self.text2hex_out.pack(fill="both", expand=True, pady=(6, 0))

        btns = ttk.Frame(tab)
        btns.pack(fill="x", padx=12, pady=(0, 12))

        ttk.Button(btns, text="Convert", command=self._on_text2hex).pack(side="left")
        ttk.Button(btns, text="Copy output", command=lambda: self._copy_text(self.text2hex_out)).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Clear", command=lambda: self._clear_pair(self.text2hex_in, self.text2hex_out)).pack(side="left", padx=(8, 0))

    def _build_hex2int(self, tab: ttk.Frame) -> None:
        body = ttk.Frame(tab)
        body.pack(fill="both", expand=True, padx=12, pady=12)

        ttk.Label(body, text="Hex integer input (e.g. FF, 0x10, -0x2A):", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.hex2int_in = self._make_text_area(body, height=6)
        self.hex2int_in.pack(fill="x", expand=False, pady=(6, 8))

        ttk.Label(body, text="Decimal output:", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.hex2int_out = self._make_text_area(body, height=6)
        self.hex2int_out.pack(fill="x", expand=False, pady=(6, 0))

        btns = ttk.Frame(tab)
        btns.pack(fill="x", padx=12, pady=(0, 12))

        ttk.Button(btns, text="Convert", command=self._on_hex2int).pack(side="left")
        ttk.Button(btns, text="Copy output", command=lambda: self._copy_text(self.hex2int_out)).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Clear", command=lambda: self._clear_pair(self.hex2int_in, self.hex2int_out)).pack(side="left", padx=(8, 0))

    def _set_error(self, msg: str) -> None:
        self.status_var.set(f"Error: {msg}")

    def _on_hex2text(self) -> None:
        enc = self.encoding_var.get().strip() or "utf-8"
        src = self._get_text(self.hex2text_in)
        r = safe_hex_to_text(src, encoding=enc)
        if r.ok:
            self._set_text(self.hex2text_out, r.output)
            self.status_var.set("Converted hex -> text")
        else:
            self._set_text(self.hex2text_out, "")
            self._set_error(r.error)

    def _on_text2hex(self) -> None:
        enc = self.encoding_var.get().strip() or "utf-8"
        src = self._get_text(self.text2hex_in)
        r = safe_text_to_hex(src, encoding=enc, uppercase=self.uppercase_var.get(), sep=self.sep_var.get())
        if r.ok:
            self._set_text(self.text2hex_out, r.output)
            self.status_var.set("Converted text -> hex")
        else:
            self._set_text(self.text2hex_out, "")
            self._set_error(r.error)

    def _on_hex2int(self) -> None:
        src = self._get_text(self.hex2int_in)
        r = safe_hex_to_int(src)
        if r.ok:
            self._set_text(self.hex2int_out, r.output)
            self.status_var.set("Converted hex -> int")
        else:
            self._set_text(self.hex2int_out, "")
            self._set_error(r.error)


def main() -> None:
    root = tk.Tk()
    root.title("Hex2Asc Utilities")
    root.minsize(820, 520)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure("TButton", padding=(10, 6))
    style.configure("TNotebook.Tab", padding=(14, 8))

    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
