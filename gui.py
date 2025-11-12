import tkinter as tk
from tkinter import ttk
from datetime import datetime
import re
import io
import sys

TS_FMT = "%Y-%m-%d %H:%M:%S.%f"


def _get_node_name(n):
    return getattr(n, "name", getattr(n, "ns_name", "Unknown"))


def _get_node_domains(n):
    raw = _get_node_name(n)
    parts = [p for p in raw.split(" ") if p.strip()]
    domains = set()
    for part in parts:
        part = part.lstrip("/")
        segs = part.split("/")
        if segs and segs[0]:
            domains.add(segs[0])
    return sorted(domains)


def _parse_ts(ts):
    try:
        return datetime.strptime(ts, TS_FMT)
    except Exception:
        return datetime.min


class LogGUI:
    def __init__(self, controller, title="NDN Debugger – Logs"):
        self.controller = controller
        self.root = tk.Tk()
        self.root.title(title)
        self.root.geometry("1100x700")
        self.root.minsize(900, 550)

        self.selected_nodes = set()
        self.auto_refresh = tk.BooleanVar(value=True)
        self.search_term = tk.StringVar(value="")
        self.command_entries = []

        # for node tables
        self.current_table = "FIB"
        self.table_buttons = {}
        self.table_tree = None
        self.table_tree_scroll = None
        self.table_message = None

        self._build_layout()
        self._populate_filters()
        self._start_refresh_loop()
        self._update_table_tab_styles()
        self._update_node_table()

    # ui
    def _build_layout(self):
        self.root.configure(bg="white")
        self.root.grid_columnconfigure(0, weight=4, uniform="col")
        self.root.grid_columnconfigure(1, weight=2, uniform="col")
        self.root.grid_rowconfigure(0, weight=1)

        # global logs
        left_wrap = tk.Frame(self.root, bg="#e0e0e0")
        left_wrap.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        left = tk.Frame(left_wrap, bg="#e0e0e0")
        left.pack(fill="both", expand=True, padx=8, pady=8)

        header = ttk.Label(
            left,
            text="Global Logs",
            font=("Segoe UI", 14, "bold"),
            background="#e0e0e0",
        )
        header.pack(anchor="w")

        controls = tk.Frame(left, bg="#e0e0e0")
        controls.pack(fill="x", pady=(6, 6))
        ttk.Checkbutton(controls, text="Auto refresh", variable=self.auto_refresh).pack(
            side="left"
        )
        ttk.Button(controls, text="Refresh now", command=self.refresh).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(controls, text="Clear", command=self._clear_logs_view).pack(
            side="left", padx=(8, 0)
        )

        ttk.Label(controls, text="Search:").pack(side="left", padx=(12, 4))
        search_entry = ttk.Entry(controls, textvariable=self.search_term, width=24)
        search_entry.pack(side="left")
        search_entry.bind("<Return>", lambda e: self.refresh())

        # scrollable text
        log_container = tk.Frame(left, bg="#e0e0e0")
        log_container.pack(expand=True, fill="both")

        self.log_text = tk.Text(
            log_container, wrap="word", state="disabled", bg="white", fg="black"
        )
        self.log_text.pack(side="left", fill="both", expand=True)
        self.log_text.tag_configure("match", background="#fff2a8")

        yscroll = ttk.Scrollbar(
            log_container, orient="vertical", command=self.log_text.yview
        )
        yscroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=yscroll.set)

        # bottom input area
        bottom = tk.Frame(left, bg="#e0e0e0")
        bottom.pack(fill="x", pady=(10, 0))
        self.footer_box = tk.Text(bottom, height=3)
        self.footer_box.pack(fill="x")

        # for commands
        cmd_bar = tk.Frame(left, bg="#e0e0e0")
        cmd_bar.pack(fill="x", pady=(6, 0))
        ttk.Button(cmd_bar, text="Send", command=self._send_command).pack(side="right")
        ttk.Label(cmd_bar, text="Command (press Enter to send):").pack(side="left")

        def _on_return(event):
            self._send_command()
            return "break"

        self.footer_box.bind("<Return>", _on_return)
        self.footer_box.bind("<Control-Return>", lambda e: None)

        # logs filter + node tables
        right_wrap = tk.Frame(self.root, bg="#e0e0e0")
        right_wrap.grid(row=0, column=1, sticky="nsew", padx=12, pady=12)
        right = tk.Frame(right_wrap, bg="#e0e0e0")
        right.pack(fill="both", expand=True, padx=8, pady=8)

        rf_head = ttk.Label(
            right,
            text="Logs Filter",
            font=("Segoe UI", 14, "bold"),
            background="#e0e0e0",
        )
        rf_head.pack(anchor="w")

        # top scrollable filter
        filters_container = tk.Frame(right, bg="#e0e0e0")
        filters_container.pack(fill="both", expand=True)

        self.filter_canvas = tk.Canvas(
            filters_container, highlightthickness=0, bg="#e0e0e0"
        )
        self.filter_scroll = ttk.Scrollbar(
            filters_container, orient="vertical", command=self.filter_canvas.yview
        )
        self.filter_canvas.configure(yscrollcommand=self.filter_scroll.set)
        self.filter_scroll.pack(side="right", fill="y")
        self.filter_canvas.pack(side="left", fill="both", expand=True)

        self.filters_frame = tk.Frame(self.filter_canvas, bg="#e0e0e0")
        self.filter_canvas.create_window(
            (0, 0), window=self.filters_frame, anchor="nw"
        )
        self.filters_frame.bind(
            "<Configure>",
            lambda e: self.filter_canvas.configure(
                scrollregion=self.filter_canvas.bbox("all")
            ),
        )

        # bottom tables (FIB / CS / PIT / Neighbors / Buffer / Logs / Registry)
        self.tables_panel = tk.Frame(right, bg="#e0e0e0")
        self.tables_panel.pack(fill="both", expand=False, pady=(8, 0))
        self._build_node_tables(self.tables_panel)

    # tables ui
    def _build_node_tables(self, parent):
        title = ttk.Label(
            parent,
            text="Node Tables",
            font=("Segoe UI", 12, "bold"),
            background="#e0e0e0",
        )
        title.pack(anchor="w")

        modes_row = tk.Frame(parent, bg="#e0e0e0")
        modes_row.pack(fill="x", pady=(4, 2))

        def make_mode_button(label, mode):
            btn = tk.Button(
                modes_row,
                text=label,
                bg="white",
                fg="black",
                activebackground="#f0f0f0",
                activeforeground="black",
                relief="flat",
                padx=8,
                pady=4,
                bd=1,
                highlightthickness=1,
                highlightbackground="#000000",
                command=lambda m=mode: self._set_table_mode(m),
            )
            btn.pack(side="left", padx=(0, 4))
            self.table_buttons[mode] = btn

        # main modes
        make_mode_button("FIB", "FIB")
        make_mode_button("CS", "CS")
        make_mode_button("PIT", "PIT")
        make_mode_button("Neighbors", "NEIGHBORS")
        make_mode_button("Buffer", "BUFFER")
        make_mode_button("Logs", "LOGS")
        make_mode_button("Registry", "REGISTRY")

        # refresh button
        refresh_row = tk.Frame(parent, bg="#e0e0e0")
        refresh_row.pack(fill="x", pady=(0, 4))
        ttk.Button(
            refresh_row, text="Refresh Table", command=self._update_node_table
        ).pack(side="left")

        # table
        self.table_container = tk.Frame(parent, bg="#e0e0e0")
        self.table_container.pack(fill="both", expand=True)

        # when no node selected
        self.table_message = ttk.Label(
            self.table_container,
            text="Select exactly one node to view FIB / CS / PIT / Neighbors / Buffer / Logs / Registry.",
            background="#e0e0e0",
            foreground="#555555",
        )
        self.table_message.pack(expand=True)

        # actual table
        self.table_tree = ttk.Treeview(self.table_container, show="headings")
        self.table_tree_scroll = ttk.Scrollbar(
            self.table_container, orient="vertical", command=self.table_tree.yview
        )
        self.table_tree.configure(yscrollcommand=self.table_tree_scroll.set)

    def _set_table_mode(self, mode):
        self.current_table = mode
        self._update_table_tab_styles()
        self._update_node_table()

    def _update_table_tab_styles(self):
        for mode, btn in self.table_buttons.items():
            if mode == self.current_table:
                btn.configure(
                    bg="black",
                    fg="white",
                    activebackground="#333333",
                    activeforeground="white",
                    relief="raised",
                    bd=2,
                    highlightbackground="#000000",
                )
            else:
                btn.configure(
                    bg="white",
                    fg="black",
                    activebackground="#f0f0f0",
                    activeforeground="black",
                    relief="flat",
                    bd=1,
                    highlightbackground="#000000",
                )

    def _get_selected_single_node(self):
        if len(self.selected_nodes) != 1:
            return None
        target_name = next(iter(self.selected_nodes))
        for n in self.controller.nodes.values():
            if _get_node_name(n) == target_name:
                return n
        return None

    def _update_node_table(self):
        node = self._get_selected_single_node()

        if node is None:
            self.table_tree.pack_forget()
            self.table_tree_scroll.pack_forget()
            self.table_message.configure(
                text="Select exactly one node to view FIB / CS / PIT / Neighbors / Buffer / Logs / Registry."
            )
            self.table_message.pack(expand=True)
            return

        self.table_message.pack_forget()
        self.table_tree.pack(side="left", fill="both", expand=True)
        self.table_tree_scroll.pack(side="right", fill="y")

        # clear
        for col in self.table_tree["columns"]:
            self.table_tree.heading(col, text="")
        self.table_tree.delete(*self.table_tree.get_children())

        mode = self.current_table
        rows = []

        if mode == "FIB":
            cols = ("name", "next_hop", "hop_count", "expiration")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("name", width=220, anchor="w")
            self.table_tree.column("next_hop", width=80, anchor="center")
            self.table_tree.column("hop_count", width=80, anchor="center")
            self.table_tree.column("expiration", width=100, anchor="center")

            fib = getattr(node, "fib", {})
            for name, info in fib.items():
                nh = info.get("NextHops", "")
                hc = info.get("HopCount", "")
                exp = info.get("ExpirationTime", "")
                rows.append((name, nh, hc, exp))

        elif mode == "CS":
            cols = ("name", "data")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("name", width=260, anchor="w")
            self.table_tree.column("data", width=260, anchor="w")

            cs = getattr(node, "cs", {})
            for name, data in cs.items():
                text = str(data)
                if len(text) > 80:
                    text = text[:77] + "..."
                rows.append((name, text))

        elif mode == "PIT":
            cols = ("name", "interfaces")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("name", width=260, anchor="w")
            self.table_tree.column("interfaces", width=180, anchor="w")

            pit = getattr(node, "pit", {})
            for name, interfaces in pit.items():
                if isinstance(interfaces, (list, tuple, set)):
                    iface_str = ", ".join(str(i) for i in interfaces)
                else:
                    iface_str = str(interfaces)
                rows.append((name, iface_str))

        elif mode == "NEIGHBORS":
            cols = ("neighbor", "last_seen")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("neighbor", width=260, anchor="w")
            self.table_tree.column("last_seen", width=180, anchor="center")

            neighbor_table = getattr(node, "neighbor_table", None)
            if neighbor_table is None and hasattr(node, "get_neigbors"):
                try:
                    neighbor_table = node.get_neigbors()
                except Exception:
                    neighbor_table = {}
            if neighbor_table is None:
                neighbor_table = {}

            for name, ts in neighbor_table.items():
                rows.append((name, ts))

        elif mode == "BUFFER":
            cols = (
                "packet",
                "source",
                "destination",
                "status",
                "timestamp",
                "hop_history",
                "reason",
                "next_hop",
                "forwarded_to_ns",
            )
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())

            self.table_tree.column("packet", width=100, anchor="w")
            self.table_tree.column("source", width=100, anchor="w")
            self.table_tree.column("destination", width=160, anchor="w")
            self.table_tree.column("status", width=80, anchor="center")
            self.table_tree.column("timestamp", width=150, anchor="center")
            self.table_tree.column("hop_history", width=140, anchor="w")
            self.table_tree.column("reason", width=160, anchor="w")
            self.table_tree.column("next_hop", width=80, anchor="center")
            self.table_tree.column("forwarded_to_ns", width=110, anchor="center")

            buf = getattr(node, "buffer", [])
            try:
                iterator = list(buf)
            except TypeError:
                iterator = []

            for entry in iterator:
                pkt = entry.get("packet", "")
                pkt_str = repr(pkt)
                if len(pkt_str) > 40:
                    pkt_str = pkt_str[:37] + "..."

                src = entry.get("source", "")
                dest = entry.get("destination", "")
                status = entry.get("status", "")
                ts = entry.get("timestamp", "")

                hop_history = entry.get("hop_history", [])
                if isinstance(hop_history, (list, tuple, set)):
                    hop_str = " → ".join(str(h) for h in hop_history)
                else:
                    hop_str = str(hop_history)

                reason = entry.get("reason", "")
                nh = entry.get("next_hop", "")

                fwd = entry.get("forwarded_to_ns", "")
                if isinstance(fwd, bool):
                    fwd_str = "Yes" if fwd else "No"
                else:
                    fwd_str = str(fwd)

                rows.append(
                    (
                        pkt_str,
                        src,
                        dest,
                        status,
                        ts,
                        hop_str,
                        reason,
                        nh,
                        fwd_str,
                    )
                )

        elif mode == "LOGS":
            cols = ("timestamp", "message")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("timestamp", width=170, anchor="center")
            self.table_tree.column("message", width=320, anchor="w")

            logs = getattr(node, "logs", [])
            for entry in logs:
                ts = entry.get("timestamp", "")
                msg = entry.get("message", "")
                rows.append((ts, msg))

        elif mode == "REGISTRY":
            cols = ("name", "info")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("name", width=260, anchor="w")
            self.table_tree.column("info", width=240, anchor="w")

            reg = getattr(node, "registry", getattr(node, "registered_nodes", {}))
            if reg is None:
                reg = {}
            if isinstance(reg, dict):
                for name, info in reg.items():
                    rows.append((name, str(info)))
            else:
                rows.append(("Registry", str(reg)))

        # alternating row colors
        for idx, row in enumerate(rows):
            tag = "odd" if idx % 2 else "even"
            self.table_tree.insert("", "end", values=row, tags=(tag,))

        self.table_tree.tag_configure("even", background="#ffffff")
        self.table_tree.tag_configure("odd", background="#f5f5f5")

    # nodes
    def _populate_filters(self):
        by_domain = {}
        for n in self.controller.nodes.values():
            for d in _get_node_domains(n):
                by_domain.setdefault(d, []).append(n)

        for child in self.filters_frame.winfo_children():
            child.destroy()

        self.node_buttons = {}

        for domain, nodes in sorted(by_domain.items(), key=lambda kv: kv[0]):
            box = tk.LabelFrame(
                self.filters_frame,
                text=domain,
                bg="#e0e0e0",
                fg="black",
                padx=8,
                pady=8,
            )
            box.pack(fill="x", padx=4, pady=6)

            # select all / clear
            row = tk.Frame(box, bg="#e0e0e0")
            row.pack(fill="x", pady=(0, 6))
            ttk.Button(row, text="Select all", command=lambda ns=nodes: self._select_nodes(ns)).pack(
                side="left"
            )
            ttk.Button(row, text="Clear", command=lambda ns=nodes: self._deselect_nodes(ns)).pack(
                side="left", padx=6
            )

            # node buttons
            for n in sorted(nodes, key=lambda x: _get_node_name(x).lower()):
                name = _get_node_name(n)
                btn = tk.Button(
                    box,
                    text=name,
                    bg="white",
                    fg="black",
                    activebackground="#f0f0f0",
                    activeforeground="black",
                    relief="flat",
                    padx=10,
                    pady=6,
                    bd=1,
                    highlightthickness=1,
                    highlightbackground="#000000",
                )
                btn.pack(fill="x", pady=3)
                self.node_buttons[name] = btn

                def _toggle(ev=None, nm=name, b=btn):
                    if nm in self.selected_nodes:
                        self.selected_nodes.remove(nm)
                    else:
                        self.selected_nodes.add(nm)
                    self._update_button_styles()
                    self.refresh()
                    self._update_node_table()

                btn.bind("<Button-1>", _toggle)

        # reset selection
        bottom = tk.Frame(self.filters_frame, bg="#e0e0e0")
        bottom.pack(fill="x", pady=10)
        ttk.Button(bottom, text="Reset selection", command=self._reset_selection).pack(
            side="left"
        )

        self._update_button_styles()

    def _select_nodes(self, nodes):
        for n in nodes:
            self.selected_nodes.add(_get_node_name(n))
        self._update_button_styles()
        self.refresh()
        self._update_node_table()

    def _deselect_nodes(self, nodes):
        for n in nodes:
            self.selected_nodes.discard(_get_node_name(n))
        self._update_button_styles()
        self.refresh()
        self._update_node_table()

    def _reset_selection(self):
        self.selected_nodes.clear()
        self._update_button_styles()
        self.refresh()
        self._update_node_table()

    def _update_button_styles(self):
        for name, btn in self.node_buttons.items():
            if name in self.selected_nodes:
                btn.configure(
                    bg="black",
                    fg="white",
                    activebackground="#333333",
                    activeforeground="white",
                    relief="raised",
                    bd=2,
                    highlightbackground="#000000",
                )
            else:
                btn.configure(
                    bg="white",
                    fg="black",
                    activebackground="#f0f0f0",
                    activeforeground="black",
                    relief="flat",
                    bd=1,
                    highlightbackground="#000000",
                )

    # refresh logs
    def _collect_logs(self):
        selected = self.selected_nodes
        logs = []

        # node logs
        for n in self.controller.nodes.values():
            nm = _get_node_name(n)
            if selected and nm not in selected:
                continue
            entries = getattr(n, "logs", [])
            for e in entries:
                ts = e.get("timestamp", "")
                msg = e.get("message", "").strip()
                if not msg:
                    continue
                logs.append((ts, f"[{nm}] {msg}"))

        # command logs
        logs.extend(self.command_entries)

        # sort by timestamp
        logs.sort(key=lambda t: _parse_ts(t[0]))
        return logs

    def _clear_logs_view(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def refresh(self):
        logs = self._collect_logs()
        self._clear_logs_view()
        self.log_text.configure(state="normal")
        self.log_text.tag_configure("divider", foreground="#888888")

        last_was_cmd = False
        for ts, line in logs:
            if line.startswith("[CMD]") and not last_was_cmd:
                self.log_text.insert(
                    "end", "------------------------------\n", ("divider",)
                )
            self.log_text.insert("end", f"[{ts}] {line}\n")
            last_was_cmd = line.startswith("[CMD]") or line.startswith("[CMD-OUT]")

        # highlight search
        term = self.search_term.get().strip()
        self.log_text.tag_remove("match", "1.0", "end")
        if term:
            pattern = re.escape(term)
            start = "1.0"
            while True:
                idx = self.log_text.search(
                    pattern, start, nocase=True, stopindex="end", regexp=False
                )
                if not idx:
                    break
                end = f"{idx}+{len(term)}c"
                self.log_text.tag_add("match", idx, end)
                start = end

        # auto scroll
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _refresh_tick(self):
        if self.auto_refresh.get():
            self.refresh()
            self._update_node_table()
        self.root.after(800, self._refresh_tick)

    def _start_refresh_loop(self):
        self.root.after(800, self._refresh_tick)

    # commands
    def _send_command(self):
        raw = self.footer_box.get("1.0", "end-1c").strip()
        if not raw:
            return
        self.footer_box.delete("1.0", "end")

        for line in [ln.strip() for ln in raw.splitlines() if ln.strip()]:
            buf = io.StringIO()
            old = sys.stdout
            try:
                sys.stdout = buf
                try:
                    self.controller.process_command(line)
                except Exception as e:
                    print(f"[GUI] Error: {e}")
            finally:
                sys.stdout = old
            out = buf.getvalue().strip()
            ts = datetime.now().strftime(TS_FMT)
            self.command_entries.append((ts, f"[CMD] {line}"))
            if out:
                for ol in out.splitlines():
                    self.command_entries.append((ts, f"[CMD-OUT] {ol}"))
        self.refresh()

    def run(self):
        self.refresh()
        self._update_node_table()
        self.root.mainloop()


# just for testing
if __name__ == "__main__":
    class DummyNode:
        def __init__(self, name):
            self.name = name
            self.logs = []
            self.fib = {}
            self.cs = {}
            self.pit = {}
            self.neighbor_table = {}
            self.buffer = []

        def add(self, msg, ts):
            self.logs.append({"timestamp": ts, "message": msg})

    class DummyController:
        def __init__(self, nodes):
            self.nodes = {n.name: n for n in nodes}

    a = DummyNode("/DLSU/Andrew")
    g = DummyNode("/DLSU/Gokongwei")
    r = DummyNode("/DLSU/Router1 /ADMU/Router1")
    a.add("Sent INTEREST to 5003", "2025-10-19 23:11:19.000000")
    g.add(
        "Added /DLSU/Gokongwei/hello.txt to PIT with interfaces: [5002]",
        "2025-10-19 23:11:20.100000",
    )
    g.add(
        "Data found in CS for /DLSU/Gokongwei/hello.txt, sending DATA back to ('127.0.0.1', 5002)",
        "2025-10-19 23:11:20.300000",
    )
    r.add("Forwarded ROUTING_DATA to PIT port 5002", "2025-10-19 23:11:20.400000")

    a.fib["/DLSU/Andrew/PC1"] = {
        "NextHops": 5001,
        "HopCount": 1,
        "ExpirationTime": 5000,
    }
    a.cs["/DLSU/Andrew/data.txt"] = "Sample payload for Andrew"
    a.pit["/DLSU/Andrew/request.txt"] = [5002, 5003]
    a.neighbor_table["/DLSU/Gokongwei"] = "2025-10-19 23:11:18.000000"
    a.buffer.append({
        "packet": b"\x10\x01...",
        "source": "/DLSU/Andrew",
        "destination": "/UP/Salcedo/PC1/status.txt",
        "status": "waiting",
        "timestamp": "2025-10-19 23:11:25.000000",
        "hop_history": [5002, 5005],
        "reason": "No FIB route available",
        "next_hop": "",
        "forwarded_to_ns": False,
    })

    ctrl = DummyController([a, g, r])
    LogGUI(ctrl).run()
