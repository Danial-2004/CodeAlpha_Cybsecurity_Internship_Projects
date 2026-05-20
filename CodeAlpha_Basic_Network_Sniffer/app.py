import csv
import threading
import time
from collections import Counter
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from scapy.all import sniff, conf, wrpcap
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.packet import Raw
except Exception as e:
    raise SystemExit(
        "Scapy is required. Install dependencies with: pip install -r requirements.txt\n"
        f"Original import error: {e}"
    )


class PacketSnifferGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CodeAlpha - Basic Network Sniffer")
        self.root.geometry("1280x780")
        self.root.minsize(1100, 700)

        self.captured_packets = []
        self.displayed_indices = []
        self.packet_counter = 0
        self.protocol_counter = Counter()
        self.capture_thread = None
        self.stop_sniff = threading.Event()
        self.running = False
        self.start_time = None

        self._configure_style()
        self._build_header()
        self._build_controls()
        self._build_main_area()
        self._build_status_bar()
        self._populate_interfaces()
        self._schedule_ui_refresh()

    def _configure_style(self):
        self.root.configure(bg="#0f172a")
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        bg = "#0f172a"
        panel = "#111827"
        card = "#1e293b"
        accent = "#38bdf8"
        text = "#e5e7eb"
        muted = "#94a3b8"

        style.configure("TFrame", background=bg)
        style.configure("Card.TFrame", background=panel)
        style.configure("Header.TLabel", background=bg, foreground=text, font=("Segoe UI", 22, "bold"))
        style.configure("SubHeader.TLabel", background=bg, foreground=muted, font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background=panel, foreground=text, font=("Segoe UI", 11, "bold"))
        style.configure("CardText.TLabel", background=panel, foreground=muted, font=("Segoe UI", 10))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.map("Accent.TButton", background=[("active", accent)])
        style.configure("TLabel", background=bg, foreground=text, font=("Segoe UI", 10))
        style.configure("TEntry", padding=6)
        style.configure("TCombobox", padding=4)
        style.configure("Treeview",
                        background="#0b1220",
                        foreground="#e5e7eb",
                        fieldbackground="#0b1220",
                        rowheight=28,
                        bordercolor=card,
                        borderwidth=0,
                        font=("Consolas", 10))
        style.configure("Treeview.Heading",
                        background=card,
                        foreground="#f8fafc",
                        relief="flat",
                        font=("Segoe UI", 10, "bold"))
        style.map("Treeview",
                  background=[("selected", "#1d4ed8")],
                  foreground=[("selected", "#ffffff")])
        style.configure("Status.TLabel", background="#020617", foreground="#cbd5e1", font=("Segoe UI", 10))

    def _build_header(self):
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=16, pady=(14, 6))
        ttk.Label(header, text="Basic Network Sniffer", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Capture packets, inspect protocols, and export findings for CodeAlpha cybersecurity task.",
            style="SubHeader.TLabel",
        ).pack(anchor="w", pady=(2, 0))

    def _build_controls(self):
        controls = ttk.Frame(self.root, style="Card.TFrame", padding=14)
        controls.pack(fill="x", padx=16, pady=10)

        ttk.Label(controls, text="Interface:", style="CardText.TLabel").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_box = ttk.Combobox(controls, textvariable=self.interface_var, state="readonly", width=28)
        self.interface_box.grid(row=0, column=1, padx=6, pady=6, sticky="w")

        ttk.Label(controls, text="Protocol Filter:", style="CardText.TLabel").grid(row=0, column=2, padx=6, pady=6, sticky="w")
        self.filter_var = tk.StringVar(value="ALL")
        self.filter_box = ttk.Combobox(
            controls,
            textvariable=self.filter_var,
            state="readonly",
            values=["ALL", "TCP", "UDP", "ICMP", "ARP", "HTTP-like"],
            width=15,
        )
        self.filter_box.grid(row=0, column=3, padx=6, pady=6, sticky="w")

        ttk.Label(controls, text="Search IP / Port:", style="CardText.TLabel").grid(row=0, column=4, padx=6, pady=6, sticky="w")
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(controls, textvariable=self.search_var, width=24)
        self.search_entry.grid(row=0, column=5, padx=6, pady=6, sticky="w")
        self.search_var.trace_add("write", lambda *_: self.refresh_packet_table())
        self.filter_var.trace_add("write", lambda *_: self.refresh_packet_table())

        self.start_btn = ttk.Button(controls, text="Start Capture", command=self.start_capture, style="Accent.TButton")
        self.start_btn.grid(row=0, column=6, padx=6, pady=6)
        self.stop_btn = ttk.Button(controls, text="Stop", command=self.stop_capture)
        self.stop_btn.grid(row=0, column=7, padx=6, pady=6)
        self.clear_btn = ttk.Button(controls, text="Clear", command=self.clear_packets)
        self.clear_btn.grid(row=0, column=8, padx=6, pady=6)
        self.export_csv_btn = ttk.Button(controls, text="Export CSV", command=self.export_csv)
        self.export_csv_btn.grid(row=0, column=9, padx=6, pady=6)
        self.export_pcap_btn = ttk.Button(controls, text="Export PCAP", command=self.export_pcap)
        self.export_pcap_btn.grid(row=0, column=10, padx=6, pady=6)

        for i in range(11):
            controls.grid_columnconfigure(i, weight=0)
        controls.grid_columnconfigure(11, weight=1)

    def _build_main_area(self):
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=16, pady=(0, 10))
        main.grid_columnconfigure(0, weight=3)
        main.grid_columnconfigure(1, weight=2)
        main.grid_rowconfigure(1, weight=1)

        stats = ttk.Frame(main)
        stats.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        stats.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.cards = {}
        card_data = [
            ("Packets", "0"),
            ("Top Protocol", "-"),
            ("Duration", "00:00:00"),
            ("Status", "Idle"),
        ]
        for idx, (title, value) in enumerate(card_data):
            frame = ttk.Frame(stats, style="Card.TFrame", padding=14)
            frame.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 8, 0))
            ttk.Label(frame, text=title, style="CardText.TLabel").pack(anchor="w")
            lbl = ttk.Label(frame, text=value, style="CardTitle.TLabel", font=("Segoe UI", 18, "bold"))
            lbl.pack(anchor="w", pady=(8, 0))
            self.cards[title] = lbl

        left = ttk.Frame(main, style="Card.TFrame", padding=10)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        ttk.Label(left, text="Captured Packets", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))

        columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        for col, width in {
            "No": 60,
            "Time": 110,
            "Source": 170,
            "Destination": 170,
            "Protocol": 90,
            "Length": 80,
            "Info": 350,
        }.items():
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")
        self.tree.grid(row=1, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self.show_packet_details)

        yscroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        yscroll.grid(row=1, column=1, sticky="ns")

        right = ttk.Frame(main, style="Card.TFrame", padding=10)
        right.grid(row=1, column=1, sticky="nsew")
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        ttk.Label(right, text="Packet Details", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.details = tk.Text(
            right,
            wrap="word",
            bg="#020617",
            fg="#e5e7eb",
            insertbackground="#e5e7eb",
            relief="flat",
            font=("Consolas", 10),
            padx=10,
            pady=10,
        )
        self.details.grid(row=1, column=0, sticky="nsew")

        self.status_chart = tk.Text(
            right,
            wrap="word",
            height=8,
            bg="#0b1220",
            fg="#93c5fd",
            relief="flat",
            font=("Consolas", 10),
            padx=10,
            pady=10,
        )
        self.status_chart.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        self.status_chart.insert("1.0", "Protocol distribution will appear here.")
        self.status_chart.config(state="disabled")

    def _build_status_bar(self):
        bar = ttk.Frame(self.root, padding=(12, 8), style="Card.TFrame")
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready. Select an interface and start capture.")
        ttk.Label(bar, textvariable=self.status_var, style="Status.TLabel").pack(anchor="w")

    def _populate_interfaces(self):
        interfaces = list(conf.ifaces.data.keys())
        if not interfaces:
            interfaces = [conf.iface]
        self.interface_box["values"] = interfaces
        if interfaces:
            default = conf.iface if conf.iface in interfaces else interfaces[0]
            self.interface_var.set(default)

    def _schedule_ui_refresh(self):
        self.update_stats()
        self.root.after(1000, self._schedule_ui_refresh)

    def start_capture(self):
        if self.running:
            messagebox.showinfo("Capture running", "Packet capture is already running.")
            return
        interface = self.interface_var.get().strip()
        if not interface:
            messagebox.showwarning("Missing interface", "Please select a network interface.")
            return

        self.running = True
        self.stop_sniff.clear()
        self.start_time = time.time()
        self.status_var.set(f"Capturing packets on {interface}...")
        self.cards["Status"].config(text="Running")

        self.capture_thread = threading.Thread(target=self._sniff_packets, args=(interface,), daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        if not self.running:
            self.status_var.set("Capture already stopped.")
            return
        self.stop_sniff.set()
        self.running = False
        self.cards["Status"].config(text="Stopped")
        self.status_var.set("Stopping capture...")

    def clear_packets(self):
        if self.running:
            if not messagebox.askyesno("Capture active", "Stop capture and clear all packets?"):
                return
            self.stop_capture()
        self.captured_packets.clear()
        self.displayed_indices.clear()
        self.packet_counter = 0
        self.protocol_counter.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.details.delete("1.0", tk.END)
        self.status_var.set("Cleared all captured packets.")
        self.update_protocol_chart()
        self.update_stats()

    def _sniff_packets(self, interface: str):
        def packet_handler(packet):
            if self.stop_sniff.is_set():
                return False
            self.handle_packet(packet)

        try:
            sniff(
                iface=interface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: self.stop_sniff.is_set(),
            )
        except PermissionError:
            self.running = False
            self.root.after(0, lambda: messagebox.showerror(
                "Permission error",
                "Packet capture requires elevated privileges.\nRun the app as administrator/root."
            ))
            self.root.after(0, lambda: self.status_var.set("Permission denied while starting packet capture."))
        except OSError as e:
            self.running = False
            self.root.after(0, lambda: messagebox.showerror("Capture error", str(e)))
            self.root.after(0, lambda: self.status_var.set(f"Capture error: {e}"))
        finally:
            self.running = False
            self.root.after(0, lambda: self.cards["Status"].config(text="Stopped"))
            self.root.after(0, lambda: self.status_var.set("Capture stopped."))

    def handle_packet(self, packet):
        packet_info = self.extract_packet_info(packet)
        self.captured_packets.append((packet, packet_info))
        self.packet_counter += 1
        self.protocol_counter[packet_info["protocol"]] += 1
        self.root.after(0, self.refresh_packet_table)

    def extract_packet_info(self, packet):
        timestamp = datetime.now().strftime("%H:%M:%S")
        src = "-"
        dst = "-"
        protocol = "OTHER"
        length = len(packet)
        info = packet.summary()
        src_port = ""
        dst_port = ""
        payload_preview = ""

        if packet.haslayer(Ether):
            src = getattr(packet[Ether], "src", src)
            dst = getattr(packet[Ether], "dst", dst)

        if packet.haslayer(ARP):
            protocol = "ARP"
            src = getattr(packet[ARP], "psrc", src)
            dst = getattr(packet[ARP], "pdst", dst)
            info = f"ARP {getattr(packet[ARP], 'op', '')} {src} -> {dst}"

        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            proto_num = packet[IP].proto
            protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, f"IP/{proto_num}")

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = str(packet[TCP].sport)
            dst_port = str(packet[TCP].dport)
            flags = packet[TCP].flags
            info = f"TCP {src}:{src_port} → {dst}:{dst_port} Flags={flags}"
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = str(packet[UDP].sport)
            dst_port = str(packet[UDP].dport)
            info = f"UDP {src}:{src_port} → {dst}:{dst_port}"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            icmp_type = getattr(packet[ICMP], 'type', '?')
            icmp_code = getattr(packet[ICMP], 'code', '?')
            info = f"ICMP {src} → {dst} Type={icmp_type} Code={icmp_code}"

        if packet.haslayer(Raw):
            raw_data = bytes(packet[Raw].load)
            payload_preview = raw_data[:80].decode(errors="replace")
            if b"HTTP" in raw_data or b"GET " in raw_data or b"POST " in raw_data:
                protocol = "HTTP-like"
                info = f"HTTP-like payload {src}:{src_port} → {dst}:{dst_port}"

        return {
            "no": self.packet_counter + 1,
            "time": timestamp,
            "source": src,
            "destination": dst,
            "protocol": protocol,
            "length": length,
            "info": info,
            "src_port": src_port,
            "dst_port": dst_port,
            "payload_preview": payload_preview,
        }

    def refresh_packet_table(self):
        selected_filter = self.filter_var.get().strip().upper()
        search = self.search_var.get().strip().lower()

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.displayed_indices.clear()

        for idx, (_, info) in enumerate(self.captured_packets):
            protocol_match = selected_filter == "ALL" or info["protocol"].upper() == selected_filter
            searchable = f"{info['source']} {info['destination']} {info['src_port']} {info['dst_port']} {info['info']}".lower()
            search_match = not search or search in searchable
            if protocol_match and search_match:
                self.displayed_indices.append(idx)
                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        info["no"],
                        info["time"],
                        info["source"],
                        info["destination"],
                        info["protocol"],
                        info["length"],
                        info["info"],
                    ),
                )
        self.update_protocol_chart()
        self.update_stats()

    def show_packet_details(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        row_index = self.tree.index(selection[0])
        packet_index = self.displayed_indices[row_index]
        packet, info = self.captured_packets[packet_index]

        detail_text = [
            f"Packet Number : {info['no']}",
            f"Captured Time : {info['time']}",
            f"Source        : {info['source']}",
            f"Destination   : {info['destination']}",
            f"Protocol      : {info['protocol']}",
            f"Length        : {info['length']} bytes",
            f"Source Port   : {info['src_port'] or '-'}",
            f"Dest. Port    : {info['dst_port'] or '-'}",
            "",
            "Payload Preview:",
            info['payload_preview'] or "(No printable raw payload preview)",
            "",
            "Scapy Summary:",
            packet.summary(),
            "",
            "Detailed Layers:",
        ]

        try:
            detail_text.append(packet.show(dump=True))
        except Exception as e:
            detail_text.append(f"Unable to render packet details: {e}")

        self.details.delete("1.0", tk.END)
        self.details.insert("1.0", "\n".join(detail_text))

    def update_protocol_chart(self):
        self.status_chart.config(state="normal")
        self.status_chart.delete("1.0", tk.END)
        if not self.protocol_counter:
            self.status_chart.insert("1.0", "Protocol distribution will appear here.")
            self.status_chart.config(state="disabled")
            return

        lines = ["Protocol Distribution\n" + "-" * 26]
        total = sum(self.protocol_counter.values())
        for proto, count in self.protocol_counter.most_common():
            bar = "█" * max(1, int((count / total) * 30))
            lines.append(f"{proto:<10} {count:>4}  {bar}")
        self.status_chart.insert("1.0", "\n".join(lines))
        self.status_chart.config(state="disabled")

    def update_stats(self):
        self.cards["Packets"].config(text=str(self.packet_counter))
        top_protocol = self.protocol_counter.most_common(1)[0][0] if self.protocol_counter else "-"
        self.cards["Top Protocol"].config(text=top_protocol)
        duration = 0
        if self.start_time:
            duration = int(time.time() - self.start_time) if self.running else int(max(0, time.time() - self.start_time))
        self.cards["Duration"].config(text=time.strftime("%H:%M:%S", time.gmtime(duration)))
        if not self.running and self.packet_counter == 0:
            self.cards["Status"].config(text="Idle")

    def export_csv(self):
        if not self.captured_packets:
            messagebox.showinfo("No data", "No packets available to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Save packet analysis as CSV",
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["No", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Payload Preview"])
            for _, info in self.captured_packets:
                writer.writerow([
                    info["no"], info["time"], info["source"], info["destination"],
                    info["protocol"], info["length"], info["info"], info["payload_preview"]
                ])
        self.status_var.set(f"Exported packet summary to {path}")

    def export_pcap(self):
        if not self.captured_packets:
            messagebox.showinfo("No data", "No packets available to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP Files", "*.pcap")],
            title="Save captured packets as PCAP",
        )
        if not path:
            return
        wrpcap(path, [pkt for pkt, _ in self.captured_packets])
        self.status_var.set(f"Exported PCAP to {path}")


def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
