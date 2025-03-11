import tkinter as tk
from tkinter import ttk, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from database.database import get_packets_by_timeframe

# Define protocol colors for grouped bar chart
PROTOCOL_COLORS = {
    "TCP": "red",
    "UDP": "green",
    "ICMP": "blue",
    "Other": "gray"
}

REFRESH_INTERVAL = 5000  # Refresh every 5 seconds

def create_packets_tab(parent):
    """Creates the packets GUI tab with table, grouped bar chart, and export functionality."""
    frame = ttk.Frame(parent, padding=10)

    # ✅ Title Label
    ttk.Label(frame, text="📡 Packet Traffic Overview", font=("Arial", 14, "bold")).pack(pady=5)

    # ✅ Filter Frame (Timeframe Selection & Protocol Filter)
    filter_frame = ttk.Frame(frame)
    filter_frame.pack(fill=tk.X, padx=5, pady=5)

    ttk.Label(filter_frame, text="📅 View Packets:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
    timeframe_var = tk.StringVar(value="Daily")
    timeframe_dropdown = ttk.Combobox(filter_frame, textvariable=timeframe_var, values=["Daily", "Weekly", "Monthly", "All-Time"])
    timeframe_dropdown.pack(side=tk.LEFT, padx=5)

    ttk.Label(filter_frame, text="🛠 Protocol:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
    protocol_var = tk.StringVar(value="All")
    protocol_dropdown = ttk.Combobox(filter_frame, textvariable=protocol_var, values=["All", "TCP", "UDP", "ICMP"])
    protocol_dropdown.pack(side=tk.LEFT, padx=5)

    # ✅ Total Packets Summary
    packet_summary_label = ttk.Label(frame, text="Total Packets: 0", font=("Arial", 10, "bold"))
    packet_summary_label.pack(pady=5)

    # ✅ Table for Packets
    table_frame = ttk.Frame(frame)
    table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    columns = ("Timestamp", "Source IP", "Destination IP", "Protocol", "Length")
    packet_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)

    for col in columns:
        packet_tree.heading(col, text=col, anchor=tk.W)
        packet_tree.column(col, width=120 if col in ["Timestamp", "Protocol"] else 180, anchor=tk.W)

    v_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=packet_tree.yview)
    packet_tree.configure(yscrollcommand=v_scroll.set)
    v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    packet_tree.pack(fill=tk.BOTH, expand=True)

    # ✅ Graph Area - Grouped Bar Chart
    graph_frame = ttk.Frame(frame)
    graph_frame.pack(fill="both", expand=True, padx=5, pady=5)

    fig, ax = plt.subplots(figsize=(7, 4))
    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    def update_packets():
        """Fetch and update packet data in the table and grouped bar chart."""
        packet_tree.delete(*packet_tree.get_children())  # Clear table
        packets = get_packets_by_timeframe(timeframe_var.get().lower())  # Fetch packets

        if packets:
            # ✅ Process Data for Visualization
            dates = sorted(set([entry[0] for entry in packets]))  # Unique dates
            protocol_counts = {protocol: [0] * len(dates) for protocol in PROTOCOL_COLORS}  # Protocol-wise counts

            for timestamp, src_ip, dest_ip, protocol, length in packets:
                if protocol not in PROTOCOL_COLORS:
                    protocol = "Other"  # Handle unknown protocols
                protocol_counts[protocol][dates.index(timestamp.split()[0])] += 1  # Count packets per date

            # ✅ Update Total Packets Summary
            total_packets = sum(sum(counts) for counts in protocol_counts.values())
            packet_summary_label.config(text=f"Total Packets: {total_packets}")

            # ✅ Populate Table
            for timestamp, src_ip, dest_ip, protocol, length in packets:
                if protocol_var.get() == "All" or protocol_var.get() == protocol:
                    packet_tree.insert("", tk.END, values=(timestamp, src_ip, dest_ip, protocol, length))

            # ✅ Update Bar Chart
            ax.clear()
            bar_width = 0.2  # Adjust for grouped bars
            x_positions = range(len(dates))

            selected_protocol = protocol_var.get()
            for i, (protocol, counts) in enumerate(protocol_counts.items()):
                if selected_protocol == "All" or selected_protocol == protocol:
                    ax.bar([x + i * bar_width for x in x_positions], counts, width=bar_width, label=protocol, color=PROTOCOL_COLORS[protocol])

            ax.set_xticks([x + bar_width for x in x_positions])
            ax.set_xticklabels(dates, rotation=45)
            ax.set_title(f"Packet Distribution Over Time ({timeframe_var.get()})")
            ax.set_ylabel("Packet Count")
            ax.legend()

        canvas.draw()
        frame.after(REFRESH_INTERVAL, update_packets)  # Auto-refresh every 5s

    # ✅ Export Functionality
    def export_packets():
        """Exports the displayed packet data to a CSV file."""
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not filename:
            return  # User canceled

        with open(filename, "w") as file:
            file.write("Timestamp,Source IP,Destination IP,Protocol,Length\n")
            for item in packet_tree.get_children():
                file.write(",".join(packet_tree.item(item, "values")) + "\n")

        tk.messagebox.showinfo("Export Successful", f"Packet data saved to {filename}")

    export_button = ttk.Button(frame, text="📤 Export Packets", command=export_packets)
    export_button.pack(pady=5)

    # ✅ Bind dropdown selection changes to update the graph
    timeframe_dropdown.bind("<<ComboboxSelected>>", lambda event: update_packets())
    protocol_dropdown.bind("<<ComboboxSelected>>", lambda event: update_packets())

    update_packets()  # Initial Load

    return frame


















