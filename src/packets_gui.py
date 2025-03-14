import tkinter as tk
from tkinter import ttk, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.ticker as mticker  # ✅ For "K" number formatting
import numpy as np
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
    ttk.Label(frame, text="📡 Packet Traffic Overview",
              font=("Arial", 14, "bold")).pack(pady=5)

    # ✅ Filter Frame (Timeframe Selection & Protocol Filter)
    filter_frame = ttk.Frame(frame)
    filter_frame.pack(fill=tk.X, padx=5, pady=5)

    ttk.Label(filter_frame, text="📅 View Packets:",
              font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
    timeframe_var = tk.StringVar(value="Weekly")  # ✅ Default view is Weekly
    timeframe_dropdown = ttk.Combobox(filter_frame, textvariable=timeframe_var, values=[
                                      "Daily", "Weekly", "Monthly", "All-Time"])
    timeframe_dropdown.pack(side=tk.LEFT, padx=5)

    ttk.Label(filter_frame, text="🛠 Protocol:", font=(
        "Arial", 10)).pack(side=tk.LEFT, padx=5)
    protocol_var = tk.StringVar(value="All")
    protocol_dropdown = ttk.Combobox(
        filter_frame, textvariable=protocol_var, values=["All", "TCP", "UDP", "ICMP"])
    protocol_dropdown.pack(side=tk.LEFT, padx=5)

    # ✅ Total Packets Summary
    packet_summary_label = ttk.Label(
        frame, text="Total Packets: 0", font=("Arial", 10, "bold"))
    packet_summary_label.pack(pady=5)

    # ✅ Table for Packets
    table_frame = ttk.Frame(frame)
    table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    columns = ("Timestamp", "Source IP",
               "Destination IP", "Protocol", "Length")
    packet_tree = ttk.Treeview(
        table_frame, columns=columns, show="headings", height=8)

    for col in columns:
        packet_tree.heading(col, text=col, anchor=tk.W)
        packet_tree.column(col, width=120 if col in [
                           "Timestamp", "Protocol"] else 180, anchor=tk.W)

    v_scroll = ttk.Scrollbar(
        table_frame, orient="vertical", command=packet_tree.yview)
    packet_tree.configure(yscrollcommand=v_scroll.set)
    v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    packet_tree.pack(fill=tk.BOTH, expand=True)
    
    # ✅ IP Activity Frame
    ip_activity_frame = ttk.LabelFrame(frame, text="Top 5 Active IPs")
    ip_activity_frame.pack(fill=tk.X, padx=2.5, pady=2.5)

    ip_tree = ttk.Treeview(ip_activity_frame, columns=(
        "IP", "Packets"), show="headings", height=5)  # Increased height for resizing
    ip_tree.heading("IP", text="IP Address", anchor=tk.W)
    ip_tree.heading("Packets", text="Packet Count", anchor=tk.W)
    ip_tree.column("IP", width=100, anchor=tk.W)  # Adjusted column width
    ip_tree.column("Packets", width=50, anchor=tk.W)  # Adjusted column width
    ip_tree.pack(fill=tk.BOTH, expand=False)
    
    # ✅ Graph Area - Grouped Bar Chart
    graph_frame = ttk.Frame(frame)
    graph_frame.pack(fill="both", expand=True, padx=5, pady=5)

    fig, ax = plt.subplots(figsize=(7, 4))
    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    

    # ✅ Tooltip Label (Hidden by default)
    tooltip_label = tk.Label(graph_frame, bg="yellow",
                             fg="black", relief="solid", borderwidth=1)
    tooltip_label.place_forget()  # Hide tooltip initially

    def format_large_numbers(x, _):
        """Formats numbers into 'K' for thousands (e.g., 1.2K)."""
        if x >= 1000:
            return f"{x / 1000:.1f}K"
        return str(int(x))

    def compute_moving_average(data, window_size=3):
        """
        Compute the moving average for a given list of data.

        Args:
            data (list): List of numerical values.
            window_size (int): Number of points to average over.

        Returns:
            list: Moving average values (same length as input, padded with NaN at start).
        """
        if len(data) < window_size:
            return data  # Not enough data for averaging

        return np.convolve(data, np.ones(window_size)/window_size, mode='valid').tolist()

    def update_packets():
        """Fetch and update packet data in the table and grouped bar chart."""
        packet_tree.delete(*packet_tree.get_children())  # Clear table
        packets = get_packets_by_timeframe(
            timeframe_var.get().lower())  # Fetch packets

        if packets:
            # ✅ Process Data for Visualization
            dates = sorted(set([entry[0]
                           for entry in packets]))  # Unique dates
            # Protocol-wise counts
            protocol_counts = {protocol: [
                0] * len(dates) for protocol in PROTOCOL_COLORS}

            for timestamp, src_ip, dest_ip, protocol, length in packets:
                if protocol not in PROTOCOL_COLORS:
                    protocol = "Other"  # Handle unknown protocols
                protocol_counts[protocol][dates.index(
                    timestamp.split()[0])] += 1  # Count packets per date

            # ✅ Update Total Packets Summary
            total_packets = sum(sum(counts)
                                for counts in protocol_counts.values())
            packet_summary_label.config(text=f"Total Packets: {total_packets}")

            # ✅ Identify Top 5 IPs
            ip_counts = {}
            for _, src_ip, _, _, _ in packets:
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1

            sorted_ips = sorted(ip_counts.items(),
                                key=lambda x: x[1], reverse=True)[:5]

            ip_tree.delete(*ip_tree.get_children())
            for ip, count in sorted_ips:
                ip_tree.insert("", tk.END, values=(ip, count))

            # ✅ Populate Table
            for timestamp, src_ip, dest_ip, protocol, length in packets:
                if protocol_var.get() == "All" or protocol_var.get() == protocol:
                    packet_tree.insert("", tk.END, values=(
                        timestamp, src_ip, dest_ip, protocol, length))

            # ✅ Update Bar Chart
            ax.clear()
            bar_width = 0.2  # Adjust for grouped bars
            x_positions = range(len(dates))

            selected_protocol = protocol_var.get()
            bars = []  # Store bars for hover interaction
            for i, (protocol, counts) in enumerate(protocol_counts.items()):
                if selected_protocol == "All" or selected_protocol == protocol:
                    bar = ax.bar([x + i * bar_width for x in x_positions], counts,
                                 width=bar_width, label=protocol, color=PROTOCOL_COLORS[protocol])
                    bars.append((protocol, bar))

            ax.set_xticks([x + bar_width for x in x_positions])
            ax.set_xticklabels(dates, rotation=45)
            ax.set_title(
                f"Packet Distribution Over Time ({timeframe_var.get()})")
            ax.set_ylabel("Packet Count")
            ax.legend()
            ax.yaxis.set_major_formatter(mticker.FuncFormatter(
                format_large_numbers))  # ✅ Apply 'K' format

            canvas.draw()

            # ✅ Compute Moving Average for Total Packets Over Time
            total_packets_per_day = [sum(counts) for counts in zip(
                *protocol_counts.values())]  # Sum across all protocols
            moving_avg = compute_moving_average(
                total_packets_per_day, window_size=3)  # Smooth data

            # ✅ Plot Moving Average Line
            ax.plot(range(1, len(moving_avg) + 1), moving_avg, marker="o",
                    linestyle="-", color="black", linewidth=2, label="Moving Avg")

            ax.legend()  # Ensure legend is updated

            ax.set_xticks([x + bar_width for x in x_positions])
            ax.set_xticklabels(dates, rotation=45)
            ax.set_title(
                f"Packet Distribution Over Time ({timeframe_var.get()})")
            ax.set_ylabel("Packet Count")

            ax.legend()
            canvas.draw()

            # ✅ Hover Event Handler

            def on_hover(event):
                """Displays protocol details on hover."""
                if event.inaxes == ax:
                    for protocol, bar_set in bars:
                        for rect in bar_set:
                            if rect.contains(event)[0]:
                                tooltip_label.config(
                                    text=f"{protocol}: {int(rect.get_height())} packets")
                                tooltip_label.place(
                                    x=event.x + 10, y=event.y - 20)
                                return
                tooltip_label.place_forget()  # Hide tooltip if not hovering over a bar

            canvas.mpl_connect("motion_notify_event",
                               on_hover)  # Attach hover event

        frame.after(REFRESH_INTERVAL, update_packets)  # Auto-refresh every 5s

    def export_chart():
                """Save the current graph as an image."""
                file_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                         filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg")])
                if file_path:
                    fig.savefig(file_path)
                    tk.messagebox.showinfo(
                        "Export Successful", f"Chart saved to {file_path}")

                    # Add button to UI
    export_button = ttk.Button(
                frame, text="📤 Export Chart", command=export_chart)
    export_button.pack(pady=5)


    # ✅ Export Functionality

    def export_packets():
        """Exports the displayed packet data to a CSV file."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not filename:
            return  # User canceled

        with open(filename, "w") as file:
            file.write("Timestamp,Source IP,Destination IP,Protocol,Length\n")
            for item in packet_tree.get_children():
                file.write(",".join(packet_tree.item(item, "values")) + "\n")

        tk.messagebox.showinfo("Export Successful",
                               f"Packet data saved to {filename}")

    export_button = ttk.Button(
        frame, text="📤 Export Packets", command=export_packets)
    export_button.pack(pady=5)

    # ✅ Bind dropdown selection changes to update the graph
    timeframe_dropdown.bind("<<ComboboxSelected>>",
                            lambda event: update_packets())
    protocol_dropdown.bind("<<ComboboxSelected>>",
                           lambda event: update_packets())

    update_packets()  # Initial Load

    return frame
