import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Toplevel
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.ticker as mticker  # ✅ "K" formatting for large numbers
import numpy as np
from database.database import get_packets_by_timeframe, fetch_top_active_ips  # ✅ Import database functions


def show_top_active_ips():
    top_ips = fetch_top_active_ips(5)
    
    if not top_ips:
        return
    
    # Create popup window
    popup = tk.Toplevel()
    popup.title("Top 5 Active IPs")
    
    # Create table
    tree = ttk.Treeview(popup, columns=("IP Address", "Packet Count"), show="headings")
    tree.heading("IP Address", text="IP Address")
    tree.heading("Packet Count", text="Packet Count")
    tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # Insert data into table
    for ip, packet_count in top_ips:
        tree.insert("", tk.END, values=(ip, packet_count))
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

    # ✅ Filters (Timeframe & Protocol Selection)
    filter_frame = ttk.Frame(frame)
    filter_frame.pack(fill=tk.X, padx=5, pady=5)

    ttk.Label(filter_frame, text="📅 View Packets:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
    timeframe_var = tk.StringVar(value="All-Time")  # ✅ Default view is Weekly
    timeframe_dropdown = ttk.Combobox(filter_frame, textvariable=timeframe_var, values=["Daily", "Weekly", "Monthly", "All-Time"])
    timeframe_dropdown.pack(side=tk.LEFT, padx=5)

    ttk.Label(filter_frame, text="🛠 Protocol:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
    protocol_var = tk.StringVar(value="All")
    protocol_dropdown = ttk.Combobox(filter_frame, textvariable=protocol_var, values=["All", "TCP", "UDP", "ICMP"])
    protocol_dropdown.pack(side=tk.LEFT, padx=5)


  # ✅ Summary Section (Total Packets & Packets Per Second)
    summary_frame = ttk.Frame(frame)
    summary_frame.pack(fill=tk.X, padx=5, pady=5)

    packet_summary_label = ttk.Label(summary_frame, text="Total Packets: 0", font=("Arial", 10, "bold"))
    packet_summary_label.pack(side=tk.LEFT, padx=5)

    pps_label = ttk.Label(summary_frame, text=" | Packets Per Second: 0", font=("Arial", 10, "bold"))
    pps_label.pack(side=tk.LEFT, padx=5)
    
        
        # ✅ Table & IP Activity Section
    data_container = ttk.Frame(frame)
    data_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # ✅ Packets Table
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
    
   
    
    show_ips_button = ttk.Button(frame, text="Show Top Active IPs", command=show_top_active_ips)
    show_ips_button.pack(pady=10)

    # ✅ Graph - Grouped Bar Chart
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
        return f"{x / 1000:.1f}K" if x >= 1000 else str(int(x))

    def compute_moving_average(data, window_size=3):
        """Computes moving average over a window."""
        return np.convolve(data, np.ones(window_size) / window_size, mode='valid').tolist() if len(data) >= window_size else data
    
        # ✅ Track previous packet count to calculate PPS
    last_packet_count = [0]

    def update_packets():
        """Fetch and update packet data in the table and grouped bar chart."""
        packet_tree.delete(*packet_tree.get_children())  # Clear table
        packets = get_packets_by_timeframe(timeframe_var.get().lower())

        if packets:
            dates = sorted(set(entry[0] for entry in packets))  # Unique dates
            protocol_counts = {protocol: [0] * len(dates) for protocol in PROTOCOL_COLORS}

            for timestamp, src_ip, dest_ip, protocol, length in packets:
                protocol = protocol if protocol in PROTOCOL_COLORS else "Other"
                protocol_counts[protocol][dates.index(timestamp.split()[0])] += 1

            total_packets = sum(sum(counts) for counts in protocol_counts.values())
            packet_summary_label.config(text=f"Total Packets: {total_packets}")

            # ✅ Correct PPS Calculation
            pps_value = (total_packets - last_packet_count[0]) / (REFRESH_INTERVAL / 1000)
            last_packet_count[0] = total_packets  # Update stored count
            pps_label.config(text=f" | Packets Per Second: {pps_value:.2f}")

            # ✅ Populate Packets Table
            for timestamp, src_ip, dest_ip, protocol, length in packets:
                if protocol_var.get() == "All" or protocol_var.get() == protocol:
                    packet_tree.insert("", tk.END, values=(timestamp, src_ip, dest_ip, protocol, length))

            # ✅ Update Bar Chart
            ax.clear()
            bar_width = 0.2
            x_positions = range(len(dates))

            bars = []  # Store protocol and bar objects
            for i, (protocol, counts) in enumerate(protocol_counts.items()):
                if protocol_var.get() == "All" or protocol_var.get() == protocol:
                    bar_objects = ax.bar([x + i * bar_width for x in x_positions], counts,
                                        width=bar_width, label=protocol, color=PROTOCOL_COLORS[protocol])
                    bars.append((protocol, bar_objects))  # Store protocol and bar objects

            ax.set_xticks([x + bar_width for x in x_positions])
            ax.set_xticklabels(dates, rotation=45)
            ax.set_title(f"Packet Distribution Over Time ({timeframe_var.get()})")
            ax.set_ylabel("Packet Count")
            ax.legend()
            ax.yaxis.set_major_formatter(mticker.FuncFormatter(format_large_numbers))  # ✅ Apply 'K' format

            # ✅ Compute Moving Average for Total Packets Over Time
            total_packets_per_day = [sum(counts) for counts in zip(*protocol_counts.values())]
            moving_avg = compute_moving_average(total_packets_per_day, window_size=3)

            # ✅ Plot Moving Average Line
            ax.plot(range(1, len(moving_avg) + 1), moving_avg, marker="o",
                    linestyle="-", color="black", linewidth=2, label="Moving Avg")

            ax.legend()
            canvas.draw()

        # ✅ Ensure only ONE instance of update_packets() is scheduled
        frame.after(REFRESH_INTERVAL, update_packets)


        # ✅ Move Hover Function Outside of update_packets()
        def on_hover(event):
            """Displays protocol details on hover."""
            if event.inaxes == ax:
                for protocol, bar_set in bars:
                    for rect in bar_set:
                        if rect.contains(event)[0]:
                            tooltip_label.config(text=f"{protocol}: {int(rect.get_height())} packets")
                            tooltip_label.place(x=event.x + 10, y=event.y - 20)
                            return
            tooltip_label.place_forget()  # Hide tooltip if not hovering over a bar


        # ✅ Ensure on_hover() is only attached once
        canvas.mpl_connect("motion_notify_event", on_hover)

  
            
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
        

    timeframe_dropdown.bind("<<ComboboxSelected>>", lambda event: update_packets())
    protocol_dropdown.bind("<<ComboboxSelected>>", lambda event: update_packets())

    update_packets()  # Initial Load

    return frame
