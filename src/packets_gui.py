import tkinter as tk
from tkinter import ttk
from database.database import get_packets
from tkcalendar import DateEntry  # Install with: pip install tkcalendar

# Refresh interval (5 seconds)
REFRESH_INTERVAL = 5000  

def create_packets_tab(parent):
    """Creates the Packets GUI tab with a table and export functionality."""
    frame = ttk.Frame(parent, padding=10)

    # ✅ Title Label
    ttk.Label(frame, text="📡 Captured Packets", font=("Arial", 14, "bold")).pack(pady=5)

    # ✅ Table Frame with Scrollbars
    table_frame = ttk.Frame(frame)
    table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    columns = ("Timestamp", "Source IP", "Destination IP", "Protocol", "Length")
    packet_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=10)

    for col in columns:
        packet_tree.heading(col, text=col, anchor=tk.W)
        packet_tree.column(col, width=150 if col == "Timestamp" else 120, anchor=tk.W)

    v_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=packet_tree.yview)
    packet_tree.configure(yscrollcommand=v_scroll.set)
    v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    packet_tree.pack(fill=tk.BOTH, expand=True)

    # ✅ Refresh Function
    def update_packets():
        """Fetch and update packet data in the table."""
        packet_tree.delete(*packet_tree.get_children())  # Clear table
        packets = get_packets()  # Fetch packets from database

        for timestamp, src_ip, dst_ip, protocol, length in packets:
            packet_tree.insert("", tk.END, values=(timestamp, src_ip, dst_ip, protocol, length))

        frame.after(REFRESH_INTERVAL, update_packets)  # Auto-refresh every 5s

    # ✅ Export Function
    def export_packets():
        """Exports packet data to a CSV file."""
        from tkinter import filedialog
        import csv

        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not file_path:
            return

        with open(file_path, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(columns)  # Write headers
            for row in packet_tree.get_children():
                writer.writerow(packet_tree.item(row)["values"])

        tk.messagebox.showinfo("Export Successful", f"Packets exported to {file_path}")

    # ✅ Buttons for Refresh & Export
    button_frame = ttk.Frame(frame)
    button_frame.pack(pady=5)

    ttk.Button(button_frame, text="Refresh Now", command=update_packets).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="Export to CSV", command=export_packets).pack(side=tk.LEFT, padx=5)

    # Initial Load
    update_packets()

    return frame
