import sqlite3
from tkinter import ttk


def get_device_status_data():
    """Retrieve device status counts for the pie chart."""
    try:
        conn = sqlite3.connect("network_monitoring.db")
        cursor = conn.cursor()
        cursor.execute("SELECT status, COUNT(*) FROM network_devices GROUP BY status")
        data = cursor.fetchall()
        conn.close()
        
        labels = [row[0] for row in data]
        sizes = [row[1] for row in data]
        return labels, sizes
    except sqlite3.Error as e:
        print(f"Error fetching device status data: {e}")
        return [], []

def get_protocol_usage_data():
    """Retrieve protocol usage counts for the bar chart."""
    try:
        conn = sqlite3.connect("network_monitoring.db")
        cursor = conn.cursor()
        cursor.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol")
        data = cursor.fetchall()
        conn.close()
        
        protocols = [row[0] for row in data]
        counts = [row[1] for row in data]
        return protocols, counts
    except sqlite3.Error as e:
        print(f"Error fetching protocol usage data: {e}")
        return [], []

def get_alerts_over_time_data():
    """Retrieve alert counts over time for the line chart."""
    try:
        conn = sqlite3.connect("network_monitoring.db")
        cursor = conn.cursor()
        cursor.execute("SELECT DATE(timestamp), COUNT(*) FROM alerts GROUP BY DATE(timestamp)")
        data = cursor.fetchall()
        conn.close()
        
        timestamps = [row[0] for row in data]
        alert_counts = [row[1] for row in data]
        return timestamps, alert_counts
    except sqlite3.Error as e:
        print(f"Error fetching alert data: {e}")
        return [], []


def get_summary_data():
    """Retrieve counts of devices, packets, and alerts."""
    try:
        conn = sqlite3.connect("network_monitoring.db")
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM network_devices")
        devices_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM packets")
        packets_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts")
        alerts_count = cursor.fetchone()[0]

        conn.close()
        return devices_count, packets_count, alerts_count
    except sqlite3.Error as e:
        print(f"Error retrieving summary data: {e}")
        return 0, 0, 0

REFRESH_INTERVAL = 5000  # Refresh interval in milliseconds

def create_table_view(parent, columns, table_name):
    """Create a styled table view inside a given parent widget."""
    frame = ttk.Frame(parent, padding=10)

    tree = ttk.Treeview(frame, columns=columns, show="headings", height=10, style="info.Treeview")

    # Define column properties
    for col in columns:
        tree.heading(col, text=col, anchor="center")
        tree.column(col, anchor="center", width=100)

    # Apply alternating row colors
    tree.tag_configure("evenrow", background="#636363")  # Light gray
    tree.tag_configure("oddrow", background="#3b3b3b")   # dark grey

    # Fetch data from database
    conn = sqlite3.connect("network_monitoring.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()
    conn.close()

    # Insert data into table
    for i, row in enumerate(rows):
        tag = "evenrow" if i % 2 == 0 else "oddrow"
        tree.insert("", "end", values=row, tags=(tag,))

    tree.pack(fill="both", expand=True, padx=5, pady=5)
    return frame

