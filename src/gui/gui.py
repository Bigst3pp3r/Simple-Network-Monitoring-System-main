import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from views import create_table_view, get_summary_data
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import ttkbootstrap as ttkbootstrap
from ttkbootstrap import Style
from ttkbootstrap.constants import *
from dashboard import create_dashboard
import sqlite3
from settings import create_settings_tab

REFRESH_INTERVAL = 5000  # 5 seconds

def check_new_alerts():
    """Check for new alerts and display pop-up notifications."""
    conn = sqlite3.connect("network_monitoring.db")
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, message FROM alerts ORDER BY id DESC LIMIT 1")
    latest_alert = cursor.fetchone()
    conn.close()

    if latest_alert:
        timestamp, message = latest_alert
        messagebox.showwarning("⚠️ Network Alert", f"Time: {timestamp}\nAlert: {message}")

    # Check for new alerts every 10 seconds
    root.after(1000000000000, check_new_alerts)

root = tk.Tk()
root.after(5000000, check_new_alerts)  # Start checking after 5 seconds





def update_dashboard(lbl_devices, lbl_packets, lbl_alerts):
    """Updates the dashboard statistics in real time."""
    devices_count, packets_count, alerts_count = get_summary_data()
    
    lbl_devices.config(text=f"Devices: {devices_count}")
    lbl_packets.config(text=f"Packets: {packets_count}")
    lbl_alerts.config(text=f"Alerts: {alerts_count}")

    # Refresh every REFRESH_INTERVAL
    lbl_devices.after(REFRESH_INTERVAL, update_dashboard, lbl_devices, lbl_packets, lbl_alerts)


def create_gui():
    """Initialize the main GUI application with a modern theme."""
    # Apply ttkbootstrap styling
    style = Style(theme="superhero")  # Choose from ('cosmo', 'minty', 'superhero', etc.)

    root = style.master
    root.title("📡 Network Monitoring System")
    root.geometry("1000x600")

    # Notebook (Tabs)
    notebook = ttk.Notebook(root, style="TNotebook")
    notebook.pack(fill="both", expand=True, padx=10, pady=10)

    # Define Columns
    device_columns = ["ID", "IP", "MAC", "Manufacturer", "Device Name", "Type", "First Seen", "Last Seen", "Status"]
    packets_columns = ["ID", "Timestamp", "Source IP", "Destination IP", "Protocol"]
    alerts_columns = ["ID", "Timestamp", "Message", "Type", "Severity"]

    
    frame_dashboard = create_dashboard(notebook)  # Dashboard with real-time updates
    frame_devices = create_table_view(notebook, device_columns, "network_devices")
    frame_packets = create_table_view(notebook, packets_columns, "packets")
    frame_alerts = create_table_view(notebook, alerts_columns, "alerts")

    # Add tabs to notebook
    notebook.add(frame_dashboard, text="📊 Dashboard")
    notebook.add(frame_devices, text="🖥️ Logged Devices")
    notebook.add(frame_packets, text="📡 Captured Packets")
    notebook.add(frame_alerts, text="⚠️ Alerts")
    
    
    # Inside create_gui()
    frame_settings = create_settings_tab(notebook)
    notebook.add(frame_settings, text="⚙️ Settings")

    # Custom Exit Button
    btn_exit = ttk.Button(root, text="🚪 Exit", command=root.quit, style="danger.TButton")
    btn_exit.pack(pady=10)

    root.mainloop()
