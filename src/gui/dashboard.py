import tkinter as tk
from tkinter import ttk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from views import get_device_status_data, get_protocol_usage_data, get_alerts_over_time_data
import ttkbootstrap as ttkbootstrap
from ttkbootstrap import Style
from ttkbootstrap.constants import *
import sqlite3


def create_dashboard(notebook):
    """Create a modern dashboard with improved UI styling."""
    frame_dashboard = ttk.Frame(notebook, padding=10)
    
    # Styling
    frame_dashboard.configure(style="secondary.TFrame")

  # 🟢 Status Label
    status_label = ttk.Label(frame_dashboard, text="Network Status: 🟢 GOOD", style="success.TLabel", font=("Arial", 14, "bold"))
    status_label.pack(pady=10)

    # Start real-time updates
    update_status_label(status_label, status_label)

    # Create Graphs
    fig1, ax1 = plt.subplots(figsize=(4, 3))
    fig2, ax2 = plt.subplots(figsize=(4, 3))
    fig3, ax3 = plt.subplots(figsize=(5, 3))

    # Function to Update Charts in Real Time
    def update_charts():
        ax1.clear()
        ax2.clear()
        ax3.clear()

        # Device Status Pie Chart
        labels, sizes = get_device_status_data()
        ax1.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=90, colors=["green", "red"])
        ax1.set_title("Device Status", fontsize=12, fontweight="bold")

        # Protocol Usage Bar Chart
        protocols, counts = get_protocol_usage_data()
        ax2.bar(protocols, counts, color="blue")
        ax2.set_title("Network Traffic by Protocol", fontsize=12, fontweight="bold")

        # Alerts Over Time Line Chart
        timestamps, alert_counts = get_alerts_over_time_data()
        ax3.plot(timestamps, alert_counts, marker="o", linestyle="-", color="red")
        ax3.set_title("Alerts Over Time", fontsize=12, fontweight="bold")
        ax3.set_xticklabels(timestamps, rotation=45)

        # Redraw Canvas
        canvas1.draw()
        canvas2.draw()
        canvas3.draw()

        # Schedule next update
        frame_dashboard.after(5000, update_charts)

    # Embed Graphs into Dashboard
    canvas1 = FigureCanvasTkAgg(fig1, master=frame_dashboard)
    canvas1.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=5)

    canvas2 = FigureCanvasTkAgg(fig2, master=frame_dashboard)
    canvas2.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=5)

    canvas3 = FigureCanvasTkAgg(fig3, master=frame_dashboard)
    canvas3.get_tk_widget().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=5)

    update_charts()

    return frame_dashboard

def get_network_status():
    """Determine network health based on active alerts."""
    try:
        conn = sqlite3.connect("network_monitoring.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='Critical'")
        critical_alerts = cursor.fetchone()[0]
        conn.close()

        if critical_alerts >= 3:
            return "🔴 CRITICAL", "danger"
        elif critical_alerts > 0:
            return "🟡 WARNING", "warning"
        else:
            return "🟢 GOOD", "success"
    except sqlite3.Error:
        return "⚪ UNKNOWN", "secondary"

def update_status_label(label, style):
    """Update the network status label dynamically."""
    status_text, theme = get_network_status()
    label.config(text=f"Network Status: {status_text}", style=f"{theme}.TLabel")
    label.after(5000, lambda: update_status_label(label, style))  # Auto-refresh every 5s



