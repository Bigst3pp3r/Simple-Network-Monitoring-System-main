import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from database.database import get_alerts_by_timeframe  # Fetch alerts by day/week/month

# ✅ Severity color mapping
SEVERITY_COLORS = {
    "High": "red",
    "Medium": "orange",
    "Low": "green"
}

REFRESH_INTERVAL = 5000  # Auto-refresh every 5 seconds

def create_alerts_tab(parent):
    """Creates the alerts GUI tab with a table, alerts over time chart, and export feature."""
    frame = ttk.Frame(parent, padding=10)

    # ✅ Title Label
    ttk.Label(frame, text="🚨 Alerts & Statistics", font=("Arial", 14, "bold")).pack(pady=5)

    # ✅ Table Frame with Scrollbars
    table_frame = ttk.Frame(frame)
    table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    columns = ("Timestamp", "Message", "Type", "Severity")
    alert_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)

    for col in columns:
        alert_tree.heading(col, text=col, anchor=tk.W)
        alert_tree.column(col, width=150 if col == "Timestamp" else 250, anchor=tk.W)

    v_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=alert_tree.yview)
    alert_tree.configure(yscrollcommand=v_scroll.set)
    v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    alert_tree.pack(fill=tk.BOTH, expand=True)

    # ✅ Graph Area - Alerts Over Time
    graph_frame = ttk.Frame(frame)
    graph_frame.pack(fill="both", expand=True, padx=5, pady=5)

    fig, ax = plt.subplots(figsize=(6, 3))
    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    # ✅ Dropdown for Timeframe Selection
    timeframe_var = tk.StringVar(value="Daily")
    ttk.Label(frame, text="View Alerts:", font=("Arial", 10)).pack()
    timeframe_dropdown = ttk.Combobox(frame, textvariable=timeframe_var, values=["Daily", "Weekly", "Monthly"])
    timeframe_dropdown.pack(pady=2)

    def update_alerts():
        """Fetch and update alert data in table & graph."""
        alert_tree.delete(*alert_tree.get_children())  # Clear table
        alerts = get_alerts_by_timeframe(timeframe_var.get().lower())  # Fetch alerts (day/week/month)

        if alerts:
            # Populate Table
            for timestamp, message, alert_type, severity in alerts:
                alert_tree.insert("", tk.END, values=(timestamp, message, alert_type, severity))

            # Update Graph
            ax.clear()
            severity_counts = {"High": 0, "Medium": 0, "Low": 0}
            for _, _, _, severity in alerts:
                severity_counts[severity] += 1

            ax.bar(severity_counts.keys(), severity_counts.values(), color=[SEVERITY_COLORS[s] for s in severity_counts])
            ax.set_title(f"Alerts Over Time ({timeframe_var.get()})")
            ax.set_ylabel("Alert Count")

        canvas.draw()
        frame.after(REFRESH_INTERVAL, update_alerts)  # Auto-refresh every 5s

    # ✅ Export Alerts Function
    def export_alerts():
        """Export alerts to a CSV file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv")],
                                                 title="Save Alerts As")
        if not file_path:
            return  # User canceled

        alerts = get_alerts_by_timeframe(timeframe_var.get().lower())  # Fetch alerts

        if not alerts:
            messagebox.showinfo("No Data", "No alerts to export.")
            return

        try:
            with open(file_path, mode="w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "Message", "Type", "Severity"])  # Header
                writer.writerows(alerts)  # Alert data

            messagebox.showinfo("Success", f"Alerts exported successfully to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export alerts: {e}")

    # ✅ Export Button
    export_button = ttk.Button(frame, text="📁 Export Alerts", command=export_alerts)
    export_button.pack(pady=5)

    timeframe_dropdown.bind("<<ComboboxSelected>>", lambda event: update_alerts())
    update_alerts()  # Initial Load

    return frame
