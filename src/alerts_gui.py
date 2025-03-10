import tkinter as tk
from tkinter import ttk, filedialog
from tkcalendar import DateEntry  # ✅ Requires 'pip install tkcalendar'
import csv
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from database.database import get_alerts_by_timeframe, get_alerts_by_date_range  # ✅ New function needed in database

# Severity color mapping
SEVERITY_COLORS = {
    "High": "red",
    "Medium": "orange",
    "Low": "green"
}

REFRESH_INTERVAL = 5000  # 5 seconds

def create_alerts_tab(parent):
    """Creates the alerts GUI tab with search, filters, date range, and graph."""
    frame = ttk.Frame(parent, padding=10)

    # ✅ Title Label
    ttk.Label(frame, text="🚨 Alerts & Statistics", font=("Arial", 14, "bold")).pack(pady=5)

    # ✅ Filter Frame
    filter_frame = ttk.Frame(frame)
    filter_frame.pack(fill=tk.X, padx=5, pady=5)

    # Search Bar
    ttk.Label(filter_frame, text="🔍 Search:").pack(side=tk.LEFT, padx=5)
    search_entry = ttk.Entry(filter_frame, width=20)
    search_entry.pack(side=tk.LEFT, padx=5)

    # Severity Filter
    ttk.Label(filter_frame, text="⚠️ Severity:").pack(side=tk.LEFT, padx=5)
    severity_var = tk.StringVar(value="All")
    severity_dropdown = ttk.Combobox(filter_frame, textvariable=severity_var, values=["All", "High", "Medium", "Low"], width=10)
    severity_dropdown.pack(side=tk.LEFT, padx=5)

    # ✅ Date Range Selection
    ttk.Label(filter_frame, text="📅 From:").pack(side=tk.LEFT, padx=5)
    start_date = DateEntry(filter_frame, width=10, background="darkblue", foreground="white", date_pattern="yyyy-mm-dd")
    start_date.pack(side=tk.LEFT, padx=5)

    ttk.Label(filter_frame, text="📅 To:").pack(side=tk.LEFT, padx=5)
    end_date = DateEntry(filter_frame, width=10, background="darkblue", foreground="white", date_pattern="yyyy-mm-dd")
    end_date.pack(side=tk.LEFT, padx=5)

    # Apply & Reset Buttons
    apply_btn = ttk.Button(filter_frame, text="Apply Filter", command=lambda: update_alerts())
    apply_btn.pack(side=tk.LEFT, padx=5)

    reset_btn = ttk.Button(filter_frame, text="Reset", command=lambda: reset_filters())
    reset_btn.pack(side=tk.LEFT, padx=5)

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
    ttk.Label(frame, text="📅 View Alerts:", font=("Arial", 10)).pack()
    timeframe_dropdown = ttk.Combobox(frame, textvariable=timeframe_var, values=["Daily", "Weekly", "Monthly"])
    timeframe_dropdown.pack(pady=2)

    def update_alerts():
        """Fetch and update alert data in table & graph based on filters."""
        alert_tree.delete(*alert_tree.get_children())  # Clear table
        alerts = []

        if start_date.get() and end_date.get():
            alerts = get_alerts_by_date_range(start_date.get(), end_date.get())  # Fetch by date range
        else:
            alerts = get_alerts_by_timeframe(timeframe_var.get().lower())  # Fetch by timeframe

        # Apply search and severity filters
        search_term = search_entry.get().lower()
        severity_filter = severity_var.get()

        filtered_alerts = [
            (timestamp, message, alert_type, severity) 
            for timestamp, message, alert_type, severity in alerts 
            if (search_term in message.lower() or search_term in alert_type.lower()) and
               (severity_filter == "All" or severity == severity_filter)
        ]

        # Populate Table
        for timestamp, message, alert_type, severity in filtered_alerts:
            alert_tree.insert("", tk.END, values=(timestamp, message, alert_type, severity))

        # Update Graph
        ax.clear()
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for _, _, _, severity in filtered_alerts:
            severity_counts[severity] += 1

        ax.bar(severity_counts.keys(), severity_counts.values(), color=[SEVERITY_COLORS[s] for s in severity_counts])
        ax.set_title(f"Alerts Over Time ({timeframe_var.get()})")
        ax.set_ylabel("Alert Count")

        canvas.draw()
        frame.after(REFRESH_INTERVAL, update_alerts)  # Auto-refresh every 5s
        
    def reset_filters():
        """Reset all filters and refresh alerts."""
        search_entry.delete(0, tk.END)
        severity_var.set("All")
        start_date.set_date(start_date._date)  # ✅ Reset to the last valid date
        end_date.set_date(end_date._date)  # ✅ Reset to the last valid date
        update_alerts()


    # ✅ Export Filtered Alerts to CSV
    def export_filtered_alerts():
        """Export alerts based on applied filters to a CSV file."""
        alerts = []

        if start_date.get() and end_date.get():
            alerts = get_alerts_by_date_range(start_date.get(), end_date.get())  # Fetch by date range
        else:
            alerts = get_alerts_by_timeframe(timeframe_var.get().lower())  # Fetch by timeframe

        # Apply search and severity filters
        search_term = search_entry.get().lower()
        severity_filter = severity_var.get()

        filtered_alerts = [
            (timestamp, message, alert_type, severity) 
            for timestamp, message, alert_type, severity in alerts 
            if (search_term in message.lower() or search_term in alert_type.lower()) and
               (severity_filter == "All" or severity == severity_filter)
        ]

        if not filtered_alerts:
            tk.messagebox.showinfo("Export", "No alerts to export for the selected filters.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Save Filtered Alerts"
        )

        if file_path:
            try:
                with open(file_path, mode="w", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    writer.writerow(["Timestamp", "Message", "Type", "Severity"])  # Header row
                    writer.writerows(filtered_alerts)  # Write alert data

                tk.messagebox.showinfo("Export", f"Alerts exported successfully to {file_path}")
            except Exception as e:
                tk.messagebox.showerror("Export Error", f"Error exporting alerts: {e}")

    # ✅ Buttons for manual refresh, clear, and export
    button_frame = ttk.Frame(frame)
    button_frame.pack(pady=5)

    ttk.Button(button_frame, text="Refresh Now", command=update_alerts).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="Clear Alerts", command=reset_filters).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="📤 Export Data", command=export_filtered_alerts).pack(side=tk.LEFT, padx=5)  # Export button

    timeframe_dropdown.bind("<<ComboboxSelected>>", lambda event: update_alerts())
    update_alerts()  # Initial Load

    return frame
