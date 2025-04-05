import tkinter as tk
from tkinter import ttk, filedialog
from tkcalendar import DateEntry
import csv
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from database.database import get_alerts_by_timeframe, get_alerts_by_date_range

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

    # ✅ Title Label (unchanged)
    ttk.Label(frame, text="🚨 Alerts & Statistics", font=("Arial", 14, "bold")).pack(pady=5)

    # ✅ Filter Frame (unchanged)
    filter_frame = ttk.Frame(frame)
    filter_frame.pack(fill=tk.X, padx=5, pady=5)

    # Search Bar (unchanged)
    ttk.Label(filter_frame, text="🔍 Search:").pack(side=tk.LEFT, padx=5)
    search_entry = ttk.Entry(filter_frame, width=20)
    search_entry.pack(side=tk.LEFT, padx=5)

    # Severity Filter (unchanged)
    ttk.Label(filter_frame, text="⚠️ Severity:").pack(side=tk.LEFT, padx=5)
    severity_var = tk.StringVar(value="All")
    severity_dropdown = ttk.Combobox(filter_frame, textvariable=severity_var, 
                                   values=["All", "High", "Medium", "Low"], width=10)
    severity_dropdown.pack(side=tk.LEFT, padx=5)

    # Date Range Selection (unchanged)
    ttk.Label(filter_frame, text="📅 From:").pack(side=tk.LEFT, padx=5)
    start_date = DateEntry(filter_frame, width=10, background="darkblue", 
                         foreground="white", date_pattern="yyyy-mm-dd")
    start_date.pack(side=tk.LEFT, padx=5)

    ttk.Label(filter_frame, text="📅 To:").pack(side=tk.LEFT, padx=5)
    end_date = DateEntry(filter_frame, width=10, background="darkblue", 
                        foreground="white", date_pattern="yyyy-mm-dd")
    end_date.pack(side=tk.LEFT, padx=5)

    # Apply & Reset Buttons (unchanged)
    apply_btn = ttk.Button(filter_frame, text="Apply Filter", command=lambda: update_alerts())
    apply_btn.pack(side=tk.LEFT, padx=5)

    reset_btn = ttk.Button(filter_frame, text="Reset", command=lambda: reset_filters())
    reset_btn.pack(side=tk.LEFT, padx=5)

    # ✅ Table Frame with Scrollbars (unchanged)
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

    # ✅ Enhanced Graph Area with Time Period Dropdown
    graph_frame = ttk.Frame(frame)
    graph_frame.pack(fill="both", expand=True, padx=5, pady=5)

    # Create figure
    fig = plt.figure(figsize=(8, 4))
    ax = fig.add_subplot(111)  # Single subplot for the chart

    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    # Time period dropdown above the graph
    time_frame = ttk.Frame(frame)
    time_frame.pack(fill=tk.X, padx=5, pady=(5, 0))
    
    ttk.Label(time_frame, text="Time Period:").pack(side=tk.LEFT, padx=5)
    time_var = tk.StringVar(value="Day")
    time_dropdown = ttk.Combobox(time_frame, textvariable=time_var, 
                                values=["Day", "Week", "Month", "All Time"],
                                state="readonly", width=10)
    time_dropdown.pack(side=tk.LEFT, padx=5)
    time_dropdown.bind("<<ComboboxSelected>>", lambda e: update_alerts())

    def update_alerts():
        """Fetch and update alert data in table & graph based on filters."""
        alert_tree.delete(*alert_tree.get_children())  # Clear table
        alerts = []

        if start_date.get() and end_date.get():
            alerts = get_alerts_by_date_range(start_date.get(), end_date.get())
        else:
            # Use the selected time period from dropdown
            selected_period = time_var.get().lower()
            if selected_period == "all time":
                alerts = get_alerts_by_timeframe("all")
            else:
                alerts = get_alerts_by_timeframe(selected_period)

        # Apply search and severity filters
        search_term = search_entry.get().lower()
        severity_filter = severity_var.get()

        filtered_alerts = [
            (timestamp, message, alert_type, severity) 
            for timestamp, message, alert_type, severity in alerts 
            if (search_term in message.lower() or search_term in alert_type.lower()) and
               (severity_filter == "All" or severity == severity_filter)
        ]

        # Populate Table (unchanged)
        for timestamp, message, alert_type, severity in filtered_alerts:
            alert_tree.insert("", tk.END, values=(timestamp, message, alert_type, severity))

        # Update Graph with combined view
        ax.clear()
        
        # Group by severity and time
        time_groups = {}
        for timestamp, _, _, severity in filtered_alerts:
            # Time grouping logic
            if time_var.get() == "Day":
                time_key = timestamp.split()[0]  # Just date
            elif time_var.get() == "Week":
                # Implement week grouping logic here
                time_key = timestamp.split()[0]  # Placeholder - should group by week
            elif time_var.get() == "Month":
                time_key = "-".join(timestamp.split("-")[:2])  # Year-month
            else:  # All Time
                time_key = "All Time"
            
            if time_key not in time_groups:
                time_groups[time_key] = {"High": 0, "Medium": 0, "Low": 0}
            time_groups[time_key][severity] += 1

        # Prepare data for stacked bar chart
        time_labels = sorted(time_groups.keys())
        high_counts = [time_groups[t]["High"] for t in time_labels]
        medium_counts = [time_groups[t]["Medium"] for t in time_labels]
        low_counts = [time_groups[t]["Low"] for t in time_labels]

        # Create stacked bars
        if time_labels:
            ax.bar(time_labels, low_counts, color=SEVERITY_COLORS["Low"], label="Low")
            ax.bar(time_labels, medium_counts, bottom=low_counts, 
                  color=SEVERITY_COLORS["Medium"], label="Medium")
            ax.bar(time_labels, high_counts, 
                  bottom=[l+m for l, m in zip(low_counts, medium_counts)],
                  color=SEVERITY_COLORS["High"], label="High")

            ax.set_title(f"Alerts by Severity ({time_var.get()} View)")
            ax.set_ylabel("Alert Count")
            ax.legend()
            
            # Rotate x-axis labels if needed
            if len(time_labels) > 5:
                plt.setp(ax.get_xticklabels(), rotation=45, ha="right")

        canvas.draw()
        frame.after(REFRESH_INTERVAL, update_alerts)

    def reset_filters():
        """Reset all filters and refresh alerts."""
        search_entry.delete(0, tk.END)
        severity_var.set("All")
        start_date.set_date(start_date._date)
        end_date.set_date(end_date._date)
        time_var.set("Day")
        update_alerts()

    def export_filtered_alerts():
        """Export alerts based on applied filters to a CSV file."""
        alerts = []

        if start_date.get() and end_date.get():
            alerts = get_alerts_by_date_range(start_date.get(), end_date.get())
        else:
            selected_period = time_var.get().lower()
            if selected_period == "all time":
                alerts = get_alerts_by_timeframe("all")
            else:
                alerts = get_alerts_by_timeframe(selected_period)

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
                    writer.writerow(["Timestamp", "Message", "Type", "Severity"])
                    writer.writerows(filtered_alerts)

                tk.messagebox.showinfo("Export", f"Alerts exported successfully to {file_path}")
            except Exception as e:
                tk.messagebox.showerror("Export Error", f"Error exporting alerts: {e}")

    # Buttons for manual refresh, clear, and export (unchanged)
    button_frame = ttk.Frame(frame)
    button_frame.pack(pady=5)

    ttk.Button(button_frame, text="Refresh Now", command=update_alerts).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="Clear Alerts", command=reset_filters).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="📤 Export Data", command=export_filtered_alerts).pack(side=tk.LEFT, padx=5)

    update_alerts()  # Initial Load

    return frame