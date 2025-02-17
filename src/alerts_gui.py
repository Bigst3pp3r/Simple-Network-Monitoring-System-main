import tkinter as tk
from tkinter import ttk, messagebox
from database.database import get_alerts # Fetch stored alerts


# Severity color mapping
SEVERITY_COLORS = {
    "High": "red",
    "Medium": "orange",
    "Low": "green"
}

REFRESH_INTERVAL = 5000  # 5 seconds (adjust as needed)

def display_alert(message):
        """Function to display alerts in the Alerts tab."""
        print(f"ALERT: {message}")  # Modify this to update the GUI instead of printing

def create_alerts_tab(parent):
    """Creates the alerts GUI tab for real-time monitoring and past alerts."""
    frame = ttk.Frame(parent, padding=10)

    # Title Label
    ttk.Label(frame, text="Real-Time Alerts", font=("Arial", 12, "bold")).pack(pady=5)

    # Table (Treeview) with Scrollbars
    columns = ("Timestamp", "Message", "Type", "Severity")
    
    tree_frame = ttk.Frame(frame)
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    alert_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=10)
    
    # Define column headings
    alert_tree.heading("Timestamp", text="Timestamp", anchor=tk.W)
    alert_tree.heading("Message", text="Message", anchor=tk.W)
    alert_tree.heading("Severity", text="Severity", anchor=tk.W)

    # Define column widths
    alert_tree.column("Timestamp", width=150, anchor=tk.W)
    alert_tree.column("Message", width=300, anchor=tk.W)
    alert_tree.heading("Type", text="Type", anchor=tk.W)
    alert_tree.column("Severity", width=100, anchor=tk.CENTER)

    # Add vertical scrollbar
    v_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=alert_tree.yview)
    alert_tree.configure(yscrollcommand=v_scroll.set)
    v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    # Add horizontal scrollbar
    h_scroll = ttk.Scrollbar(frame, orient="horizontal", command=alert_tree.xview)
    alert_tree.configure(xscrollcommand=h_scroll.set)
    h_scroll.pack(fill=tk.X)

    alert_tree.pack(fill=tk.BOTH, expand=True)
    

    def load_alerts():
        """Loads and displays alerts from the database."""
        alert_tree.delete(*alert_tree.get_children())  # Clear previous entries
        alerts = get_alerts()

        if not alerts:
            return

        for timestamp, message, type, severity in alerts:
            alert_tree.insert("", tk.END, values=(timestamp, message, type, severity))

        # Schedule next refresh
        frame.after(REFRESH_INTERVAL, load_alerts)  # Auto-refresh every 5 seconds
        
    def clear_alerts():
        """Clears the alert table display."""
        alert_tree.delete(*alert_tree.get_children())

    # Buttons for manual refresh and clear
    button_frame = ttk.Frame(frame)
    button_frame.pack(pady=5)

    ttk.Button(button_frame, text="Refresh Now", command=load_alerts).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="Clear Alerts", command=clear_alerts).pack(side=tk.LEFT, padx=5)

    # Load alerts initially and start auto-refresh
    load_alerts()

    return frame
