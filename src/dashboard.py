import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque
import time
from datetime import datetime
import matplotlib.dates as mdates

def create_dashboard_tab(parent, monitor):
    frame = tk.Frame(parent, bg="white")

    # ✅ Traffic Summary Window (unchanged)
    summary_frame = tk.Frame(frame, bg="#f0f0f0", padx=10, pady=10, relief="groove", borderwidth=2)
    summary_frame.pack(fill="x", pady=5)
    summary_label = tk.Label(summary_frame, text="📊 Live Traffic Summary", font=("Arial", 12, "bold"), bg="#f0f0f0")
    summary_label.pack()
    summary_text = tk.Label(summary_frame, text="Packets: 0 | Alerts: 0", font=("Arial", 10), bg="#f0f0f0")
    summary_text.pack()
    
    def toggle_monitoring():
        if monitor.state.is_active:
            monitor.state.is_active = False
            monitoring_status.set("Resume Monitoring")
        else:
            monitor.state.is_active = True
            monitoring_status.set("Pause Monitoring")
    
    # ✅ Pause/Continue Monitoring Button (unchanged)
    monitoring_status = tk.StringVar(value="Pause Monitoring")
    pause_button = ttk.Button(frame, textvariable=monitoring_status, command=toggle_monitoring)
    pause_button.pack(pady=5)

    # ✅ Create Matplotlib figure with subplots (modified for scaling)
    fig, axs = plt.subplots(2, 2, figsize=(8, 6))
    plt.subplots_adjust(hspace=0.5, wspace=0.3)

    # Store time (x) and packet count (y) data with fixed length
    max_points = 60  # Show last minute of data (assuming 1 update per second)
    x_data = deque(maxlen=max_points)
    y_data = deque(maxlen=max_points)
    
    # Initialize line graph with empty data
    line, = axs[0, 0].plot([], [], marker="o", linestyle="-", color="blue")
    axs[0, 0].set_title("Traffic Over Time")
    axs[0, 0].set_xlabel("Time")
    axs[0, 0].set_ylabel("Packet Count")
    axs[0, 0].grid(True)
    
    # Initialize other charts (unchanged)
    axs[0, 1].set_title("Protocol Distribution")
    axs[0, 1].set_ylabel("Packet Count")
    
    axs[1, 0].set_title("Traffic Composition")
    
    severity_colors = ["red", "orange", "green"]
    severity_labels = ["High", "Medium", "Low"]
    axs[1, 1].set_title("Alerts by Severity")
    axs[1, 1].set_ylabel("Count")

    # ✅ Embed Matplotlib canvas (unchanged)
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    # Tooltip (unchanged)
    tooltip_text = tk.StringVar()
    tooltip_label = tk.Label(frame, textvariable=tooltip_text, bg="yellow", relief="solid", borderwidth=1)

    # ✅ Modified update_charts function (scaling fixes)
    def update_charts():
        if not monitor.state.is_active:
            frame.after(1000, update_charts)
            return

        packet_count = monitor.get_packet_count()
        protocol_counts = monitor.get_protocol_counts()
        alert_counts = monitor.get_alert_count_by_severity()

        # ✅ Update Traffic Summary Window (unchanged)
        summary_text.config(text=f"Packets: {packet_count} | Alerts: {sum(alert_counts.values())}")

        # ✅ Update Line Graph (modified for better scaling)
        current_time = datetime.now()
        x_data.append(current_time)
        y_data.append(packet_count)
        
        line.set_data(x_data, y_data)
        axs[0, 0].relim()
        axs[0, 0].autoscale_view()
        
        # Format x-axis as time
        if len(x_data) > 1:
            axs[0, 0].xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            plt.setp(axs[0, 0].get_xticklabels(), rotation=45, ha='right')

        # ✅ Update Protocol Bar Chart (unchanged functionality, better scaling)
        axs[0, 1].clear()
        bars = axs[0, 1].bar(protocol_counts.keys(), protocol_counts.values(), color=["red", "green", "blue"])
        axs[0, 1].set_title("Protocol Distribution")
        axs[0, 1].yaxis.set_major_locator(plt.MaxNLocator(integer=True))
        
        # Reconnect hover event
        canvas.mpl_connect("motion_notify_event", on_hover)

        # ✅ Update Pie Chart (unchanged)
        axs[1, 0].clear()
        axs[1, 0].pie(protocol_counts.values(), labels=protocol_counts.keys(), autopct="%1.1f%%")
        axs[1, 0].set_title("Traffic Composition")

        # ✅ Update Alerts Bar Chart (unchanged)
        axs[1, 1].clear()
        axs[1, 1].bar(severity_labels, [alert_counts.get(s, 0) for s in severity_labels], color=severity_colors)
        axs[1, 1].set_title("Alerts by Severity")
        axs[1, 1].yaxis.set_major_locator(plt.MaxNLocator(integer=True))

        canvas.draw()
        frame.after(5000, update_charts)

    # ✅ Unchanged on_hover function
    def on_hover(event):
        protocol_counts = monitor.get_protocol_counts()
        if event.inaxes == axs[0, 1]:
            x, y = event.xdata, event.ydata
            if x is not None and y is not None:
                index = int(round(x)) if 0 <= round(x) < len(protocol_counts) else None
                if index is not None:
                    protocol = list(protocol_counts.keys())[index]
                    packet_count = protocol_counts.get(protocol, 0)
                    tooltip_text.set(f"{protocol}: {packet_count} packets")
                    tooltip_label.place(x=event.x, y=event.y)
        else:
            tooltip_label.place_forget()

    update_charts()
    return frame