import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.patches import Rectangle
import time

def create_dashboard_tab(parent, monitor):
    frame = tk.Frame(parent, bg="white")

    # ✅ Traffic Summary Window
    summary_frame = tk.Frame(frame, bg="#f0f0f0", padx=10, pady=10, relief="groove", borderwidth=2)
    summary_frame.pack(fill="x", pady=5)
    summary_label = tk.Label(summary_frame, text="📊 Live Traffic Summary", font=("Arial", 12, "bold"), bg="#f0f0f0")
    summary_label.pack()
    summary_text = tk.Label(summary_frame, text="Packets: 0 | Alerts: 0", font=("Arial", 10), bg="#f0f0f0")
    summary_text.pack()
    
    
    def toggle_monitoring():
            """Pauses or resumes packet monitoring."""
            if monitor.state.is_active:
                monitor.state.is_active = False
                monitoring_status.set("Resume Monitoring")  # Update button text
            else:
                monitor.state.is_active = True
                monitoring_status.set("Pause Monitoring")
    
    # ✅ Pause/Continue Monitoring Button
    monitoring_status = tk.StringVar(value="Pause Monitoring")  # Default state
    pause_button = ttk.Button(frame, textvariable=monitoring_status, command=toggle_monitoring)
    pause_button.pack(pady=5)


    # ✅ Create a Matplotlib figure with subplots
    fig, axs = plt.subplots(2, 2, figsize=(8, 6))  # 2 Rows, 2 Columns

    # Line Graph - Traffic Over Time
    axs[0, 0].set_title("Traffic Over Time")
    axs[0, 0].set_xlabel("Time")
    axs[0, 0].set_ylabel("Packet Count")
    line, = axs[0, 0].plot([], marker="o", linestyle="-", color="blue")

    # Bar Chart - Protocol Distribution
    axs[0, 1].set_title("Protocol Distribution")
    axs[0, 1].set_ylabel("Packet Count")

    # Pie Chart - Traffic Composition
    axs[1, 0].set_title("Traffic Composition")

    # Bar Chart - Alerts by Severity
    axs[1, 1].set_title("Alerts by Severity")
    axs[1, 1].set_ylabel("Count")
    severity_colors = ["red", "orange", "green"]
    severity_labels = ["High", "Medium", "Low"]

    # ✅ Embed Matplotlib canvas inside Tkinter
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    # Store time (x) and packet count (y) data
    x_data, y_data = [], []

    # Create a tooltip label for displaying protocol information
    tooltip_text = tk.StringVar()
    tooltip_label = tk.Label(frame, textvariable=tooltip_text, bg="yellow", relief="solid", borderwidth=1)
    


    # ✅ Function to Update Charts
    def update_charts():
        if not monitor.state.is_active:
            frame.after(1000, update_charts)  # Check again in 1s
            return  # Stop updates when paused

        packet_count = monitor.get_packet_count()
        protocol_counts = monitor.get_protocol_counts()
        alert_counts = monitor.get_alert_count_by_severity()  # Fetch severity count

        # ✅ Update Traffic Summary Window
        summary_text.config(text=f"Packets: {packet_count} | Alerts: {sum(alert_counts.values())}")

        # ✅ Update Line Graph
        x_data.append(time.time())  # Use timestamp for X-axis
        y_data.append(packet_count)  # Store packet count
        axs[0, 0].clear()
        axs[0, 0].set_title("Traffic Over Time")
        axs[0, 0].set_xlabel("Time")
        axs[0, 0].set_ylabel("Packet Count")
        axs[0, 0].plot(x_data, y_data, marker="o", linestyle="-", color="blue")

        # ✅ Update Protocol Bar Chart
        axs[0, 1].clear()
        bars = axs[0, 1].bar(protocol_counts.keys(), protocol_counts.values(), color=["red", "green", "blue"])
        axs[0, 1].set_title("Protocol Distribution")

        canvas.mpl_connect("motion_notify_event", on_hover)  # Attach hover event

        # ✅ Update Pie Chart
        axs[1, 0].clear()
        axs[1, 0].pie(protocol_counts.values(), labels=protocol_counts.keys(), autopct="%1.1f%%")
        axs[1, 0].set_title("Traffic Composition")

        # ✅ Update Alerts Bar Chart (Sorted by Severity)
        axs[1, 1].clear()
        axs[1, 1].bar(severity_labels, [alert_counts.get(s, 0) for s in severity_labels], color=severity_colors)
        axs[1, 1].set_title("Alerts by Severity")

        canvas.draw()
        frame.after(5000, update_charts)  # Refresh every 5s

        
    def on_hover(event):
        """Displays tooltip on hover over protocol bars."""
        protocol_counts = monitor.get_protocol_counts()  # Fetch protocol counts
        if event.inaxes == axs[0, 1]:  # Ensure the event is inside the bar chart
            x, y = event.xdata, event.ydata
            if x is not None and y is not None:
                # Find the closest bar (protocol) based on x-coordinates
                index = int(round(x)) if 0 <= round(x) < len(protocol_counts) else None
                if index is not None:
                    protocol = list(protocol_counts.keys())[index]  # Get protocol name
                    packet_count = protocol_counts.get(protocol, 0)  # Get packet count
                    
                    # Show tooltip info
                    tooltip_text.set(f"{protocol}: {packet_count} packets")
                    tooltip_label.place(x=event.x, y=event.y)
        else:
            tooltip_label.place_forget()  # Hide tooltip if outside the bar chart


        fig.canvas.mpl_connect("motion_notify_event", on_hover)

    update_charts()  # Start updating

    return frame
