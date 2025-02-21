import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
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

    # Create Matplotlib figure with 3 subplots
    fig, axs = plt.subplots(3, 1, figsize=(5, 8))
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    # ✅ Line Graph - Traffic Over Time
    axs[0].set_title("Traffic Over Time")
    axs[0].set_xlabel("Time")
    axs[0].set_ylabel("Packet Count")
    line, = axs[0].plot([], marker="o", linestyle="-", color="blue")

    # ✅ Bar Chart - Protocol Distribution
    axs[1].set_title("Protocol Distribution")
    axs[1].set_ylabel("Packet Count")

    # ✅ Pie Chart - Traffic Composition
    axs[2].set_title("Traffic Composition")

    # Store time (x) and packet count (y) data
    x_data, y_data = [], []  

    # ✅ Tooltip Label (For Hovering)
    tooltip_label = tk.Label(frame, text="", font=("Arial", 10), bg="yellow", relief="solid", borderwidth=1)
    tooltip_label.place_forget()  # Hide initially

    # ✅ Bar Chart Hover Storage (Stores Bars & Protocol Data)
    bar_patches = []  
    protocol_labels = []  

    def update_charts():
        """ Updates charts with real-time data """
        packet_count = monitor.get_packet_count()
        protocol_counts = monitor.get_protocol_counts()
        alert_count = monitor.get_alert_count()

        # ✅ Update Traffic Summary Window
        summary_text.config(text=f"Packets: {packet_count} | Alerts: {alert_count}")

        # ✅ Update Line Graph - Track Traffic Over Time
        x_data.append(time.time())  # Use timestamp for X-axis
        y_data.append(packet_count)  # Store packet count

        axs[0].clear()
        axs[0].set_title("Traffic Over Time")
        axs[0].set_xlabel("Time")
        axs[0].set_ylabel("Packet Count")
        axs[0].plot(x_data, y_data, marker="o", linestyle="-", color="blue")

        # ✅ Update Bar Chart - Protocol Distribution
        axs[1].clear()
        bar_patches.clear()
        protocol_labels.clear()
        bars = axs[1].bar(protocol_counts.keys(), protocol_counts.values(), color=["red", "green", "blue"])
        axs[1].set_title("Protocol Distribution")

        # ✅ Store bar patches & protocol labels for hovering
        for bar, (protocol, count) in zip(bars, protocol_counts.items()):
            bar_patches.append(bar)
            protocol_labels.append(f"{protocol}: {count} packets")

        # ✅ Update Pie Chart - Traffic Composition
        axs[2].clear()
        axs[2].pie(protocol_counts.values(), labels=protocol_counts.keys(), autopct="%1.1f%%")
        axs[2].set_title("Traffic Composition")

        canvas.draw()
        frame.after(5000, update_charts)  # Refresh every 5s

    # ✅ Hovering Tooltip Function
    def on_hover(event):
        """Displays tooltip when hovering over graphs."""
        for i, ax in enumerate(axs):
            if ax.contains(event)[0]:  # Check if mouse is inside a graph
                if i == 0:  # Line Graph
                    tooltip_label.config(text=f"Packet Count: {monitor.get_packet_count()}")
                elif i == 1:  # Bar Chart (Protocol Distribution)
                    for bar, label in zip(bar_patches, protocol_labels):
                        if bar.contains(event)[0]:  # Check if hovering over a bar
                            tooltip_label.config(text=label)
                            break
                elif i == 2:  # Pie Chart
                    tooltip_label.config(text="Traffic Composition")

                tooltip_label.place(x=event.x + 20, y=event.y + 20)
                return
        
        tooltip_label.place_forget()  # Hide tooltip if not hovering

    canvas.mpl_connect("motion_notify_event", on_hover)  # Bind hovering event
    update_charts()  # Start updating

    return frame
