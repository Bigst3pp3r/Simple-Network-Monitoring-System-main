import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time


def create_dashboard_tab(parent, monitor):
    frame = tk.Frame(parent, bg="white")

    fig, axs = plt.subplots(3, 1, figsize=(5, 8))

    # Line Graph - Traffic Over Time
    axs[0].set_title("Traffic Over Time")
    axs[0].set_xlabel("Time")
    axs[0].set_ylabel("Packet Count")
    line, = axs[0].plot([], marker="o", linestyle="-", color="blue")

    # Bar Chart - Protocol Distribution
    axs[1].set_title("Protocol Distribution")
    axs[1].set_ylabel("Packet Count")

    # Pie Chart - Traffic Composition
    axs[2].set_title("Traffic Composition")

    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.get_tk_widget().pack(fill="both", expand=True)

        #Store time (x) and packet count (y) data
    x_data, y_data = [], []  

    def update_charts():
        packet_count = monitor.get_packet_count()
        protocol_counts = monitor.get_protocol_counts()

        # ✅ Update Line Graph - Track Traffic Over Time
        x_data.append(time.time())  # Use timestamp for X-axis
        y_data.append(packet_count)  # Store packet count

        axs[0].clear()  # Clear before redrawing
        axs[0].set_title("Traffic Over Time")
        axs[0].set_xlabel("Time")
        axs[0].set_ylabel("Packet Count")
        axs[0].plot(x_data, y_data, marker="o", linestyle="-", color="blue")

        # ✅ Update Bar Chart - Protocol Distribution
        axs[1].clear()
        axs[1].bar(protocol_counts.keys(), protocol_counts.values(), color=["red", "green", "blue"])
        axs[1].set_title("Protocol Distribution")

        # ✅ Update Pie Chart - Traffic Composition
        axs[2].clear()
        axs[2].pie(protocol_counts.values(), labels=protocol_counts.keys(), autopct="%1.1f%%")
        axs[2].set_title("Traffic Composition")

        canvas.draw()
        frame.after(5000, update_charts)  # Refresh every 5s

    update_charts()  # Start updating
    return frame