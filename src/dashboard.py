import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkinter import ttk
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

    # Create a main container frame for better layout
    container = tk.Frame(frame, bg="white")
    container.pack(fill="both", expand=True, padx=10, pady=10)

    # Create a Matplotlib figure with 3 subplots
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

    # Create bordered frames for each graph
    graph_frames = []
    for i in range(3):
        frame_border = tk.Frame(container, bg="black", bd=2, relief="solid")
        frame_border.pack(fill="both", expand=True, padx=5, pady=5)
        graph_frames.append(frame_border)

    # Embed Matplotlib canvas inside the graph container
    canvas = FigureCanvasTkAgg(fig, master=graph_frames[0])
    canvas.get_tk_widget().pack(fill="both", expand=True)

    # Store time (x) and packet count (y) data
    x_data, y_data = [], []  

    def update_charts():
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
