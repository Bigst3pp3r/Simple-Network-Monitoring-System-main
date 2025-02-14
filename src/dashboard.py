import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import random  # Simulating data updates

def create_dashboard_tab(parent):
    frame = tk.Frame(parent, bg="white")

    # Create Matplotlib Figure for Charts
    fig, axs = plt.subplots(3, 1, figsize=(5, 8))

    # Line Graph - Traffic Over Time
    axs[0].set_title("Traffic Over Time")
    axs[0].set_xlabel("Time")
    axs[0].set_ylabel("Packet Count")
    traffic_data = [random.randint(50, 150) for _ in range(10)]
    line, = axs[0].plot(traffic_data, marker="o", linestyle="-", color="blue")

    # Bar Chart - Protocol Distribution
    protocol_counts = [random.randint(20, 100) for _ in range(3)]  # [TCP, UDP, ICMP]
    protocols = ["TCP", "UDP", "ICMP"]
    axs[1].bar(protocols, protocol_counts, color=["red", "green", "blue"])
    axs[1].set_title("Protocol Distribution")
    axs[1].set_ylabel("Packet Count")

    # Pie Chart - Traffic Composition
    axs[2].pie(protocol_counts, labels=protocols, autopct="%1.1f%%", colors=["red", "green", "blue"])
    axs[2].set_title("Traffic Composition")

    # Embed Charts in Tkinter
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    # Update Function for Real-Time Graphs
    def update_charts():
        nonlocal traffic_data, protocol_counts

        # Update Traffic Line Graph
        traffic_data.append(random.randint(50, 150))
        traffic_data.pop(0)
        line.set_ydata(traffic_data)

        # Update Protocol Distribution (Bar Chart)
        protocol_counts = [random.randint(20, 100) for _ in range(3)]
        axs[1].clear()
        axs[1].bar(protocols, protocol_counts, color=["red", "green", "blue"])
        axs[1].set_title("Protocol Distribution")
        axs[1].set_ylabel("Packet Count")

        # Update Traffic Composition (Pie Chart)
        axs[2].clear()
        axs[2].pie(protocol_counts, labels=protocols, autopct="%1.1f%%", colors=["red", "green", "blue"])
        axs[2].set_title("Traffic Composition")

        canvas.draw()
        frame.after(5000, update_charts)  # Update every 5 seconds

    # Start Real-Time Updates
    update_charts()

    return frame
