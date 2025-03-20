import tkinter as tk
import threading
from dashboard import create_dashboard_tab
from settings_gui import create_settings_tab
from alerts_gui import create_alerts_tab
from packets_gui import create_packets_tab  # ✅ Import Packets Tab
from devices_gui import create_devices_tab  # ✅ Import Devices Tab

# ✅ Lazy Import to Prevent Circular Dependency
def initialize_monitor():
    from monitoring_core import NetworkMonitor  # Import inside function
    return NetworkMonitor()

root = tk.Tk()
root.title("Network Monitoring System")
root.geometry("900x600")

sidebar = tk.Frame(root, width=200, bg="#2C3E50")
sidebar.pack(side="left", fill="y")

main_content = tk.Frame(root, bg="#ECF0F1")
main_content.pack(side="right", expand=True, fill="both")

# ✅ Create Monitor Instance
monitor = initialize_monitor()

tabs = {
    "📊 Dashboard": create_dashboard_tab(main_content, monitor),  # Pass monitor
    "📡 Packets": create_packets_tab(main_content),  # ✅ Add Packets Tab
    "🚨 Alerts": create_alerts_tab(main_content),
    "🖥️Devices": create_devices_tab(main_content),
    "⚙ Settings": create_settings_tab(main_content), 
    
}

def switch_tab(tab_name):
    for frame in tabs.values():
        frame.pack_forget()
    tabs[tab_name].pack(fill="both", expand=True)

for tab_name in tabs.keys():
    button = tk.Button(sidebar, text=tab_name, font=("Arial", 12), fg="white", bg="#34495E",
                       command=lambda t=tab_name: switch_tab(t))
    button.pack(fill="x", pady=5)

tabs["📊 Dashboard"].pack(fill="both", expand=True)

# ✅ Start Monitoring in a Background Thread
def start_monitoring():
    monitoring_thread = threading.Thread(target=monitor.start_monitoring, daemon=True)
    monitoring_thread.start()

start_monitoring()


root.mainloop()
























