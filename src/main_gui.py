import tkinter as tk
from tkinter import ttk
from dashboard import create_dashboard_tab
from settings_gui import create_settings_tab

# Create main application window
root = tk.Tk()
root.title("Network Monitoring System")
root.geometry("900x600")

# Left Sidebar for Navigation
sidebar = tk.Frame(root, width=200, bg="#2C3E50")
sidebar.pack(side="left", fill="y")

# Main Content Frame
main_content = tk.Frame(root, bg="#ECF0F1")
main_content.pack(side="right", expand=True, fill="both")

# Sidebar Buttons & Tabs
tabs = {
    "📊 Dashboard": create_dashboard_tab(main_content),
    "⚙ Settings": create_settings_tab(main_content),
}

def switch_tab(tab_name):
    for frame in tabs.values():
        frame.pack_forget()
    tabs[tab_name].pack(fill="both", expand=True)

# Sidebar Navigation
for tab_name in tabs.keys():
    button = tk.Button(sidebar, text=tab_name, font=("Arial", 12), fg="white", bg="#34495E",
                       command=lambda t=tab_name: switch_tab(t))
    button.pack(fill="x", pady=5)

# Set Dashboard as Default View
tabs["📊 Dashboard"].pack(fill="both", expand=True)

# Run Tkinter Main Loop
root.mainloop()
