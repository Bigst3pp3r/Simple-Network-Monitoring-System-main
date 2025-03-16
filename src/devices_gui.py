import tkinter as tk
from tkinter import ttk
import threading
from scapy.all import ARP, Ether, srp
import socket
import requests

# ✅ OUI API for MAC lookup
OUI_LOOKUP_API = "https://api.maclookup.app/v2/macs/"

def get_manufacturer(mac_address):
    """Fetches manufacturer using MAC address."""
    try:
        response = requests.get(OUI_LOOKUP_API + mac_address, timeout=3)
        data = response.json()
        return data.get("company", "Unknown Manufacturer")
    except:
        return "Lookup Failed"

def get_device_name(ip):
    """Retrieves the hostname (device name) if available."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def scan_network(network_ip, update_ui_callback):
    """Scans the network using ARP and updates the UI."""
    devices = []
    try:
        arp = ARP(pdst=network_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]

        for sent, received in result:
            ip = received.psrc
            mac_address = received.hwsrc.upper()
            manufacturer = get_manufacturer(mac_address)
            device_name = get_device_name(ip)

            devices.append((ip, mac_address, manufacturer, device_name))
        
        if devices:
            print(f"✅ {len(devices)} Devices Found!")  # Debugging output
        else:
            print("⚠️ No devices detected.")

    except Exception as e:
        print(f"❌ Error during scan: {e}")
    
    # ✅ Update UI after scanning
    update_ui_callback(devices)

def create_devices_tab(parent):
    """Creates the devices GUI tab."""
    frame = ttk.Frame(parent, padding=10)

    # ✅ Title Label
    ttk.Label(frame, text="🖥️ Connected Devices", font=("Arial", 14, "bold")).pack(pady=5)

    # ✅ Scan Button
    scan_button = ttk.Button(frame, text="🔍 Scan Network", command=lambda: start_scan(update_table))
    scan_button.pack(pady=5)

    # ✅ Table Frame
    table_frame = ttk.Frame(frame)
    table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    columns = ("IP Address", "MAC Address", "Manufacturer", "Device Name")
    device_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)

    for col in columns:
        device_tree.heading(col, text=col, anchor=tk.W)
        device_tree.column(col, width=150 if col == "IP Address" else 200, anchor=tk.W)

    v_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=device_tree.yview)
    device_tree.configure(yscrollcommand=v_scroll.set)
    v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    device_tree.pack(fill=tk.BOTH, expand=True)

    def update_table(devices):
        """Updates the UI table with scanned devices."""
        device_tree.delete(*device_tree.get_children())  # Clear table

        if not devices:
            print("⚠️ No devices to display.")  # Debugging
            return

        for device in devices:
            device_tree.insert("", tk.END, values=device)

    def start_scan(callback):
        """Starts the network scan in a separate thread."""
        network_range = "192.168.0.1/24"  # Adjust based on your network
        threading.Thread(target=scan_network, args=(network_range, callback), daemon=True).start()

    return frame
