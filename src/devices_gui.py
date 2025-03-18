import tkinter as tk
from tkinter import ttk
import threading
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import socket
import requests
import sqlite3
from database.database import log_device, get_logged_devices, update_device_status
# ✅ OUI API for MAC lookup
OUI_LOOKUP_API = "https://api.maclookup.app/v2/macs/"

def get_manufacturer(mac_address):
    """Fetches manufacturer using MAC address (fallback for failures)."""
    try:
        response = requests.get(OUI_LOOKUP_API + mac_address, timeout=3)
        if response.status_code == 200:
            data = response.json()
            return data.get("company", "Unknown Manufacturer")
    except requests.RequestException:
        pass  # Ignore errors

    # Fallback: Extract first 6 characters of MAC (OUI) and guess
    oui_prefix = mac_address[:8].upper()
    known_vendors = {
        "00:1A:79": "Cisco",
        "00:17:3F": "Apple",
        "FC:A1:3E": "Samsung",
        "00:25:9C": "Dell",
        "AC:CF:5C": "Huawei",
        "20:37:06": "HP",
    }
    return known_vendors.get(oui_prefix, "Unknown Manufacturer")


def get_device_name(ip):
    """Retrieves the hostname (device name) if available."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"
    
def get_ttl(ip):
    """Gets the TTL value by sending an ICMP packet (handles no response)."""
    try:
        pkt = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
        return pkt.ttl if pkt else "Unknown"
    except Exception:
        return "Unknown"
    
def get_device_type(ip, mac):
    """Determines the device type based on MAC and TTL values."""
    manufacturer = get_manufacturer(mac)
    ttl = get_ttl(ip)

    # ✅ Ensure TTL is an integer
    try:
        ttl = int(ttl)  # Convert TTL to integer
    except (ValueError, TypeError):
        ttl = None  # If conversion fails, set TTL to None

    if "Apple" in manufacturer:
        return "MacBook / iPhone"
    elif "Dell" in manufacturer or "Lenovo" in manufacturer:
        return "Laptop / PC"
    elif "TP-Link" in manufacturer or "Cisco" in manufacturer:
        return "Router / Network Device"
    elif ttl is not None:
        if ttl <= 64:
            return "Linux / Android"
        elif ttl <= 128:
            return "Windows Device"
        elif ttl >= 200:
            return "Router / IoT Device"
    
    return "Unknown Device"




    

def scan_network(network_ip, update_ui_callback):
    """
    Scans the network using ARP, logs devices into the database, and updates the UI.

    Args:
        network_ip (str): The network IP range (e.g., '192.168.1.0/24').
        update_ui_callback (function): Function to update the UI with scanned results.
    """
    devices = []
    detected_ips = set()

    try:
        # Send ARP requests
        arp = ARP(pdst=network_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]

        for sent, received in result:
            ip = received.psrc
            mac_address = received.hwsrc.upper()
            manufacturer = get_manufacturer(mac_address)
            device_name = get_device_name(ip)
            device_type = get_device_type(ip, mac_address)

            detected_ips.add(ip)  # Track active IPs
            
            # ✅ Log the device into the database (or update if it exists)
            log_device(ip, mac_address, manufacturer, device_name, device_type, status="active")

            # ✅ Append to UI update list
            devices.append((ip, mac_address, manufacturer, device_name, device_type))

        # ✅ Mark disconnected devices in the database
        all_logged_devices = get_logged_devices()
        for logged_device in all_logged_devices:
            db_ip = logged_device[1]  # Get IP from database
            if db_ip not in detected_ips:
                update_device_status(db_ip, status="disconnected")

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
    scan_button = ttk.Button(frame, text="🔍 Scan Network", command=lambda: start_scan_thread(update_table))
    scan_button.pack(pady=5)

    # ✅ Table Frame
    table_frame = ttk.Frame(frame)
    table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # ✅ Define Columns
    columns = ("IP Address", "MAC Address", "Manufacturer", "Device Name", "Device Type", "Status")
    device_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)

    # ✅ Style Headers
    for col in columns:
        device_tree.heading(col, text=col, anchor=tk.CENTER)
        device_tree.column(col, width=150, anchor=tk.CENTER)

    # ✅ Apply Row Stripes & Styling
    style = ttk.Style()
    style.configure("Treeview", font=("Arial", 10), rowheight=25)  # Adjust row height
    style.configure("Treeview.Heading", font=("Arial", 11, "bold"))  # Bold headers
    style.map("Treeview", background=[("selected", "#3498db")])  # Row selection color
    
    # ✅ Add Vertical Scrollbar
    v_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=device_tree.yview)
    device_tree.configure(yscrollcommand=v_scroll.set)
    v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    # ✅ Add Horizontal Scrollbar
    h_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=device_tree.xview)
    device_tree.configure(xscrollcommand=h_scroll.set)
    h_scroll.pack(fill=tk.X)

    device_tree.pack(fill=tk.BOTH, expand=True)

    def update_table(devices):
        """Updates the UI table with scanned devices, including their status."""
        device_tree.delete(*device_tree.get_children())  # Clear table

        if not devices:
            print("⚠️ No devices to display.")  # Debugging
            return

        for device in devices:
            ip, mac, manufacturer, name, device_type = device
            
            # ✅ Fetch device status from DB
            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT status FROM logged_devices WHERE ip_address = ?", (ip,))
                status = cursor.fetchone()
            
            status_text = status[0] if status else "Unknown"

            # ✅ Insert row with status
            device_tree.insert("", tk.END, values=(ip, mac, manufacturer, name, device_type, status_text))


    def start_scan_thread(update_ui_callback):
        """Starts the network scan in a separate thread to avoid UI freezing."""
        threading.Thread(target=scan_network, args=("192.168.0.1/24", update_ui_callback), daemon=True).start()

    return frame
