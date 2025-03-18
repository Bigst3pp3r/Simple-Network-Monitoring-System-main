import tkinter as tk
from tkinter import ttk
import threading
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import socket
import requests
import sqlite3
from database.database import log_device, get_logged_devices, update_device_status, get_logged_ips
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




    

def is_device_logged(ip):
    """Checks if a device with the given IP is already logged in the database."""
    with sqlite3.connect("network_monitoring.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logged_devices WHERE ip_address = ?", (ip,))
        return cursor.fetchone()[0] > 0


# ✅ Global Variable for Auto-Scanning
auto_scan_running = False  

def scan_network(network_ip, update_ui_callback, scan_button):
    """Scans the network using ARP, logs devices into the database, and updates the UI."""
    devices = []
    detected_ips = set()

    try:
        # ✅ Show Scanning Status
        scan_button.config(text="🔄 Scanning... Please Wait", state=tk.DISABLED)

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
          

            detected_ips.add(ip)

            # ✅ Check if device is new
            if not is_device_logged(ip):
                log_device(ip, mac_address, manufacturer, device_name, device_type, status="active")
            else:
                update_device_status(ip, status="active")  

            # ✅ Append to UI update list
            devices.append((ip, mac_address, manufacturer, device_name, device_type))

        # ✅ Detect Disconnected Devices
        for logged_ip in get_logged_ips():
            if logged_ip not in detected_ips:
                update_device_status(logged_ip, status="disconnected")

        print(f"✅ {len(devices)} Devices Found!") if devices else print("⚠️ No devices detected.")

    except Exception as e:
        print(f"❌ Error during scan: {e}")

    # ✅ Restore UI After Scanning
    update_ui_callback(devices)
    scan_button.config(text="🔍 Scan Network", state=tk.NORMAL)


def create_devices_tab(parent):
    """Creates the devices GUI tab."""
    frame = ttk.Frame(parent, padding=10)

    # ✅ Title Label
    ttk.Label(frame, text="🖥️ Connected Devices", font=("Arial", 14, "bold")).pack(pady=5)

    # ✅ Scan Button
    scan_button = ttk.Button(frame, text="🔍 Scan Network", command=lambda: start_scan_thread(update_table, scan_button))
    scan_button.pack(pady=5)

    # ✅ Auto-Scan Button
    auto_scan_button = ttk.Button(frame, text="▶ Start Scanning", command=lambda: toggle_auto_scan(auto_scan_button, scan_button))
    auto_scan_button.pack(pady=5)

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

    # ✅ Scrollbars
    v_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=device_tree.yview)
    device_tree.configure(yscrollcommand=v_scroll.set)
    v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    h_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=device_tree.xview)
    device_tree.configure(xscrollcommand=h_scroll.set)
    h_scroll.pack(fill=tk.X)

    device_tree.pack(fill=tk.BOTH, expand=True)

    def update_table(devices):
        """Updates the UI table with scanned devices."""
        device_tree.delete(*device_tree.get_children())  

        if not devices:
            print("⚠️ No devices to display.")  
            return

        for device in devices:
            ip, mac, manufacturer, name, device_type = device

            # ✅ Fetch device status from DB
            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT status FROM logged_devices WHERE ip_address = ?", (ip,))
                status = cursor.fetchone()
            
            status_text = status[0] if status else "Unknown"
            device_tree.insert("", tk.END, values=(ip, mac, manufacturer, name, device_type, status_text))

    def start_scan_thread(update_ui_callback, scan_button):
        """Starts the network scan in a separate thread to avoid UI freezing."""
        threading.Thread(target=scan_network, args=("192.168.0.1/24", update_ui_callback, scan_button), daemon=True).start()

    def toggle_auto_scan(auto_scan_button, scan_button):
        """Starts or stops automatic network scanning."""
        global auto_scan_running  
        if auto_scan_running:
            auto_scan_running = False
            auto_scan_button.config(text="▶ Start Scanning")
        else:
            auto_scan_running = True
            auto_scan_button.config(text="⏹ Stop Scanning")
            auto_scan_loop(scan_button)

    def auto_scan_loop(scan_button):
        """Continuously scans the network at intervals."""
        if auto_scan_running:
            start_scan_thread(update_table, scan_button)  
            frame.after(15000, lambda: auto_scan_loop(scan_button))  # Repeat every 15 sec


    return frame

