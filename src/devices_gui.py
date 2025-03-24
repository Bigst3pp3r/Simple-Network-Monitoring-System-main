import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import socket
import requests
import sqlite3
from database.database import log_device, get_most_active_devices, generate_device_report
from datetime import datetime
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure



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
        pass  
    return "Unknown"

def get_device_name(ip):
    """Retrieves the hostname (device name) if available."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def get_ttl(ip):
    """Gets the TTL value by sending an ICMP packet."""
    try:
        pkt = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
        return pkt.ttl if pkt else None
    except Exception:
        return None

def get_device_type(ip, mac):
    """Determines the device type based on MAC and TTL values."""
    manufacturer = get_manufacturer(mac)
    ttl = get_ttl(ip)

    if "Apple" in manufacturer:
        return "MacBook / iPhone"
    elif "Dell" in manufacturer or "Lenovo" in manufacturer:
        return "Laptop / PC"
    elif "TP-Link" in manufacturer or "Cisco" in manufacturer:
        return "Router / Network Device"
    elif ttl:
        if ttl <= 64:
            return "Linux / Android"
        elif ttl <= 128:
            return "Windows Device"
        elif ttl >= 200:
            return "Router / IoT Device"
    return "Unknown Device"

# ✅ Global Variable for Auto-Scanning
auto_scan_running = False  

def scan_network(network_ip, update_ui_callback, scan_button):
    """Scans the network and updates the database without removing inactive devices."""
    active_macs = set()

    if not network_ip or "/" not in network_ip:
        print("❌ Invalid network IP format. Example: '192.168.1.0/24'")
        return

    def scan():
        try:
            scan_button.config(text="🔄 Scanning... Please wait", state=tk.DISABLED)
            
            arp = ARP(pdst=network_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=2, verbose=0)[0]

            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()

                for sent, received in result:
                    ip = received.psrc
                    mac_address = received.hwsrc.upper()
                    manufacturer = get_manufacturer(mac_address)
                    device_name = get_device_name(ip)
                    device_type = get_device_type(ip, mac_address)
                    last_seen = datetime.now()

                    active_macs.add(mac_address)

                    cursor.execute("SELECT id FROM logged_devices WHERE mac_address = ?", (mac_address,))
                    existing = cursor.fetchone()

                    if existing:
                        cursor.execute("""
                            UPDATE logged_devices 
                            SET status = 'Active', last_seen = ?, ip_address = ?, manufacturer = ?, device_name = ?, device_type = ?
                            WHERE mac_address = ?
                        """, (last_seen, ip, manufacturer, device_name, device_type, mac_address))
                    else:
                        cursor.execute("""
                            INSERT INTO logged_devices (ip_address, mac_address, manufacturer, device_name, device_type, status, last_seen) 
                            VALUES (?, ?, ?, ?, ?, 'Active', ?)
                        """, (ip, mac_address, manufacturer, device_name, device_type, last_seen))

                    conn.commit()

                cursor.execute("SELECT mac_address FROM logged_devices WHERE status = 'Active'")
                logged_macs = {row[0] for row in cursor.fetchall()}

                for mac in logged_macs - active_macs:
                    cursor.execute("UPDATE logged_devices SET status = 'Inactive' WHERE mac_address = ?", (mac,))
                conn.commit()
                
        except Exception as e:
            print(f"❌ Error during scan: {e}")

        update_ui_callback()  # ✅ Update UI with the new statuses
        scan_button.config(text="🔍 Scan Network", state=tk.NORMAL)

    # Run scan in a separate thread to prevent UI freezing
    threading.Thread(target=scan, daemon=True).start()
    
def show_most_active_devices():
    """Displays a compact pop-up showing the most active devices."""
    top = tk.Toplevel()
    top.title("Most Active Devices")
    top.geometry("500x300")  # ✅ Set a fixed size (width x height)

    # Center the pop-up on screen
    top.update_idletasks()
    screen_width = top.winfo_screenwidth()
    screen_height = top.winfo_screenheight()
    x = (screen_width // 2) - (500 // 2)  # Center horizontally
    y = (screen_height // 2) - (300 // 2)  # Center vertically
    top.geometry(f"+{x}+{y}")

    label = tk.Label(top, text="Most Active Devices", font=("Arial", 12, "bold"))
    label.pack(pady=5)

    # Fetch data
    most_active = get_most_active_devices(limit=5)

    # Create a compact table
    tree = ttk.Treeview(top, columns=("IP", "MAC", "Name", "Type", "Activity"), show="headings", height=5)
    tree.pack(pady=5, padx=10)

    # Define column headings
    columns = [("IP", "IP Address"), ("MAC", "MAC Address"), ("Name", "Device Name"), 
               ("Type", "Device Type"), ("Activity", "Activity Count")]
    
    for col, heading in columns:
        tree.heading(col, text=heading)
        tree.column(col, width=90, anchor="center")  # ✅ Set fixed column width

    # Insert data
    for device in most_active:
        tree.insert("", "end", values=device)

    # Close button
    close_button = ttk.Button(top, text="Close", command=top.destroy)
    close_button.pack(pady=10)

    # Prevent resizing
    top.resizable(False, False)  # ✅ Disable resizing

def show_new_device_popup(device):
    """Displays a pop-up window with new device details."""
    popup = tk.Toplevel()
    popup.title("New Device Detected")
    popup.geometry("400x250")
    
    ttk.Label(popup, text=f"New Device Detected!", font=("Arial", 14, "bold")).pack(pady=10)
    
    details = f"IP: {device[0]}\nMAC: {device[1]}\nManufacturer: {device[2]}\nDevice: {device[3]} ({device[4]})"
    ttk.Label(popup, text=details, font=("Arial", 12)).pack(pady=10)
    
    ttk.Button(popup, text="OK", command=popup.destroy).pack(pady=10)

# ✅ Save Report Function
def save_report():
    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
        title="Save Device Report"
    )
    
    if file_path:  # If user selects a location
        generate_device_report(file_path)
        messagebox.showinfo("Success", f"Report saved successfully!\n📂 {file_path}")
        
def create_network_graph(frame):
    """Displays a force-directed network graph with edges representing communication."""
    G = nx.Graph()

    with sqlite3.connect("network_monitoring.db") as conn:
        cursor = conn.cursor()

        # ✅ Fetch devices (Ensure status is not NULL)
        cursor.execute("SELECT ip_address, mac_address, COALESCE(status, '') FROM logged_devices")
        devices = cursor.fetchall()

        # ✅ Fetch communications (Modify this query if needed)
        cursor.execute("""
            SELECT source_ip, destination_ip FROM packets
            WHERE protocol != 'ARP'  -- Ignore ARP, focus on real communication
        """)
        connections = cursor.fetchall()

    # ✅ Add nodes (devices)
    for ip, mac, status in devices:
        is_active = (status.lower() == "active")  # Normalize status check
        G.add_node(ip, label=ip, active=is_active)

    def is_valid_ip(ip):
        """Ignore multicast (224.x - 239.x) & broadcast (255.255.255.255)."""
        return ip and not ip.startswith(("239.", "224.")) and ip != "255.255.255.255"

    # ✅ Add edges only for valid device communications
    for src, dst in connections:
        if is_valid_ip(src) and is_valid_ip(dst) and src in G and dst in G:
            G.add_edge(src, dst)

    # ✅ Create figure
    fig = Figure(figsize=(6, 4))
    ax = fig.add_subplot(111)
    pos = nx.spring_layout(G)  # Force-directed layout

    # ✅ Debug: Ensure all nodes have attributes
    print("Nodes in Graph:", G.nodes(data=True))

    # ✅ Draw Nodes
    active_nodes = [n for n, attr in G.nodes(data=True) if attr.get("active", False)]
    inactive_nodes = [n for n, attr in G.nodes(data=True) if not attr.get("active", False)]

    nx.draw(G, pos, ax=ax, node_size=500, with_labels=True, labels=nx.get_node_attributes(G, "label"))
    nx.draw_networkx_nodes(G, pos, ax=ax, nodelist=active_nodes, node_color="green")
    nx.draw_networkx_nodes(G, pos, ax=ax, nodelist=inactive_nodes, node_color="red")

    # ✅ Draw Edges
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="blue")

    # ✅ Embed in Tkinter
    for widget in frame.winfo_children():
        widget.destroy()  # Clear old graph before redrawing

    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # ✅ Refresh every 10 seconds for real-time updates
    frame.after(10000, lambda: create_network_graph(frame))
 

def create_devices_tab(parent):
    """Creates the devices GUI tab."""
    frame = ttk.Frame(parent, padding=10)

    # ✅ Title Label
    ttk.Label(frame, text="🖥️ Connected Devices", font=("Arial", 14, "bold")).pack(pady=5)

    # ✅ Scan Button
    scan_button = ttk.Button(frame, text="🔍 Scan Network", command=lambda: start_scan_thread(update_table, scan_button))
    scan_button.pack(pady=5)

    # ✅ Auto-Scan Button
    auto_scan_button = ttk.Button(frame, text="▶ Start Auto-Scanning", command=lambda: toggle_auto_scan(auto_scan_button, scan_button))
    auto_scan_button.pack(pady=5)
    
    # ✅ Most Active Devices Button (Opens Modal)
    device_frame = ttk.Frame(frame)
    device_frame.pack(fill=tk.X, pady=2)

    # ✅ Most Active Devices Button (Opens Modal)
    most_active_button = ttk.Button(device_frame, text="Most Active Devices", command=show_most_active_devices)
    most_active_button.pack(side=tk.LEFT, pady=2.5)

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
    
    # ✅ Report Button
    report_button = ttk.Button(frame, text="📄 Generate CSV Report", command=save_report)
    report_button.pack(pady=10)
    
    # ✅ Frame for the network graph
    graph_frame = ttk.Frame(frame)
    graph_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # ✅ Call function to generate the network graph
    create_network_graph(graph_frame)

    # ✅ Update Table
    def update_table():
        """Fetches all devices from the database and updates the UI."""
        
        device_tree.delete(*device_tree.get_children())  # Clear table before inserting new data

        with sqlite3.connect("network_monitoring.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address, mac_address, manufacturer, device_name, device_type, status FROM logged_devices")
            devices = cursor.fetchall()

        if not devices:
            print("⚠️ No devices found in the database.")
            return

        for device in devices:
            ip, mac, manufacturer, name, device_type, status = device
            
            # ✅ Normalize status inside the loop (Fixes the NameError issue)
            normalized_status = "Active" if status.lower() == "active" else "Inactive"
            
            color = "green" if normalized_status == "Active" else "red"
            device_tree.insert("", tk.END, values=(ip, mac, manufacturer, name, device_type, normalized_status), tags=(normalized_status,))

        # ✅ Apply color tags
        device_tree.tag_configure("Active", foreground="green")
        device_tree.tag_configure("Inactive", foreground="red")


  
            
    def start_scan_thread(update_ui_callback, scan_button):
        """Starts the network scan in a separate thread to avoid UI freezing."""
        threading.Thread(target=scan_network, args=("192.168.0.1/24", update_ui_callback, scan_button), daemon=True).start()

    def toggle_auto_scan(auto_scan_button, scan_button):
        """Starts or stops automatic network scanning."""
        global auto_scan_running  
        if auto_scan_running:
            auto_scan_running = False
            auto_scan_button.config(text="▶ Start Auto-Scanning")
        else:
            auto_scan_running = True
            auto_scan_button.config(text="⏹ Stop Auto-Scanning")
            auto_scan_loop(scan_button)

    def auto_scan_loop(scan_button):
        """Continuously scans the network at intervals."""
        if auto_scan_running:
            start_scan_thread(update_table, scan_button)  
            frame.after(15000, lambda: auto_scan_loop(scan_button))  # Repeat every 15 sec

    return frame

