import tkinter as tk
from tkinter import ttk, messagebox

# Default settings (could be loaded from a file or database later)
settings = {
    "filter": None,  # Filter string (None means no filter)
    "high_packet_rate_threshold": 100,
    "icmp_activity_threshold": 10,
    "blacklisted_ips": [],
    "network_range": "192.168.1.0/24"
}

def create_settings_tab(notebook):
    """
    Creates the Settings tab with sections for Filters, Thresholds, Blacklist,
    Real-Time Device Monitoring, and Start/Save Monitoring.
    Returns the settings frame.
    """
    frame = ttk.Frame(notebook, padding=10)
    
    # --- Filters Section ---
    lf_filters = ttk.LabelFrame(frame, text="Filter Settings", padding=10)
    lf_filters.pack(fill="x", pady=5)
    
    # Filter Type Dropdown
    ttk.Label(lf_filters, text="Select Filter Type:").grid(row=0, column=0, sticky="w")
    filter_options = ["No filter", "Protocol", "IP", "Port"]
    filter_var = tk.StringVar(value="No filter")
    cmb_filter = ttk.Combobox(lf_filters, textvariable=filter_var, values=filter_options, state="readonly", width=15)
    cmb_filter.grid(row=0, column=1, padx=5, pady=5)
    
    # Filter Value Entry (only used if filter type is not "No filter")
    ttk.Label(lf_filters, text="Filter Value:").grid(row=1, column=0, sticky="w")
    filter_value_var = tk.StringVar()
    entry_filter_value = ttk.Entry(lf_filters, textvariable=filter_value_var, width=20)
    entry_filter_value.grid(row=1, column=1, padx=5, pady=5)
    
    def apply_filter():
        f_type = filter_var.get()
        f_val = filter_value_var.get().strip()
        if f_type == "No filter":
            settings["filter"] = None
        elif f_type == "Protocol":
            settings["filter"] = f"{f_val.lower()}" if f_val else None
        elif f_type == "IP":
            settings["filter"] = f"host {f_val}" if f_val else None
        elif f_type == "Port":
            settings["filter"] = f"port {f_val}" if f_val else None
        messagebox.showinfo("Filter Updated", f"Filter set to: {settings['filter']}")
    
    btn_apply_filter = ttk.Button(lf_filters, text="Apply Filter", command=apply_filter)
    btn_apply_filter.grid(row=2, column=0, columnspan=2, pady=5)
    
    # --- Threshold Management Section ---
    lf_threshold = ttk.LabelFrame(frame, text="Threshold Management", padding=10)
    lf_threshold.pack(fill="x", pady=5)
    
    # High Packet Rate Threshold
    ttk.Label(lf_threshold, text="High Packet Rate Threshold:").grid(row=0, column=0, sticky="w")
    high_rate_var = tk.IntVar(value=settings["high_packet_rate_threshold"])
    entry_high_rate = ttk.Entry(lf_threshold, textvariable=high_rate_var, width=10)
    entry_high_rate.grid(row=0, column=1, padx=5, pady=5)
    
    # ICMP Activity Threshold
    ttk.Label(lf_threshold, text="ICMP Activity Threshold:").grid(row=1, column=0, sticky="w")
    icmp_threshold_var = tk.IntVar(value=settings["icmp_activity_threshold"])
    entry_icmp_threshold = ttk.Entry(lf_threshold, textvariable=icmp_threshold_var, width=10)
    entry_icmp_threshold.grid(row=1, column=1, padx=5, pady=5)
    
    def update_thresholds():
        try:
            settings["high_packet_rate_threshold"] = high_rate_var.get()
            settings["icmp_activity_threshold"] = icmp_threshold_var.get()
            messagebox.showinfo("Thresholds Updated", f"High Packet Rate: {settings['high_packet_rate_threshold']}\nICMP Threshold: {settings['icmp_activity_threshold']}")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid input: {e}")
    
    btn_update_thresholds = ttk.Button(lf_threshold, text="Update Thresholds", command=update_thresholds)
    btn_update_thresholds.grid(row=2, column=0, columnspan=2, pady=5)
    
    # --- Blacklist Management Section ---
    lf_blacklist = ttk.LabelFrame(frame, text="Blacklist Management", padding=10)
    lf_blacklist.pack(fill="x", pady=5)
    
    ttk.Label(lf_blacklist, text="Add IP to Blacklist:").grid(row=0, column=0, sticky="w")
    blacklist_ip_var = tk.StringVar()
    entry_blacklist_ip = ttk.Entry(lf_blacklist, textvariable=blacklist_ip_var, width=20)
    entry_blacklist_ip.grid(row=0, column=1, padx=5, pady=5)
    
    def add_to_blacklist():
        ip = blacklist_ip_var.get().strip()
        if ip and ip not in settings["blacklisted_ips"]:
            settings["blacklisted_ips"].append(ip)
            update_blacklist_list()
            messagebox.showinfo("Blacklist", f"Added {ip} to blacklist.")
        else:
            messagebox.showwarning("Blacklist", f"IP is empty or already blacklisted.")
    
    btn_add_blacklist = ttk.Button(lf_blacklist, text="Add to Blacklist", command=add_to_blacklist)
    btn_add_blacklist.grid(row=1, column=0, columnspan=2, pady=5)
    
    ttk.Label(lf_blacklist, text="Current Blacklisted IPs:").grid(row=2, column=0, sticky="w")
    list_blacklist = tk.Listbox(lf_blacklist, height=4)
    list_blacklist.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
    
    def update_blacklist_list():
        list_blacklist.delete(0, tk.END)
        for ip in settings["blacklisted_ips"]:
            list_blacklist.insert(tk.END, ip)
    
    def remove_from_blacklist():
        selected = list_blacklist.curselection()
        if selected:
            ip = list_blacklist.get(selected[0])
            settings["blacklisted_ips"].remove(ip)
            update_blacklist_list()
            messagebox.showinfo("Blacklist", f"Removed {ip} from blacklist.")
        else:
            messagebox.showwarning("Blacklist", "No IP selected.")
    
    btn_remove_blacklist = ttk.Button(lf_blacklist, text="Remove Selected IP", command=remove_from_blacklist)
    btn_remove_blacklist.grid(row=4, column=0, columnspan=2, pady=5)
    
    update_blacklist_list()
    
    # --- Real-Time Device Monitoring Section ---
    lf_realtime = ttk.LabelFrame(frame, text="Real-Time Device Monitoring", padding=10)
    lf_realtime.pack(fill="x", pady=5)
    
    ttk.Label(lf_realtime, text="Network IP Range (e.g., 192.168.1.0/24):").grid(row=0, column=0, sticky="w")
    network_range_var = tk.StringVar(value=settings["network_range"])
    entry_network_range = ttk.Entry(lf_realtime, textvariable=network_range_var, width=20)
    entry_network_range.grid(row=0, column=1, padx=5, pady=5)
    
    def update_network_range():
        nr = network_range_var.get().strip()
        if nr:
            settings["network_range"] = nr
            messagebox.showinfo("Network Range Updated", f"Network range set to: {nr}")
        else:
            messagebox.showwarning("Network Range", "Please enter a valid network range.")
    
    btn_update_network_range = ttk.Button(lf_realtime, text="Update Network Range", command=update_network_range)
    btn_update_network_range.grid(row=1, column=0, columnspan=2, pady=5)
    
    # --- Start Monitoring & Save Settings Section ---
    lf_monitor = ttk.LabelFrame(frame, text="Monitoring Control", padding=10)
    lf_monitor.pack(fill="x", pady=5)
    
    start_monitor_var = tk.BooleanVar(value=False)
    chk_save_settings = ttk.Checkbutton(lf_monitor, text="Save Settings Persistently", variable=start_monitor_var)
    chk_save_settings.grid(row=0, column=0, columnspan=2, pady=5)
    
    def start_monitoring_from_settings():
        update_network_range()  # Ensure network range is updated
        # Here we simply show a message; later, integrate with the monitoring process.
        messagebox.showinfo("Start Monitoring", f"Monitoring started with settings:\nFilter: {settings['filter']}\nHigh Packet Rate Threshold: {settings['high_packet_rate_threshold']}\nICMP Threshold: {settings['icmp_activity_threshold']}\nBlacklisted IPs: {', '.join(settings['blacklisted_ips'])}\nNetwork Range: {settings['network_range']}")
    
    btn_start_monitoring = ttk.Button(lf_monitor, text="Start Monitoring", command=start_monitoring_from_settings)
    btn_start_monitoring.grid(row=1, column=0, columnspan=2, pady=5)
    
    return frame



