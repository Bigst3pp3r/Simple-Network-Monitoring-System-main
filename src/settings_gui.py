import tkinter as tk
from tkinter import ttk, messagebox
from filters import get_thresholds, update_thresholds, get_blacklisted_ips, add_blacklisted_ip, remove_blacklisted_ip
from filters import get_filters, add_filter, remove_filter


def create_settings_tab(parent):
    frame = ttk.Frame(parent)
    # --- Threshold Settings ---
    ttk.Label(frame, text="Threshold Settings",
              font=("Arial", 12, "bold")).pack(pady=5)
    threshold_values = get_thresholds()

    ttk.Label(frame, text="High Packet Rate Threshold:").pack()
    high_packet_entry = ttk.Entry(frame)
    high_packet_entry.insert(0, str(threshold_values["high_packet_threshold"]))
    high_packet_entry.pack(pady=2)

    ttk.Label(frame, text="Suspicious ICMP Activity Threshold:").pack()
    icmp_threshold_entry = ttk.Entry(frame)
    icmp_threshold_entry.insert(
        0, str(threshold_values["icmp_activity_threshold"]))
    icmp_threshold_entry.pack(pady=2)

    def save_thresholds():
        try:
            new_high = int(high_packet_entry.get())
            new_icmp = int(icmp_threshold_entry.get())
            update_thresholds(new_high, new_icmp)
            messagebox.showinfo("Success", "Thresholds updated successfully!")
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers!")

    ttk.Button(frame, text="Save Thresholds",
               command=save_thresholds).pack(pady=5)

    # --- Blacklist Management ---
    ttk.Label(frame, text="Manage Blacklisted IPs",
              font=("Arial", 12, "bold")).pack(pady=10)
    blacklist_listbox = tk.Listbox(frame, height=5)
    for ip in get_blacklisted_ips():
        blacklist_listbox.insert(tk.END, ip)
    blacklist_listbox.pack(pady=5)

    ip_entry = ttk.Entry(frame)
    ip_entry.pack(pady=2)

    def add_ip():
        ip = ip_entry.get().strip()
        if ip:
            add_blacklisted_ip(ip)
            blacklist_listbox.insert(tk.END, ip)
            ip_entry.delete(0, tk.END)
            messagebox.showinfo("Success", f"Added {ip} to blacklist.")

    def remove_selected_ip():
        selected_ip = blacklist_listbox.get(tk.ANCHOR)
        if selected_ip:
            remove_blacklisted_ip(selected_ip)
            blacklist_listbox.delete(tk.ANCHOR)
            messagebox.showinfo(
                "Success", f"Removed {selected_ip} from blacklist.")

    ttk.Button(frame, text="Add IP", command=add_ip).pack(pady=2)
    ttk.Button(frame, text="Remove Selected IP",
               command=remove_selected_ip).pack(pady=2)


# --- FILTER MANAGEMENT ---
    ttk.Label(frame, text="Manage Protocol & Port Filters",
          font=("Arial", 12, "bold")).pack(pady=10)

    filter_listbox = tk.Listbox(frame, height=5)
    for protocol, port in get_filters():
        filter_listbox.insert(tk.END, f"{protocol}:{port}")
    filter_listbox.pack(pady=5)

    protocol_entry = ttk.Entry(frame)
    protocol_entry.pack(pady=2)
    protocol_entry.insert(0, "TCP")  # Default protocol

    port_entry = ttk.Entry(frame)
    port_entry.pack(pady=2)
    port_entry.insert(0, "80")  # Default port


    def add_protocol_filter():
        protocol = protocol_entry.get().strip().upper()
        port = port_entry.get().strip()
        if protocol and port.isdigit():
            add_filter(protocol, int(port))
            filter_listbox.insert(tk.END, f"{protocol}:{port}")
            protocol_entry.delete(0, tk.END)
            port_entry.delete(0, tk.END)
            messagebox.showinfo("Success", f"Added filter: {protocol}:{port}")


    def remove_selected_filter():
        selected_filter = filter_listbox.get(tk.ANCHOR)
        if selected_filter:
            protocol, port = selected_filter.split(":")
            remove_filter(protocol, int(port))
            filter_listbox.delete(tk.ANCHOR)
            messagebox.showinfo("Success", f"Removed filter: {protocol}:{port}")


    ttk.Button(frame, text="Add Filter", command=add_protocol_filter).pack(pady=2)
    ttk.Button(frame, text="Remove Selected Filter",
            command=remove_selected_filter).pack(pady=2)

    return frame
