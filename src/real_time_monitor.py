from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
from prettytable import PrettyTable
import socket
import requests
import time
from database.database import log_device

# OUI API URL for MAC Address lookup
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

def get_ttl(ip):
    """Gets the TTL value by sending an ICMP packet."""
    try:
        pkt = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if pkt:
            return pkt.ttl
    except:
        return None

def get_device_type(ip, mac):
    """Determines the device type based on MAC and TTL values."""
    manufacturer = get_manufacturer(mac)
    ttl = get_ttl(ip)

    # Guess device based on MAC manufacturer
    if "Apple" in manufacturer:
        return "MacBook / iPhone"
    elif "Dell" in manufacturer or "Lenovo" in manufacturer or "HP" in manufacturer or "Acer" in manufacturer or "Microsoft" in manufacturer or "Intel" in manufacturer or "ASUSTek" in manufacturer or "Toshiba" in manufacturer:
        return "Laptop / PC"
    elif "TP-Link" in manufacturer or "Cisco" in manufacturer or "Netgear" in manufacturer:
        return "Router / Network Device"
    elif "Hikvision" in manufacturer or "Dahua" in manufacturer or "Axis Communications" in manufacturer or "Hanwha Techwin" in manufacturer or "Panasonic" in manufacturer:
        return "IP Camera"
    elif "GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD" in manufacturer or "Xiaomi" in manufacturer or "OnePlus" in manufacturer or "Vivo" in manufacturer or "Realme" in manufacturer or "Motorola" in manufacturer or "Nokia" in manufacturer or "Sony" in manufacturer or "Google" in manufacturer or "Asus" in manufacturer or "LG" in manufacturer or "HTC" in manufacturer or "ZTE" in manufacturer or "Huawei" in manufacturer or "Samsung" in manufacturer  or "Infinix" in manufacturer or "Tecno" in manufacturer or "Itel" in manufacturer:
        return "Android Device"

    # Guess OS based on TTL
    if ttl:
        if ttl <= 64:
            return "Linux Device / android"
        elif ttl <= 128:
            return "Windows Device"
        elif ttl >= 200:
            return "Router / IoT Device"

    return "Unknown Device"

def scan_network(network_ip):
    """Scans the network using ARP requests."""
    devices = []
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

        devices.append({
            "ip": ip,
            "mac": mac_address,
            "manufacturer": manufacturer,
            "device_name": device_name,
            "device_type": device_type
        })
    
    return devices

def display_devices(devices):
    """Displays the device list in a table format."""
    table = PrettyTable()
    table.field_names = ["IP Address", "MAC Address", "Manufacturer", "Device Name", "Device Type"]
    
    for device in devices:
        table.add_row([device["ip"], device["mac"], device["manufacturer"], device["device_name"], device["device_type"]])
    
    print(table)

def monitor_network(network_ip, interval=10):
    """
    Continuously monitors the network for active devices.
    """
    known_devices = []
    print("\n--- Real-Time Device Monitoring ---")
    print("Press Ctrl+C to stop monitoring.\n")

    try:
        while True:
            current_devices = scan_network(network_ip)
            current_ips = {device["ip"] for device in current_devices}

            for device in current_devices:
                if device not in known_devices:
                    print(f"\n🔹 New Device Connected: IP={device['ip']}, MAC={device['mac']}, Name={device['device_name']}, Type={device['device_type']}")
                    log_device(device["ip"], device["mac"], device["manufacturer"], device["device_name"], device["device_type"], status="connected")

            for device in known_devices:
                if device["ip"] not in current_ips:
                    print(f"\n❌ Device Disconnected: IP={device['ip']}, MAC={device['mac']}, Name={device['device_name']}, Type={device['device_type']}")
                    log_device(device["ip"], device["mac"], device["manufacturer"], device["device_name"], device["device_type"], status="disconnected")

            known_devices = current_devices
            print("\n--- Current Devices ---")
            display_devices(current_devices)
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    except Exception as e:
        print(f"Error during monitoring: {e}")

if __name__ == "__main__":
    network_range = "192.168.0.1/24"
    monitor_network(network_range)
