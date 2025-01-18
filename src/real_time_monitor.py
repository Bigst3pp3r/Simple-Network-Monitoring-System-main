from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
from prettytable import PrettyTable
import socket
import requests
import time
import nmap
import re

# OUI API URL for MAC Address lookup
OUI_LOOKUP_API = "https://api.maclookup.app/v2/macs/"

def get_manufacturer(mac_address):
    """
    Fetches the manufacturer of a device using its MAC address.
    """
    try:
        response = requests.get(OUI_LOOKUP_API + mac_address, timeout=3)
        data = response.json()
        return data.get("company", "Unknown Manufacturer")
    except:
        return "Lookup Failed"

def get_device_name(ip):
    """
    Retrieves the hostname (device name) if available.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def get_ttl(ip):
    """
    Sends a ping request to check the Time-To-Live (TTL) value.
    TTL helps determine the device type or OS.
    """
    try:
        pkt = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if pkt:
            return pkt.ttl
    except:
        return None

def get_http_banner(ip):
    """
    Attempts to grab an HTTP banner for additional fingerprinting.
    """
    try:
        response = requests.get(f"http://{ip}", timeout=2)
        server_header = response.headers.get("Server", "Unknown")
        return server_header
    except:
        return "No HTTP Response"

def scan_ports(ip):
    """
    Scans common ports to help determine device type.
    """
    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip, arguments="-p 22,80,443,554,3389 --open")
        open_ports = [port for port in scanner[ip]['tcp'].keys() if scanner[ip]['tcp'][port]['state'] == 'open']
        return open_ports
    except:
        return []

def get_device_type(ip, mac):
    """
    Determines the type of device based on MAC manufacturer, TTL, open ports, and HTTP banners.
    """
    manufacturer = get_manufacturer(mac)
    ttl = get_ttl(ip)
    http_banner = get_http_banner(ip)
    open_ports = scan_ports(ip)
    
    if "Apple" in manufacturer:
        return "MacBook / iPhone"
    elif "Samsung" in manufacturer:
        return "Samsung Device"
    elif "Dell" in manufacturer or "Lenovo" in manufacturer or "HP" in manufacturer:
        return "Laptop / PC"
    elif "TP-Link" in manufacturer or "Cisco" in manufacturer or "Netgear" in manufacturer:
        return "Router / Network Device"
    elif "Hikvision" in manufacturer or "Dahua" in manufacturer:
        return "IP Camera"
    
    if ttl:
        if ttl <= 64:
            return "Linux Device"
        elif ttl <= 128:
            return "Windows Device"
        elif ttl >= 200:
            return "Router / IoT Device"
    
    if "Apache" in http_banner or "nginx" in http_banner:
        return "Web Server"
    if 22 in open_ports:
        return "SSH Server"
    if 554 in open_ports:
        return "Surveillance Camera"
    if 3389 in open_ports:
        return "Windows RDP Server"
    
    return "Unknown Device"

def scan_network(network_ip):
    """
    Scans the network for active devices using ARP requests.
    Returns a list of detected devices with IP, MAC, manufacturer, and name.
    """
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
    """
    Displays the list of devices in a table format.
    """
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

            for device in known_devices:
                if device["ip"] not in current_ips:
                    print(f"\n❌ Device Disconnected: IP={device['ip']}, MAC={device['mac']}, Name={device['device_name']}, Type={device['device_type']}")

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
