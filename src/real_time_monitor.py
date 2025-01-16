from scapy.all import ARP, Ether, srp
from prettytable import PrettyTable
import time

def scan_network(network_ip):
    """
    Scans the network for active devices.
    """
    devices = []
    arp = ARP(pdst=network_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

def display_devices(devices):
    """
    Displays the list of devices in a table format.
    """
    table = PrettyTable()
    table.field_names = ["IP Address", "MAC Address"]
    for device in devices:
        table.add_row([device["ip"], device["mac"]])
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

            # Check for new devices
            for device in current_devices:
                if device not in known_devices:
                    print(f"New Device Connected: IP={device['ip']}, MAC={device['mac']}")

            # Check for disconnected devices
            for device in known_devices:
                if device["ip"] not in current_ips:
                    print(f"Device Disconnected: IP={device['ip']}, MAC={device['mac']}")

            # Update known devices
            known_devices = current_devices

            # Display the current devices in a table
            print("\n--- Current Devices ---")
            display_devices(current_devices)

            # Wait for the next scan
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    except Exception as e:
        print(f"Error during monitoring: {e}")
