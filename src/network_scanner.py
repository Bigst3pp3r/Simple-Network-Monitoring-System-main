from scapy.all import ARP, Ether, srp
import scapy.all as scapy

def scan_network(network_ip):
    """
    Scans the network for devices and returns a list of detected devices.

    Args:
        network_ip (str): The subnet or range to scan (e.g., '192.168.1.0/24').

    Returns:
        list: A list of dictionaries with IP and MAC addresses of found devices.
    """
    print(f"Scanning network: {network_ip}...")

    # Send ARP requests and gather responses
    arp_request = scapy.ARP(pdst=network_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    # Process the responses
    devices = []
    for response in answered_list:
        devices.append({
            "ip": response[1].psrc,
            "mac": response[1].hwsrc.upper(),  # Format MAC address properly
        })

    return devices  # ✅ Now returns results to be used in the GUI

# Example usage
if __name__ == "__main__":
    network = input("Enter the network range (e.g., 192.168.1.0/24): ").strip()
    found_devices = scan_network(network)
    
    if found_devices:
        print("\nDevices Found:")
        for device in found_devices:
            print(f"IP: {device['ip']}  |  MAC: {device['mac']}")
    else:
        print("\nNo devices found on the network.")
# ✅ Now returns results to be used in the GUI
