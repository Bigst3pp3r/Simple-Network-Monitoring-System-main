from scapy.all import ARP, Ether, srp
import socket

def scan_network(ip_range="192.168.0.1/24"):
    """
    Scans the local network for devices using ARP requests.

    Args:
        ip_range (str): The IP range to scan (default is the common private network range).

    Returns:
        list[dict]: A list of dictionaries with device details (IP, MAC, hostname).
    """
    print("Scanning the network. Please wait...")
    devices = []
    
    try:
        # Create an ARP request packet
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
        packet = ether / arp

        # Send the packet and capture the response
        result = srp(packet, timeout=3, verbose=0)[0]

        for sent, received in result:
            # Resolve hostname (optional)
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except socket.herror:
                hostname = "Unknown"

            # Add the device details to the list
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "hostname": hostname,
            })

        return devices
    except Exception as e:
        print(f"Error during network scan: {e}")
        return []

if __name__ == "__main__":
    # Example usage
    devices = scan_network()
    if devices:
        print("\n--- Devices Found ---")
        for idx, device in enumerate(devices, 1):
            print(f"{idx}. IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}")
    else:
        print("No devices found.")
