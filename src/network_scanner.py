from scapy.all import ARP, Ether, srp
import scapy.all as scapy
from tabulate import tabulate

def scan_network(network_ip):
    """
    Scans the network for devices and formats the results in a table.

    Args:
        network_ip (str): The subnet or range to scan (e.g., '192.168.1.0/24').

    Returns:
        None
    """
    print(f"Scanning network: {network_ip}...")

    # Send ARP requests and gather responses
    arp_request = scapy.ARP(pdst=network_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    # Process the responses
    devices = []
    for response in answered_list:
        devices.append({
            "IP Address": response[1].psrc,
            "MAC Address": response[1].hwsrc,
        })

    if devices:
        # Print the results in a table format
        print("\nDevices Found:")
        print(tabulate(devices, headers="keys", tablefmt="grid"))
    else:
        print("\nNo devices found on the network.")

# Example usage
if __name__ == "__main__":
    network = input("Enter the network range (e.g., 192.168.1.0/24): ").strip()
    scan_network(network)

