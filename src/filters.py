# Function to get user-defined filter choice
def get_filter_choice():
    """
    Displays filter options to the user and returns the chosen filter.

    Returns:
        str or None: The filter string for Scapy or None for no filter.
    """
    print("Choose a filter option:")
    print("1. No filter (capture all traffic)")
    print("2. Filter by protocol (TCP, UDP, ICMP)")
    print("3. Filter by source or destination IP")
    print("4. Filter by port number")
    
    choice = input("Enter your choice (1-4): ").strip()
    if choice == "1":
        return None
    elif choice == "2":
        protocol = input("Enter protocol to filter (TCP/UDP/ICMP): ").strip().upper()
        if protocol in ["TCP", "UDP", "ICMP"]:
            return f"{protocol.lower()}"
        else:
            print("Invalid protocol. Capturing all traffic.")
            return None
    elif choice == "3":
        ip = input("Enter the IP address to filter: ").strip()
        return f"host {ip}"
    elif choice == "4":
        port = input("Enter the port number to filter: ").strip()
        return f"port {port}"
    else:
        print("Invalid choice. Capturing all traffic.")
        return None

