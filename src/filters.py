# Define global threshold values
HIGH_PACKET_RATE_THRESHOLD = 100  # Default high packet rate threshold
ICMP_ACTIVITY_THRESHOLD = 10  # Default suspicious ICMP activity threshold
BLACKLISTED_IPS = []  # Default list of blacklisted IP addresses

# Function to get user-defined filter choice
def get_filter_choice():
    """
    Displays filter options to the user and returns the chosen filter.
    """
    while True:
        print("\n--- Filter Options ---")
        print("1. No filter (capture all traffic)")
        print("2. Filter by protocol (TCP, UDP, ICMP)")
        print("3. Filter by source or destination IP")
        print("4. Filter by port number")
        print("5. Return to main menu")

        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == "1":
            return None
        elif choice == "2":
            protocol = input("Enter protocol to filter (TCP/UDP/ICMP): ").strip().upper()
            if protocol in ["TCP", "UDP", "ICMP"]:
                return f"{protocol.lower()}"
            else:
                print("Invalid protocol. Returning to main menu.")
                return None
        elif choice == "3":
            ip = input("Enter the IP address to filter: ").strip()
            return f"host {ip}"
        elif choice == "4":
            port = input("Enter the port number to filter: ").strip()
            return f"port {port}"
        elif choice == "5":
            return None
        else:
            print("Invalid choice. Please try again.")


# Function to manage alert thresholds
def manage_thresholds():
    """
    Allows the user to define custom alert thresholds.

    Users can set thresholds for high packet rates, suspicious protocol counts, or specific IP addresses.
    """
    print("\n--- Threshold Management ---")
    print("1. Set high packet rate threshold")
    print("2. Set suspicious ICMP activity threshold")
    print("3. Add a blacklisted IP address")
    print("4. Remove a blacklisted IP address")
    print("5. View current thresholds")
    print("6. Return to main menu")

    global HIGH_PACKET_RATE_THRESHOLD, ICMP_ACTIVITY_THRESHOLD, BLACKLISTED_IPS  # Use global variables

    while True:
        choice = input("\nEnter your choice (1-6): ").strip()
        if choice == "1":
            try:
                threshold = int(input("Enter the new high packet rate threshold: ").strip())
                HIGH_PACKET_RATE_THRESHOLD = threshold
                print(f"High packet rate threshold updated to {threshold}.")
            except ValueError:
                print("Invalid input. Please enter a valid number.")
        elif choice == "2":
            try:
                threshold = int(input("Enter the new ICMP activity threshold: ").strip())
                ICMP_ACTIVITY_THRESHOLD = threshold
                print(f"Suspicious ICMP activity threshold updated to {threshold}.")
            except ValueError:
                print("Invalid input. Please enter a valid number.")
        elif choice == "3":
            ip = input("Enter the IP address to blacklist: ").strip()
            if ip not in BLACKLISTED_IPS:
                BLACKLISTED_IPS.append(ip)
                print(f"IP address {ip} added to the blacklist.")
            else:
                print(f"IP address {ip} is already blacklisted.")
        elif choice == "4":
            ip = input("Enter the IP address to remove from the blacklist: ").strip()
            if ip in BLACKLISTED_IPS:
                BLACKLISTED_IPS.remove(ip)
                print(f"IP address {ip} removed from the blacklist.")
            else:
                print(f"IP address {ip} is not in the blacklist.")
        elif choice == "5":
            print("\n--- Current Thresholds ---")
            print(f"High Packet Rate Threshold: {HIGH_PACKET_RATE_THRESHOLD}")
            print(f"Suspicious ICMP Activity Threshold: {ICMP_ACTIVITY_THRESHOLD}")
            print(f"Blacklisted IPs: {', '.join(BLACKLISTED_IPS) if BLACKLISTED_IPS else 'None'}")
        elif choice == "6":
            print("Returning to main menu...")
            break
        else:
            print("Invalid choice. Please try again.")
