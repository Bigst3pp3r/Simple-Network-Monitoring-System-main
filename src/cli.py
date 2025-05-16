from .monitoring_core import NetworkMonitor

def main():
    monitor = NetworkMonitor()

    while True:
        print("\n--- Network Monitoring System ---")
        print("1. Set Filters")
       
        print("3. Start Packet Monitoring")
        print("4. Scan Network for Devices")
        print("5. Real-Time Device Monitoring")
        print("6. Exit")

        choice = input("\nSelect an option (1-6): ")

        if choice == "1":
            monitor.set_filter()
       
        elif choice == "3":
            monitor.start_monitoring()
        elif choice == "4":
            network_ip = input("Enter network IP range (e.g., 192.168.1.0/24): ").strip()
            monitor.scan_network_devices(network_ip)
        elif choice == "5":
            network_ip = input("Enter network IP range (e.g., 192.168.1.0/24): ").strip()
            monitor.monitor_network_devices(network_ip)
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

