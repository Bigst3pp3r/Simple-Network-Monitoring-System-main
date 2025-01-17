import threading
from filters import get_filter_choice, manage_thresholds  # Import filter and threshold functions
from logging_setup import setup_logging
from packet_processing import process_packet
from traffic_summary import display_summary
from monitor_state import MonitorState
from alerts import check_alert_conditions
from database.database import initialize_database, save_packet, save_alert
from network_scanner import scan_network
from real_time_monitor  import monitor_network


def alert_monitor(state):
    """
    Monitor for alert conditions in a separate thread.

    Args:
        state (MonitorState): The shared state object for monitoring.
    """
    while state.is_active:
        check_alert_conditions(
            state.packet_count, state.protocol_counter, state.ip_counter, state
        )
        threading.Event().wait(5)

def start_monitoring(chosen_filter):
    """
    Starts the network monitoring process with user-defined filters and thresholds.

    Args:
        chosen_filter (str or None): The filter string for Scapy or None for no filter.
    """
    # Initialize the database
    initialize_database()
    # Setup logging
    setup_logging()

    # Initialize shared state
    state = MonitorState()

    # Start the traffic summary thread
    summary_thread = threading.Thread(
        target=display_summary,
        args=(state,),
        daemon=True,
    )
    summary_thread.start()

    # Start the alert monitoring thread
    alert_thread = threading.Thread(
        target=alert_monitor,
        args=(state,),
        daemon=True,
    )
    alert_thread.start()

    try:
        # Import sniffing functionality from Scapy
        from scapy.all import sniff
        print("Starting packet capture... Press Ctrl+C to stop.")
        sniff(
            prn=lambda packet: process_packet(packet, state),
            store=False,
            filter=chosen_filter,
        )
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        state.is_active = False  # Stop all monitoring threads

def main():
    """
    CLI for managing and starting the network monitoring system.
    """
    chosen_filter = None  # Initialize filter to None

    while True:
        print("\n--- Network Monitoring System ---")
        print("1. Set Filters")
        print("2. Manage Thresholds")
        print("3. Start Packet Monitoring")
        print("4. Scan Network for Devices")
        print("5. Real-Time Device Monitoring")
        print("6. Exit")

        choice = input("\nSelect an option (1-5): ")

        if choice == "1":
            chosen_filter = get_filter_choice()
            print(f"Filter set: {chosen_filter}")
        elif choice == "2":
            manage_thresholds()
        elif choice == "3":
            start_monitoring(chosen_filter)
        elif choice == "4":
            network_ip = input("Enter the network IP range (e.g., 192.168.1.0/24): ").strip()
            if network_ip:
                scan_network(network_ip)
            else:
                print("Invalid input. Please enter a valid network IP range.")
        elif choice == "5":
            network_ip = input("Enter the network IP range (e.g., 192.168.1.0/24): ").strip()
            if network_ip:
                monitor_network(network_ip)
            else:
                print("Invalid input. Please enter a valid network IP range.")
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
