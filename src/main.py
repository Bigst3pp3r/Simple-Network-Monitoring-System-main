import threading

from .logging_setup import setup_logging
from .packet_processing import process_packet
from .traffic_summary import display_summary
from .monitor_state import MonitorState
from .alerts import check_alert_conditions
from database.database import initialize_database, save_packet, save_alert
from .network_scanner import scan_network
from .real_time_monitor  import monitor_network



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

    This function initializes the database, sets up logging, creates a shared state,
    and starts threads for traffic summary and alert monitoring. It then begins
    packet capture using Scapy with the specified filter.
    Args:
        chosen_filter (str or None): The filter string for Scapy to apply during
            packet capture. If None, no filter is applied.

    Returns:
        None

    Raises:
        KeyboardInterrupt: If the user manually stops the monitoring process.
        Exception: For any other errors that occur during the monitoring process.

    Note:
        The function will run indefinitely until interrupted by the user (Ctrl+C)
        or an exception occurs. Upon termination, it ensures all monitoring threads
        are stopped by setting the shared state's 'is_active' flag to False.
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
    Command-line interface for managing and starting the network monitoring system.

    This function provides a menu-driven interface for users to interact with
    various features of the network monitoring system. It allows users to:
    1. Set packet capture filters
    2. Manage alert thresholds
    3. Start packet monitoring
    4. Scan the network for devices
    5. Monitor devices in real-time
    6. Exit the program

    The function runs in a loop, continuously presenting options to the user
    until they choose to exit.

    Parameters:
    None

    Returns:
    None

    Note:
    - The function uses global state to manage the chosen filter.
    - It calls other functions to handle specific tasks based on user input.
    - Invalid inputs are handled with appropriate error messages.
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
            chosen_filter = get_filter_choice() # type: ignore
            print(f"Filter set: {chosen_filter}")
            manage_thresholds()  # type: ignore # Ensure this function is defined or imported correctly
            manage_thresholds() # type: ignore
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
