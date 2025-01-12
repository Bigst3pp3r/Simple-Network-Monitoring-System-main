# main.py

import threading
from filters import get_filter_choice, manage_thresholds  # Import filter and threshold functions
from logging_setup import setup_logging
from packet_processing import process_packet
from traffic_summary import display_summary
from monitor_state import MonitorState
from alerts import check_alert_conditions
from database.database import initialize_database, save_packet, save_alert

def alert_monitor(state):
    """
    Monitor for alert conditions in a separate thread.

    This function continuously checks the shared monitoring state for any conditions
    that meet predefined alert thresholds and triggers alerts accordingly.

    Args:
        state (MonitorState): The shared state object for monitoring.

    Returns:
        None
    """
    while True:
        check_alert_conditions(
            state.packet_count, state.protocol_counter, state.ip_counter, state
        )
        # Check for alerts at regular intervals (e.g., every 5 seconds)
        threading.Event().wait(5)

def start_monitoring():
    """
    Starts the network monitoring process with user-defined filters and thresholds.
    """
    # Initialize the database for storing packet data and alerts
    initialize_database()

    # Initialize logging setup
    setup_logging()

    # Initialize shared state for packet monitoring
    state = MonitorState()

    # Get the user-defined filter choice
    chosen_filter = get_filter_choice()
    

    # Start the traffic summary thread to display real-time updates
    summary_thread = threading.Thread(
        target=display_summary,
        args=(state,),  # Pass the shared state to the thread
        daemon=True,
    )
    summary_thread.start()

    # Start the alert monitoring thread
    alert_thread = threading.Thread(
        target=alert_monitor,  # Alert monitoring function
        args=(state,),  # Pass the shared state to the alert system
        daemon=True,
    )
    alert_thread.start()

    try:
        # Import sniffing functionality from Scapy
        from scapy.all import sniff
        print("Starting packet capture... Press Ctrl+C to stop.")
        # Start sniffing packets, applying the user-defined filter if any
        sniff(
            prn=lambda packet: process_packet(packet, state),  # Process each captured packet
            store=False,  # Don't store packets in memory
            filter=chosen_filter,  # Apply the filter
        )
    except Exception as e:
        print(f"Error occurred: {e}")

def main():
    """
    CLI for managing and starting the network monitoring system.
    """
    while True:
        print("\n--- Network Monitoring System ---")
        print("1. Start Packet Monitoring")
        print("2. Manage Filters")
        print("3. Manage Thresholds")
        print("4. Exit")

        choice = input("\nSelect an option (1-4): ")

        if choice == "1":
            start_monitoring()
        elif choice == "2":
            # Let user choose and set filters
            selected_filter = get_filter_choice()
            print(f"\nSelected Filter: {selected_filter}")
        elif choice == "3":
            # Manage thresholds interactively
            manage_thresholds()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()



