 # Entry point for the application
 # main.py
import threading
from filters import get_filter_choice
from logging_setup import setup_logging
from packet_processing import process_packet
from traffic_summary import display_summary
from monitor_state import MonitorState

# Main function to initialize and run the network monitoring system
def main():
    """
    Initialize and run the network monitoring system.

    This function serves as the entry point for the application. It sets up logging,
    initializes the shared state for packet monitoring, gets the user-defined filter,
    starts a thread for displaying real-time traffic summaries, and begins packet
    capture using Scapy.

    The function performs the following steps:
    1. Sets up logging
    2. Initializes the shared state
    3. Gets the user-defined filter
    4. Starts a thread for displaying traffic summaries
    5. Begins packet capture using Scapy with the specified filter

    No parameters are required for this function.

    Returns:
        None

    Raises:
        Exception: If an error occurs during packet capture or processing.
    """
    # Initialize logging setup
    setup_logging()

    # Initialize shared state for packet monitoring
    state = MonitorState()

    # Get the user-defined filter choice
    chosen_filter = get_filter_choice()

    # Start the traffic summary thread to display real-time updates
    summary_thread = threading.Thread(
        target=display_summary,  # Target function to run
        args=(state,),  # Pass the shared state to the thread
        daemon=True,  # Daemon thread allows program to exit when main thread ends
    )
    summary_thread.start()

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


if __name__ == "__main__":
    main()  # Run the program
