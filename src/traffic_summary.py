# Real-time traffic summary logic
from datetime import datetime
from monitor_state import MonitorState
import threading
from alerts import check_alert_conditions  # Import the alert checking function


def display_summary(state: MonitorState):
    """
    Continuously displays real-time traffic statistics and checks for alerts.

    This function runs in an infinite loop, periodically updating and printing
    a summary of network traffic statistics. It includes information such as
    total packets captured, protocol breakdown, and top talkers (IP addresses).

    Additionally, it integrates an alert system that checks for specific
    conditions (e.g., high traffic or suspicious behavior) and triggers actions.

    Args:
        state (MonitorState): The shared monitoring state object containing
                              current traffic statistics and a lock for
                              thread-safe access.

    Returns:
        None: This function runs indefinitely and does not return.

    Note:
        This function is designed to be run in a separate thread, as it
        contains an infinite loop with periodic updates.
    """
    while True:
        with state.lock:  # Thread-safe access to shared state
            print("\n=== Real-Time Traffic Summary ===")
            print(f"Total Packets Captured: {state.packet_count}")
            print(f"Protocol Breakdown: {dict(state.protocol_counter)}")
            print("Top Talkers (IP Addresses):")
            for ip, count in state.ip_counter.most_common(5):
                print(f"    - {ip}: {count} packets")
            print(f"Last Update: {
                  datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("---------------------------------\n")

            # Check for alert conditions (integrated here)
            check_alert_conditions(
                packet_count=state.packet_count,
                protocol_counter=state.protocol_counter,
                ip_counter=state.ip_counter,
                monitor_state=state  # pass the shared state to alert system
            )

        # Wait for 5 seconds before refreshing the summary
        threading.Event().wait(5)
