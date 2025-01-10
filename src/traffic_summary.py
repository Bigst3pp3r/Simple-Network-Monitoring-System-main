# Real-time traffic summary logic
from datetime import datetime
from monitor_state import MonitorState
import threading
from alerts import check_alert_conditions  # Import the alert checking function
import time


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

            # Protocol Breakdown - Top 5 Protocols
            print("\nProtocol Breakdown (Top 5):")
            if hasattr(state.protocol_counter, "most_common"):
                for protocol, count in state.protocol_counter.most_common(5):
                    print(f"    - {protocol}: {count} packets")
            else:
                for protocol, count in list(state.protocol_counter.items())[:5]:
                    print(f"    - {protocol}: {count} packets")

            # Top Talkers (IP Addresses)
            print("\nTop Talkers (IP Addresses):")
            if hasattr(state.ip_counter, "most_common"):
                for ip, count in state.ip_counter.most_common(5):
                    print(f"    - {ip}: {count} packets")
            else:
                for ip, count in list(state.ip_counter.items())[:5]:
                    print(f"    - {ip}: {count} packets")

              # Calculate traffic volume in bytes per second
            current_time = time.time()
            elapsed_time = current_time - state.last_volume_timestamp
            if elapsed_time > 0:
                bytes_per_second = state.traffic_volume / elapsed_time
            else:
                bytes_per_second = 0.0

            print(f"Traffic Volume: {bytes_per_second:.2f} bytes/second")
            print(f"Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("---------------------------------\n")
            
            # Reset traffic volume for the next calculation
            state.traffic_volume = 0
            state.last_volume_timestamp = current_time
            
            # Check for alert conditions
            check_alert_conditions(
                packet_count=state.packet_count,
                protocol_counter=state.protocol_counter,
                ip_counter=state.ip_counter,
                monitor_state=state  # Pass the shared state to the alert system
            )

        # Wait for 5 seconds before refreshing the summary
        threading.Event().wait(5)
