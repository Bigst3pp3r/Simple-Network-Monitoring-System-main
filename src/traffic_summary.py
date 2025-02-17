# Real-time traffic summary logic
from datetime import datetime
from monitor_state import MonitorState
import threading
from alerts import check_alert_conditions  # Import the alert checking function
import time


def display_summary(state: MonitorState):
    """
    Continuously updates real-time traffic statistics and stores them in `state.traffic_summary`.
    """
    while state.is_active:
        with state.lock:  # Thread-safe access to shared state
            summary = "\n=== Real-Time Traffic Summary ===\n"
            summary += f"Total Packets Captured: {state.packet_count}\n\n"

            # Protocol Breakdown - Top 5 Protocols
            summary += "Protocol Breakdown (Top 5):\n"
            if hasattr(state.protocol_counter, "most_common"):
                for protocol, count in state.protocol_counter.most_common(5):
                    summary += f"    - {protocol}: {count} packets\n"
            else:
                for protocol, count in list(state.protocol_counter.items())[:5]:
                    summary += f"    - {protocol}: {count} packets\n"

            # Top Talkers (IP Addresses)
            summary += "\nTop Talkers (IP Addresses):\n"
            if hasattr(state.ip_counter, "most_common"):
                for ip, count in state.ip_counter.most_common(5):
                    summary += f"    - {ip}: {count} packets\n"
            else:
                for ip, count in list(state.ip_counter.items())[:5]:
                    summary += f"    - {ip}: {count} packets\n"

            # Calculate traffic volume in bytes per second
            current_time = time.time()
            elapsed_time = current_time - state.last_volume_timestamp
            if elapsed_time > 0:
                bytes_per_second = state.traffic_volume / elapsed_time
            else:
                bytes_per_second = 0.0

            summary += f"\nTraffic Volume: {bytes_per_second:.2f} bytes/second\n"
            summary += f"Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            summary += "---------------------------------\n"

            # ✅ Store the formatted summary in `state.traffic_summary`
            state.traffic_summary = summary.strip()

            # Reset traffic volume for the next calculation
            state.traffic_volume = 0
            state.last_volume_timestamp = current_time

            # Check for alert conditions
            check_alert_conditions(
                packet_count=state.packet_count,
                protocol_counter=state.protocol_counter,
                ip_counter=state.ip_counter,
                monitor_state=state
            )

        # Wait for 5 seconds before refreshing the summary
        time.sleep(5)
