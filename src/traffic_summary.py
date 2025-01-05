# Real-time traffic summary logic
from datetime import datetime
from monitor_state import MonitorState
import threading

# Function to display real-time traffic summary
def display_summary(state: MonitorState):
    """
    Continuously displays real-time traffic statistics.
    
    Args:
        state: The shared monitoring state object.
    """
    while True:
        with state.lock:  # Thread-safe access to shared state
            print("\n=== Real-Time Traffic Summary ===")
            print(f"Total Packets Captured: {state.packet_count}")
            print(f"Protocol Breakdown: {dict(state.protocol_counter)}")
            print("Top Talkers (IP Addresses):")
            for ip, count in state.ip_counter.most_common(5):
                print(f"    - {ip}: {count} packets")
            print(f"Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("---------------------------------\n")
        # Wait for 5 seconds before refreshing the summary
        threading.Event().wait(5)
