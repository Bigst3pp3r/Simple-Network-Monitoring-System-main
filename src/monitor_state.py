from collections import Counter
import threading
import time

class MonitorState:
    """
    Shared state for network monitoring.

    Attributes:
        packet_count (int): Total number of packets captured.
        protocol_counter (Counter): Tracks the number of packets by protocol.
        ip_counter (Counter): Tracks the number of packets by IP address.
        lock (threading.Lock): Ensures thread-safe access to shared state.
        is_active (bool): Indicates whether monitoring is currently active.
    """
       
    def __init__(self):
        self.packet_count = 0  # Total packets captured
        self.protocol_counter = Counter()  # Protocol statistics
        self.ip_counter = Counter()  # IP address statistics
        self.traffic_volume = 0  # Total traffic volume in bytes
        self.last_volume_timestamp = time.time()  # Last volume calculation timestamp
        self.lock = threading.Lock()  # Thread-safety lock
        self.is_active = True  # Flag to control monitoring activity
        
    # Custom alert thresholds
        self.alert_thresholds = {
            "packet_rate": 100,  # Packets per second
            "protocol_limits": {},  # e.g., {"TCP": 500, "UDP": 1000}
            "ip_limits": {},  # e.g., {"192.168.0.1": 200}
        }

    def toggle_activity(self):
        """
        Toggle the monitoring activity state.

        Returns:
            bool: The new state of `is_active` after toggling.
        """
        with self.lock:
            self.is_active = not self.is_active
            return self.is_active

    def reset_counters(self):
        """
        Reset packet count, protocol statistics, and IP counters.
        """
        with self.lock:
            self.packet_count = 0
            self.protocol_counter.clear()
            self.ip_counter.clear()

    def get_state(self):
        """
        Retrieve the current monitoring state.

        Returns:
            dict: A dictionary containing the current monitoring statistics.
        """
        with self.lock:
            return {
                "packet_count": self.packet_count,
                "protocol_counter": dict(self.protocol_counter),
                "ip_counter": dict(self.ip_counter),
                "is_active": self.is_active
            }
