# monitor_state.py

from collections import Counter
import threading

class MonitorState:
    """
    Shared state for network monitoring.
    """
    def __init__(self):
        self.packet_count = 0  # Total packets captured
        self.protocol_counter = Counter()  # Protocol statistics
        self.ip_counter = Counter()  # IP address statistics
        self.lock = threading.Lock()  # Thread-safety lock
        self.is_active = True  # Flag to control monitoring activity

    def toggle_activity(self):
        """
        Toggle the monitoring activity state.
        """
        with self.lock:
            self.is_active = not self.is_active
