from collections import Counter
import threading

# Class to manage shared monitoring state
class MonitorState:
    """
    A thread-safe class to hold and manage shared monitoring data.
    """
    def __init__(self):
        self.packet_count = 0  # Total number of packets captured
        self.protocol_counter = Counter()  # Counter for protocol distribution
        self.ip_counter = Counter()  # Counter for IP addresses
        self.lock = threading.Lock()  # Lock for thread-safe operations
