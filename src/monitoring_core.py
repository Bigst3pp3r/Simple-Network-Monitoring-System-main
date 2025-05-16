
import threading
from scapy.all import sniff
from .filters import get_filters
from .logging_setup import setup_logging
from .packet_processing import process_packet
from .monitor_state import MonitorState
from .alerts import check_alert_conditions
from .database.database import initialize_database
from .network_scanner import scan_network
from .real_time_monitor import monitor_network
from .traffic_summary import display_summary  # ✅ Import function
from database.database import get_alerts_by_severity  # Import database function

class NetworkMonitor:
    def __init__(self):
        """Initialize network monitoring system with shared state."""
        self.state = MonitorState()
        self.chosen_filter = None
        self.packet_count = 0
        self.protocol_counts = {}
        self.alert_count = 0  # ✅ Track alert count

        # ✅ Start traffic summary in a background thread
        summary_thread = threading.Thread(target=display_summary, args=(self.state,), daemon=True)
        summary_thread.start()


    def start_monitoring(self):
        """Starts network monitoring in a non-blocking way."""
        initialize_database()
        setup_logging()

        self.state.is_active = True  # Ensure monitoring is active

        alert_thread = threading.Thread(target=self.alert_monitor, args=(self.state,), daemon=True)
        alert_thread.start()

        try:
            print("Starting packet capture... Press Ctrl+C to stop.")
            sniff(prn=lambda packet: process_packet(packet, self.state), store=False, filter=self.chosen_filter, timeout=5)
            
            # ✅ Restart sniffing in intervals to avoid freezing
            if self.state.is_active:
                threading.Thread(target=self.start_monitoring, daemon=True).start()

        except Exception as e:
            print(f"Error occurred: {e}")

        finally:
            self.state.is_active = False  # Stop monitoring when exiting


    def get_packet_count(self):
        """Returns the total number of packets captured."""
        return self.state.packet_count

    def get_protocol_counts(self):
        """Returns a dictionary of protocol counts."""
        return dict(self.state.protocol_counter)
    
    def get_alert_count(self):
        """Returns the total alert count."""
        return self.alert_count
    
    
    def get_alert_count_by_severity(self):
        """
        Retrieves the count of alerts categorized by severity.

        Returns:
            dict: {"High": count, "Medium": count, "Low": count}
        """
        return get_alerts_by_severity() 

    def get_traffic_summary(self):
        """Fetches the latest real-time traffic summary from state."""
        return self.state.traffic_summary  # ✅ Fetch latest summary

    def alert_monitor(self, state):
        """Continuously check for alert conditions and send alerts to GUI."""
        while state.is_active:
            check_alert_conditions(state.packet_count, state.protocol_counter, state.ip_counter, state)
            threading.Event().wait(5)

    def set_filter(self):
        """Set user-defined filter."""
        self.chosen_filter = get_filters()
        print(f"Filter set: {self.chosen_filter}")

    def scan_network_devices(self, network_ip):
        """Scan network for active devices."""
        scan_network(network_ip)

    def monitor_network_devices(self, network_ip):
        """Monitor network devices in real time."""
        monitor_network(network_ip)
