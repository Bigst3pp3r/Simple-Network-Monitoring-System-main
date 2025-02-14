import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
from filters import get_filters  # Import filter settings
from logging_setup import setup_logging
from packet_processing import process_packet
from traffic_summary import display_summary
from monitor_state import MonitorState
from alerts import check_alert_conditions
from database.database import initialize_database
from network_scanner import scan_network
from real_time_monitor import monitor_network

class NetworkMonitor:
    def __init__(self):
        """Initialize network monitoring system with shared state."""
        self.state = MonitorState()
        self.chosen_filter = None

    def start_monitoring(self):
        """Starts the network monitoring process."""
        initialize_database()
        setup_logging()

        summary_thread = threading.Thread(target=display_summary, args=(self.state,), daemon=True)
        summary_thread.start()

        alert_thread = threading.Thread(target=self.alert_monitor, args=(self.state,), daemon=True)
        alert_thread.start()

        try:
            from scapy.all import sniff
            print("Starting packet capture... Press Ctrl+C to stop.")
            sniff(prn=lambda packet: process_packet(packet, self.state), store=False, filter=self.chosen_filter)
        except KeyboardInterrupt:
            print("\nStopping packet capture...")
        except Exception as e:
            print(f"Error occurred: {e}")
        finally:
            self.state.is_active = False  # Stop monitoring

    def alert_monitor(self, state):
        """Continuously check for alert conditions."""
        while state.is_active:
            check_alert_conditions(state.packet_count, state.protocol_counter, state.ip_counter, state)
            threading.Event().wait(5)

    def set_filter(self):
        """Set user-defined filter."""
        self.chosen_filter = get_filter_choice()
        print(f"Filter set: {self.chosen_filter}")

    def scan_network_devices(self, network_ip):
        """Scan network for active devices."""
        scan_network(network_ip)

    def monitor_network_devices(self, network_ip):
        """Monitor network devices in real time."""
        monitor_network(network_ip)

    def configure_thresholds(self):
        """Manage alert thresholds."""
        manage_thresholds()
