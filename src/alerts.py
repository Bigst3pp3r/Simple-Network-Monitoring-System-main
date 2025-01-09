# Handles alert conditions and notifications
import logging
from datetime import datetime
from database.database import save_alert  # Import save_alert from the database module

# Configure logging for alerts
alerts_log_file = "alerts_log.txt"
logging.basicConfig(
    filename=alerts_log_file,
    level=logging.INFO,
    format="%(asctime)s | ALERT: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Example threshold values
HIGH_PACKET_RATE_THRESHOLD = 100  # Packets per second
BLACKLISTED_IPS = ["192.168.1.100", "10.0.0.5"]

def check_alert_conditions(packet_count, protocol_counter, ip_counter, monitor_state):
    """
    Evaluate conditions to trigger alerts based on the current monitor state.

    Args:
        packet_count: Total number of packets captured.
        protocol_counter: Counter for different protocols in the traffic.
        ip_counter: Counter for IP addresses involved in the traffic.
        monitor_state: Shared monitoring state object.
    """
    if not monitor_state.is_active:  # Skip if monitoring is inactive
        return

    # High packet rate alert
    if packet_count > HIGH_PACKET_RATE_THRESHOLD:
        log_alert(f"High traffic detected: {packet_count} packets captured!")

    # Suspicious ICMP activity
    if "ICMP" in protocol_counter and protocol_counter["ICMP"] > 10:
        log_alert(f"Unusual ICMP activity detected: {protocol_counter['ICMP']} packets.")

    # Traffic involving blacklisted IPs
    for ip in BLACKLISTED_IPS:
        if ip in ip_counter:
            log_alert(f"Traffic involving blacklisted IP {ip}: {ip_counter[ip]} packets.")

def log_alert(message):
    """
    Logs and saves alert messages to the database.

    Args:
        message: The alert message to log and save.
    """
    # Record the current timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Print and log the alert
    print(f"ALERT: {message}")
    logging.info(message)

    # Save the alert to the database
    save_alert(timestamp, message)
