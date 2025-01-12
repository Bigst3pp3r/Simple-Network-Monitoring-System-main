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

# Example threshold values (can be made configurable)
HIGH_PACKET_RATE_THRESHOLD = 100  # Packets per second
ICMP_ACTIVITY_THRESHOLD = 10      # ICMP packets before alert
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

    # Define the list of alert checks
    alert_checks = [
        lambda: check_high_packet_rate(packet_count),
        lambda: check_icmp_activity(protocol_counter),
        lambda: check_blacklisted_ips(ip_counter),
    ]

    # Execute each alert check
    for check in alert_checks:
        check()

def check_high_packet_rate(packet_count):
    """
    Check for high packet rate and trigger an alert if exceeded.
    
    Args:
        packet_count: Total number of packets captured.
    """
    if packet_count > HIGH_PACKET_RATE_THRESHOLD:
        log_alert(f"High traffic detected: {packet_count} packets captured!")

def check_icmp_activity(protocol_counter):
    """
    Check for unusual ICMP activity and trigger an alert if exceeded.
    
    Args:
        protocol_counter: Counter for different protocols in the traffic.
    """
    if "ICMP" in protocol_counter and protocol_counter["ICMP"] > ICMP_ACTIVITY_THRESHOLD:
        log_alert(f"Unusual ICMP activity detected: {protocol_counter['ICMP']} packets.")

def check_blacklisted_ips(ip_counter):
    """
    Check for traffic involving blacklisted IPs and trigger alerts if found.
    
    Args:
        ip_counter: Counter for IP addresses involved in the traffic.
    """
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
    try:
        save_alert(timestamp, message)
    except Exception as e:
        print(f"Error saving alert to database: {e}")
