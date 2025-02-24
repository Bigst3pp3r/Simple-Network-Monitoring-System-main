import logging
from datetime import datetime
from database.database import save_alert  


# Configure logging
alerts_log_file = "alerts_log.txt"
logging.basicConfig(
    filename=alerts_log_file,
    level=logging.INFO,
    format="%(asctime)s | ALERT: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Threshold values (Configurable from GUI)
HIGH_PACKET_RATE_THRESHOLD = 100  
ICMP_ACTIVITY_THRESHOLD = 10      
BLACKLISTED_IPS = ["192.168.1.100", "10.0.0.5"]



def check_alert_conditions(packet_count, protocol_counter, ip_counter, monitor_state):
    """ Evaluate conditions and trigger alerts in GUI. """
    if not monitor_state.is_active:
        return

    alert_checks = [
        lambda: check_high_packet_rate(packet_count),
        lambda: check_icmp_activity(protocol_counter),
        lambda: check_blacklisted_ips(ip_counter),
    ]

    for check in alert_checks:
        check()

def check_high_packet_rate(packet_count):
    """ Trigger alert if high packet rate is detected. """
    if packet_count > HIGH_PACKET_RATE_THRESHOLD:
        log_alert(f"High traffic detected: {packet_count} packets!", "Traffic", "High")

def check_icmp_activity(protocol_counter):
    """ Trigger alert if unusual ICMP activity is detected. """
    if "ICMP" in protocol_counter and protocol_counter["ICMP"] > ICMP_ACTIVITY_THRESHOLD:
        log_alert(f"Unusual ICMP activity: {protocol_counter['ICMP']} packets.", "ICMP", "Medium")

def check_blacklisted_ips(ip_counter):
    """ Trigger alert if traffic from blacklisted IPs is detected. """
    for ip in BLACKLISTED_IPS:
        if ip in ip_counter:
            log_alert(f"Blacklisted IP detected: {ip} ({ip_counter[ip]} packets)", "Security", "Critical")

def log_alert(message, alert_type="General", severity="Medium"):
    """ Log and save alerts, then display them in the GUI. """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Log to file
    logging.info(f"{message} [Type: {alert_type}, Severity: {severity}]")

    # Save to database
    save_alert(timestamp, message, alert_type, severity)

 
