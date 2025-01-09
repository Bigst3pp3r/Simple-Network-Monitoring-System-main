# Functions for packet processing
from scapy.layers.inet import IP
from datetime import datetime
from monitor_state import MonitorState
from database.database import save_packet  # Import save_packet from the database module

# Protocol mapping for translating protocol numbers to names
protocol_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",  # IPv6 ICMP
}

# Function to process and analyze packets
def process_packet(packet, state: MonitorState):
    """
    Processes a single captured packet, updating monitoring state and saving to the database.
    
    Args:
        packet: The captured packet to process.
        state: The shared monitoring state object.
    """
    try:
        # Check if the packet contains an IP layer
        if IP in packet:
            with state.lock:  # Thread-safe access to shared state
                # Update packet count
                state.packet_count += 1

                # Extract source and destination IP addresses
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # Update IP address counters
                state.ip_counter[src_ip] += 1
                state.ip_counter[dst_ip] += 1

                # Identify the protocol and update protocol counters
                proto_number = packet[IP].proto
                protocol = protocol_map.get(proto_number, f"Unknown ({proto_number})")
                state.protocol_counter[protocol] += 1

            # Log packet details
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"{timestamp}, Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}"
            print(log_entry)

            # Save packet details to the database
            try:
                save_packet(timestamp, src_ip, dst_ip, protocol)
            except Exception as db_error:
                print(f"Error saving packet to the database: {db_error}")

    except Exception as e:
        print(f"Error processing packet: {e}")
