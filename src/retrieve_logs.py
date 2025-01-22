import sqlite3
from prettytable import PrettyTable

def get_logged_devices():
    """
    Retrieve all logged network devices.
    """
    try:
        conn = sqlite3.connect("network_monitoring.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM network_devices")
        devices = cursor.fetchall()
        conn.close()

        table = PrettyTable()
        table.field_names = ["id", "ip_address", "mac_address", "manufacturer", "device_name", "device_type", "first_seen TIMESTAMP", "last_seen TIMESTAMP", "status"]

        for device in devices:
            table.add_row(device)

        print(table if devices else "No devices logged yet.")
    except sqlite3.Error as e:
        print(f"Error retrieving devices: {e}")

def get_captured_packets():
    """
    Retrieve all captured network packets.
    """
    try:
        conn = sqlite3.connect("network_monitoring.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM packets")
        packets = cursor.fetchall()
        conn.close()

        table = PrettyTable()
        table.field_names = ["ID", "Timestamp", "Source IP", "Destination IP", "Protocol"]

        for packet in packets:
            table.add_row(packet)

        print(table if packets else "No packets captured yet.")
    except sqlite3.Error as e:
        print(f"Error retrieving packets: {e}")

def get_alerts():
    """
    Retrieve all alerts.
    """
    try:
        conn = sqlite3.connect("network_monitoring.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts")
        alerts = cursor.fetchall()
        conn.close()

        table = PrettyTable()
        table.field_names = ["ID", "Timestamp", "Message", "Type", "Severity"]

        for alert in alerts:
            table.add_row(alert)

        print(table if alerts else "No alerts recorded yet.")
    except sqlite3.Error as e:
        print(f"Error retrieving alerts: {e}")

if __name__ == "__main__":
    while True:
        print("\nNetwork Monitoring Logs Retrieval")
        print("1. View Logged Devices")
        print("2. View Captured Packets")
        print("3. View Alerts")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            get_logged_devices()
        elif choice == "2":
            get_captured_packets()
        elif choice == "3":
            get_alerts()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice, try again.")
