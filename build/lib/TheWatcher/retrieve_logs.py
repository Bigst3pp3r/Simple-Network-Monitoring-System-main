import sqlite3
from prettytable import PrettyTable

DB_FILE = "network_monitoring.db"

def check_table_exists(table_name):
    """Check if a table exists in the database."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
            )
            return cursor.fetchone() is not None
    except sqlite3.Error as e:
        print(f"Error checking table {table_name}: {e}")
        return False

def get_logged_devices():
    """Retrieve all logged network devices."""
    if not check_table_exists("network_devices"):
        print("⚠️ No logged devices found (Table does not exist).")
        return

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM network_devices ORDER BY last_seen DESC")
            devices = cursor.fetchall()

        table = PrettyTable()
        table.field_names = ["ID", "IP Address", "MAC Address", "Manufacturer", "Device Name", "Device Type", "First Seen", "Last Seen", "Status"]

        for device in devices:
            table.add_row(device)

        print(table if devices else "📭 No devices logged yet.")
    except sqlite3.Error as e:
        print(f"❌ Error retrieving devices: {e}")

def get_captured_packets():
    """Retrieve all captured network packets."""
    if not check_table_exists("packets"):
        print("⚠️ No captured packets found (Table does not exist).")
        return

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM packets ORDER BY timestamp DESC")
            packets = cursor.fetchall()

        table = PrettyTable()
        table.field_names = ["ID", "Timestamp", "Source IP", "Destination IP", "Protocol"]

        for packet in packets:
            table.add_row(packet)

        print(table if packets else "📭 No packets captured yet.")
    except sqlite3.Error as e:
        print(f"❌ Error retrieving packets: {e}")

def get_alerts():
    """Retrieve all alerts."""
    if not check_table_exists("alerts"):
        print("⚠️ No alerts found (Table does not exist).")
        return

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
            alerts = cursor.fetchall()

        table = PrettyTable()
        table.field_names = ["ID", "Timestamp", "Message", "Type", "Severity"]

        for alert in alerts:
            table.add_row(alert)

        print(table if alerts else "📭 No alerts recorded yet.")
    except sqlite3.Error as e:
        print(f"❌ Error retrieving alerts: {e}")

if __name__ == "__main__":
    while True:
        print("\n📡 Network Monitoring Logs Retrieval")
        print("1️⃣ View Logged Devices")
        print("2️⃣ View Captured Packets")
        print("3️⃣ View Alerts")
        print("4️⃣ Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            get_logged_devices()
        elif choice == "2":
            get_captured_packets()
        elif choice == "3":
            get_alerts()
        elif choice == "4":
            print("🚪 Exiting...")
            break
        else:
            print("❌ Invalid choice, try again.")
