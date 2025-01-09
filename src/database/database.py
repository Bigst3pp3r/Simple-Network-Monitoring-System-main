import sqlite3

# Initialize the database connection
def initialize_database():
    """
    Create or connect to an SQLite database and initialize necessary tables.
    """
    try:
        with sqlite3.connect("network_monitoring.db") as connection:
            cursor = connection.cursor()

            # Create tables for storing packet data and alerts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_message TEXT NOT NULL
                )
            """)
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")

# Save a captured packet to the database
def save_packet(timestamp, source_ip, destination_ip, protocol):
    """
    Save a captured packet to the database.

    Parameters:
    timestamp (str): The timestamp of the packet.
    source_ip (str): The source IP address of the packet.
    destination_ip (str): The destination IP address of the packet.
    protocol (str): The protocol of the packet.

    Returns:
    None
    """
    try:
        with sqlite3.connect("network_monitoring.db") as connection:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO packets (timestamp, source_ip, destination_ip, protocol)
                VALUES (?, ?, ?, ?)
            """, (timestamp, source_ip, destination_ip, protocol))
    except sqlite3.Error as e:
        print(f"Error saving packet: {e}")

# Save an alert to the database
def save_alert(timestamp, alert_message):
    """
    Save an alert to the database.

    Parameters:
    timestamp (str): The timestamp of the alert.
    alert_message (str): The message of the alert.

    Returns:
    None
    """
    try:
        with sqlite3.connect("network_monitoring.db") as connection:
            cursor = connection.cursor()

            # Insert the alert record into the database
            cursor.execute("""
                INSERT INTO alerts (timestamp, alert_message)
                VALUES (?, ?)
            """, (timestamp, alert_message))
    except sqlite3.Error as e:
        print(f"Error saving alert: {e}")
