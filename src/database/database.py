import sqlite3

# Initialize the database connection


def initialize_database():
    """
    Initializes the database with necessary tables.
    """
    try:
        conn = sqlite3.connect("network_monitor.db")
        cursor = conn.cursor()



        # Create the packets table (if not already created)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                protocol TEXT NOT NULL
            )
            """
        )

        # Create the alerts table (if not already created)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                message TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT
            )
            """
        )

        conn.commit()
        print("Database initialized successfully.")
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")
    finally:
        conn.close()
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


def save_alert(timestamp, message, alert_type, severity="Medium"):
    """
    Save an alert to the database.

    Args:
        timestamp (str): The time the alert was generated.
        message (str): The alert message.
        alert_type (str): The type/category of the alert.
        severity (str): The severity of the alert (default: Medium).
    """
    try:
        conn = sqlite3.connect("network_monitor.db")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO alerts (timestamp, message, type, severity)
            VALUES (?, ?, ?, ?)
            """,
            (timestamp, message, alert_type, severity),
        )
        conn.commit()
        print(f"Alert saved: {message}")
    except sqlite3.Error as e:
        print(f"Error saving alert to database: {e}")
    finally:
        conn.close()
