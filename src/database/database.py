import sqlite3
from datetime import datetime, timedelta

# Initialize the database connection

def initialize_database():
    """
    Initializes the database with necessary tables.
    """
    try:
        conn = sqlite3.connect("network_monitoring.db")
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
        
         #Create the network_devices table to store monitored devices
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS network_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                mac_address TEXT NOT NULL UNIQUE,
                manufacturer TEXT,
                device_name TEXT,
                device_type TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT
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
        
        
def get_packets(limit=100):
        """
        Fetches the most recent packets from the database.

        Args:
            limit (int): Number of packets to retrieve (default: 100).

        Returns:
            list of tuples: Each tuple contains (timestamp, source_ip, destination_ip, protocol, length).
        """
        try:
            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT timestamp, source_ip, destination_ip, protocol, LENGTH(protocol) 
                    FROM packets
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
                return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Error fetching packets: {e}")
            return []



import sqlite3
from datetime import datetime, timedelta

def get_packets_by_timeframe(timeframe):
    """
    Fetch packets grouped by date and protocol for visualization.
    
    Args:
        timeframe (str): "daily", "weekly", "monthly", or "all-time"
    
    Returns:
        List of tuples: [(date, source_ip, destination_ip, protocol, length)]
    """
    with sqlite3.connect("network_monitoring.db") as conn:
        cursor = conn.cursor()

        # Get current date
        today = datetime.now().date()

        if timeframe == "daily":
            query = """
                SELECT DATE(timestamp), source_ip, destination_ip, protocol, LENGTH(protocol)
                FROM packets 
                WHERE DATE(timestamp) = ?
            """
            cursor.execute(query, (today.strftime('%Y-%m-%d'),))
        
        elif timeframe == "weekly":
            week_start = today - timedelta(days=today.weekday())  # Start of the week (Monday)
            query = """
                SELECT DATE(timestamp), source_ip, destination_ip, protocol, LENGTH(protocol)
                FROM packets 
                WHERE DATE(timestamp) >= ?
            """
            cursor.execute(query, (week_start.strftime('%Y-%m-%d'),))
        
        elif timeframe == "monthly":
            month_start = today.replace(day=1)  # First day of the month
            query = """
                SELECT DATE(timestamp), source_ip, destination_ip, protocol, LENGTH(protocol)
                WHERE DATE(timestamp) >= ?
            """
            cursor.execute(query, (month_start.strftime('%Y-%m-%d'),))
        
        elif timeframe == "all-time":
            query = """
                SELECT DATE(timestamp), source_ip, destination_ip, protocol, LENGTH(protocol)
                FROM packets
            """
            cursor.execute(query)
        
        else:
            return []  # Invalid timeframe
        
        return cursor.fetchall()  # ✅ Returns properly formatted dates





def save_alert(timestamp, message, type, severity="Medium"):
    """
    Save an alert to the database.

    Args:
        timestamp (str): The time the alert was generated.
        message (str): The alert message.
        alert_type (str): The type/category of the alert.
        severity (str): The severity of the alert (default: Medium).
    """
    try:
        conn = sqlite3.connect("network_monitoring.db")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO alerts (timestamp, message, type, severity)
            VALUES (?, ?, ?, ?)
            """,
            (timestamp, message, type, severity),
        )
        conn.commit()
        print(f"Alert saved: {message}")
    except sqlite3.Error as e:
        print(f"Error saving alert to database: {e}")
    finally:
        conn.close()
        
def get_alerts():
    """
    Fetches the most recent alerts from the database.
    
    Returns:
        list: A list of tuples containing alert data.
    """
    try:
        conn = sqlite3.connect("network_monitoring.db")
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, message, type, severity FROM alerts ORDER BY timestamp DESC")
        alerts = cursor.fetchall()
        return alerts
    except sqlite3.Error as e:
        print(f"Error fetching alerts: {e}")
        return []
    finally:
        conn.close()
        

def get_alerts_by_severity():
    """
    Retrieves the count of alerts grouped by severity.

    Returns:
        dict: {"High": count, "Medium": count, "Low": count}
    """
    severity_levels = ["High", "Medium", "Low"]
    counts = {level: 0 for level in severity_levels}  # Initialize counts

    try:
        with sqlite3.connect("network_monitoring.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
            results = cursor.fetchall()

            for severity, count in results:
                if severity in counts:
                    counts[severity] = count  # Update count for severity

    except sqlite3.Error as e:
        print(f"Error fetching alert counts: {e}")

    return counts  # Return dictionary of severity counts


def get_alerts_by_timeframe(timeframe):
    """
    Fetch alerts grouped by a specific timeframe (daily, weekly, monthly).
    
    Args:
        timeframe (str): "daily", "weekly", or "monthly"
    
    Returns:
        List of tuples (timestamp, message, alert_type, severity)
    """
    with sqlite3.connect("network_monitoring.db") as conn:
        cursor = conn.cursor()

        # ✅ Determine the date range based on timeframe
        if timeframe == "daily":
            query = "SELECT timestamp, message, type, severity FROM alerts WHERE timestamp >= date('now', '-1 day')"
        elif timeframe == "weekly":
            query = "SELECT timestamp, message, type, severity FROM alerts WHERE timestamp >= date('now', '-7 days')"
        elif timeframe == "monthly":
            query = "SELECT timestamp, message, type, severity FROM alerts WHERE timestamp >= date('now', '-1 month')"
        else:
            return []  # Invalid timeframe
        
        cursor.execute(query)
        return cursor.fetchall()
     
def get_alerts_by_date_range(start_date, end_date):
        """
        Retrieve alerts from the database within a given date range.

        Args:
            start_date (str): The starting date (YYYY-MM-DD).
            end_date (str): The ending date (YYYY-MM-DD).

        Returns:
            list: A list of tuples containing (timestamp, message, type, severity).
        """
        try:
            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()
                query = """
                    SELECT timestamp, message, type, severity
                    FROM alerts
                    WHERE DATE(timestamp) BETWEEN ? AND ?
                    ORDER BY timestamp ASC
                """
                cursor.execute(query, (start_date, end_date))
                return cursor.fetchall()  # Returns a list of (timestamp, message, type, severity) tuples
        except sqlite3.Error as e:
            print(f"Error retrieving alerts by date range: {e}")
            return []
     

                
def log_device(ip, mac, manufacturer, device_name, device_type, status="connected"):
    """
    Logs or updates a network device in the database.

    Parameters:
    ip (str): IP address of the device.
    mac (str): MAC address of the device.
    manufacturer (str): Manufacturer of the device.
    device_name (str): Device hostname.
    device_type (str): Type of device.
    status (str): Connection status (default: "connected").
    """
    try:
        conn = sqlite3.connect("network_monitoring.db")
        cursor = conn.cursor()

        # Check if the device already exists
        cursor.execute(
            "SELECT id FROM network_devices WHERE mac_address = ?",
            (mac,),
        )
        device = cursor.fetchone()

        if device:
            # Update the last seen timestamp and status if the device already exists
            cursor.execute(
                """
                UPDATE network_devices 
                SET last_seen = CURRENT_TIMESTAMP, status = ? 
                WHERE mac_address = ?
                """,
                (status, mac),
            )
        else:
            # Insert a new record for a new device
            cursor.execute(
                """
                INSERT INTO network_devices (ip_address, mac_address, manufacturer, device_name, device_type, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (ip, mac, manufacturer, device_name, device_type, status),
            )

        conn.commit()
    except sqlite3.Error as e:
        print(f"Error logging device: {e}")
    finally:
        conn.close()


     
