import sqlite3
from datetime import datetime, timedelta
import threading
import time

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
        
         # ✅ Create `logged_devices` Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logged_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                mac_address TEXT UNIQUE,
                manufacturer TEXT,
                device_name TEXT,
                device_type TEXT,
                status TEXT CHECK(status IN ('active', 'disconnected')),
                last_seen TIMESTAMP
            )
        """)
     
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
                FROM packets 
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
     

                
def log_device(ip, mac, manufacturer, name, device_type, status="active"):
    """
    Logs a device in the database or updates its status if it exists.
    """
    with sqlite3.connect("network_monitoring.db") as conn:
        cursor = conn.cursor()
        
        # ✅ Check if the device already exists
        cursor.execute("SELECT id FROM logged_devices WHERE mac_address = ?", (mac,))
        existing = cursor.fetchone()

        if existing:
            # ✅ Update device status & last seen
            cursor.execute("""
                UPDATE logged_devices 
                SET status = ?, last_seen = ?
                WHERE mac_address = ?
            """, (status, datetime.now(), mac))
        else:
            # ✅ Insert new device
            cursor.execute("""
                INSERT INTO logged_devices (ip_address, mac_address, manufacturer, device_name, device_type, status, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ip, mac, manufacturer, name, device_type, status, datetime.now()))

        conn.commit()

def get_logged_devices():
    """Fetches all logged devices from the database."""
    with sqlite3.connect("network_monitoring.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logged_devices")
        return cursor.fetchall()

def update_device_status(ip, status="disconnected"):
    """
    Updates the device's status in the database.
    """
    with sqlite3.connect("network_monitoring.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE logged_devices 
            SET status = ?, last_seen = ?
            WHERE ip_address = ?
        """, (status, datetime.now(), ip))
        conn.commit()

def get_logged_ips():
    """
    Fetches all logged IP addresses from the logged_devices table.
    """
    with sqlite3.connect("network_monitoring.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM logged_devices")  # ✅ Ensure the correct table is used
        return [row[0] for row in cursor.fetchall()]  # ✅ Returns a list of IPs
    

def remove_disconnected_devices(threshold_hours=24, interval=3600):
    """
    Removes devices that have been inactive for more than the specified threshold.
    Runs automatically at a given interval.
    
    Args:
        threshold_hours (int): The number of hours after which an inactive device should be removed.
        interval (int): Time interval in seconds to run the cleanup automatically.
    """
    def cleanup_task():
        while True:
            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()
                time_threshold = datetime.now() - timedelta(hours=threshold_hours)
                
                cursor.execute("""
                    DELETE FROM logged_devices 
                    WHERE status = 'Inactive' AND last_seen < ?
                """, (time_threshold,))
                
                conn.commit()
            print("✅ Inactive devices cleaned up.")
            time.sleep(interval)  # Wait before running again
    
    threading.Thread(target=cleanup_task, daemon=True).start()
def get_most_active_devices(limit=5):
    """
    Fetches the top N most active devices based on occurrences in logs.
    
    Args:
        limit (int): Number of devices to fetch.
    
    Returns:
        List of most active devices.
    """
    with sqlite3.connect("network_monitoring.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip_address, mac_address, manufacturer, device_name, device_type, COUNT(*) as activity_count 
            FROM logged_devices 
            WHERE status = 'Active' 
            GROUP BY mac_address 
            ORDER BY activity_count DESC 
            LIMIT ?
        """, (limit,))
        
        return cursor.fetchall()

def notify_new_devices():
    """
    Alerts when a new device joins the network.
    """
    # Function implementation already handled elsewhere.
    pass

def generate_device_report(format='csv'):
    """
    Exports device logs to CSV or PDF.
    
    Args:
        format (str): 'csv' or 'pdf'.
    """
    import csv
    
    with sqlite3.connect("network_monitoring.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logged_devices")
        devices = cursor.fetchall()
    
    if format == 'csv':
        with open("device_report.csv", "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["IP Address", "MAC Address", "Manufacturer", "Device Name", "Device Type", "Status", "Last Seen"])
            writer.writerows(devices)
        print("✅ Device report saved as CSV.")
    elif format == 'pdf':
        # Placeholder for PDF export
        print("📄 PDF export not implemented yet.")

def bulk_insert_devices(devices_list):
    """
    Inserts multiple devices at once to speed up scanning.
    
    Args:
        devices_list (list of tuples): Each tuple contains (ip, mac, manufacturer, name, device_type, status, last_seen).
    """
    with sqlite3.connect("network_monitoring.db") as conn:
        cursor = conn.cursor()
        cursor.executemany("""
            INSERT INTO logged_devices (ip_address, mac_address, manufacturer, device_name, device_type, status, last_seen) 
            VALUES (?, ?, ?, ?, ?, ?, ?) 
            ON CONFLICT(mac_address) DO UPDATE SET status = 'Active', last_seen = ?
        """, [(d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[6]) for d in devices_list])
        conn.commit()
def optimize_db_cleanup(interval=2592000):  # Run every 30 days
    """
    Periodically cleans up old or duplicate logs.
    """
    def cleanup_task():
        while True:
            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()
                
                # Remove duplicate entries keeping the latest
                cursor.execute("""
                    DELETE FROM logged_devices 
                    WHERE id NOT IN (
                        SELECT MIN(id) FROM logged_devices GROUP BY mac_address
                    )
                """)
                
                conn.commit()
            print("✅ Database optimized.")
            time.sleep(interval)  # Wait before running again
    
    threading.Thread(target=cleanup_task, daemon=True).start()

# Start automatic cleanup in the background
remove_disconnected_devices()
optimize_db_cleanup()