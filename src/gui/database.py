import sqlite3

DB_FILE = "network_monitoring.db"

def fetch_data(table_name):
    """Fetch all records from a table."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table_name}")
            return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []


def initialize_database():
    """Ensure required tables exist in the existing database without deleting data."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Ensure network_devices table exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    manufacturer TEXT,
                    device_name TEXT,
                    device_type TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    status TEXT
                )
            """)

            # Ensure packets table exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL
                )
            """)

            # Ensure alerts table exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    message TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT
                )
            """)

            print("✅ Database structure verified. Existing data is intact.")
            conn.commit()
    except sqlite3.Error as e:
        print(f"⚠️ Error initializing database: {e}")
