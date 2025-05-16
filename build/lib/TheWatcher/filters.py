import sqlite3

DB_FILE = "network_monitoring.db"

# Ensure the filters table exists
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        
        # Create the filters table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS filters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT,
                port INTEGER,
                source_ip TEXT,
                destination_ip TEXT
            )
        ''')
        
        # Create the thresholds table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS thresholds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                high_packet_threshold INTEGER,
                icmp_activity_threshold INTEGER
            )
        ''')

        # Create the blacklisted_ips table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE
            )
        ''')

        # Create the ip_filters table for source/destination IP filters
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_filters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL
            )
        ''')

        # Create the filter_status table to store the toggle setting
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS filter_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enabled INTEGER DEFAULT 1
            )
        ''')

        # Initialize the filter toggle setting to enabled (if it doesn't already exist)
        cursor.execute('''
            INSERT INTO filter_status (enabled) 
            VALUES (1) ON CONFLICT DO NOTHING;
        ''')

        conn.commit()

# --- PROTOCOL & PORT FILTER MANAGEMENT ---
def get_filters():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT protocol, port FROM filters")
    filters = [(row[0], row[1]) for row in cursor.fetchall()]
    conn.close()
    return filters

def add_filter(protocol, port):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO filters (protocol, port) VALUES (?, ?)", (protocol, port))
    conn.commit()
    conn.close()

def remove_filter(protocol, port):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM filters WHERE protocol=? AND port=?", (protocol, port))
    conn.commit()
    conn.close()


# --- SOURCE/DESTINATION IP FILTERS ---
def get_ip_filters():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM ip_filters")
    ip_filters = [row[0] for row in cursor.fetchall()]
    conn.close()
    return ip_filters

def add_ip_filter(ip):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ip_filters (ip) VALUES (?)", (ip,))
    conn.commit()
    conn.close()

def remove_ip_filter(ip):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ip_filters WHERE ip=?", (ip,))
    conn.commit()
    conn.close()


# --- FILTER TOGGLE ---
def get_filter_status():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT enabled FROM filter_status LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return row[0] == 1 if row else True  # Default to True if not set

def update_filter_status(status):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE filter_status SET enabled=?", (1 if status else 0,))
    conn.commit()
    conn.close()
    
# --- THRESHOLD MANAGEMENT ---
def get_thresholds():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT high_packet_threshold, icmp_activity_threshold FROM thresholds LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return {"high_packet_threshold": row[0], "icmp_activity_threshold": row[1]} if row else {"high_packet_threshold": 100, "icmp_activity_threshold": 50}

def update_thresholds(high_threshold, icmp_threshold):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE thresholds SET high_packet_threshold=?, icmp_activity_threshold=?", (high_threshold, icmp_threshold))
    conn.commit()
    conn.close()

# --- BLACKLISTED IP MANAGEMENT ---
def get_blacklisted_ips():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address FROM blacklist")
    ips = [row[0] for row in cursor.fetchall()]
    conn.close()
    return ips

def add_blacklisted_ip(ip):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO blacklist (ip) VALUES (?)", (ip,))
    conn.commit()
    conn.close()

def remove_blacklisted_ip(ip):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blacklist WHERE ip=?", (ip,))
    conn.commit()
    conn.close()
# Ensure database structure exists on import

init_db()
