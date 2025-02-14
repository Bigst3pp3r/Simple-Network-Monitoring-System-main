import sqlite3

DB_FILE = "network_monitoring.db"

# Ensure the filters table exists
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS filters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT,
                port INTEGER
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS thresholds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                high_packet_threshold INTEGER,
                icmp_activity_threshold INTEGER
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklisted_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE
            )
        ''')
        conn.commit()

# --- FILTERS: Protocol & Port ---
def add_filter(protocol, port):
    """ Add a new protocol/port filter to the database """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO filters (protocol, port) VALUES (?, ?)", (protocol, port))
        conn.commit()

def remove_filter(protocol, port):
    """ Remove a protocol/port filter from the database """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM filters WHERE protocol = ? AND port = ?", (protocol, port))
        conn.commit()

def get_filters():
    """ Retrieve all active protocol/port filters """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT protocol, port FROM filters")
        return cursor.fetchall()  # Returns a list of (protocol, port) tuples

# --- THRESHOLDS ---
def get_thresholds():
    """ Get current thresholds for high packet rate & ICMP activity """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT high_packet_threshold, icmp_activity_threshold FROM thresholds ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        if result:
            return {"high_packet_threshold": result[0], "icmp_activity_threshold": result[1]}
        return {"high_packet_threshold": 1000, "icmp_activity_threshold": 50}  # Default values

def update_thresholds(high_packet_threshold, icmp_activity_threshold):
    """ Update threshold values in the database """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO thresholds (high_packet_threshold, icmp_activity_threshold) VALUES (?, ?)", 
                       (high_packet_threshold, icmp_activity_threshold))
        conn.commit()

# --- BLACKLISTED IPs ---
def get_blacklisted_ips():
    """ Retrieve all blacklisted IPs """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM blacklisted_ips")
        return [row[0] for row in cursor.fetchall()]

def add_blacklisted_ip(ip):
    """ Add a new IP to the blacklist """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO blacklisted_ips (ip_address) VALUES (?)", (ip,))
        conn.commit()

def remove_blacklisted_ip(ip):
    """ Remove an IP from the blacklist """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blacklisted_ips WHERE ip_address = ?", (ip,))
        conn.commit()

# Ensure database structure exists on import
init_db()
