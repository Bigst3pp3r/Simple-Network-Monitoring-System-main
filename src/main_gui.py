# login_system.py (your modified login file)
import tkinter as tk
from tkinter import messagebox
import sqlite3
import bcrypt
import threading
from dashboard import create_dashboard_tab
from settings_gui import create_settings_tab
from alerts_gui import create_alerts_tab
from packets_gui import create_packets_tab
from devices_gui import create_devices_tab

def create_users_table():
    connection = sqlite3.connect("network_monitoring.db")
    cursor = connection.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
     
    connection.commit()
    connection.close()

def admin_exists():
    connection = sqlite3.connect("network_monitoring.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    exists = cursor.fetchone()[0] > 0
    
    connection.close()
    return exists

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(hashed_password, entered_password):
    return bcrypt.checkpw(entered_password.encode(), hashed_password.encode())

def create_admin(username, password):
    if admin_exists():
        print("Admin already exists!")
        return
    
    connection = sqlite3.connect("network_monitoring.db")
    cursor = connection.cursor()
    
    hashed_password = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')", 
                      (username, hashed_password))
        connection.commit()
        print("Admin account created successfully!")
    except sqlite3.IntegrityError:
        print("Username already exists!")
    finally:
        connection.close()

def authenticate_user(username, password):
    connection = sqlite3.connect("network_monitoring.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    connection.close()
    
    if result and verify_password(result[0], password):
        return result[1]
    return None

def initialize_monitor():
    from monitoring_core import NetworkMonitor
    return NetworkMonitor()

def create_main_application(monitor):
    root = tk.Tk()
    root.title("Network Monitoring System")
    root.geometry("900x600")

    sidebar = tk.Frame(root, width=200, bg="#2C3E50")
    sidebar.pack(side="left", fill="y")

    main_content = tk.Frame(root, bg="#ECF0F1")
    main_content.pack(side="right", expand=True, fill="both")

    tabs = {
        "📊 Dashboard": create_dashboard_tab(main_content, monitor),
        "📡 Packets": create_packets_tab(main_content),
        "🖥️Devices": create_devices_tab(main_content),
        "🚨 Alerts": create_alerts_tab(main_content),
        "⚙ Settings": create_settings_tab(main_content),
    }

    def switch_tab(tab_name):
        for frame in tabs.values():
            frame.pack_forget()
        tabs[tab_name].pack(fill="both", expand=True)

    for tab_name in tabs.keys():
        button = tk.Button(sidebar, text=tab_name, font=("Arial", 12), fg="white", bg="#34495E",
                         command=lambda t=tab_name: switch_tab(t))
        button.pack(fill="x", pady=5)

    tabs["📊 Dashboard"].pack(fill="both", expand=True)

    def start_monitoring():
        monitoring_thread = threading.Thread(target=monitor.start_monitoring, daemon=True)
        monitoring_thread.start()

    start_monitoring()
    return root

def login():
    username = username_entry.get()
    password = password_entry.get()
    role = authenticate_user(username, password)
    
    if role:
        messagebox.showinfo("Login Success", f"Welcome, {username}!")
        login_window.destroy()
        monitor = initialize_monitor()
        app = create_main_application(monitor)
        app.mainloop()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")

# Initialize database and check for admin
create_users_table()
if not admin_exists():
    print("No admin found. Please create an admin account.")
    admin_username = input("Enter admin username: ")
    admin_password = input("Enter admin password: ")
    create_admin(admin_username, admin_password)

# GUI Setup for login
login_window = tk.Tk()
login_window.title("Login - Network Monitoring System")
login_window.geometry("300x200")

tk.Label(login_window, text="Username").pack()
username_entry = tk.Entry(login_window)
username_entry.pack()

tk.Label(login_window, text="Password").pack()
password_entry = tk.Entry(login_window, show="*")
password_entry.pack()

tk.Button(login_window, text="Login", command=login).pack(pady=10)

login_window.mainloop()