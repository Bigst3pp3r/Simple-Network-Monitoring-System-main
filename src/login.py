import tkinter as tk
from tkinter import messagebox
import sqlite3
import bcrypt
from monitoring_core import NetworkMonitor  # Import the function to start monitoring

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(stored_password, entered_password):
    return bcrypt.checkpw(entered_password.encode(), stored_password)

def authenticate_user(username, password):
    connection = sqlite3.connect("network_monitoring.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    connection.close()
    
    if result and verify_password(result[0], password):
        return True
    return False

def login():
    username = username_entry.get()
    password = password_entry.get()
    
    if authenticate_user(username, password):
        login_window.destroy()
        NetworkMonitor()  # Start the main system
    else:
        messagebox.showerror("Login Failed", "Invalid credentials!")

# GUI Setup
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
