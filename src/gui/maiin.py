from database import initialize_database
from gui import create_gui

if __name__ == "__main__":
    initialize_database()  # Ensure database tables exist
create_gui()  # Launch the GUI


