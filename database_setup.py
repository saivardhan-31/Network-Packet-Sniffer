# database_setup.py
import sqlite3

def setup_database():
    """Initializes the SQLite database and creates tables."""
    # This will create the file in your project folder
    conn = sqlite3.connect('traffic.db')
    cursor = conn.cursor()

    print("Creating 'packets' table...")
    # Create a table to log all captured packets
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            dest_ip TEXT,
            source_port INTEGER,
            dest_port INTEGER,
            protocol TEXT,
            length INTEGER,
            flags TEXT
        )
    ''')

    print("Creating 'alerts' table...")
    # Create a table to log detected alerts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type TEXT,
            description TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print("Database setup complete. 'traffic.db' is ready.")

# This allows the script to be run directly from the terminal
if __name__ == '__main__':
    setup_database()