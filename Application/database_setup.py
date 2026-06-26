import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "security_logs.db")

os.makedirs(os.path.join(BASE_DIR, "database"), exist_ok=True)

connection = sqlite3.connect(DB_PATH)
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE,
    mac_address TEXT,
    device_name TEXT,
    device_type TEXT,
    custom_name TEXT,
    custom_type TEXT,
    trust_status TEXT DEFAULT 'Unknown',
    connection_status TEXT DEFAULT 'Online',
    connection_type TEXT,
    signal_strength TEXT,
    last_seen TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type TEXT,
    ip_address TEXT,
    status TEXT DEFAULT 'active',
    detected_time TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    mac_address TEXT,
    port_number INTEGER,
    service_name TEXT,
    risk_level TEXT,
    risk_points INTEGER,
    reason TEXT,
    detected_time TEXT
)
""")


def add_column_if_missing(table_name, column_name, column_definition):
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()

    existing_columns = []

    for column in columns:
        existing_columns.append(column[1])

    if column_name not in existing_columns:
        cursor.execute(f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name} {column_definition}
        """)

        print(f"Added column {column_name} to {table_name}")


add_column_if_missing("devices", "device_name", "TEXT")
add_column_if_missing("devices", "device_type", "TEXT")
add_column_if_missing("devices", "custom_name", "TEXT")
add_column_if_missing("devices", "custom_type", "TEXT")
add_column_if_missing("devices", "trust_status", "TEXT DEFAULT 'Unknown'")
add_column_if_missing("devices", "connection_status", "TEXT DEFAULT 'Online'")
add_column_if_missing("devices", "connection_type", "TEXT")
add_column_if_missing("devices", "signal_strength", "TEXT")
add_column_if_missing("devices", "last_seen", "TEXT")

connection.commit()
connection.close()

print("Database setup completed successfully.")