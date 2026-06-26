import sqlite3

connection = sqlite3.connect("database/security_logs.db")

cursor = connection.cursor()

cursor.execute("""
INSERT INTO threats (threat_type, ip_address, status)
VALUES (?, ?, ?)
""", ("Port Scan Detected", "10.0.0.55", "Active"))

connection.commit()
connection.close()

print("Sample threat inserted successfully")