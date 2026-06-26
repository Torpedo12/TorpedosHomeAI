import sqlite3

connection = sqlite3.connect("database/security_logs.db")

cursor = connection.cursor()

cursor.execute("SELECT * FROM threats")

threats = cursor.fetchall()

for threat in threats:
    print(threat)

connection.close()