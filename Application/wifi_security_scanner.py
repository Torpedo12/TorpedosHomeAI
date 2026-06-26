import socket
import sqlite3

# Device to scan
target_ip = "10.0.0.12"

# Risky ports
ports = {

    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    445: "SMB",
    3389: "RDP"

}


def save_threat(
    threat_type,
    ip_address,
    status
):

    connection = sqlite3.connect(
        "database/security_logs.db"
    )

    cursor = connection.cursor()

    cursor.execute("""

    INSERT INTO threats
    (
        threat_type,
        ip_address,
        status,
        detected_time
    )

    VALUES (?, ?, ?, datetime('now'))

    """, (

        threat_type,
        ip_address,
        status

    ))

    connection.commit()

    connection.close()


print("Scanning:", target_ip)

print("------------------------")

for port, service in ports.items():

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(1)

    result = sock.connect_ex(
        (target_ip, port)
    )

    if result == 0:

        print(
            f"[OPEN] {service} ({port})"
        )

        save_threat(

            f"Risky Port Open: {service}",

            target_ip,

            "Active"

        )

    sock.close()

print("------------------------")

print("Wi-Fi Security Scan Completed")