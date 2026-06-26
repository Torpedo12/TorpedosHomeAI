import socket
import sqlite3
import time
import os
import ipaddress
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "security_logs.db")

SCAN_INTERVAL = 60

COMMON_PORTS = {
    21: ("High", 10, "FTP can expose file transfer access."),
    22: ("Low", 5, "SSH remote login service is open."),
    23: ("Critical", 15, "Telnet is insecure because it sends data in plain text."),
    53: ("Low", 5, "DNS service is open."),
    80: ("Low", 5, "HTTP web service is open."),
    135: ("Medium", 10, "Windows RPC service is open."),
    139: ("Medium", 10, "NetBIOS may expose Windows network information."),
    443: ("Low", 5, "HTTPS web service is open."),
    445: ("High", 15, "SMB file sharing service is open."),
    3306: ("High", 15, "MySQL database service is open."),
    3389: ("Critical", 20, "Remote Desktop service is open."),
    5900: ("High", 15, "VNC remote control service is open."),
    8080: ("Medium", 10, "Alternative web service is open.")
}


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def is_valid_scan_ip(ip_address):
    try:
        if not ip_address:
            return False

        if ip_address == "Unknown":
            return False

        ip = ipaddress.ip_address(ip_address)

        if ip.is_multicast:
            return False

        if ip.is_loopback:
            return False

        if ip.is_unspecified:
            return False

        if ip.is_reserved:
            return False

        if ip_address.endswith(".0"):
            return False

        if ip_address.endswith(".255"):
            return False

        return True

    except Exception:
        return False


def get_online_devices():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT ip_address,
               mac_address,
               device_name,
               device_type
        FROM devices
        WHERE connection_status IS NULL
           OR connection_status = 'Online'
        ORDER BY last_seen DESC
    """)

    rows = cursor.fetchall()
    connection.close()

    devices = []

    seen_ips = set()

    for row in rows:
        ip_address = row["ip_address"]

        if not is_valid_scan_ip(ip_address):
            continue

        if ip_address in seen_ips:
            continue

        seen_ips.add(ip_address)

        devices.append({
            "ip": ip_address,
            "mac": row["mac_address"] or "Unknown",
            "name": row["device_name"] or ip_address,
            "type": row["device_type"] or "Connected Device"
        })

    return devices


def is_port_open(ip_address, port_number):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip_address, port_number))

        sock.close()

        return result == 0

    except Exception:
        return False


def vulnerability_exists(ip_address, mac_address, port_number):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM vulnerabilities
        WHERE ip_address = ?
        AND lower(mac_address) = lower(?)
        AND port_number = ?
    """, (
        ip_address,
        mac_address,
        port_number
    ))

    existing = cursor.fetchone()

    connection.close()

    return existing is not None


def save_vulnerability(ip_address, mac_address, port_number, risk_level, risk_points, reason):
    if vulnerability_exists(ip_address, mac_address, port_number):
        print(f"[SKIP] Open port already saved: {ip_address}:{port_number}")
        return

    connection = get_connection()
    cursor = connection.cursor()

    detected_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO vulnerabilities (
            ip_address,
            mac_address,
            port_number,
            service_name,
            risk_level,
            risk_points,
            reason,
            detected_time
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ip_address,
        mac_address,
        port_number,
        "Hidden",
        risk_level,
        risk_points,
        reason,
        detected_time
    ))

    connection.commit()
    connection.close()

    print(f"[SAVED] Open port saved: {ip_address}:{port_number}")


def scan_device(ip_address, mac_address):
    if not is_valid_scan_ip(ip_address):
        print(f"[SKIP] Invalid scan IP: {ip_address}")
        return []

    print(f"\n[SCAN] Scanning device: {ip_address}")

    open_ports = []

    for port_number, details in COMMON_PORTS.items():
        risk_level = details[0]
        risk_points = details[1]
        reason = details[2]

        if is_port_open(ip_address, port_number):
            print(f"[OPEN] {ip_address}:{port_number}")

            save_vulnerability(
                ip_address,
                mac_address,
                port_number,
                risk_level,
                risk_points,
                reason
            )

            open_ports.append(port_number)

    if not open_ports:
        print(f"[SAFE] No common open ports found on {ip_address}")

    return open_ports


def start_port_scan():
    devices = get_online_devices()

    if not devices:
        print("No online devices found in database.")
        print("Run router_scanner.py first.")
        return

    print("\nStarting port scan for online router devices...")
    print("---------------------------------------------")

    for device in devices:
        print(f"[DEVICE] {device['name']} | {device['ip']} | {device['mac']}")
        scan_device(
            device["ip"],
            device["mac"]
        )

    print("\nPort scan completed.")


if __name__ == "__main__":
    print("Torpedo'sHome AI Port Scanner Started")
    print(f"Scanning every {SCAN_INTERVAL} seconds")

    while True:
        try:
            start_port_scan()

        except Exception as error:
            print(f"[ERROR] {error}")

        print(f"\nWaiting {SCAN_INTERVAL} seconds before next scan...")
        time.sleep(SCAN_INTERVAL)