import os
import sqlite3
import time
import subprocess
import platform
import socket
import ipaddress
from datetime import datetime

from scapy.all import ARP, Ether, srp

from port_scanner import scan_device

from device_identifier import (
    is_valid_device_ip,
    identify_device_type,
    build_device_display_name
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "security_logs.db")

SCAN_INTERVAL = 10


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    return connection


def get_local_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))

        local_ip = sock.getsockname()[0]

        sock.close()

        return local_ip

    except Exception:
        return None


def get_current_subnet_prefix():
    local_ip = get_local_ip()

    if not local_ip:
        return None

    parts = local_ip.split(".")

    if len(parts) != 4:
        return None

    return f"{parts[0]}.{parts[1]}.{parts[2]}."


def is_current_network_ip(ip_address):
    subnet_prefix = get_current_subnet_prefix()

    if not subnet_prefix:
        return False

    return ip_address.startswith(subnet_prefix)


def get_network_range():
    local_ip = get_local_ip()

    if not local_ip:
        return None

    ip_parts = local_ip.split(".")

    network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    return network_range


def cleanup_old_network_rows():
    subnet_prefix = get_current_subnet_prefix()

    if not subnet_prefix:
        return 0

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, ip_address
        FROM devices
    """)

    rows = cursor.fetchall()
    deleted_count = 0

    for row in rows:
        row_id = row[0]
        ip_address = row[1]

        if not is_valid_device_ip(ip_address) or not ip_address.startswith(subnet_prefix):
            cursor.execute("""
                DELETE FROM devices
                WHERE id = ?
            """, (row_id,))

            cursor.execute("""
                DELETE FROM threats
                WHERE ip_address = ?
            """, (ip_address,))

            cursor.execute("""
                DELETE FROM vulnerabilities
                WHERE ip_address = ?
            """, (ip_address,))

            deleted_count += 1

    connection.commit()
    connection.close()

    if deleted_count > 0:
        print(f"[CLEANUP] Removed {deleted_count} old/fake device rows.")

    return deleted_count


def device_exists(ip_address):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM devices
        WHERE ip_address = ?
    """, (ip_address,))

    existing = cursor.fetchone()

    connection.close()

    return existing is not None


def save_device(ip_address, mac_address):
    if not is_valid_device_ip(ip_address):
        print(f"[IGNORED] Not a real device IP: {ip_address}")
        return False

    if not is_current_network_ip(ip_address):
        print(f"[IGNORED] Not current Wi-Fi subnet: {ip_address}")
        return False

    connection = get_connection()
    cursor = connection.cursor()

    last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    device_type = identify_device_type(
        ip_address,
        mac_address
    )

    device_name = build_device_display_name(
        ip_address,
        mac_address
    )

    if device_type == "Ignored":
        connection.close()
        return False

    if device_exists(ip_address):
        cursor.execute("""
            UPDATE devices
            SET mac_address = ?,
                device_name = ?,
                device_type = ?,
                last_seen = ?
            WHERE ip_address = ?
        """, (
            mac_address,
            device_name,
            device_type,
            last_seen,
            ip_address
        ))

        is_new_device = False

    else:
        cursor.execute("""
            INSERT INTO devices (
                ip_address,
                mac_address,
                device_name,
                device_type,
                trust_status,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            ip_address,
            mac_address,
            device_name,
            device_type,
            "Unknown",
            last_seen
        ))

        is_new_device = True

    connection.commit()
    connection.close()

    return is_new_device


def save_new_device_threat(ip_address):
    if not is_valid_device_ip(ip_address):
        return

    if not is_current_network_ip(ip_address):
        return

    connection = get_connection()
    cursor = connection.cursor()

    detected_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    threat_type = "New Device Detected"

    cursor.execute("""
        SELECT id
        FROM threats
        WHERE ip_address = ?
        AND threat_type = ?
        AND status = 'active'
    """, (
        ip_address,
        threat_type
    ))

    existing = cursor.fetchone()

    if existing:
        connection.close()
        return

    cursor.execute("""
        INSERT INTO threats (
            threat_type,
            ip_address,
            status,
            detected_time
        )
        VALUES (?, ?, ?, ?)
    """, (
        threat_type,
        ip_address,
        "active",
        detected_time
    ))

    connection.commit()
    connection.close()

    print(f"[ALERT] New Device Detected: {ip_address}")


def arp_scan():
    devices = []

    network_range = get_network_range()

    if not network_range:
        return devices

    try:
        print(f"Running ARP scan on {network_range}")

        arp_request = ARP(pdst=network_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        answered = srp(
            packet,
            timeout=2,
            verbose=False
        )[0]

        for sent, received in answered:
            ip_address = received.psrc
            mac_address = received.hwsrc

            if is_valid_device_ip(ip_address) and is_current_network_ip(ip_address):
                devices.append({
                    "ip": ip_address,
                    "mac": mac_address
                })

    except Exception as error:
        print(f"[ARP SCAN ERROR] {error}")

    return devices


def extract_ip_from_arp_line(line):
    line = line.strip()

    ip_match = None

    if "(" in line and ")" in line:
        start = line.find("(") + 1
        end = line.find(")")
        ip_match = line[start:end]
    else:
        parts = line.split()

        for part in parts:
            try:
                ipaddress.ip_address(part)
                ip_match = part
                break
            except Exception:
                pass

    return ip_match


def extract_mac_from_arp_line(line):
    mac_pattern = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
    match = re_search_mac(mac_pattern, line)

    if match:
        return match.replace("-", ":").lower()

    return "Unknown"


def re_search_mac(pattern, text):
    import re

    result = re.search(pattern, text)

    if result:
        return result.group(0)

    return None


def arp_table_scan():
    devices = []

    try:
        command = ["arp", "-a"]

        result = subprocess.check_output(
            command,
            text=True,
            errors="ignore"
        )

        lines = result.splitlines()

        for line in lines:
            ip_address = extract_ip_from_arp_line(line)
            mac_address = extract_mac_from_arp_line(line)

            if not ip_address:
                continue

            if is_valid_device_ip(ip_address) and is_current_network_ip(ip_address):
                devices.append({
                    "ip": ip_address,
                    "mac": mac_address
                })

    except Exception as error:
        print(f"[ARP TABLE ERROR] {error}")

    return devices


def ping_device(ip_address):
    if not is_valid_device_ip(ip_address):
        return False

    if not is_current_network_ip(ip_address):
        return False

    try:
        system_name = platform.system().lower()

        if "windows" in system_name:
            command = ["ping", "-n", "1", "-w", "300", ip_address]
        else:
            command = ["ping", "-c", "1", "-W", "1", ip_address]

        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return result.returncode == 0

    except Exception:
        return False


def ping_sweep():
    devices = []

    local_ip = get_local_ip()

    if not local_ip:
        return devices

    ip_parts = local_ip.split(".")
    base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"

    print(f"Running ping sweep on {base_ip}.0/24")

    for number in range(1, 255):
        ip_address = f"{base_ip}.{number}"

        if ping_device(ip_address):
            devices.append({
                "ip": ip_address,
                "mac": "Unknown"
            })

    return devices


def merge_devices(device_lists):
    merged = {}

    for device_list in device_lists:
        for device in device_list:
            ip_address = device.get("ip")
            mac_address = device.get("mac", "Unknown")

            if not ip_address:
                continue

            if not is_valid_device_ip(ip_address):
                continue

            if not is_current_network_ip(ip_address):
                continue

            if ip_address not in merged:
                merged[ip_address] = mac_address

            elif merged[ip_address] == "Unknown" and mac_address != "Unknown":
                merged[ip_address] = mac_address

    final_devices = []

    for ip_address, mac_address in merged.items():
        final_devices.append({
            "ip": ip_address,
            "mac": mac_address
        })

    return final_devices


def discover_devices():
    cleanup_old_network_rows()

    arp_devices = arp_scan()
    arp_table_devices = arp_table_scan()
    ping_devices = ping_sweep()

    devices = merge_devices([
        arp_devices,
        arp_table_devices,
        ping_devices
    ])

    return devices


def process_devices(devices):
    if not devices:
        print("No devices discovered.")
        return

    for device in devices:
        ip_address = device["ip"]
        mac_address = device["mac"]

        if not is_valid_device_ip(ip_address):
            print(f"[IGNORED] Invalid device IP: {ip_address}")
            continue

        if not is_current_network_ip(ip_address):
            print(f"[IGNORED] Old network IP: {ip_address}")
            continue

        is_new_device = save_device(
            ip_address,
            mac_address
        )

        if is_new_device:
            print(f"[NEW DEVICE] {ip_address} - {mac_address}")

            save_new_device_threat(ip_address)

            print(f"[AUTO PORT SCAN] Starting scan for new device {ip_address}")

            scan_device(
                ip_address,
                mac_address
            )

        else:
            print(f"[UPDATED] {ip_address} - {mac_address}")


def start_background_scanner():
    print("Torpedo'sHome AI Background Scanner Started")
    print(f"Scanning every {SCAN_INTERVAL} seconds")

    while True:
        try:
            devices = discover_devices()

            print(f"\nDiscovered real current-network devices: {len(devices)}")

            process_devices(devices)

        except Exception as error:
            print(f"[BACKGROUND SCANNER ERROR] {error}")

        print(f"\nWaiting {SCAN_INTERVAL} seconds before next scan...")
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    start_background_scanner()