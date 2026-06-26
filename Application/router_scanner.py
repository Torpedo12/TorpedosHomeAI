import os
import re
import time
import sqlite3
import requests
import smtplib
from email.message import EmailMessage
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "security_logs.db")

ROUTER_URL = "Router_Gateway"
ROUTER_USERNAME = "Your_Router_Admin_Pannel_User_Id"
ROUTER_PASSWORD = "Your_Router_Admin_Pannel_Password"

SCAN_INTERVAL = 30

EMAIL_ALERTS_ENABLED = True

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

ALERT_EMAIL_SENDER = os.getenv("TORPEDO_EMAIL_SENDER", "")
ALERT_EMAIL_PASSWORD = os.getenv("TORPEDO_EMAIL_PASSWORD", "")
ALERT_EMAIL_RECEIVER = os.getenv("TORPEDO_EMAIL_RECEIVER", "")


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def normalize_mac(mac):
    if not mac:
        return "Unknown"
    return mac.strip().lower().replace("-", ":")


def clean_name(name):
    if not name:
        return "Unknown Device"
    return name.strip()


def classify_device_type(name):
    text = name.lower()

    if "iphone" in text:
        return "Phone"
    if "ipad" in text:
        return "Tablet"
    if "watch" in text:
        return "Wearable"
    if "samsung" in text:
        return "Smart TV"
    if "s24" in text or "galaxy" in text:
        return "Phone"
    if "torpedo" in text or "nilaypatel" in text:
        return "Laptop"
    if "printer" in text:
        return "Printer"
    if "camera" in text:
        return "Camera"

    return "Connected Device"


def get_icon(device_type):
    icons = {
        "Phone": "📱",
        "Tablet": "📱",
        "Wearable": "⌚",
        "Laptop": "💻",
        "Smart TV": "📺",
        "Printer": "🖨️",
        "Camera": "📷",
        "Connected Device": "📡"
    }

    return icons.get(device_type, "📡")


def send_email_alert(subject, message):
    if not EMAIL_ALERTS_ENABLED:
        return

    if ALERT_EMAIL_SENDER == "" or ALERT_EMAIL_PASSWORD == "" or ALERT_EMAIL_RECEIVER == "":
        print("[EMAIL ALERT] Email settings missing. Alert not sent.")
        return

    try:
        email = EmailMessage()
        email["From"] = ALERT_EMAIL_SENDER
        email["To"] = ALERT_EMAIL_RECEIVER
        email["Subject"] = subject
        email.set_content(message)

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(ALERT_EMAIL_SENDER, ALERT_EMAIL_PASSWORD)
        server.send_message(email)
        server.quit()

        print("[EMAIL ALERT] Email sent successfully.")

    except Exception as error:
        print("[EMAIL ALERT ERROR]", error)


def login_router():
    session = requests.Session()

    session.post(
        f"{ROUTER_URL}/check.jst",
        data={
            "username": ROUTER_USERNAME,
            "password": ROUTER_PASSWORD,
            "locale": "false"
        },
        timeout=10
    )

    return session


def fetch_router_page():
    try:
        session = login_router()

        response = session.get(
            f"{ROUTER_URL}/connected_devices_computers.jst",
            timeout=10
        )

        if response.status_code != 200:
            return ""

        return response.text

    except Exception as error:
        print("[ROUTER ERROR]", error)
        return ""


def extract_array(html, variable_name):
    pattern = rf'var\s+{variable_name}\s*=\s*\[(.*?)\];'
    match = re.search(pattern, html, re.DOTALL)

    if not match:
        return []

    return re.findall(r'"(.*?)"', match.group(1))


def extract_online_ips(html):
    ips = re.findall(
        r'IPv4 Address.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        html,
        re.DOTALL
    )

    clean_ips = []

    for ip in ips:
        if ip not in clean_ips:
            clean_ips.append(ip)

    return clean_ips


def build_device(name, mac, ip, status):
    clean_device_name = clean_name(name)
    clean_mac = normalize_mac(mac)

    device_type = classify_device_type(clean_device_name)
    icon = get_icon(device_type)

    return {
        "device_name": f"{icon} {clean_device_name}",
        "device_type": device_type,
        "ip_address": ip,
        "mac_address": clean_mac,
        "connection_status": status
    }


def extract_devices(html):
    online_names = extract_array(html, "onlineHostNameArr")
    online_macs = extract_array(html, "onlineHostMAC")
    offline_names = extract_array(html, "offlineHostNameArr")
    offline_macs = extract_array(html, "offlineHostMAC")
    online_ips = extract_online_ips(html)

    devices = []

    online_count = min(len(online_names), len(online_macs))

    for index in range(online_count):
        ip = None

        if index < len(online_ips):
            ip = online_ips[index]

        devices.append(
            build_device(
                online_names[index],
                online_macs[index],
                ip,
                "Online"
            )
        )

    offline_count = min(len(offline_names), len(offline_macs))

    for index in range(offline_count):
        devices.append(
            build_device(
                offline_names[index],
                offline_macs[index],
                None,
                "Offline"
            )
        )

    return devices


def cleanup_old_unknown_ip_rows():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM devices
        WHERE ip_address = 'Unknown'
    """)

    connection.commit()
    connection.close()


def threat_exists(threat_type, ip_address):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM threats
        WHERE threat_type = ?
          AND ip_address = ?
          AND lower(status) = 'active'
    """, (
        threat_type,
        ip_address
    ))

    row = cursor.fetchone()
    connection.close()

    return row is not None


def create_threat_alert(threat_type, ip_address, device_name="Unknown Device", mac_address="Unknown", device_type="Connected Device"):
    if not ip_address:
        return

    if threat_exists(threat_type, ip_address):
        return

    connection = get_connection()
    cursor = connection.cursor()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
        now
    ))

    connection.commit()
    connection.close()

    print(f"[ALERT] {threat_type} | IP: {ip_address}")

    email_subject = f"Torpedo'sHome AI Alert - {threat_type}"

    email_message = f"""
Torpedo'sHome AI Security Alert

Alert Type:
{threat_type}

Device:
{device_name}

Device Type:
{device_type}

IP Address:
{ip_address}

MAC Address:
{mac_address}

Status:
Active

Detected Time:
{now}

Recommended Action:
Review this device from the Torpedo'sHome AI dashboard. If you do not recognize this device, change your Wi-Fi password and restart the router.
"""

    send_email_alert(email_subject, email_message)


def save_device(device):
    connection = get_connection()
    cursor = connection.cursor()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    mac_address = device["mac_address"]
    ip_address = device["ip_address"]
    connection_status = device["connection_status"]

    cursor.execute("""
        SELECT id,
               ip_address,
               mac_address,
               trust_status,
               connection_status
        FROM devices
        WHERE lower(mac_address) = lower(?)
    """, (
        mac_address,
    ))

    existing = cursor.fetchone()

    is_new_device = existing is None
    current_trust_status = "Unknown"

    if existing:
        current_trust_status = existing["trust_status"] or "Unknown"

        if connection_status == "Online":
            cursor.execute("""
                UPDATE devices
                SET ip_address = ?,
                    device_name = ?,
                    device_type = ?,
                    connection_status = ?,
                    last_seen = ?
                WHERE id = ?
            """, (
                ip_address,
                device["device_name"],
                device["device_type"],
                connection_status,
                now,
                existing["id"]
            ))

        else:
            cursor.execute("""
                UPDATE devices
                SET device_name = ?,
                    device_type = ?,
                    connection_status = ?
                WHERE id = ?
            """, (
                device["device_name"],
                device["device_type"],
                connection_status,
                existing["id"]
            ))

    else:
        cursor.execute("""
            INSERT INTO devices (
                ip_address,
                mac_address,
                device_name,
                device_type,
                trust_status,
                connection_status,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            ip_address,
            mac_address,
            device["device_name"],
            device["device_type"],
            "Unknown",
            connection_status,
            now
        ))

        current_trust_status = "Unknown"

    connection.commit()
    connection.close()

    if connection_status == "Online" and ip_address:
        if is_new_device:
            create_threat_alert(
                "New Device Detected",
                ip_address,
                device["device_name"],
                mac_address,
                device["device_type"]
            )

        if current_trust_status.lower() != "trusted":
            create_threat_alert(
                "Unknown Device Connected",
                ip_address,
                device["device_name"],
                mac_address,
                device["device_type"]
            )


def scan_router():
    print("\n============================")
    print("TORPEDO'SHOME AI")
    print("ROUTER DEVICE SCAN STARTED")
    print("============================\n")

    html = fetch_router_page()

    if not html:
        print("[ROUTER] Router page unavailable.")
        return []

    if "onlineHostNameArr" not in html:
        print("[ROUTER] Device arrays not found.")
        return []

    cleanup_old_unknown_ip_rows()

    devices = extract_devices(html)

    online_count = 0
    offline_count = 0

    print(f"[ROUTER] Found {len(devices)} total devices")

    for device in devices:
        save_device(device)

        if device["connection_status"] == "Online":
            online_count += 1
        else:
            offline_count += 1

        display_ip = device["ip_address"] if device["ip_address"] else "Unknown"

        print(
            f"[ROUTER] {device['connection_status']} | "
            f"{device['device_name']} | "
            f"{display_ip} | "
            f"{device['mac_address']} | "
            f"{device['device_type']}"
        )

    print(f"[ROUTER] Online: {online_count}")
    print(f"[ROUTER] Offline: {offline_count}")

    return devices


def start_router_monitor():
    print("\n========================================")
    print("TORPEDO'SHOME AI ROUTER MONITOR STARTED")
    print("SCAN INTERVAL: 30 SECONDS")
    print("EMAIL ALERTS: ENABLED")
    print("========================================\n")

    while True:
        try:
            scan_router()
            print(f"\nWaiting {SCAN_INTERVAL} seconds...\n")
            time.sleep(SCAN_INTERVAL)

        except Exception as error:
            print("[ROUTER MONITOR ERROR]", error)
            time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    start_router_monitor()