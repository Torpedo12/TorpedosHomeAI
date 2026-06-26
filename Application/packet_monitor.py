import os
import time
import sqlite3
from datetime import datetime
from collections import defaultdict, deque

from scapy.all import sniff, IP, TCP, UDP, ARP

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "security_logs.db")

ROUTER_IP = "10.0.0.1"

PORT_SCAN_WINDOW_SECONDS = 30
PORT_SCAN_PORT_LIMIT = 10

CONNECTION_WINDOW_SECONDS = 30
CONNECTION_ATTEMPT_LIMIT = 60

ARP_WINDOW_SECONDS = 30
ARP_REQUEST_LIMIT = 25

ROUTER_ADMIN_WINDOW_SECONDS = 60
ROUTER_ADMIN_ATTEMPT_LIMIT = 12

BRUTE_FORCE_WINDOW_SECONDS = 60
BRUTE_FORCE_ATTEMPT_LIMIT = 30

PASSWORD_GUESS_WINDOW_SECONDS = 60
PASSWORD_GUESS_ATTEMPT_LIMIT = 20

COMMON_SUSPICIOUS_PORTS = {
    21,
    22,
    23,
    53,
    80,
    135,
    139,
    443,
    445,
    3306,
    3389,
    5900,
    8080
}

ROUTER_ADMIN_PORTS = {
    80,
    443,
    8080,
    8443
}

BRUTE_FORCE_PORTS = {
    21,
    22,
    23,
    80,
    443,
    445,
    3389,
    5900,
    8080
}

AUTHENTICATION_PORTS = {
    21,
    22,
    23,
    80,
    443,
    3389,
    5900,
    8080,
    8443
}

port_activity = defaultdict(lambda: deque())
connection_activity = defaultdict(lambda: deque())
arp_activity = defaultdict(lambda: deque())
router_admin_activity = defaultdict(lambda: deque())
brute_force_activity = defaultdict(lambda: deque())
password_guess_activity = defaultdict(lambda: deque())


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def cleanup_old_events(event_queue, window_seconds):
    now = time.time()

    while event_queue and now - event_queue[0] > window_seconds:
        event_queue.popleft()


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


def create_threat_alert(threat_type, ip_address):
    if ip_address is None or ip_address == "":
        return

    if threat_exists(threat_type, ip_address):
        return

    connection = get_connection()
    cursor = connection.cursor()

    detected_time = current_time()

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

    print("\n==============================")
    print("TORPEDO'SHOME AI IDS ALERT")
    print("==============================")
    print("Alert:", threat_type)
    print("Source IP:", ip_address)
    print("Time:", detected_time)
    print("==============================\n")


def detect_port_scan(source_ip, destination_port):
    if source_ip is None or destination_port is None:
        return

    now = time.time()

    activity_key = source_ip
    port_activity[activity_key].append((now, destination_port))

    while port_activity[activity_key] and now - port_activity[activity_key][0][0] > PORT_SCAN_WINDOW_SECONDS:
        port_activity[activity_key].popleft()

    unique_ports = set()

    for event_time, port in port_activity[activity_key]:
        unique_ports.add(port)

    if len(unique_ports) >= PORT_SCAN_PORT_LIMIT:
        create_threat_alert(
            "Port Scan Detected",
            source_ip
        )


def detect_suspicious_connection_volume(source_ip):
    if source_ip is None:
        return

    now = time.time()

    connection_activity[source_ip].append(now)
    cleanup_old_events(connection_activity[source_ip], CONNECTION_WINDOW_SECONDS)

    if len(connection_activity[source_ip]) >= CONNECTION_ATTEMPT_LIMIT:
        create_threat_alert(
            "Suspicious Traffic Detected",
            source_ip
        )


def detect_network_reconnaissance(source_ip, destination_port):
    if source_ip is None or destination_port is None:
        return

    if destination_port in COMMON_SUSPICIOUS_PORTS:
        now = time.time()

        activity_key = f"{source_ip}_recon"
        port_activity[activity_key].append((now, destination_port))

        while port_activity[activity_key] and now - port_activity[activity_key][0][0] > PORT_SCAN_WINDOW_SECONDS:
            port_activity[activity_key].popleft()

        unique_ports = set()

        for event_time, port in port_activity[activity_key]:
            unique_ports.add(port)

        if len(unique_ports) >= 5:
            create_threat_alert(
                "Network Reconnaissance Detected",
                source_ip
            )


def detect_router_admin_probing(source_ip, destination_ip, destination_port):
    if source_ip is None or destination_ip is None or destination_port is None:
        return

    if destination_ip != ROUTER_IP:
        return

    if destination_port not in ROUTER_ADMIN_PORTS:
        return

    now = time.time()

    router_admin_activity[source_ip].append(now)
    cleanup_old_events(
        router_admin_activity[source_ip],
        ROUTER_ADMIN_WINDOW_SECONDS
    )

    if len(router_admin_activity[source_ip]) >= ROUTER_ADMIN_ATTEMPT_LIMIT:
        create_threat_alert(
            "Router Admin Probing Detected",
            source_ip
        )


def detect_brute_force_behavior(source_ip, destination_ip, destination_port):
    if source_ip is None or destination_ip is None or destination_port is None:
        return

    if destination_port not in BRUTE_FORCE_PORTS:
        return

    now = time.time()

    activity_key = f"{source_ip}_{destination_ip}_{destination_port}"

    brute_force_activity[activity_key].append(now)
    cleanup_old_events(
        brute_force_activity[activity_key],
        BRUTE_FORCE_WINDOW_SECONDS
    )

    if len(brute_force_activity[activity_key]) >= BRUTE_FORCE_ATTEMPT_LIMIT:
        create_threat_alert(
            "Brute Force Behavior Detected",
            source_ip
        )


def detect_password_guessing_behavior(source_ip, destination_ip, destination_port):
    if source_ip is None or destination_ip is None or destination_port is None:
        return

    if destination_port not in AUTHENTICATION_PORTS:
        return

    now = time.time()

    activity_key = f"{source_ip}_{destination_ip}_{destination_port}_auth"

    password_guess_activity[activity_key].append(now)
    cleanup_old_events(
        password_guess_activity[activity_key],
        PASSWORD_GUESS_WINDOW_SECONDS
    )

    if len(password_guess_activity[activity_key]) >= PASSWORD_GUESS_ATTEMPT_LIMIT:
        create_threat_alert(
            "Password Guessing Behavior Detected",
            source_ip
        )


def detect_arp_scan(packet):
    if not packet.haslayer(ARP):
        return

    try:
        if packet[ARP].op != 1:
            return

        source_ip = packet[ARP].psrc

        if source_ip is None or source_ip == "0.0.0.0":
            return

        now = time.time()

        arp_activity[source_ip].append(now)
        cleanup_old_events(
            arp_activity[source_ip],
            ARP_WINDOW_SECONDS
        )

        if len(arp_activity[source_ip]) >= ARP_REQUEST_LIMIT:
            create_threat_alert(
                "ARP Network Scan Detected",
                source_ip
            )

    except Exception as error:
        print("[IDS ARP ERROR]", error)


def check_packet(packet):
    try:
        detect_arp_scan(packet)

        if packet.haslayer(IP):
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            destination_port = None
            protocol_name = "IP"

            if packet.haslayer(TCP):
                destination_port = packet[TCP].dport
                protocol_name = "TCP"

            elif packet.haslayer(UDP):
                destination_port = packet[UDP].dport
                protocol_name = "UDP"

            print(
                f"[IDS] {protocol_name} | "
                f"From: {source_ip} | "
                f"To: {destination_ip} | "
                f"Port: {destination_port}"
            )

            detect_suspicious_connection_volume(source_ip)

            if destination_port is not None:
                detect_port_scan(source_ip, destination_port)
                detect_network_reconnaissance(source_ip, destination_port)
                detect_router_admin_probing(source_ip, destination_ip, destination_port)
                detect_brute_force_behavior(source_ip, destination_ip, destination_port)
                detect_password_guessing_behavior(source_ip, destination_ip, destination_port)

    except Exception as error:
        print("[IDS PACKET ERROR]", error)


def start_packet_monitor():
    print("\n========================================")
    print("TORPEDO'SHOME AI ADVANCED IDS STARTED")
    print("Packet Monitor Running")
    print("Detecting:")
    print("- Port Scan Activity")
    print("- Suspicious Traffic Volume")
    print("- Network Reconnaissance")
    print("- ARP Network Scans")
    print("- Router Admin Probing")
    print("- Brute Force Behavior")
    print("- Password Guessing Behavior")
    print("Press CTRL + C to stop.")
    print("========================================\n")

    sniff(
        prn=check_packet,
        store=False
    )


if __name__ == "__main__":
    start_packet_monitor()