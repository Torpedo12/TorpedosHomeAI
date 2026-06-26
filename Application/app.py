from flask import Flask, render_template, redirect, url_for, request, jsonify, send_file
import sqlite3
import os
import ipaddress
from io import BytesIO
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    Table,
    TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch

from ai_explainer import (
    explain_threat,
    generate_security_assessment,
    answer_vulnerability_question
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "security_logs.db")

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "Application", "static")
)


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def is_real_home_device_ip(ip_address):
    try:
        if ip_address is None or ip_address == "" or ip_address == "Unknown":
            return True

        ip = ipaddress.ip_address(ip_address)

        if ip.is_multicast or ip.is_loopback or ip.is_unspecified or ip.is_reserved:
            return False

        if ip_address == "255.255.255.255":
            return False

        if ip_address.endswith(".255") or ip_address.endswith(".0"):
            return False

        return True

    except Exception:
        return False


def get_device_icon(device_type, device_name):
    text = f"{device_type} {device_name}".lower()

    if "router" in text or "gateway" in text:
        return "🌐"
    if "iphone" in text or "phone" in text:
        return "📱"
    if "ipad" in text or "tablet" in text:
        return "📱"
    if "watch" in text or "wearable" in text:
        return "⌚"
    if "torpedo" in text or "laptop" in text or "macbook" in text:
        return "💻"
    if "desktop" in text or "pc" in text or "windows" in text:
        return "🖥️"
    if "samsung" in text or "tv" in text:
        return "📺"
    if "printer" in text:
        return "🖨️"
    if "camera" in text or "cam" in text:
        return "📷"
    if "alexa" in text or "echo" in text or "speaker" in text:
        return "🔊"

    return "📡"


def remove_existing_icon(name):
    icons = ["🌐", "📱", "⌚", "💻", "🖥️", "📺", "🖨️", "📷", "🔊", "📡", "❓"]
    clean_name = name.strip()

    for icon in icons:
        if clean_name.startswith(icon):
            clean_name = clean_name.replace(icon, "", 1).strip()

    return clean_name


def clean_device_type(device_name, device_type):
    text = f"{device_name} {device_type}".lower()

    if "router" in text or "gateway" in text:
        return "Router"
    if "iphone" in text or "phone" in text:
        return "Phone"
    if "ipad" in text or "tablet" in text:
        return "Tablet"
    if "watch" in text or "wearable" in text:
        return "Wearable"
    if "torpedo" in text or "laptop" in text or "macbook" in text:
        return "Laptop"
    if "desktop" in text or "pc" in text or "windows" in text:
        return "Desktop"
    if "samsung" in text or "tv" in text:
        return "Smart TV"
    if "printer" in text:
        return "Printer"
    if "camera" in text or "cam" in text:
        return "Camera"
    if "alexa" in text or "echo" in text or "speaker" in text:
        return "Smart Speaker"

    return device_type or "Connected Device"


def build_display_device(row):
    ip_address = row["ip_address"]

    if ip_address is None or ip_address == "":
        ip_address = "Unknown"

    mac_address = row["mac_address"] or "Unknown"
    original_name = row["device_name"] or "Unknown Device"
    original_type = row["device_type"] or "Connected Device"

    clean_name = remove_existing_icon(original_name)
    clean_type = clean_device_type(clean_name, original_type)
    icon = get_device_icon(clean_type, clean_name)

    trust_status = row["trust_status"] or "Unknown"

    try:
        connection_status = row["connection_status"] or "Online"
    except Exception:
        connection_status = "Online"

    try:
        connection_type = row["connection_type"] or ""
    except Exception:
        connection_type = ""

    try:
        signal_strength = row["signal_strength"] or ""
    except Exception:
        signal_strength = ""

    return {
        "ip": ip_address,
        "mac": mac_address,
        "name": f"{icon} {clean_name}",
        "plain_name": clean_name,
        "type": clean_type,
        "icon": icon,
        "trust_status": trust_status,
        "connection_status": connection_status,
        "connection_type": connection_type,
        "signal_strength": signal_strength,
        "last_seen": row["last_seen"],
        "trusted": trust_status.lower() == "trusted"
    }


def cleanup_bad_database_rows():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, ip_address, connection_status
        FROM devices
    """)

    rows = cursor.fetchall()
    deleted_count = 0

    for row in rows:
        ip_address = row["ip_address"]
        connection_status = row["connection_status"] or "Online"

        if connection_status == "Offline":
            continue

        if ip_address is None or ip_address == "" or ip_address == "Unknown":
            continue

        if not is_real_home_device_ip(ip_address):
            cursor.execute("DELETE FROM devices WHERE id = ?", (row["id"],))
            cursor.execute("DELETE FROM threats WHERE ip_address = ?", (ip_address,))
            cursor.execute("DELETE FROM vulnerabilities WHERE ip_address = ?", (ip_address,))
            deleted_count += 1

    connection.commit()
    connection.close()

    return deleted_count


def get_devices():
    cleanup_bad_database_rows()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM devices
        WHERE connection_status IS NULL
           OR connection_status = 'Online'
        ORDER BY last_seen DESC
    """)

    rows = cursor.fetchall()
    connection.close()

    devices = []

    for row in rows:
        devices.append(build_display_device(row))

    return devices


def get_offline_devices():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM devices
        WHERE connection_status = 'Offline'
        ORDER BY last_seen DESC
    """)

    rows = cursor.fetchall()
    connection.close()

    offline_devices = []

    for row in rows:
        offline_devices.append(build_display_device(row))

    return offline_devices


def get_device_name_by_ip(devices, ip_address):
    for device in devices:
        if device["ip"] == ip_address:
            return device["name"]

    return ip_address


def get_device_name_by_ip_or_mac(devices, ip_address, mac_address):
    for device in devices:
        if mac_address != "Unknown" and device["mac"].lower() == mac_address.lower():
            return device["name"]

        if device["ip"] == ip_address:
            return device["name"]

    return ip_address


def get_threat_explanation(threat_type):
    threat_text = threat_type.lower()

    if "new device" in threat_text:
        return "A new device has joined the home network for the first time. If this device is not recognized, it may be unauthorized."

    if "unknown device" in threat_text:
        return "An untrusted device is currently connected to the network. Review the device and mark it trusted only if you recognize it."

    if "port scan" in threat_text:
        return "The IDS detected one device attempting to connect to many different ports in a short time. This behavior may indicate reconnaissance or scanning."

    if "reconnaissance" in threat_text:
        return "The IDS detected traffic patterns commonly associated with network discovery or security probing."

    if "suspicious traffic" in threat_text:
        return "The IDS detected a high number of connection attempts in a short period. This may indicate automated scanning or abnormal network behavior."

    if "arp network scan" in threat_text:
        return "The IDS detected many ARP requests from one source. This may indicate local network discovery activity."

    return explain_threat(threat_type)


def get_threat_level(threat_type):
    threat_text = threat_type.lower()

    if "port scan" in threat_text:
        return "High"
    if "reconnaissance" in threat_text:
        return "High"
    if "suspicious traffic" in threat_text:
        return "High"
    if "arp network scan" in threat_text:
        return "Medium"
    if "unknown device" in threat_text:
        return "High"
    if "new device" in threat_text:
        return "Medium"

    return "Medium"


def get_threats(devices=None):
    if devices is None:
        devices = []

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT threat_type,
               ip_address,
               status,
               detected_time
        FROM threats
        ORDER BY detected_time DESC
    """)

    rows = cursor.fetchall()
    connection.close()

    threats = []

    for row in rows:
        ip_address = row["ip_address"]

        if not is_real_home_device_ip(ip_address):
            continue

        threat_type = row["threat_type"]
        device_display_name = get_device_name_by_ip(devices, ip_address)

        threats.append({
            "type": threat_type,
            "ip": ip_address,
            "device_name": device_display_name,
            "status": row["status"],
            "time": row["detected_time"],
            "level": get_threat_level(threat_type),
            "explanation": get_threat_explanation(threat_type)
        })

    return threats


def get_vulnerabilities(devices=None):
    if devices is None:
        devices = []

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT ip_address,
               mac_address,
               port_number,
               risk_level,
               risk_points,
               detected_time
        FROM vulnerabilities
        ORDER BY detected_time DESC
    """)

    rows = cursor.fetchall()
    connection.close()

    vulnerabilities = []

    for row in rows:
        ip_address = row["ip_address"]
        mac_address = row["mac_address"] or "Unknown"

        if not is_real_home_device_ip(ip_address):
            continue

        device_name = get_device_name_by_ip_or_mac(
            devices,
            ip_address,
            mac_address
        )

        vulnerabilities.append({
            "device_name": device_name,
            "ip": ip_address,
            "mac": mac_address,
            "port": row["port_number"],
            "risk_level": row["risk_level"] or "Low",
            "risk_points": row["risk_points"] or 0,
            "time": row["detected_time"]
        })

    return vulnerabilities


def calculate_risk_score(devices, threats, vulnerabilities):
    unknown_count = 0
    active_threat_count = 0
    vulnerability_points = 0

    for device in devices:
        if not device["trusted"]:
            unknown_count += 1

    for threat in threats:
        if threat["status"] and threat["status"].lower() == "active":
            active_threat_count += 1

    for vulnerability in vulnerabilities:
        if vulnerability["risk_points"]:
            vulnerability_points += int(vulnerability["risk_points"])

    risk_score = 100
    risk_score -= unknown_count * 3
    risk_score -= active_threat_count * 2
    risk_score -= vulnerability_points

    if risk_score < 0:
        risk_score = 0

    if risk_score > 100:
        risk_score = 100

    return risk_score


def generate_recommendations(devices, threats, vulnerabilities, risk_score):
    recommendations = []
    unknown_devices = []

    for device in devices:
        if not device["trusted"]:
            unknown_devices.append(device)

    if len(unknown_devices) > 0:
        recommendations.append({
            "title": "Review Unknown Devices",
            "level": "High",
            "message": f"{len(unknown_devices)} unknown device(s) are connected. Confirm each device and mark only recognized devices as trusted."
        })

    for threat in threats:
        if "New Device Detected" in threat["type"]:
            recommendations.append({
                "title": "Verify New Device",
                "level": "Medium",
                "message": f"New device detected at {threat['ip']}. Check whether this device belongs to you or your family."
            })

        if "Unknown Device Connected" in threat["type"]:
            recommendations.append({
                "title": "Investigate Unknown Connection",
                "level": "High",
                "message": f"Unknown device connected at {threat['ip']}. If you do not recognize it, change the Wi-Fi password and restart the router."
            })

        if "Port Scan Detected" in threat["type"]:
            recommendations.append({
                "title": "Investigate Port Scan",
                "level": "High",
                "message": f"Port scan activity was detected from {threat['ip']}. Review this device and block it if it is unknown."
            })

        if "Network Reconnaissance Detected" in threat["type"]:
            recommendations.append({
                "title": "Investigate Network Reconnaissance",
                "level": "High",
                "message": f"Network reconnaissance activity was detected from {threat['ip']}. Check whether a scanning tool or suspicious device is active."
            })

        if "Suspicious Traffic Detected" in threat["type"]:
            recommendations.append({
                "title": "Review Suspicious Traffic",
                "level": "High",
                "message": f"High connection volume was detected from {threat['ip']}. Review the device behavior and disconnect it if unknown."
            })

        if "ARP Network Scan Detected" in threat["type"]:
            recommendations.append({
                "title": "Review ARP Scan Activity",
                "level": "Medium",
                "message": f"ARP scan behavior was detected from {threat['ip']}. This may indicate local network discovery."
            })

    for vulnerability in vulnerabilities:
        port = int(vulnerability["port"])

        if port == 23:
            recommendations.append({
                "title": "Disable Telnet",
                "level": "Critical",
                "message": "Port 23 is open. Telnet is insecure because it sends data without encryption. Disable Telnet immediately."
            })

        elif port == 3389:
            recommendations.append({
                "title": "Secure Remote Desktop",
                "level": "Critical",
                "message": "Port 3389 is open. Remote Desktop should not be exposed on a home network unless absolutely required."
            })

        elif port == 445:
            recommendations.append({
                "title": "Review File Sharing",
                "level": "High",
                "message": "Port 445 is open. Windows file sharing can be risky if unknown devices are connected."
            })

        elif port == 80 or port == 8080:
            recommendations.append({
                "title": "Check Web Admin Interface",
                "level": "Medium",
                "message": f"Port {port} is open. Confirm that this web service is expected and password protected."
            })

        elif port == 21:
            recommendations.append({
                "title": "Disable FTP",
                "level": "High",
                "message": "Port 21 is open. FTP is insecure and should be replaced with encrypted file transfer."
            })

        elif port == 22:
            recommendations.append({
                "title": "Secure SSH Access",
                "level": "Medium",
                "message": "Port 22 is open. Use a strong password or key-based login and disable unused SSH access."
            })

    if risk_score < 60:
        recommendations.append({
            "title": "High Network Risk",
            "level": "Critical",
            "message": "Your network risk score is low. Review unknown devices, close unnecessary ports, and generate a full AI PDF report."
        })

    if len(recommendations) == 0:
        recommendations.append({
            "title": "Network Looks Healthy",
            "level": "Low",
            "message": "No major issues found. Continue monitoring for new devices and open ports."
        })

    unique_recommendations = []
    seen = set()

    for recommendation in recommendations:
        key = recommendation["title"] + recommendation["message"]

        if key not in seen:
            unique_recommendations.append(recommendation)
            seen.add(key)

    return unique_recommendations[:8]


def build_security_timeline(devices, offline_devices, threats, vulnerabilities):
    timeline = []

    for threat in threats:
        timeline.append({
            "event_type": "Threat Alert",
            "title": threat["type"],
            "description": f"Device: {threat['device_name']} | IP: {threat['ip']} | Status: {threat['status']}",
            "time": threat["time"],
            "level": threat["level"]
        })

    for vulnerability in vulnerabilities:
        timeline.append({
            "event_type": "Open Port Found",
            "title": f"Port {vulnerability['port']} detected",
            "description": f"Device: {vulnerability['device_name']} | IP: {vulnerability['ip']} | Risk: {vulnerability['risk_level']}",
            "time": vulnerability["time"],
            "level": vulnerability["risk_level"]
        })

    for device in offline_devices:
        timeline.append({
            "event_type": "Device Offline",
            "title": f"{device['name']} went offline",
            "description": f"IP: {device['ip']} | MAC: {device['mac']} | Type: {device['type']}",
            "time": device["last_seen"],
            "level": "Medium"
        })

    for device in devices:
        if device["trust_status"].lower() == "unknown":
            timeline.append({
                "event_type": "Unknown Device Online",
                "title": f"{device['name']} is connected",
                "description": f"IP: {device['ip']} | MAC: {device['mac']} | Type: {device['type']}",
                "time": device["last_seen"],
                "level": "High"
            })

    def timeline_sort_key(item):
        try:
            return datetime.strptime(item["time"], "%Y-%m-%d %H:%M:%S")
        except Exception:
            return datetime.min

    timeline.sort(key=timeline_sort_key, reverse=True)

    return timeline[:12]


def get_device_profile(mac_address):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM devices
        WHERE lower(mac_address) = lower(?)
    """, (
        mac_address,
    ))

    row = cursor.fetchone()
    connection.close()

    if not row:
        return None

    return build_display_device(row)


def get_device_profile_vulnerabilities(device):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT ip_address,
               mac_address,
               port_number,
               risk_level,
               risk_points,
               detected_time
        FROM vulnerabilities
        WHERE lower(mac_address) = lower(?)
           OR ip_address = ?
        ORDER BY detected_time DESC
    """, (
        device["mac"],
        device["ip"]
    ))

    rows = cursor.fetchall()
    connection.close()

    vulnerabilities = []

    for row in rows:
        vulnerabilities.append({
            "ip": row["ip_address"],
            "mac": row["mac_address"] or "Unknown",
            "port": row["port_number"],
            "risk_level": row["risk_level"] or "Low",
            "risk_points": row["risk_points"] or 0,
            "time": row["detected_time"]
        })

    return vulnerabilities


def get_device_profile_threats(device):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT threat_type,
               ip_address,
               status,
               detected_time
        FROM threats
        WHERE ip_address = ?
        ORDER BY detected_time DESC
    """, (
        device["ip"],
    ))

    rows = cursor.fetchall()
    connection.close()

    threats = []

    for row in rows:
        threats.append({
            "type": row["threat_type"],
            "ip": row["ip_address"],
            "status": row["status"],
            "time": row["detected_time"],
            "level": get_threat_level(row["threat_type"]),
            "explanation": get_threat_explanation(row["threat_type"])
        })

    return threats


def calculate_device_risk_score(device, threats, vulnerabilities):
    risk_score = 100

    if not device["trusted"]:
        risk_score -= 25

    if device["connection_status"].lower() == "offline":
        risk_score -= 5

    for threat in threats:
        if threat["status"] and threat["status"].lower() == "active":
            risk_score -= 10

    for vulnerability in vulnerabilities:
        try:
            risk_score -= int(vulnerability["risk_points"])
        except Exception:
            risk_score -= 3

    if risk_score < 0:
        risk_score = 0

    if risk_score > 100:
        risk_score = 100

    return risk_score


def generate_device_recommendation(device, threats, vulnerabilities, device_risk_score):
    if device_risk_score >= 90 and device["trusted"]:
        return "This device appears safe. It is trusted, no major active alerts are linked to it, and its current risk score is healthy."

    if not device["trusted"]:
        return "This device is currently marked as Unknown. Verify whether it belongs to you or your family. If you do not recognize it, change the Wi-Fi password and restart the router."

    for vulnerability in vulnerabilities:
        port = int(vulnerability["port"])

        if port == 23:
            return "This device has Telnet open on port 23. Telnet is insecure because it does not protect credentials properly. Disable Telnet immediately."
        if port == 3389:
            return "This device has Remote Desktop open on port 3389. Only keep this enabled if required, and protect it with strong authentication."
        if port == 445:
            return "This device has Windows file sharing open on port 445. Make sure file sharing is required and only trusted devices are connected to the network."
        if port == 21:
            return "This device has FTP open on port 21. FTP is insecure and should be disabled or replaced with a secure alternative."
        if port == 80 or port == 8080:
            return "This device has a web service open. Confirm that the web interface is expected and protected with a strong password."

    for threat in threats:
        if threat["status"].lower() == "active":
            return "This device has an active security alert. Review the alert, confirm the device identity, and take action if the device is unknown."

    return "This device has no critical issue, but continue monitoring it for new alerts, open ports, or trust status changes."


def update_device_trust(mac_address, trust_status):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE devices
        SET trust_status = ?
        WHERE lower(mac_address) = lower(?)
    """, (
        trust_status,
        mac_address
    ))

    if trust_status.lower() == "trusted":
        cursor.execute("""
            UPDATE threats
            SET status = 'resolved'
            WHERE ip_address IN (
                SELECT ip_address
                FROM devices
                WHERE lower(mac_address) = lower(?)
            )
            AND threat_type LIKE 'Unknown Device Connected%'
        """, (
            mac_address,
        ))

    connection.commit()
    connection.close()


def prepare_dashboard_data(ai_assessment):
    devices = get_devices()
    offline_devices = get_offline_devices()

    threats = get_threats(devices)
    vulnerabilities = get_vulnerabilities(devices)

    trusted_devices = []
    unknown_devices = []

    for device in devices:
        if device["trusted"]:
            trusted_devices.append(device)
        else:
            unknown_devices.append(device)

    risk_score = calculate_risk_score(
        devices,
        threats,
        vulnerabilities
    )

    recommendations = generate_recommendations(
        devices,
        threats,
        vulnerabilities,
        risk_score
    )

    security_timeline = build_security_timeline(
        devices,
        offline_devices,
        threats,
        vulnerabilities
    )

    return {
        "devices": devices,
        "trusted_devices": trusted_devices,
        "unknown_devices": unknown_devices,
        "offline_devices": offline_devices,
        "threats": threats,
        "vulnerabilities": vulnerabilities,
        "risk_score": risk_score,
        "ai_assessment": ai_assessment,
        "recommendations": recommendations,
        "security_timeline": security_timeline
    }


def clean_pdf_text(value):
    text = str(value)
    icons = ["🌐", "📱", "⌚", "💻", "🖥️", "📺", "🖨️", "📷", "🔊", "📡", "❓", "■"]
    for icon in icons:
        text = text.replace(icon, "")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.strip()


def make_paragraph(value, style):
    return Paragraph(clean_pdf_text(value), style)


def add_table(story, data, column_widths, header_color):
    table = Table(data, colWidths=column_widths, repeatRows=1)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_color),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.black),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#eef2f7")])
    ]))

    story.append(table)
    story.append(Spacer(1, 18))


def add_pdf_section(story, styles, title, content):
    story.append(Paragraph(title, styles["Heading2"]))
    story.append(Spacer(1, 8))

    if isinstance(content, list):
        if len(content) == 0:
            story.append(Paragraph("None found.", styles["Normal"]))
        else:
            for item in content:
                story.append(Paragraph(clean_pdf_text(item), styles["Normal"]))
                story.append(Spacer(1, 4))
    else:
        for line in str(content).split("\n"):
            if line.strip():
                story.append(Paragraph(clean_pdf_text(line.strip()), styles["Normal"]))
                story.append(Spacer(1, 4))

    story.append(Spacer(1, 14))


def generate_pdf_report(devices, offline_devices, threats, vulnerabilities, risk_score, ai_report, recommendations):
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        title="Torpedo'sHome AI Security Report",
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="CoverTitle",
        parent=styles["Title"],
        fontSize=28,
        leading=34,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=18
    ))

    styles.add(ParagraphStyle(
        name="CoverSubtitle",
        parent=styles["Heading1"],
        fontSize=16,
        leading=22,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0369a1"),
        spaceAfter=24
    ))

    styles.add(ParagraphStyle(
        name="SectionTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=24,
        textColor=colors.HexColor("#075985"),
        spaceAfter=12
    ))

    styles.add(ParagraphStyle(
        name="SmallBody",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11
    ))

    styles.add(ParagraphStyle(
        name="CardText",
        parent=styles["BodyText"],
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#111827")
    ))

    story = []

    if risk_score >= 85:
        grade = "A"
        status = "Healthy"
        status_color = colors.HexColor("#15803d")
    elif risk_score >= 70:
        grade = "B"
        status = "Moderate Risk"
        status_color = colors.HexColor("#ca8a04")
    elif risk_score >= 50:
        grade = "C"
        status = "Needs Attention"
        status_color = colors.HexColor("#ea580c")
    else:
        grade = "F"
        status = "Critical Risk"
        status_color = colors.HexColor("#dc2626")

    active_threats = []
    for threat in threats:
        if threat["status"] and threat["status"].lower() == "active":
            active_threats.append(threat)

    high_threats = []
    medium_threats = []
    low_threats = []

    for threat in threats:
        level = threat["level"].lower()
        if level == "high":
            high_threats.append(threat)
        elif level == "medium":
            medium_threats.append(threat)
        else:
            low_threats.append(threat)

    high_ports = []
    medium_ports = []
    low_ports = []

    for vuln in vulnerabilities:
        level = vuln["risk_level"].lower()
        if level == "high":
            high_ports.append(vuln)
        elif level == "medium":
            medium_ports.append(vuln)
        else:
            low_ports.append(vuln)

    # Cover page
    story.append(Spacer(1, 0.6 * inch))
    story.append(Paragraph("TORPEDO'SHOME AI", styles["CoverTitle"]))
    story.append(Paragraph("AI-Powered Home Network Security Assessment Report", styles["CoverSubtitle"]))
    story.append(Spacer(1, 18))

    cover_table = [
        ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Overall Risk Score", f"{risk_score}/100"],
        ["Security Grade", grade],
        ["Network Status", status],
        ["Online Devices", str(len(devices))],
        ["Offline Devices", str(len(offline_devices))],
        ["Threat Alerts", str(len(threats))],
        ["Open Port Findings", str(len(vulnerabilities))]
    ]

    cover = Table(cover_table, colWidths=[2.4 * inch, 3.4 * inch])
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#f8fafc")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.black),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10)
    ]))

    story.append(cover)
    story.append(Spacer(1, 28))

    status_card = Table([[Paragraph(f"<b>Executive Risk Status:</b> {status}", styles["CardText"])]], colWidths=[5.8 * inch])
    status_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), status_color),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("BOX", (0, 0), (-1, -1), 1, status_color),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14)
    ]))
    story.append(status_card)

    story.append(PageBreak())

    # Executive Summary
    story.append(Paragraph("Executive Summary", styles["SectionTitle"]))

    summary = (
        f"This report summarizes the current security posture of the home network monitored by "
        f"Torpedo'sHome AI. The network currently has {len(devices)} online device(s), "
        f"{len(offline_devices)} offline device(s), {len(threats)} threat alert(s), and "
        f"{len(vulnerabilities)} open port finding(s). The calculated network risk score is "
        f"{risk_score}/100, which maps to a security grade of {grade} and status of {status}."
    )

    story.append(Paragraph(clean_pdf_text(summary), styles["BodyText"]))
    story.append(Spacer(1, 16))

    dashboard_table = [
        ["Metric", "Value", "Interpretation"],
        ["Risk Score", f"{risk_score}/100", status],
        ["Online Devices", str(len(devices)), "Currently visible on the network"],
        ["Unknown Devices", str(len([d for d in devices if not d['trusted']])), "Require ownership verification"],
        ["Active Threats", str(len(active_threats)), "Alerts needing review"],
        ["High Threats", str(len(high_threats)), "Highest priority alerts"],
        ["Open Ports", str(len(vulnerabilities)), "Network services exposed"]
    ]

    add_table(
        story,
        dashboard_table,
        [1.8 * inch, 1.2 * inch, 3.3 * inch],
        colors.HexColor("#0369a1")
    )

    story.append(PageBreak())

    # Device Inventory
    story.append(Paragraph("Network Device Inventory", styles["SectionTitle"]))

    device_table = [
        ["Device", "IP Address", "MAC Address", "Type", "Trust"]
    ]

    for device in devices:
        device_table.append([
            make_paragraph(device["plain_name"], styles["SmallBody"]),
            make_paragraph(device["ip"], styles["SmallBody"]),
            make_paragraph(device["mac"], styles["SmallBody"]),
            make_paragraph(device["type"], styles["SmallBody"]),
            make_paragraph(device["trust_status"], styles["SmallBody"])
        ])

    add_table(
        story,
        device_table,
        [1.25 * inch, 1.05 * inch, 1.6 * inch, 1.25 * inch, 0.95 * inch],
        colors.HexColor("#0f172a")
    )

    story.append(Paragraph("Offline Devices", styles["SectionTitle"]))

    offline_table = [
        ["Device", "IP Address", "MAC Address", "Type", "Last Seen"]
    ]

    if offline_devices:
        for device in offline_devices:
            offline_table.append([
                make_paragraph(device["plain_name"], styles["SmallBody"]),
                make_paragraph(device["ip"], styles["SmallBody"]),
                make_paragraph(device["mac"], styles["SmallBody"]),
                make_paragraph(device["type"], styles["SmallBody"]),
                make_paragraph(device["last_seen"], styles["SmallBody"])
            ])
    else:
        offline_table.append(["None", "-", "-", "-", "-"])

    add_table(
        story,
        offline_table,
        [1.25 * inch, 1.05 * inch, 1.6 * inch, 1.25 * inch, 0.95 * inch],
        colors.HexColor("#475569")
    )

    story.append(PageBreak())

    # Threat Analysis
    story.append(Paragraph("Threat Analysis", styles["SectionTitle"]))

    threat_summary_table = [
        ["Threat Category", "Count"],
        ["High", str(len(high_threats))],
        ["Medium", str(len(medium_threats))],
        ["Low", str(len(low_threats))],
        ["Active", str(len(active_threats))]
    ]

    add_table(
        story,
        threat_summary_table,
        [2.6 * inch, 1.2 * inch],
        colors.HexColor("#dc2626")
    )

    threat_table = [
        ["Threat", "Device/IP", "Level", "Status", "Detected"]
    ]

    for threat in threats[:25]:
        threat_table.append([
            make_paragraph(threat["type"], styles["SmallBody"]),
            make_paragraph(f"{threat['device_name']} / {threat['ip']}", styles["SmallBody"]),
            make_paragraph(threat["level"], styles["SmallBody"]),
            make_paragraph(threat["status"], styles["SmallBody"]),
            make_paragraph(threat["time"], styles["SmallBody"])
        ])

    if len(threat_table) == 1:
        threat_table.append(["None", "-", "-", "-", "-"])

    add_table(
        story,
        threat_table,
        [1.55 * inch, 1.7 * inch, 0.7 * inch, 0.75 * inch, 1.35 * inch],
        colors.HexColor("#991b1b")
    )

    story.append(PageBreak())

    # Open Ports
    story.append(Paragraph("Open Port Findings", styles["SectionTitle"]))

    port_summary = [
        ["Risk Level", "Count"],
        ["High", str(len(high_ports))],
        ["Medium", str(len(medium_ports))],
        ["Low", str(len(low_ports))]
    ]

    add_table(
        story,
        port_summary,
        [2.6 * inch, 1.2 * inch],
        colors.HexColor("#ea580c")
    )

    vuln_table = [
        ["Device", "IP Address", "Port", "Risk", "Detected"]
    ]

    for vuln in vulnerabilities:
        vuln_table.append([
            make_paragraph(vuln["device_name"], styles["SmallBody"]),
            make_paragraph(vuln["ip"], styles["SmallBody"]),
            make_paragraph(vuln["port"], styles["SmallBody"]),
            make_paragraph(vuln["risk_level"], styles["SmallBody"]),
            make_paragraph(vuln["time"], styles["SmallBody"])
        ])

    if len(vuln_table) == 1:
        vuln_table.append(["None", "-", "-", "-", "-"])

    add_table(
        story,
        vuln_table,
        [1.55 * inch, 1.1 * inch, 0.65 * inch, 0.85 * inch, 1.45 * inch],
        colors.HexColor("#c2410c")
    )

    story.append(PageBreak())

    # Recommendations
    story.append(Paragraph("Security Recommendations", styles["SectionTitle"]))

    recommendation_table = [
        ["Priority", "Recommendation", "Action"]
    ]

    for recommendation in recommendations:
        recommendation_table.append([
            make_paragraph(recommendation["level"], styles["SmallBody"]),
            make_paragraph(recommendation["title"], styles["SmallBody"]),
            make_paragraph(recommendation["message"], styles["SmallBody"])
        ])

    if len(recommendation_table) == 1:
        recommendation_table.append(["Low", "Network Looks Healthy", "Continue monitoring."])

    add_table(
        story,
        recommendation_table,
        [0.9 * inch, 1.65 * inch, 3.55 * inch],
        colors.HexColor("#15803d")
    )

    story.append(PageBreak())

    # AI Assessment
    story.append(Paragraph("AI Security Assessment", styles["SectionTitle"]))

    safe_ai_report = clean_pdf_text(ai_report).replace("\n", "<br/>")
    story.append(Paragraph(safe_ai_report, styles["BodyText"]))

    story.append(PageBreak())

    # Final Scorecard
    story.append(Paragraph("Final Security Scorecard", styles["SectionTitle"]))

    scorecard = [
        ["Metric", "Result"],
        ["Risk Score", f"{risk_score}/100"],
        ["Security Grade", grade],
        ["Network Status", status],
        ["Online Devices", str(len(devices))],
        ["Offline Devices", str(len(offline_devices))],
        ["Threat Alerts", str(len(threats))],
        ["Active Threats", str(len(active_threats))],
        ["Open Port Findings", str(len(vulnerabilities))]
    ]

    add_table(
        story,
        scorecard,
        [2.6 * inch, 2.6 * inch],
        colors.HexColor("#0f766e")
    )

    closing_note = (
        "This report was generated automatically by Torpedo'sHome AI. "
        "The findings should be reviewed by the user, and unknown devices or high-risk services "
        "should be investigated immediately."
    )

    story.append(Spacer(1, 12))
    story.append(Paragraph(clean_pdf_text(closing_note), styles["BodyText"]))

    doc.build(story)
    buffer.seek(0)

    return buffer


@app.route("/")
def home():
    dashboard_data = prepare_dashboard_data(
        "Click Generate AI Assessment to analyze the current network using Ollama."
    )

    return render_template(
        "index.html",
        **dashboard_data
    )


@app.route("/risk-history")
def risk_history():
    devices = get_devices()
    threats = get_threats(devices)
    vulnerabilities = get_vulnerabilities(devices)

    current_risk_score = calculate_risk_score(
        devices,
        threats,
        vulnerabilities
    )

    labels = [
        "-60m",
        "-50m",
        "-40m",
        "-30m",
        "-20m",
        "-10m",
        "Now"
    ]

    scores = [
        min(current_risk_score + 12, 100),
        min(current_risk_score + 10, 100),
        min(current_risk_score + 8, 100),
        min(current_risk_score + 5, 100),
        min(current_risk_score + 3, 100),
        min(current_risk_score + 1, 100),
        current_risk_score
    ]

    return jsonify({
        "labels": labels,
        "scores": scores
    })


@app.route("/device/<path:mac_address>")
def device_details(mac_address):
    device = get_device_profile(mac_address)

    if device is None:
        return redirect(url_for("home"))

    device_vulnerabilities = get_device_profile_vulnerabilities(device)
    device_threats = get_device_profile_threats(device)

    device_risk_score = calculate_device_risk_score(
        device,
        device_threats,
        device_vulnerabilities
    )

    device_recommendation = generate_device_recommendation(
        device,
        device_threats,
        device_vulnerabilities,
        device_risk_score
    )

    return render_template(
        "device_details.html",
        device=device,
        device_vulnerabilities=device_vulnerabilities,
        device_threats=device_threats,
        device_risk_score=device_risk_score,
        device_recommendation=device_recommendation
    )


@app.route("/cleanup-database")
def cleanup_database():
    deleted_count = cleanup_bad_database_rows()
    print(f"Database cleanup completed. Deleted bad rows: {deleted_count}")

    return redirect(url_for("home"))


@app.route("/ai-assessment")
def ai_assessment():
    devices = get_devices()
    offline_devices = get_offline_devices()
    threats = get_threats(devices)
    vulnerabilities = get_vulnerabilities(devices)

    risk_score = calculate_risk_score(
        devices,
        threats,
        vulnerabilities
    )

    assessment = generate_security_assessment(
        devices,
        threats,
        vulnerabilities,
        risk_score
    )

    dashboard_data = prepare_dashboard_data(assessment)

    return render_template(
        "index.html",
        **dashboard_data
    )


@app.route("/download-ai-report")
def download_ai_report():
    devices = get_devices()
    offline_devices = get_offline_devices()
    threats = get_threats(devices)
    vulnerabilities = get_vulnerabilities(devices)

    risk_score = calculate_risk_score(
        devices,
        threats,
        vulnerabilities
    )

    recommendations = generate_recommendations(
        devices,
        threats,
        vulnerabilities,
        risk_score
    )

    ai_report = generate_security_assessment(
        devices,
        threats,
        vulnerabilities,
        risk_score
    )

    pdf_buffer = generate_pdf_report(
        devices,
        offline_devices,
        threats,
        vulnerabilities,
        risk_score,
        ai_report,
        recommendations
    )

    filename = f"torpedoshome_ai_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


@app.route("/ask-vulnerability", methods=["POST"])
def ask_vulnerability():
    data = request.get_json()

    if not data:
        return jsonify({
            "answer": "Invalid request. Please ask a question again."
        })

    ip = data.get("ip", "Unknown")
    port = data.get("port", "Unknown")
    risk_level = data.get("risk_level", "Unknown")
    question = data.get("question", "")

    if question.strip() == "":
        return jsonify({
            "answer": "Please type a question about this vulnerability."
        })

    answer = answer_vulnerability_question(
        ip,
        port,
        risk_level,
        question
    )

    return jsonify({
        "answer": answer
    })


@app.route("/trust/<mac_address>")
def trust_device(mac_address):
    update_device_trust(
        mac_address,
        "Trusted"
    )

    return redirect(
        url_for("home")
    )


@app.route("/untrust/<mac_address>")
def untrust_device(mac_address):
    update_device_trust(
        mac_address,
        "Unknown"
    )

    return redirect(
        url_for("home")
    )


@app.route("/connected-devices")
def connected_devices_page():
    devices = get_devices()

    return render_template(
        "category_list.html",
        title="Connected Devices",
        items=devices,
        item_type="devices"
    )


@app.route("/trusted-devices")
def trusted_devices_page():
    devices = get_devices()
    trusted_devices = []

    for device in devices:
        if device["trusted"]:
            trusted_devices.append(device)

    return render_template(
        "category_list.html",
        title="Trusted Devices",
        items=trusted_devices,
        item_type="devices"
    )


@app.route("/unknown-devices")
def unknown_devices_page():
    devices = get_devices()
    unknown_devices = []

    for device in devices:
        if not device["trusted"]:
            unknown_devices.append(device)

    return render_template(
        "category_list.html",
        title="Unknown Devices",
        items=unknown_devices,
        item_type="devices"
    )


@app.route("/offline-devices")
def offline_devices_page():
    offline_devices = get_offline_devices()

    return render_template(
        "category_list.html",
        title="Offline Devices",
        items=offline_devices,
        item_type="devices"
    )


@app.route("/threat-alerts")
def threat_alerts_page():
    devices = get_devices()
    threats = get_threats(devices)

    return render_template(
        "category_list.html",
        title="Threat Alerts",
        items=threats,
        item_type="threats"
    )


@app.route("/open-ports")
def open_ports_page():
    devices = get_devices()
    vulnerabilities = get_vulnerabilities(devices)

    return render_template(
        "category_list.html",
        title="Open Ports",
        items=vulnerabilities,
        item_type="ports"
    )


if __name__ == "__main__":
    app.run(debug=True)