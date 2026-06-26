import socket
import ipaddress
import subprocess
import platform
import re


def is_valid_device_ip(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)

        if ip.is_multicast:
            return False
        if ip.is_unspecified:
            return False
        if ip.is_loopback:
            return False
        if ip.is_reserved:
            return False
        if ip_address == "255.255.255.255":
            return False
        if ip_address.endswith(".255"):
            return False
        if ip_address.endswith(".0"):
            return False

        return True

    except Exception:
        return False


def clean_mac_address(mac_address):
    if not mac_address:
        return "Unknown"

    mac_address = mac_address.strip().lower().replace("-", ":")

    if mac_address in ["unknown", "none", ""]:
        return "Unknown"

    return mac_address


def is_private_random_mac(mac_address):
    mac_address = clean_mac_address(mac_address)

    if mac_address == "Unknown":
        return False

    try:
        first_octet = int(mac_address.split(":")[0], 16)
        return bool(first_octet & 2)
    except Exception:
        return False


def get_mac_prefix(mac_address):
    mac_address = clean_mac_address(mac_address)

    if mac_address == "Unknown":
        return "Unknown"

    parts = mac_address.split(":")

    if len(parts) >= 3:
        return ":".join(parts[:3])

    return "Unknown"


def get_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]

        if hostname:
            return hostname.strip()

        return "Unknown"

    except Exception:
        return "Unknown"


def normalize_hostname(hostname):
    if not hostname or hostname == "Unknown":
        return "Unknown"

    hostname = hostname.strip()
    hostname = hostname.replace(".local", "")
    hostname = hostname.replace(".lan", "")
    hostname = hostname.replace(".home", "")

    if hostname.endswith(".ss.shawcable.net"):
        hostname = hostname.replace(".ss.shawcable.net", "")

    hostname = re.sub(r"\s+", " ", hostname)

    if hostname == "":
        return "Unknown"

    return hostname


def get_vendor_hint(mac_address):
    prefix = get_mac_prefix(mac_address)

    vendor_map = {
        "04:ec:d8": "Apple",
        "f0:18:98": "Apple",
        "a4:83:e7": "Apple",
        "b8:e8:56": "Apple",
        "d0:03:4b": "Apple",
        "8c:85:90": "Apple",
        "a8:20:66": "Apple",
        "dc:a6:32": "Apple",

        "5c:f6:dc": "Samsung",
        "cc:46:d6": "Samsung",
        "34:23:87": "Samsung",
        "bc:14:85": "Samsung",

        "44:65:0d": "Amazon",
        "50:f5:da": "Amazon",
        "68:54:fd": "Amazon",
        "74:c2:46": "Amazon",
        "ac:63:be": "Amazon",

        "f4:f5:d8": "Google",
        "54:60:09": "Google",
        "64:16:66": "Google",
        "a4:77:33": "Google",

        "b8:a1:75": "Roku",
        "dc:3a:5e": "Roku",

        "00:1f:29": "HP",
        "3c:52:82": "HP",
        "70:5a:0f": "HP",
        "00:bb:c1": "Canon",
        "f4:81:39": "Canon",
        "00:26:ab": "Epson",
        "ac:18:26": "Epson",
        "00:80:77": "Brother",

        "f8:79:0a": "Router Vendor",
        "b0:be:76": "Router Vendor",
        "c0:56:27": "Router Vendor",
        "d8:07:b6": "Router Vendor",
    }

    return vendor_map.get(prefix, "Unknown")


def get_open_ports_quick(ip_address):
    common_ports = [
        22, 23, 53, 80, 81, 135, 139, 443, 445,
        515, 548, 554, 631, 1900, 3689, 5000,
        5900, 62078, 8008, 8009, 8080, 9100
    ]

    open_ports = []

    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.20)
            result = sock.connect_ex((ip_address, port))
            sock.close()

            if result == 0:
                open_ports.append(port)

        except Exception:
            pass

    return open_ports


def classify_from_hostname(hostname):
    text = hostname.lower()

    if hostname == "Unknown":
        return None

    if "router" in text or "gateway" in text:
        return "Router"

    if "iphone" in text or "android" in text or "galaxy" in text or "pixel" in text or "phone" in text:
        return "Phone"

    if "ipad" in text or "tablet" in text:
        return "Tablet"

    if "macbook" in text or "laptop" in text:
        return "Laptop"

    if "desktop" in text or "windows" in text or "pc" in text:
        return "Desktop"

    if "printer" in text or "hp" in text or "canon" in text or "epson" in text or "brother" in text:
        return "Printer"

    if "camera" in text or "cam" in text or "ring" in text or "wyze" in text:
        return "Camera"

    if "tv" in text or "roku" in text or "chromecast" in text or "firetv" in text:
        return "Smart TV"

    if "alexa" in text or "echo" in text or "speaker" in text:
        return "Smart Speaker"

    return None


def classify_from_vendor(vendor, hostname):
    vendor_lower = vendor.lower()
    hostname_lower = hostname.lower()

    if vendor == "Unknown":
        return None

    if "router" in vendor_lower:
        return "Router"

    if "apple" in vendor_lower:
        if "ipad" in hostname_lower:
            return "Tablet"
        if "mac" in hostname_lower or "book" in hostname_lower:
            return "Laptop"
        return "Phone"

    if "samsung" in vendor_lower:
        if "tv" in hostname_lower:
            return "Smart TV"
        return "Phone"

    if "amazon" in vendor_lower:
        if "fire" in hostname_lower or "tv" in hostname_lower:
            return "Smart TV"
        return "Smart Speaker"

    if "google" in vendor_lower:
        return "Smart TV"

    if "roku" in vendor_lower:
        return "Smart TV"

    if "hp" in vendor_lower or "canon" in vendor_lower or "epson" in vendor_lower or "brother" in vendor_lower:
        return "Printer"

    return None


def classify_from_ports(open_ports):
    if 9100 in open_ports or 631 in open_ports or 515 in open_ports:
        return "Printer"

    if 554 in open_ports or 81 in open_ports:
        return "Camera"

    if 8008 in open_ports or 8009 in open_ports or 1900 in open_ports:
        return "Smart TV"

    if 62078 in open_ports or 3689 in open_ports or 548 in open_ports:
        return "Phone"

    if 3389 in open_ports or 445 in open_ports or 135 in open_ports or 139 in open_ports:
        return "Desktop"

    if 22 in open_ports and 80 in open_ports:
        return "Router"

    if 53 in open_ports and 80 in open_ports:
        return "Router"

    return None


def identify_device_type(ip_address, mac_address="Unknown"):
    if not is_valid_device_ip(ip_address):
        return "Ignored"

    hostname = normalize_hostname(get_hostname(ip_address))
    vendor = get_vendor_hint(mac_address)

    if ip_address.endswith(".1") or ip_address.endswith(".254"):
        return "Router"

    hostname_type = classify_from_hostname(hostname)
    if hostname_type:
        return hostname_type

    vendor_type = classify_from_vendor(vendor, hostname)
    if vendor_type:
        return vendor_type

    open_ports = get_open_ports_quick(ip_address)

    port_type = classify_from_ports(open_ports)
    if port_type:
        return port_type

    if is_private_random_mac(mac_address):
        return "Phone"

    if mac_address != "Unknown":
        return "Connected Device"

    return "Unknown Device"


def get_device_icon(device_type):
    text = device_type.lower()

    if "router" in text:
        return "🌐"
    if "phone" in text:
        return "📱"
    if "tablet" in text:
        return "📱"
    if "laptop" in text:
        return "💻"
    if "desktop" in text:
        return "🖥️"
    if "printer" in text:
        return "🖨️"
    if "camera" in text:
        return "📷"
    if "tv" in text:
        return "📺"
    if "speaker" in text:
        return "🔊"
    if "connected" in text:
        return "📡"

    return "❓"


def build_device_display_name(ip_address, mac_address="Unknown"):
    if not is_valid_device_ip(ip_address):
        return "Ignored"

    device_type = identify_device_type(ip_address, mac_address)
    hostname = normalize_hostname(get_hostname(ip_address))
    vendor = get_vendor_hint(mac_address)
    icon = get_device_icon(device_type)

    if hostname != "Unknown":
        return f"{icon} {hostname}"

    if vendor != "Unknown" and "router" not in vendor.lower():
        return f"{icon} {vendor} {device_type}"

    return f"{icon} {device_type}"