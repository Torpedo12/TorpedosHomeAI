import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2"


def ask_ollama(prompt, num_predict=650):
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": num_predict,
                    "temperature": 0.25
                }
            },
            timeout=45
        )

        if response.status_code == 200:
            return response.json().get("response", "").strip()

        return "AI assistant is currently unavailable."

    except Exception:
        return "AI assistant is not connected. Make sure Ollama is running."


def explain_threat(threat_type):
    threat_type_lower = threat_type.lower()

    if "new device" in threat_type_lower:
        return "A new device joined the network. Confirm whether it belongs to you or your family."

    if "unknown device" in threat_type_lower:
        return "An untrusted device is connected. If you do not recognize it, change the Wi-Fi password and restart the router."

    if "port scan" in threat_type_lower:
        return "The IDS detected one device trying many ports in a short time. This may be a scan or reconnaissance attempt."

    if "network reconnaissance" in threat_type_lower:
        return "The IDS detected traffic that looks like network discovery. This may happen when a scanning tool is used."

    if "suspicious traffic" in threat_type_lower:
        return "The IDS detected a high number of connection attempts. This may indicate abnormal or automated activity."

    if "arp network scan" in threat_type_lower:
        return "The IDS detected many ARP requests. This may indicate a device trying to discover other devices on the network."

    return "Suspicious activity was detected. Review the affected device."


def investigate_threat(threat_type, ip_address, device_name="Unknown Device", status="active", detected_time="Unknown"):
    threat_type_lower = threat_type.lower()

    if "new device" in threat_type_lower:
        return (
            f"AI Investigation: {device_name} joined the network from IP {ip_address}. "
            "This is not always dangerous, but it should be verified. If this is your phone, laptop, TV, or family device, mark it as trusted. "
            "If you do not recognize it, change your Wi-Fi password and restart the router."
        )

    if "unknown device" in threat_type_lower:
        return (
            f"AI Investigation: An unknown device is online at IP {ip_address}. "
            "This is important because unknown devices can access the same home network as your trusted devices. "
            "Verify the device name and MAC address. If it is not yours, remove it from Wi-Fi by changing the Wi-Fi password."
        )

    if "port scan" in threat_type_lower:
        return (
            f"AI Investigation: The IDS detected possible port scanning from IP {ip_address}. "
            "This means one device tried to connect to many different ports in a short time. "
            "This behavior is commonly used to find open services before an attack. "
            "If this IP belongs to your own laptop while testing, it is expected. If not, investigate or block the device."
        )

    if "network reconnaissance" in threat_type_lower:
        return (
            f"AI Investigation: Network reconnaissance activity was detected from IP {ip_address}. "
            "This means a device may be trying to discover available services or devices on the network. "
            "If you were running Nmap or a scanner, this is normal testing. If not, treat it as suspicious and review the device."
        )

    if "suspicious traffic" in threat_type_lower:
        return (
            f"AI Investigation: High traffic activity was detected from IP {ip_address}. "
            "This may happen when a device repeatedly connects to the router or other devices. "
            "Check whether the device is downloading, updating, scanning, or behaving unexpectedly."
        )

    if "arp network scan" in threat_type_lower:
        return (
            f"AI Investigation: ARP scan behavior was detected from IP {ip_address}. "
            "ARP scanning is used to discover devices on the local network. "
            "If this came from a known security scan, it is expected. If it came from an unknown device, investigate it immediately."
        )

    return (
        f"AI Investigation: A security alert was detected from IP {ip_address}. "
        "Review the device, confirm whether it is trusted, and check for open ports or unusual behavior."
    )


def format_device_list(devices):
    if not devices:
        return "No online devices found."

    lines = []

    for device in devices:
        lines.append(
            f"- {device.get('name', 'Unknown Device')} | "
            f"IP: {device.get('ip', 'Unknown')} | "
            f"MAC: {device.get('mac', 'Unknown')} | "
            f"Type: {device.get('type', 'Unknown')} | "
            f"Trust: {device.get('trust_status', 'Unknown')}"
        )

    return "\n".join(lines)


def format_threat_list(threats):
    if not threats:
        return "No active threat alerts."

    lines = []

    for threat in threats:
        lines.append(
            f"- {threat.get('type', 'Unknown Threat')} | "
            f"Device: {threat.get('device_name', threat.get('ip', 'Unknown'))} | "
            f"IP: {threat.get('ip', 'Unknown')} | "
            f"Status: {threat.get('status', 'Unknown')} | "
            f"Detected: {threat.get('time', 'Unknown')}"
        )

    return "\n".join(lines)


def format_vulnerability_list(vulnerabilities):
    if not vulnerabilities:
        return "No open ports detected."

    lines = []

    for vuln in vulnerabilities:
        lines.append(
            f"- Device: {vuln.get('device_name', vuln.get('ip', 'Unknown'))} | "
            f"IP: {vuln.get('ip', 'Unknown')} | "
            f"Port: {vuln.get('port', 'Unknown')} | "
            f"Risk: {vuln.get('risk_level', 'Unknown')} | "
            f"MAC: {vuln.get('mac', 'Unknown')}"
        )

    return "\n".join(lines)


def generate_security_assessment(devices, threats, vulnerabilities, risk_score):
    trusted_count = 0
    unknown_count = 0
    high_risk_ports = 0
    medium_risk_ports = 0
    low_risk_ports = 0

    for device in devices:
        if device.get("trusted"):
            trusted_count += 1
        else:
            unknown_count += 1

    for vuln in vulnerabilities:
        risk = str(vuln.get("risk_level", "")).lower()

        if risk == "high" or risk == "critical":
            high_risk_ports += 1
        elif risk == "medium":
            medium_risk_ports += 1
        else:
            low_risk_ports += 1

    device_summary = format_device_list(devices)
    threat_summary = format_threat_list(threats)
    vulnerability_summary = format_vulnerability_list(vulnerabilities)

    prompt = f"""
You are Torpedo'sHome AI, a home Wi-Fi security assistant.

Generate a useful home network security report for a non-technical user.

IMPORTANT RULES:
- Use simple language.
- Do not introduce yourself.
- Do not mention that you are an AI model.
- Do not make up facts.
- Only use the data provided below.
- Keep the report practical.
- Give clear actions the user can take.
- Explain risk levels in beginner-friendly language.
- Do not say to close router ports unless the port belongs to the router.
- For device ports, recommend checking the device settings or firewall.

CURRENT NETWORK DATA:

Risk Score: {risk_score}/100

Online Devices: {len(devices)}
Trusted Devices: {trusted_count}
Unknown Devices: {unknown_count}

Threat Alerts: {len(threats)}
Open Ports Found: {len(vulnerabilities)}
High/Critical Risk Ports: {high_risk_ports}
Medium Risk Ports: {medium_risk_ports}
Low Risk Ports: {low_risk_ports}

ONLINE DEVICES:
{device_summary}

THREAT ALERTS:
{threat_summary}

OPEN PORT FINDINGS:
{vulnerability_summary}

REPORT FORMAT:

Overall Security Status:
Write 2-3 sentences about the current network condition.

Key Findings:
- Mention connected devices.
- Mention unknown devices.
- Mention threat alerts.
- Mention open ports and risk level.

Most Important Risks:
- List the biggest concerns first.
- If SMB port 445 is open, explain that file sharing may be exposed.
- If Windows ports 135 or 139 are open, explain that Windows network services are visible.
- If router ports 53 or 443 are open, explain that it may be normal for a router.

Recommended Actions:
- Tell the user what to check first.
- Tell the user to mark known devices as trusted.
- Tell the user to investigate unknown devices.
- Tell the user to review devices with High or Critical ports.
- Keep advice realistic for a home user.

Final Summary:
Give one short final conclusion.
"""

    return ask_ollama(prompt, num_predict=750)


def answer_vulnerability_question(ip, port, risk_level, question):
    prompt = f"""
You are Torpedo'sHome AI.

You are helping a home user understand a network security finding.

Context:
Device IP: {ip}
Open Port: {port}
Risk Level: {risk_level}

User Question:
{question}

Instructions:
- Answer the user's question directly.
- Use the context only when relevant.
- Do not assume what the user wants to know.
- Do not explain things that were not asked.
- Use simple language.
- Keep the answer concise and practical.
- Do not introduce yourself.
- Do not use headings.
- Do not generate a full security report.
- If the user asks a follow-up question, answer only that question.
"""

    return ask_ollama(prompt, num_predict=180)