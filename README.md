# 🛡️ Torpedo'sHome AI

## AI-Powered Home Network Security Monitoring System

Torpedo'sHome AI is an AI-powered home network security monitoring system developed as a cybersecurity capstone project at Saskatchewan Polytechnic.

The system helps home users monitor and secure their Wi-Fi network by discovering connected devices, detecting suspicious activities, identifying network vulnerabilities, monitoring real-time network traffic, and generating AI-powered security assessments through an interactive web dashboard.

---

# ✨ Features

* 🔍 Real-Time Network Device Discovery
* 📱 Connected Device Identification
* ✅ Trusted & Unknown Device Management
* 🚨 Real-Time Threat Detection
* 🛡️ Intrusion Detection System (IDS)
* 🌐 Wi-Fi Security Monitoring
* 🔓 Open Port & Vulnerability Scanner
* 🤖 AI Security Assistant (Powered by Ollama)
* 📊 Dynamic Network Risk Score
* 📄 AI-Generated Security Assessment PDF
* 📅 Security Timeline
* 💻 Interactive Cybersecurity Dashboard

---

# 🛠️ Technology Stack

### Backend

* Python
* Flask
* SQLite

### Artificial Intelligence

* Ollama
* Llama 3.2

### Network Security

* Scapy
* Socket Programming

### Frontend

* HTML
* CSS
* JavaScript

### Reporting

* ReportLab

---

# 📂 Project Structure

```text
TorpedosHomeAI/
│
├── Application/
│   ├── app.py
│   ├── ai_explainer.py
│   ├── background_scanner.py
│   ├── network_scanner.py
│   ├── packet_monitor.py
│   ├── port_scanner.py
│   ├── router_scanner.py
│   ├── wifi_security_scanner.py
│   └── static/
│
├── templates/
├── database/
├── logs/
├── screenshots/
├── requirements.txt
└── README.md
```

---

# 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Torpedo12/TorpedosHomeAI.git
```

### 2. Navigate to the Project

```bash
cd TorpedosHomeAI
```

### 3. Create a Virtual Environment

```bash
python -m venv venv
```

### 4. Activate the Virtual Environment

**Windows**

```bash
venv\Scripts\activate
```

**Linux / macOS**

```bash
source venv/bin/activate
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is unavailable:

```bash
pip install flask scapy requests reportlab
```

### 6. Install Ollama

Download Ollama from:

https://ollama.com/download

Pull the required AI model:

```bash
ollama pull llama3.2
```

Start the Ollama service before running the application.

### 7. Initialize the Database

```bash
python Application/database_setup.py
```

### 8. Run the Application

```bash
python Application/app.py
```

Open your browser:

```
http://127.0.0.1:5000
```

---

# 📸 Screenshots

Add screenshots of your application here.

Suggested screenshots:

* Dashboard
* Connected Devices
* Threat Alerts
* AI Security Assistant
* Network Map
* PDF Security Report

---

# 🔮 Future Enhancements

* Mobile Application
* Email Notifications
* SMS Alerts
* Cloud Deployment
* Threat Intelligence Integration
* Historical Analytics
* Multi-User Support

---

# ⚠️ Disclaimer

This software was developed for educational, research, and demonstration purposes only as part of a university cybersecurity capstone project.

It is intended to be used only on networks that you own or have explicit permission to test.

---

# 📜 License

Copyright © 2026 Arth Patel (Torpedo). All Rights Reserved.

This project is provided for educational and demonstration purposes only.

You are permitted to:

* View the source code.
* Clone the repository for personal learning and academic purposes.
* Use the project for demonstrations and educational presentations.

You are **NOT** permitted to:

* Use this project or any part of its source code for commercial purposes.
* Sell, distribute, sublicense, or monetize this software.
* Copy, modify, or rebrand this project as your own work.
* Create a commercial or competing product using this project or its source code without prior written permission from the author.

Unauthorized commercial use, redistribution, or reproduction of this project is strictly prohibited.

---

# 👨‍💻 Author

**Arth Patel (Torpedo)**

Cybersecurity Student

---

⭐ If you found this project useful or interesting, please consider giving it a star on GitHub!


<img width="1917" height="870" alt="111" src="https://github.com/user-attachments/assets/961e59dc-80aa-414a-8106-fecda215c051" />

<img width="1917" height="871" alt="222" src="https://github.com/user-attachments/assets/ba0acc99-3bd1-44f0-9371-68f4030bf30a" />
