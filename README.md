# 🛡️ Advanced Python Honeypot v2.0

A cross-platform honeypot built with Python for educational and monitoring purposes. Features an interactive GUI, GeoIP integration, enhanced logging, and multi-port support.

---

## 🔥 Features

* Listen on multiple ports (default: 22, 80, 21)
* Fake banners to simulate real services (SSH, HTTP, FTP)
* Thread-safe event logging with rotation
* GeoIP lookup for incoming connections
* Beautiful Tkinter GUI with start/stop/clear buttons
* Works on both Linux (Kali) and Windows

---

## 🚀 Quick Start

### 1. Clone the Project

```bash
cd ~/Desktop
mkdir honeypot_project && cd honeypot_project
touch honeypot.py  # Paste the full code here
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install requests
```

### 4. Run the Honeypot

```bash
python honeypot.py
```

---

## 📸 GUI Preview

> Dark themed GUI with real-time logs, status bar, and controls.

```
+--------------------------------------------------------+
|  [Start Honeypot] [Stop Honeypot]             [Clear]  |
|--------------------------------------------------------|
|  [Incoming connections with GeoIP logs appear here]   |
|                                                      |
+--------------------------------------------------------+
| Status: Ready / Running / Stopped                     |
+--------------------------------------------------------+
```

---

## ⚙️ Configuration

You can edit these options in the `Config` class:

```python
self.PORTS = [22, 80, 21]            # Ports to listen on
self.BG_COLOR = "#0d1117"             # Background color
self.FG_COLOR = "#ffffff"             # Foreground text color
self.LOG_FILE = "honeypot.log"        # Log file path
```

---

## 📂 Log Output Example

```
2025-07-24 17:25:33 - INFO - 192.168.1.12 (US) - Port 22
2025-07-24 17:25:38 - INFO - 45.13.244.9 (RU) - Port 80
```

Logs rotate at 5MB, with 3 backups.

---

## 💡 Use Cases

* Cybersecurity research & training
* Intrusion detection sandbox
* Safe network monitoring lab

---

## 📌 Disclaimer

This project is intended for educational and ethical research purposes **only**. Do **not** deploy it in unauthorized or production environments.

---

## 👨‍💻 Author

**Syed Muhammad Qammar Abbas Zaidi**
BS Cybersecurity Student | Python Enthusiast | Hobbyist Pentester

---

## 🧠 Credits

* Inspired by common honeypot architecture
* Built with love on Kali Linux
* Uses `requests`, `tkinter`, `logging`, and standard Python libraries
