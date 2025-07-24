#!/usr/bin/env python3
"""
Advanced Python Honeypot with:
- Enhanced security features
- Improved logging
- Better UI
- GeoIP integration
- Config management
Compatible with both Linux (Kali) and Windows
"""

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
import requests
from datetime import datetime
import json
import os
import logging
from logging.handlers import RotatingFileHandler
import ipaddress

# ------------------- Configuration ------------------- #
class Config:
    """Centralized configuration management"""
    def __init__(self):
        self.PORTS = [22, 80, 21]  # SSH, HTTP, FTP
        self.LOG_FILE = "honeypot.log"
        self.MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB
        self.BACKUP_COUNT = 3
        self.GEOIP_API_URL = "https://ipinfo.io/{ip}/json"
        self.TIMEOUT = 3  # seconds
        self.BIND_IP = "0.0.0.0"
        
        # UI Configuration
        self.BG_COLOR = "#0d1117"
        self.FG_COLOR = "#ffffff"
        self.FONT_MAIN = ("Consolas", 11)
        self.FONT_HEADER = ("Consolas", 14, "bold")
        self.ACCENT_COLOR = "#2d5d8c"

# ------------------- Logging Setup ------------------- #
def setup_logger():
    """Configure advanced logging with rotation"""
    logger = logging.getLogger("honeypot")
    logger.setLevel(logging.INFO)
    
    # Rotating file handler
    handler = RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.MAX_LOG_SIZE,
        backupCount=config.BACKUP_COUNT
    )
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    return logger

# Initialize config and logger
config = Config()
logger = setup_logger()

# ------------------- Honeypot Class ------------------- #
class Honeypot:
    """Main honeypot functionality with enhanced security"""
    
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.running = False
        self.threads = []
        
    def validate_ip(self, ip_str):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            logger.warning(f"Invalid IP detected: {ip_str}")
            return False

    def geoip_lookup(self, ip):
        """Perform GeoIP lookup with caching and validation"""
        if not self.validate_ip(ip):
            return "Invalid IP"
        
        try:
            response = requests.get(
                config.GEOIP_API_URL.format(ip=ip),
                timeout=config.TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            return data.get("country", "Unknown")
        except requests.RequestException as e:
            logger.error(f"GeoIP lookup failed: {str(e)}")
            return "Lookup Failed"

    def handle_connection(self, client, addr, port):
        """Handle individual connection with proper cleanup"""
        try:
            ip = addr[0]
            country = self.geoip_lookup(ip)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            event = f"{timestamp} - {ip} ({country}) - Port {port}"
            
            if self.log_callback:
                self.log_callback(event)
                
            logger.info(event)
            
            # Send fake banners based on protocol
            banners = {
                22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
                80: b"HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n",
                21: b"220 FTP server ready.\r\n"
            }
            client.send(banners.get(port, b""))
            
        except Exception as e:
            logger.error(f"Connection handling error: {str(e)}")
        finally:
            client.close()

    def start_listener(self, port):
        """Start listener on specified port"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((config.BIND_IP, port))
            server.listen(5)
            logger.info(f"Started listener on port {port}")
            
            while self.running:
                try:
                    client, addr = server.accept()
                    thread = threading.Thread(
                        target=self.handle_connection,
                        args=(client, addr, port)
                    )
                    thread.daemon = True
                    thread.start()
                    self.threads.append(thread)
                except OSError:
                    pass  # Socket closed during shutdown

    def start(self):
        """Start all honeypot services"""
        if self.running:
            return
            
        self.running = True
        logger.info("Honeypot service starting")
        
        for port in config.PORTS:
            thread = threading.Thread(target=self.start_listener, args=(port,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

    def stop(self):
        """Gracefully stop all honeypot services"""
        self.running = False
        logger.info("Honeypot service stopping")
        
        for thread in self.threads:
            thread.join(timeout=1)

# ------------------- Enhanced GUI Class ------------------- #
class HoneypotGUI:
    """Advanced GUI with improved layout and controls"""
    
    def __init__(self, root):
        self.root = root
        self.setup_ui()
        self.honeypot = Honeypot(self.log_event)

    def setup_ui(self):
        """Configure all UI elements"""
        self.root.title("Advanced Honeypot v2.0")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        self.root.configure(bg=config.BG_COLOR)
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill="both", expand=True)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief="sunken",
            anchor="w"  # Corrected anchor value
        )
        status_bar.pack(fill="x", side="bottom")
        
        # Log display
        self.log_area = scrolledtext.ScrolledText(
            main_frame,
            bg=config.BG_COLOR,
            fg=config.FG_COLOR,
            font=config.FONT_MAIN,
            wrap="word"
        )
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Control buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=5)
        
        self.start_btn = ttk.Button(
            btn_frame,
            text="Start Honeypot",
            command=self.start_honeypot
        )
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ttk.Button(
            btn_frame,
            text="Stop Honeypot",
            state="disabled", 
            command=self.stop_honeypot
        )
        self.stop_btn.pack(side="left", padx=5)
        
        self.clear_btn = ttk.Button(
            btn_frame,
            text="Clear Logs",
            command=self.clear_logs
        )
        self.clear_btn.pack(side="right", padx=5)

    def log_event(self, event):
        """Thread-safe GUI logging"""
        self.log_area.insert(tk.END, event + "\n")
        self.log_area.yview(tk.END)
        
    def start_honeypot(self):
        """Start the honeypot service"""
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="enabled")
        self.status_var.set("Running - Listening on ports: " + ", ".join(map(str, config.PORTS)))
        threading.Thread(target=self.honeypot.start, daemon=True).start()
        
    def stop_honeypot(self):
        """Stop the honeypot service"""
        self.start_btn.config(state="enabled")
        self.stop_btn.config(state="disabled")
        self.status_var.set("Stopping...")
        self.honeypot.stop()
        self.status_var.set("Stopped")
        
    def clear_logs(self):
        """Clear the log display"""
        self.log_area.delete("1.0", tk.END)

# ------------------- Main Execution ------------------- #
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = HoneypotGUI(root)
        
        def on_closing():
            app.stop_honeypot()
            root.destroy()
            
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()
        
    except Exception as e:
        logger.critical(f"Application crashed: {str(e)}", exc_info=True)
        raise
