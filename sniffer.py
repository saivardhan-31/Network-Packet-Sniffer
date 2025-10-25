# sniffer.py
from matplotlib.animation import FuncAnimation
import matplotlib.pyplot as plt
from collections import deque
from datetime import datetime
import sqlite3
import time
import logging
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
# --- Configuration ---
# Thresholds for anomaly detection
PORT_SCAN_THRESHOLD = 20  # Num of distinct ports scanned by one IP to trigger alert
FLOOD_THRESHOLD = 100     # Packets per second to trigger a flood alert

# Time window for detection (in seconds)
TIME_WINDOW = 10

# --- Global Data Structures ---
# These structures hold data in memory for real-time analysis
packet_counts = defaultdict(int) # Stores packet counts per second
port_scan_tracker = defaultdict(set) # Stores (src_ip -> {ports}) for port scan detection
plot_data = deque(maxlen=50) # Holds the last 50 data points for packets/sec
plot_timestamps = deque(maxlen=50) # Holds the timestamps for the x-axis

# --- Logging Setup ---
# This will create an 'alerts.log' file for a persistent record of alerts
logging.basicConfig(filename='alerts.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Database Connection ---
DB_FILE = 'traffic.db'

def log_packet_to_db(packet):
    """Logs extracted packet details into the SQLite database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = 'Other'
        flags = ''

        if packet.haslayer(TCP):
            protocol = 'TCP'
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            flags = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            protocol = 'UDP'
            source_port = packet[UDP].sport
            dest_port = packet[UDP].dport
        else:
            source_port, dest_port = 0, 0

        cursor.execute(
            "INSERT INTO packets (source_ip, dest_ip, source_port, dest_port, protocol, length, flags) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (source_ip, dest_ip, source_port, dest_port, protocol, len(packet), flags)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging packet to DB: {e}")

def log_alert(alert_type, description):
    """Logs an alert to the console, a file, and the database."""
    message = f"ALERT: {alert_type} - {description}"
    print(f"\033[91m{message}\033[0m") # Print in red color to console
    logging.info(message) # Log to alerts.log

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO alerts (alert_type, description) VALUES (?, ?)", (alert_type, description))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging alert to DB: {e}")

def process_packet(packet):
    """Callback function for Scapy's sniff(). Processes and analyzes each packet."""
    if not packet.haslayer(IP):
        return

    # Log every packet to the database
    log_packet_to_db(packet)

    # Update our real-time counters for anomaly detection
    current_time = int(time.time())
    packet_counts[current_time] += 1

    if packet.haslayer(TCP):
        source_ip = packet[IP].src
        dest_port = packet[TCP].dport
        port_scan_tracker[source_ip].add(dest_port)

def detect_anomalies():
    """Periodically checks for anomalies like flooding and port scanning."""
    current_time = time.time()
    
    # 1. Flood Detection
    packets_in_last_second = packet_counts.get(int(current_time) - 1, 0)
    if packets_in_last_second > FLOOD_THRESHOLD:
        log_alert('FLOODING DETECTED', f'{packets_in_last_second} packets/sec detected.')

    # 2. Port Scan Detection
    for src_ip, ports in list(port_scan_tracker.items()):
        if len(ports) > PORT_SCAN_THRESHOLD:
            log_alert('PORT SCAN DETECTED', f'IP {src_ip} scanned {len(ports)} distinct ports.')
            del port_scan_tracker[src_ip] # Reset after alerting

    # Cleanup old data to save memory
    cutoff_time = int(current_time - TIME_WINDOW)
    for timestamp in list(packet_counts.keys()):
        if timestamp < cutoff_time:
            del packet_counts[timestamp]
    # (Inside detect_anomalies(), at the end)
    # --- Update data for GUI plot ---
    plot_timestamps.append(datetime.now())
    plot_data.append(packets_in_last_second) 

# --- GUI Functions ---
fig, ax = plt.subplots()

def update_plot(frame):
    """This function is called repeatedly by FuncAnimation to update the graph."""
    ax.clear()
    if plot_timestamps: # Only plot if there is data
        ax.plot(plot_timestamps, plot_data, color='cyan')
        ax.set_title('Real-Time Network Traffic')
        ax.set_xlabel('Time')
        ax.set_ylabel('Packets per Second')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()

def run_gui():
    """Starts the matplotlib GUI animation."""
    # Update the plot every 1000 milliseconds (1 second)
    # This is the corrected line
    ani = FuncAnimation(fig, update_plot, interval=1000, cache_frame_data=False)
    plt.show()      

def main():
    """Main function to start sniffer, anomaly detection, and GUI in threads."""
    print("Starting Network Packet Sniffer with GUI...")
    stop_sniffing = threading.Event()

    def sniffer_loop():
        sniff(prn=process_packet, store=False, stop_filter=lambda p: stop_sniffing.is_set())

    # Run sniffer in a background thread
    sniffer_thread = threading.Thread(target=sniffer_loop, name="SnifferThread", daemon=True)
    sniffer_thread.start()

    # Run anomaly detection in a background thread
    def anomaly_detection_loop():
        while not stop_sniffing.is_set():
            time.sleep(2)
            detect_anomalies()
    
    anomaly_thread = threading.Thread(target=anomaly_detection_loop, name="AnomalyThread", daemon=True)
    anomaly_thread.start()

    print("Sniffer and anomaly detection started. GUI is loading...")
    print("Close the graph window to stop the entire application.")
    
    # The GUI must run in the main thread
    run_gui()
    
    print("\nGUI closed. Stopping sniffer...")
    stop_sniffing.set()
    print("Sniffer stopped.")

if __name__ == "__main__":
    main()