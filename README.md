# Real-Time Network Sniffer with Anomaly Detection

This project is a comprehensive network monitoring tool developed in Python. It captures network packets from a live interface, analyzes them in real-time to detect security anomalies, logs all activity to a database, and provides a live graphical user interface (GUI) to visualize network traffic.

The primary goal of this project was to build a functional security tool that demonstrates key concepts in network programming, concurrent processing, and data persistence.

## What Was Done in This Project

This project was built from the ground up to be a modular and effective network analysis tool. The development process was broken down into several key components:

### 1. Core Packet Sniffing Engine
-   **Technology:** `Scapy` library.
-   **Implementation:** A dedicated sniffer function captures every packet on the network interface. For each packet, a callback function (`process_packet`) is triggered to dissect and extract crucial information from the IP, TCP, and UDP layers, such as:
    -   Source and Destination IP Addresses
    -   Source and Destination Ports
    -   Protocol Type (TCP, UDP, etc.)
    -   Packet Length
    -   TCP Flags (SYN, ACK, FIN, etc.)

### 2. Database and Logging System
-   **Technology:** `SQLite3`.
-   **Implementation:** A robust database schema was designed to persistently store network data.
    -   A `packets` table logs the metadata for **every single packet** captured, creating a complete audit trail.
    -   An `alerts` table logs only the detected security events, providing a focused view for incident analysis.
    -   A standard Python `logging` module also writes all alerts to a text file (`alerts.log`) for easy, human-readable access.

### 3. Anomaly Detection Logic
-   **Technology:** In-memory Python data structures (`dictionaries`, `sets`) for high-speed analysis.
-   **Implementation:** Instead of querying the database for every check (which would be slow), the system maintains real-time counters in memory. A separate thread periodically analyzes this data:
    -   **Port Scan Detection:** The system tracks which ports are being contacted by each source IP. If an IP contacts more than a set number of unique ports (`PORT_SCAN_THRESHOLD`), it triggers a "Port Scan" alert.
    -   **Flood Detection:** The system counts the total number of packets per second. If this rate exceeds the `FLOOD_THRESHOLD`, it triggers a "Flooding" alert, which could indicate a denial-of-service attack.

### 4. Multi-Threaded Architecture
-   **Technology:** Python's `threading` module.
-   **Implementation:** Concurrency was essential for this application to function without freezing. The application is split into three main threads:
    1.  **Sniffer Thread:** Solely dedicated to running Scapy's blocking `sniff()` function. This ensures packet capture is never interrupted.
    2.  **Anomaly Detection Thread:** Runs in a continuous loop, checking the in-memory data for threats every few seconds.
    3.  **Main Thread (GUI):** Runs the Matplotlib GUI. It must run in the main thread as required by the library. This architecture ensures the UI remains responsive while intensive packet capture and analysis happen in the background.

### 5. Live Data Visualization (GUI)
-   **Technology:** `Matplotlib`.
-   **Implementation:** A simple but effective GUI provides a real-time line graph of network traffic, plotting packets-per-second over time.
    -   Matplotlib's `FuncAnimation` is used to update the plot every second, providing a smooth, live feed of network activity.
    -   This visual feedback makes it easy to spot sudden spikes in traffic that might correspond to an anomaly.

---

## Technologies Used

-   **Language:** **Python 3**
-   **Packet Capture/Analysis:** **Scapy**
-   **Database:** **SQLite3**
-   **Data Visualization:** **Matplotlib**
-   **Concurrency:** **Threading**

---

## How to Run This Project

#### 1. Clone the Repository
```bash
git clone https://github.com/YourUsername/Network-Packet-Sniffer.git
cd Network-Packet-Sniffer

 Initialize the Database
This only needs to be done once.
bash
python database_setup.py

# On Windows (run from an Administrator terminal)
python sniffer.py

The application will start, and the GUI window will appear

