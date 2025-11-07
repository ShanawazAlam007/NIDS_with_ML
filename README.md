# Network Intrusion Detection System (NIDS) with ML

A machine learning-driven Network Intrusion Detection System (NIDS) with real-time packet capture and alerting, built in C++ and Python.

## Features

- Real-time packet capturing and analysis
- Detection of various attack patterns using a machine learning model:
  - TCP SYN Flood attacks
  - Broadcast Ping Flood attacks
  - Random Port Connection Flood detection
  - UDP packet monitoring
- Traffic statistics monitoring
- Logging system for alerts and events
- Feature extraction for each packet, including source/destination IP, protocol, ports, and packet size
- Sends extracted features to a Python-based ML server for instant prediction
- ML server returns "Benign" or attack type; attacks are alerted with context
- CLI-driven, multithreaded, and optimized for live network monitoring (Linux)


## Prerequisites

- Linux operating system
- G++ compiler
- libpcap library (`libpcap-dev`)
- libjsoncpp library (`libjsoncpp-dev`)
- Python 3 and `pip`
- Root/sudo privileges for packet capture

# Directory Structure
 -------------------

<pre> 
NIDS_with_ML/ 
   ├── NIDS_test.c++      # Main C++ NIDS program
   ├── ml_server.py       # Python ML prediction server
   ├── nids_model_cpu.pkl # Pre-trained ML model 
   ├── scaler.pkl         # Pre-trained feature scaler
   ├── features.json      # List of features used by the model
   ├── nids_log.txt       # Generated log file with alerts
   ├── server.log         # Log file for the Python server
   ├── Aux_Program.c++    # (Optional) Utility to simulate attacks
   └── README.md
</pre>


## Installation

1. **C++ Dependencies (Linux):**
```bash
sudo apt update
sudo apt install -y g++ libpcap-dev libjsoncpp-dev build-essential
```

2. **Python Dependencies (in a virtual environment):**
```bash
sudo apt install python3-venv
python3 -m venv venv
source venv/bin/activate
pip install flask joblib pandas scikit-learn
```
## Usage

1. **Clone the repository:**
```bash
git clone https://github.com/ShanawazAlam007/NIDS_with_ML
cd NIDS_with_ML
```

2. **Compile the C++ program:**
```bash
g++ NIDS_test.c++ -o nids -lpcap -ljsoncpp -lpthread
```
3. **Run the Python ML Server:**
In a new terminal, activate the virtual environment and start the server.
```bash
source venv/bin/activate
python3 ml_server.py
```
4. **Run the NIDS program:**
In another terminal, run the compiled program with root privileges.
```bash
sudo ./nids
```
5. Enter the IP address of the machine you want to monitor when prompted.

6. The program will now monitor network traffic. It will:
   - Display real-time status messages.
   - Log alerts to `nids_log.txt` when the ML model detects a threat.
   - Show potential security threats in the console.

## (Optional) Simulating Attacks

You can use the `Aux_Program.c++` utility to test the NIDS.

1. **Compile the attack simulator:**
```bash
g++ Aux_Program.c++ -o attack_simulator
```

2. **Run the simulator:**
```bash
./attack_simulator
```
Follow the prompts to choose and launch a simulated attack against the machine being monitored by the NIDS.

## Logging

The system automatically logs events to two files:
- `nids_log.txt`: Contains high-level alerts for detected attacks.
- `server.log`: Contains detailed logs from the Python ML server, including information about each prediction.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Acknowledgments

- libpcap library developers
- Network security community
- Contributors and testers
