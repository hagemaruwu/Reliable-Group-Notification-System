# Reliable Group Notification System

A UDP-based group notification system that reliably delivers alerts to multiple subscribers with acknowledgement, retransmission, and timeout handling. Developed for Computer Networks Lab at PES University.

## 🚀 Features
- **Custom Protocol over UDP**: Uses a structured packet format with sequence numbers, message types, and a 16-bit CRC checksum for error detection.
- **Reliable Delivery layer**: Implements an ACK and Retransmission loop ensuring zero message drops even in lossy networks.
- **Keep-Alive Protocol**: Clients automatically send periodic heartbeats to maintain active subscriptions; dead clients are automatically evicted.
- **Best-Effort Baseline**: Includes an entirely separate plain UDP architecture to statistically compare the latency and processing overhead associated with reliability.
- **Automated Performance Testing**: Includes a robust test suite simulating 0% to 30% packet loss environments, tracking real-time delivery rate vs latency tradeoffs, and exporting dynamic visual Matplotlib charts.

## 👥 Team Members
- Aditya Basavaraj Jambagi (PES2UG24CS030) - Server Side & ACK Logic
- Aditya Raj (PES2UG24CS033) - Client Side & Packet Handling
- Aks Raj Singh (PES2UG24CS044) - Testing & Performance Stats

## 🛠️ Requirements
- Python 3.x
- `matplotlib` (For generating performance comparison charts)

## 🎮 How to Run

### Start the Reliable Server
```bash
python3 server.py
```

### Start Clients
Open new terminal windows and connect to the server:
```bash
python3 client.py
```

### Run Autopilot Testing
To autonomously execute both Reliable and Unreliable networks, subscribe clients, simulate network dropping limits, and automatically output graph metrics (`performance_results.png`):
```bash
python3 test_system.py
```

## 📊 Architecture & Findings
We used a **Star Topology** (1 centralized server mapping individual Unicast sockets to subscribers). When comparing Reliable UDP against Plain UDP at a 30% network packet loss rate, we witnessed the theoretical tradeoff in real laboratory outputs:
* **Delivery Rate**: Plain UDP plummets to 50-60% while our Custom Reliable implementation scores a perfect 90-100% Delivery Rate.
* **Latency Costs**: Guaranteeing ACKs and initiating recursive retransmissions dramatically increased end-to-end average packet latency.
