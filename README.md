# Reliable Group Notification System

A secure, reliable group notification system built over SSL/TLS-encrypted TCP sockets.
Designed as the **Jackfruit Mini Project** for the Computer Networks Lab at PES University.

---

## 📌 Project Abstract

The objective of this project is to design and implement a secure networked application
using low-level socket programming. The system demonstrates:

- **TCP + SSL/TLS** encrypted communication for all data and control exchanges
- A **custom binary protocol** with sequence numbers, CRC32 checksums, and message framing
- **Application-layer reliability** on top of SSL/TCP: ACK tracking, retransmission, and duplicate detection
- **Keep-Alive / Heartbeat** for automatic detection and eviction of disconnected clients
- A **best-effort UDP baseline** for head-to-head performance comparison
- **Automated testing** under 0%–30% simulated packet loss with Matplotlib performance graphs

---

## 👥 Team Members

| Roll Number     | Name                        | Responsibility                          |
|-----------------|-----------------------------|-----------------------------------------|
| PES2UG24CS030   | Aditya Basavaraj Jambagi    | Server, SSL setup, ACK/Retransmit logic |
| PES2UG24CS033   | Aditya Raj                  | Client, Protocol design, Heartbeat      |
| PES2UG24CS044   | Aks Raj Singh               | Testing framework, Performance metrics  |

---

## 🏗️ System Architecture — Hybrid (SSL/TCP Auth + UDP Data)

```
                      NOTIFICATION SERVER (server.py)
                      ┌──────────────────────────────────────────────┐
                      │                                              │
    Port 5001         │  ┌────────────────────────────────────────┐  │
  ┌─SSL/TCP Auth──────┤  │  accept_ssl_clients() thread           │  │
  │  (SUBSCRIBE only) │  │  → TLS 1.3 handshake (server.crt/.key)│  │
  │                   │  │  → Reads SUBSCRIBE + client's UDP port │  │
  │                   │  │  → Registers (IP, udp_port) in set     │  │
  │                   │  │  → Closes SSL connection (one-shot)    │  │
  │                   │  └────────────────────────────────────────┘  │
  │                   │                                              │
  │   Port 5000       │  ┌────────────────────────────────────────┐  │
  └──UDP Data─────────┤  │  listen_udp() thread                   │  │
     (NOTIFY/ACK/     │  │  → Receives ACK, HEARTBEAT, UNSUBSCRIBE│  │
      HEARTBEAT/      │  └────────────────────────────────────────┘  │
      UNSUBSCRIBE)    │                                              │
                      │  ┌────────────────────────────────────────┐  │
                      │  │  retransmission_thread()               │  │
                      │  │  → Retransmits unACK'd UDP packets     │  │
                      │  │  → Evicts clients silent for 5s        │  │
                      │  └────────────────────────────────────────┘  │
                      └─────────────────┬────────────────────────────┘
                                        │
                     UDP broadcasts (NOTIFY) → all subscribers
                          ┌─────────────┴──────────────┐
                          │                            │
               ┌──────────▼──────────┐    ┌───────────▼─────────┐
               │    CLIENT A          │    │    CLIENT B          │
               │  (client.py)         │    │  (client.py)         │
               │                      │    │                      │
               │ 1. subscribe():       │    │ 1. subscribe():      │
               │    SSL/TCP to :5001  │    │    SSL/TCP to :5001  │
               │    sends UDP port    │    │    sends UDP port    │
               │    → closes SSL      │    │    → closes SSL      │
               │                      │    │                      │
               │ 2. listen() [UDP]:   │    │ 2. listen() [UDP]:   │
               │    recv NOTIFY       │    │    recv NOTIFY       │
               │    → send ACK (UDP)  │    │    → send ACK (UDP)  │
               │                      │    │                      │
               │ 3. heartbeat [UDP]:  │    │ 3. heartbeat [UDP]:  │
               │    ping every 2s     │    │    ping every 2s     │
               └──────────────────────┘    └─────────────────────┘

Topology : Star (1 server ↔ N clients, individual unicast sockets)
Auth     : SSL/TLS (TLS 1.3) on port 5001 — SUBSCRIBE only (one-shot)
Data     : UDP on port 5000 — NOTIFY, ACK, HEARTBEAT, UNSUBSCRIBE
Protocol : Custom binary packet [4B seq | 1B type | 2B len | 2B CRC32] + payload
```

---

## 📦 Custom Packet Format

Every message — whether a SUBSCRIBE, NOTIFY, ACK, HEARTBEAT, or UNSUBSCRIBE — uses
the same 9-byte binary header format defined in `protocol.py`:

```
 0       4   5     7     9         9 + payload_len
 ┌───────────┬──┬──────┬──────┬────────────────────┐
 │ Seq Num   │Ty│ Len  │ CRC  │     Payload         │
 │ (4 bytes) │pe│(2 B) │(2 B) │  (variable length)  │
 │ uint32    │(1│uint16│uint16│  UTF-8 string        │
 └───────────┴──┴──────┴──────┴────────────────────┘
```

- **Seq Num**: Monotonically increasing ID for reliable delivery tracking
- **Type**: `1=SUBSCRIBE`, `2=NOTIFY`, `3=ACK`, `4=UNSUBSCRIBE`, `5=HEARTBEAT`
- **Len**: Payload byte count (used by TCP framing helpers)
- **CRC**: 16-bit CRC32 checksum for corruption detection
- **Payload**: For NOTIFY: `"timestamp|message"` (timestamp used for latency calculation)

---

## 🔒 SSL/TLS Security

All communication between the server and clients is encrypted using TLS 1.3
via Python's built-in `ssl` module.

### Certificate Files

| File         | Description                                      |
|--------------|--------------------------------------------------|
| `server.crt` | X.509 self-signed public certificate (shared)    |
| `server.key` | RSA-2048 private key (kept on server only)       |

### Regenerating Certificates

If the certificates expire or are missing, regenerate them with:

```bash
openssl req -x509 -newkey rsa:2048 \
            -keyout server.key \
            -out server.crt \
            -days 365 \
            -nodes \
            -subj '/CN=localhost'
```

> **Note:** The `-nodes` flag skips passphrase encryption on the private key
> (required for non-interactive server startup). For production environments,
> use a CA-signed certificate and enable `ssl.CERT_REQUIRED` on the client.

---

## 🛠️ Requirements

| Requirement | Version / Notes                      |
|-------------|--------------------------------------|
| Python      | 3.8 or higher                        |
| `ssl`       | Built into Python standard library   |
| `socket`    | Built into Python standard library   |
| `struct`    | Built into Python standard library   |
| `zlib`      | Built into Python standard library   |
| `matplotlib`| For performance graph generation     |

Install `matplotlib`:

```bash
pip install matplotlib
```

Verify SSL certificate files exist before starting the server:

```bash
ls -lh server.crt server.key
```

---

## 🚀 How to Run

### 1. Start the Reliable SSL Server

```bash
python3 server.py
```

Expected output:
```
2024-xx-xx - [INFO] - SSL certificate loaded: server.crt
2024-xx-xx - [INFO] - SSL Server listening on 0.0.0.0:5000
SSL Server is active! Type any message to broadcast to all subscribers.
```

### 2. Connect Subscriber Clients

Open one or more new terminal windows and run:

```bash
python3 client.py
```

Expected output:
```
2024-xx-xx - [INFO] - SSL connection established with ('127.0.0.1', 5000) [Protocol: TLSv1.3]
2024-xx-xx - [INFO] - Subscribing to server at ('127.0.0.1', 5000)...
Connected! You will receive notifications here.
Type 'quit' and press Enter to disconnect cleanly.
```

### 3. Broadcast a Notification

In the **server terminal**, type any message and press Enter:

```
Hello team! This is a test notification.
```

Clients will display:
```
>>> NOTIFICATION [1]: Hello team! This is a test notification.
```

### 4. Graceful Client Disconnect

In the **client terminal**, type:
```
quit
```

### 5. Run Automated Performance Tests

Runs all tests (0%–30% loss) for both systems and saves the graph:

```bash
python3 test_system.py
```

Output: `performance_results.png` with 4 comparison panels.

---

## 📊 Architecture & Design Decisions

### Why TCP instead of UDP for the Reliable system?

SSL/TLS was designed specifically for stream-oriented (TCP) sockets. While DTLS
(Datagram TLS) exists for UDP, Python's `ssl` module does not natively support it.
Switching to TCP+SSL gives us full encryption with standard library support.

### Why keep ACKs and retransmission on top of TCP?

TCP guarantees bytes arrive at the OS receive buffer. Our application-level ACKs
provide a stronger guarantee: the **client application processed the notification**.
This semantic difference is important for notification systems where silent drops
(app crashed after receive but before processing) would otherwise go undetected.

### Why star topology with unicast?

Unlike multicast (which has router support requirements), unicast over individual
SSL sockets gives us per-client delivery tracking. We know exactly which client
received which message and can retransmit selectively.

---

## 📈 Performance Findings

Tests conducted with 3 clients, 5 notifications per run, at four loss levels:

| Metric           | System       | 0% Loss | 10% Loss | 20% Loss | 30% Loss |
|------------------|--------------|---------|----------|----------|----------|
| Delivery Rate    | Reliable SSL | ~100%   | ~100%    | ~100%    | ~90-100% |
| Delivery Rate    | Plain UDP    | ~100%   | ~80%     | ~65%     | ~50%     |
| Avg Latency      | Reliable SSL | Low     | Moderate | Moderate | High     |
| Avg Latency      | Plain UDP    | Low     | Low      | Low      | Low*     |
| Retransmissions  | Reliable SSL | 0       | Low      | Moderate | High     |

_*Plain UDP latency appears lower at high loss because undelivered messages are
simply not counted — the sample set is smaller and biased toward fast arrivals._

### Key Takeaway

> At 30% packet loss, Plain UDP delivers only **~50% of messages**.
> Our Reliable SSL system maintains **90–100% delivery** — at the cost of
> higher latency due to retransmission wait times. This is the classic
> **reliability vs. latency tradeoff** in network systems design.

---

## 📂 File Overview

| File               | Description                                                        |
|--------------------|--------------------------------------------------------------------|
| `protocol.py`      | Custom binary packet format, CRC checksum, TCP framing helpers     |
| `server.py`        | SSL/TCP notification server with ACK, retransmit, heartbeat        |
| `client.py`        | SSL/TCP subscriber client with listener, heartbeat, latency track  |
| `plain_udp.py`     | Best-effort UDP baseline (no SSL, no ACKs, no retransmission)      |
| `test_system.py`   | Automated testing framework — 4 metrics, 4 loss levels, 4 graphs  |
| `server.crt`       | SSL public certificate (X.509, self-signed, RSA-2048)              |
| `server.key`       | SSL private key (RSA-2048, not encrypted, lab use only)            |
| `performance_results.png` | Output graph from the last test run                         |
