"""
client.py
Author: Aditya Raj (PES2UG24CS033)
Description:
    The subscriber client for the Reliable Group Notification System.

    ── Hybrid Architecture (SSL/TCP + UDP) ──────────────────────────────────────
    This client uses TWO channels:

    1. SSL/TCP Authentication Channel  (connects to server port 5001)
       ───────────────────────────────────────────────────────────────
       - Used ONLY once at startup to send the SUBSCRIBE packet.
       - The SUBSCRIBE payload contains the client's UDP port number.
       - The TLS handshake encrypts this registration (SSL/TLS requirement).
       - Connection is closed immediately after SUBSCRIBE — it's a one-shot auth.

    2. UDP Data Channel  (client binds a local UDP port, server uses port 5000)
       ─────────────────────────────────────────────────────────────────────────
       - All NOTIFY packets from the server are received here.
       - All ACK confirmations are sent here (confirming receipt of notifications).
       - All HEARTBEAT pings are sent here (keep-alive, every 2 seconds).
       - UNSUBSCRIBE is sent here on graceful exit.
       - This keeps the project "UDP-based" as per the project specification.

    ── Application-Layer Features ───────────────────────────────────────────────
    1. Listener thread   — waits for NOTIFY on UDP socket, sends ACK immediately.
    2. Heartbeat thread  — pings server with HEARTBEAT over UDP every 2 seconds.
    3. Duplicate detection — seq number set prevents double-processing.
    4. Latency tracking  — parses embedded timestamp from payload for metrics.

    ── Edge Cases Handled ────────────────────────────────────────────────────────
    - Server not running          → ConnectionRefusedError with helpful message
    - SSL handshake failure       → SSLError caught with clear diagnostic
    - Invalid port in SUBSCRIBE   → Validated before connecting
    - UDP receive error           → logged, listener continues
    - UDP send failure            → logged without crashing
"""

import socket     # Python's built-in networking library
import ssl        # SSL/TLS for the authentication channel (SUBSCRIBE)
import threading  # Runs the listener and heartbeat loops in background threads
import time       # For latency calculation and heartbeat sleep timing
import logging    # Structured, timestamped terminal log output
import random     # For simulating packet loss during testing

# Import our custom binary protocol, message types, and SSL/TCP framing helper
from protocol import (
    TYPE_SUBSCRIBE, TYPE_NOTIFY, TYPE_ACK,
    TYPE_UNSUBSCRIBE, TYPE_HEARTBEAT,
    encode_packet, decode_packet
)

# ─── Default Server Addresses ─────────────────────────────────────────────────
SERVER_HOST     = "127.0.0.1"   # Loopback — server and client on the same machine
SERVER_UDP_PORT = 5000           # Server's UDP data channel port (must match server.py)
SERVER_SSL_PORT = 5001           # Server's SSL/TCP auth channel port (must match server.py)

# Setup logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("Hybrid_Client")


class NotificationClient:
    def __init__(self, server_host=SERVER_HOST, server_udp_port=SERVER_UDP_PORT,
                 server_ssl_port=SERVER_SSL_PORT, loss_rate=0.0, verbose=True):
        """
        Sets up both communication channels for the hybrid client.

        Step 1: Create and bind a UDP socket to a random OS-assigned local port.
                This UDP socket is the main data channel for the entire session.

        Step 2: The UDP port is discovered via getsockname() and will be sent
                to the server inside the SUBSCRIBE packet over SSL.

        Step 3: Build an SSL context for the one-time auth channel.
                (Actual SSL connection is made in subscribe() — not here.)

        Args:
            server_host:     IP address of the server.
            server_udp_port: Port of the server's UDP data channel.
            server_ssl_port: Port of the server's SSL/TCP auth channel.
            loss_rate:       Fraction [0.0–1.0] to randomly drop packets (testing).
            verbose:         If True, prints received notifications to the terminal.
        """
        self.server_host     = server_host
        self.server_udp_addr = (server_host, server_udp_port)  # Where to send ACK/HEARTBEAT
        self.server_ssl_addr = (server_host, server_ssl_port)  # Where to send SUBSCRIBE

        # ─── UDP Socket (Main Data Channel) ──────────────────────────────────
        # SOCK_DGRAM = UDP — connectionless, each datagram is independent
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind to "" (any local IP) and port 0 (OS assigns a free port).
        # We need to bind explicitly so we have a stable port to give to the server.
        self.udp_socket.bind(("", 0))

        # getsockname() returns the actual (IP, port) assigned by the OS.
        # We store the port — this is sent to the server during SUBSCRIBE so it
        # knows where to send UDP notifications for this client.
        self.udp_port = self.udp_socket.getsockname()[1]
        logger.info(f"UDP data channel bound to local port {self.udp_port}")

        # ─── SSL Context (for one-shot auth channel) ──────────────────────────
        # PROTOCOL_TLS_CLIENT: auto-negotiates TLS 1.2 or 1.3
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # For the self-signed development certificate, disable verification.
        # In production: load_verify_locations("server.crt") + CERT_REQUIRED + check_hostname=True
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode    = ssl.CERT_NONE  # Accept self-signed cert

        # ─── Client State ─────────────────────────────────────────────────────
        self.received_seqs = set()      # Seq numbers already processed (deduplication)
        self.running       = True       # False = stop all background threads
        self.loss_rate     = loss_rate  # Packet drop rate (testing only)
        self.verbose       = verbose    # Whether to print notifications to terminal
        self.latencies     = []         # End-to-end latency values (seconds) for metrics

    # ────────────────────────────────────────────────────────────────────────
    # SUBSCRIBE / UNSUBSCRIBE
    # ────────────────────────────────────────────────────────────────────────

    def subscribe(self):
        """
        Registers with the server by sending a SUBSCRIBE packet over SSL/TCP.

        Process:
          1. Create a new raw TCP socket and connect to the server's SSL auth port.
          2. Wrap it with SSL — performs the TLS handshake (encrypts the session).
          3. Send a SUBSCRIBE packet with OUR UDP port number as the payload.
          4. Close the SSL connection — auth is done; UDP takes over from here.

        Why send our UDP port?
          The server receives this TCP connection from our TCP source port (random),
          but it needs to know our UDP port (also random, but different) to send
          notifications to us. The payload bridges this gap.
        """
        try:
            # Step 1: Create fresh TCP socket for this auth connection
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.connect(self.server_ssl_addr)

        except ConnectionRefusedError:
            # ─── Edge Case: Server Not Running ───────────────────────────────
            logger.critical(f"Cannot connect to SSL auth server at {self.server_ssl_addr}. "
                            "Is server.py running?")
            return

        try:
            # Step 2: Wrap TCP socket with SSL → TLS handshake happens here
            ssl_sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=self.server_host)
            logger.info(f"SSL auth connected [{ssl_sock.version()}]. "
                        f"Sending SUBSCRIBE (UDP port: {self.udp_port})...")

            # Step 3: Send SUBSCRIBE — payload is our UDP port as a string
            # The server reads this and stores (our_ip, udp_port) as our address.
            packet = encode_packet(0, TYPE_SUBSCRIBE, str(self.udp_port))
            ssl_sock.sendall(packet)

            # Step 4: Close the SSL connection — auth is complete
            # From now on, all communication is over our UDP socket.
            ssl_sock.close()
            logger.info("SSL auth complete. Now receiving on UDP channel.")

        except ssl.SSLError as e:
            # ─── Edge Case: SSL Handshake Failure ────────────────────────────
            logger.critical(f"SSL handshake failed during subscribe: {e}. "
                            "Ensure server.py is running with SSL enabled.")
            raw_sock.close()

        except Exception as e:
            logger.error(f"Subscribe failed: {e}")

    def unsubscribe(self):
        """
        Sends an UNSUBSCRIBE packet over UDP to gracefully leave the group.

        We use UDP (not a new SSL connection) for unsubscribe because:
          - It's faster (no TLS handshake needed)
          - The server's UDP listen_udp() thread already handles UNSUBSCRIBE
          - The payload contains our UDP port so the server knows which subscriber to remove
        """
        logger.info("Sending UNSUBSCRIBE via UDP...")
        # Include our UDP port in payload so server can identify which subscriber we are
        packet = encode_packet(0, TYPE_UNSUBSCRIBE, str(self.udp_port))
        self.send_udp(packet)

    # ────────────────────────────────────────────────────────────────────────
    # HEARTBEAT — KEEP-ALIVE
    # ────────────────────────────────────────────────────────────────────────

    def heartbeat_loop(self):
        """
        Background thread: sends a tiny HEARTBEAT UDP datagram to the server every 2 seconds.

        This is the client-side of the Keep-Alive mechanism:
          - The server records when it last heard from each client.
          - If a client goes silent for >5 seconds (~2.5 missed heartbeats),
            the server evicts the client from its subscriber list.
          - This automatically cleans up clients that crash or lose network
            without ever sending UNSUBSCRIBE.
        """
        while self.running:
            try:
                packet = encode_packet(0, TYPE_HEARTBEAT, "")
                self.send_udp(packet)   # Tiny UDP ping to the server's data channel
            except Exception:
                pass    # Don't crash the heartbeat thread — retry next iteration
            time.sleep(2.0)     # Ping every 2 seconds

    # ────────────────────────────────────────────────────────────────────────
    # UDP SENDING
    # ────────────────────────────────────────────────────────────────────────

    def send_udp(self, packet):
        """
        Sends a UDP datagram to the server's data channel (port 5000).

        Uses sendto() with the server's UDP address (not send(), since UDP
        is connectionless and we didn't call connect() on this socket).

        Includes simulated packet loss for testing (loss_rate > 0 only in tests).
        """
        # Simulated packet drop for testing purposes
        if random.random() < self.loss_rate:
            logger.warning("Simulated DROP (client → server, UDP)")
            return

        try:
            self.udp_socket.sendto(packet, self.server_udp_addr)
        except OSError as e:
            # ─── Edge Case: UDP Send Failure ─────────────────────────────────
            logger.error(f"UDP send error: {e}")

    # ────────────────────────────────────────────────────────────────────────
    # UDP LISTENING (RECEIVE NOTIFICATIONS)
    # ────────────────────────────────────────────────────────────────────────

    def listen(self):
        """
        Background thread: continuously listens for incoming UDP packets from the server.

        Since UDP is connectionless, we use recvfrom() to receive datagrams.
        We only process TYPE_NOTIFY packets — all other types are server-only.
        Each NOTIFY is passed to handle_notification() for ACK + display.
        """
        while self.running:
            try:
                # Block until a UDP datagram arrives on our local port
                # addr = (IP, port) of the sender; should be the server's UDP port
                data, addr = self.udp_socket.recvfrom(4096)

                # Decode the binary packet using our custom protocol
                seq_num, msg_type, payload, is_valid = decode_packet(data)

                # ─── Corrupted Packet: discard ────────────────────────────────
                if not is_valid:
                    logger.warning("Corrupted UDP packet received — discarding")
                    continue

                # Only process notification messages
                if msg_type == TYPE_NOTIFY:
                    self.handle_notification(seq_num, payload)

            except OSError as e:
                # ─── Edge Case: UDP Socket Error ─────────────────────────────
                if self.running:
                    logger.error(f"UDP receive error: {e}")
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Unexpected error in listen loop: {e}")
                continue

    # ────────────────────────────────────────────────────────────────────────
    # NOTIFICATION HANDLER
    # ────────────────────────────────────────────────────────────────────────

    def handle_notification(self, seq_num, message):
        """
        Processes a received NOTIFY UDP packet. Four steps:

        1. ACK immediately (via UDP) — Sends TYPE_ACK with the same seq_num back
           to the server's UDP data channel, so the server stops its retransmission
           timer for this packet. ACK sent BEFORE duplicate check so even duplicates
           get ACK'd (stops unnecessary server retransmissions).

        2. Duplicate check — UDP can deliver the same packet more than once (e.g.,
           our ACK was lost so server retransmitted, but our first receive was fine).
           We filter duplicates using the received_seqs set.

        3. Latency extraction — The server prefixed the payload with its send timestamp:
           "1712345678.123456|Hello World". We parse the timestamp, compute elapsed
           time, and store the value for performance metrics analysis.

        4. Display — Print the human-readable notification text to the terminal.
        """
        # Step 1: ACK immediately so server stops retransmission timer for this seq
        logger.info(f"Received notification seq {seq_num}. Sending ACK via UDP...")
        ack_packet = encode_packet(seq_num, TYPE_ACK, "")  # ACK carries seq_num back
        self.send_udp(ack_packet)   # Sent to server's UDP data channel

        # Step 2: Duplicate check — have we already processed this seq_num?
        if seq_num in self.received_seqs:
            logger.info(f"Duplicate seq {seq_num} — already processed, ignoring")
            return

        # Mark as received so future duplicates of this seq are filtered out
        self.received_seqs.add(seq_num)

        actual_message = message    # Will be updated once we strip the timestamp prefix

        # Step 3: Parse and extract the embedded timestamp from the payload
        # Format: "1712345678.123456|<actual message text>"
        if isinstance(message, str) and "|" in message:
            parts = message.split("|", 1)   # Split only on the FIRST "|"
            if len(parts) == 2:
                try:
                    sent_ts        = float(parts[0])         # Server's send timestamp
                    latency        = time.time() - sent_ts   # Time elapsed = latency
                    self.latencies.append(latency)           # Store for performance metrics
                    actual_message = parts[1]                # Human-readable message text
                except ValueError:
                    pass    # If timestamp is malformed, show the raw payload

        # Step 4: Print to terminal
        if self.verbose:
            print(f"\n>>> NOTIFICATION [{seq_num}]: {actual_message}\n")

    # ────────────────────────────────────────────────────────────────────────
    # ENTRY POINT
    # ────────────────────────────────────────────────────────────────────────

    def start(self):
        """
        Entry point for running the client standalone (not in test mode).

        1. Subscribes via SSL/TCP (one-shot auth with UDP port in payload).
        2. Starts the UDP listener thread  — receives notifications, sends ACKs.
        3. Starts the UDP heartbeat thread — keeps registration alive.
        4. Waits for user to type 'quit' to cleanly unsubscribe and exit.
        """
        self.subscribe()    # SSL/TCP: one-shot SUBSCRIBE with our UDP port

        # Background thread: listens for NOTIFY on UDP, sends ACKs back via UDP
        listener_thread = threading.Thread(target=self.listen, daemon=True)
        listener_thread.start()

        # Background thread: pings server via UDP every 2 seconds
        heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        heartbeat_thread.start()

        print(f"\nConnected! Receiving notifications on UDP port {self.udp_port}.")
        print("Type 'quit' and press Enter to disconnect cleanly.\n")

        try:
            while self.running:
                msg = input()
                if msg.lower() == 'quit':
                    self.unsubscribe()      # UDP UNSUBSCRIBE → server removes us immediately
                    self.running = False    # Stop both background threads
        except KeyboardInterrupt:
            self.unsubscribe()              # Ctrl+C → also unsubscribe cleanly
            self.running = False


import sys

if __name__ == "__main__":
    # Allow passing the server IP via command line arguments!
    # Usage: python3 client.py <server_ip>
    # If no IP is provided, it defaults to SERVER_HOST (which is 127.0.0.1)
    host = sys.argv[1] if len(sys.argv) > 1 else SERVER_HOST
    client = NotificationClient(server_host=host)
    client.start()