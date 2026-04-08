"""
server.py
Author: Aditya Basavaraj Jambagi (PES2UG24CS030)
Description:
    The central notification server for the Reliable Group Notification System.

    ── Hybrid Architecture (SSL/TCP + UDP) ──────────────────────────────────────
    This server runs TWO channels simultaneously:

    1. SSL/TCP Authentication Channel  (port 5001 by default)
       ─────────────────────────────────────────────────────
       - Uses TLS 1.3 encryption via Python's ssl module (server.crt + server.key).
       - ONLY used for the initial SUBSCRIBE handshake when a client joins.
       - The client sends its UDP port number in the SUBSCRIBE payload.
       - The server stores the client's (IP, UDP port) and immediately closes the SSL conn.
       - This satisfies the mandatory SSL/TLS security requirement.

    2. UDP Data Channel  (port 5000 by default)
       ──────────────────────────────────────────
       - All NOTIFY broadcasts are sent here (fire + reliable ACK tracking).
       - All ACK confirmations are received here (removes from retransmit queue).
       - All HEARTBEAT pings are received here (keep-alive eviction tracking).
       - All UNSUBSCRIBE messages are received here (graceful client exit).
       - This keeps the project "UDP-based" as specified in the project abstract.

    ── Application-Layer Reliability (on top of UDP) ────────────────────────────
    1. ACK + Retransmission:
       Every sent notification is tracked in 'unacked'. If no ACK arrives within
       2 seconds, the packet is retransmitted. After 3 failed retries, the client
       is assumed offline and removed from the subscriber list.

    2. Keep-Alive / Heartbeat:
       Clients ping the server via UDP every 2 seconds. If the server hears
       nothing for 5+ seconds, it evicts the client automatically.

    3. Duplicate Detection:
       Sequence numbers ensure clients only process each notification once.

    ── Edge Cases Handled ────────────────────────────────────────────────────────
    - SSL handshake failure    → logged, server continues accepting other clients
    - Abrupt client disconnect → detected via heartbeat timeout, auto-evicted
    - Invalid SUBSCRIBE payload → validated before storing client info
    - Invalid broadcast input  → empty/oversized messages rejected
    - UDP send failure         → logged per client, doesn't crash other deliveries
    - Thread safety            → threading.Lock() on all shared data structures
"""

import socket     # Python's built-in networking library
import ssl        # SSL/TLS wrapper — encrypts the authentication channel
import threading  # Runs all background loops in parallel threads
import time       # For timeout tracking and timestamp embedding
import logging    # Structured, timestamped terminal log messages
import random     # For simulating packet loss in testing

# Import our custom binary protocol from protocol.py.
# recv_packet is used on the SSL/TCP auth channel to read SUBSCRIBE packets correctly.
from protocol import (
    TYPE_SUBSCRIBE, TYPE_NOTIFY, TYPE_ACK,
    TYPE_UNSUBSCRIBE, TYPE_HEARTBEAT,
    encode_packet, decode_packet, recv_packet
)

# ─── Server Port Configuration ───────────────────────────────────────────────
SERVER_IP       = "0.0.0.0"  # Listen on all network interfaces
SERVER_UDP_PORT = 5000        # UDP data channel: NOTIFY, ACK, HEARTBEAT, UNSUBSCRIBE
SERVER_SSL_PORT = 5001        # SSL/TCP auth channel: SUBSCRIBE only

# ─── SSL Certificate Files ───────────────────────────────────────────────────
# Generated with:
#   openssl req -x509 -newkey rsa:2048 -keyout server.key \
#               -out server.crt -days 365 -nodes -subj '/CN=localhost'
SSL_CERT = "server.crt"   # Public X.509 certificate (shared with clients)
SSL_KEY  = "server.key"   # Private RSA key (kept on server only — never share)

# Maximum allowed broadcast message length (prevents buffer abuse)
MAX_MESSAGE_LENGTH = 1000

# Logger setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("Hybrid_Server")


class NotificationServer:
    def __init__(self, host=SERVER_IP, udp_port=SERVER_UDP_PORT,
                 ssl_port=SERVER_SSL_PORT, loss_rate=0.0):
        """
        Initializes both the UDP data socket and the SSL/TCP auth socket.

        Two sockets are created:
          - self.udp_socket         : UDP (SOCK_DGRAM) on udp_port
              Used for: broadcasts, receiving ACKs, heartbeats, unsubscribes.
          - self.ssl_server_socket  : SSL-wrapped TCP (SOCK_STREAM) on ssl_port
              Used only for: receiving SUBSCRIBE packets with the client's UDP port.

        Args:
            host:      IP to bind both sockets to.
            udp_port:  Port for the UDP data channel.
            ssl_port:  Port for the SSL/TCP authentication channel.
            loss_rate: Fraction [0.0–1.0] of UDP sends to randomly drop (for testing).
        """
        self.server_host = host
        self.server_addr = (host, udp_port)

        # ─── UDP Socket (Main Data Channel) ──────────────────────────────────
        # AF_INET = IPv4; SOCK_DGRAM = UDP (connectionless, no handshake)
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow port reuse to prevent 'Address already in use' during quick restarts
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_socket.bind((host, udp_port))
        logger.info(f"UDP data channel ready on port {udp_port}")

        # ─── SSL/TCP Socket (Authentication Channel) ─────────────────────────
        # PROTOCOL_TLS_SERVER: auto-negotiates the best TLS version (TLS 1.2/1.3)
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            # Load certificate + private key. The certificate is sent to the client
            # during the TLS handshake to prove the server's identity.
            self.ssl_context.load_cert_chain(certfile=SSL_CERT, keyfile=SSL_KEY)
            logger.info(f"SSL certificate loaded: {SSL_CERT}")
        except FileNotFoundError:
            logger.critical(
                f"SSL cert/key not found ({SSL_CERT}, {SSL_KEY}). Generate with: "
                "openssl req -x509 -newkey rsa:2048 -keyout server.key "
                "-out server.crt -days 365 -nodes -subj '/CN=localhost'"
            )
            raise

        # Create TCP socket, allow port reuse, bind and listen
        raw_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # SO_REUSEADDR lets the server restart on the same port without waiting 60s
        raw_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_tcp.bind((host, ssl_port))
        raw_tcp.listen(10)
        # Wrap TCP socket with SSL — all accepted clients will perform TLS handshake
        self.ssl_server_socket = self.ssl_context.wrap_socket(raw_tcp, server_side=True)
        logger.info(f"SSL/TCP auth channel ready on port {ssl_port}")

        # ─── Internal State ───────────────────────────────────────────────────
        self.subscribers       = set()  # Set of (IP, udp_port) tuples — all active clients
        self.client_heartbeats = {}     # {(IP, udp_port) → timestamp} last heartbeat
        self.running           = True   # False = stop all threads
        self.loss_rate         = loss_rate

        self.seq_num              = 0   # Global notification sequence counter
        self.unacked              = {}  # {(seq, addr) → entry} — awaiting ACK
        self.retransmission_count = 0   # Total retransmissions (for metrics)

        # Protects shared state from concurrent access by multiple threads
        self._lock = threading.Lock()

    # ────────────────────────────────────────────────────────────────────────
    # SSL/TCP AUTH CHANNEL — SUBSCRIBE ONLY
    # ────────────────────────────────────────────────────────────────────────

    def accept_ssl_clients(self):
        """
        SSL/TCP accept loop — runs on a dedicated background thread.

        Waits for clients to connect, reads their SUBSCRIBE packet (which contains
        their UDP port), registers that UDP address, then closes the SSL connection.

        The SSL connection is intentionally short-lived (one-shot auth):
          connect → TLS handshake → SUBSCRIBE → register → close SSL

        After this, ALL communication with the client happens over UDP.
        """
        logger.info("SSL auth channel accepting connections...")
        while self.running:
            try:
                # accept() performs both the TCP handshake and the TLS handshake.
                # client_ssl is an encrypted socket; tcp_addr is the client's TCP address.
                client_ssl, tcp_addr = self.ssl_server_socket.accept()

                # Handle each auth request in its own thread to avoid blocking
                # the accept loop if a client is slow to send its SUBSCRIBE.
                t = threading.Thread(
                    target=self._handle_ssl_auth,
                    args=(client_ssl, tcp_addr),
                    daemon=True
                )
                t.start()

            except ssl.SSLError as e:
                # ─── Edge Case: SSL Handshake Failure ────────────────────────
                # Happens if the client connects without SSL or uses a bad cert.
                # Log and continue — one bad client never breaks other connections.
                if self.running:
                    logger.error(f"SSL handshake failed from {tcp_addr if 'tcp_addr' in dir() else 'unknown'}: {e}")

            except OSError:
                # SSL server socket was closed (shutdown) → exit the loop
                break

    def _handle_ssl_auth(self, client_ssl, tcp_addr):
        """
        Handles one SSL/TCP connection: reads SUBSCRIBE, registers the client's UDP address.

        The client sends a SUBSCRIBE packet over SSL where the payload is its
        UDP port number (as a string, e.g. "54321"). We combine the TCP source
        IP with this UDP port to form the client's UDP address for broadcasting.

        After reading and registering, we close the SSL connection immediately.
        The client from this point on only communicates via UDP.
        """
        try:
            # recv_packet() reads one complete packet from the TCP stream.
            # Needed because TCP doesn't preserve message boundaries (see protocol.py).
            seq, msg_type, payload, valid = recv_packet(client_ssl)

            if not valid:
                logger.warning(f"Invalid SSL packet from {tcp_addr}")
                return

            if msg_type == TYPE_SUBSCRIBE:
                # ─── Edge Case: Validate UDP Port ────────────────────────────
                # The payload should be the client's UDP port as a string.
                # Validate it's a real port number before storing.
                try:
                    udp_port = int(payload.strip())
                    if not (1024 <= udp_port <= 65535):
                        raise ValueError("Port out of range")
                except ValueError as e:
                    logger.warning(f"Invalid UDP port in SUBSCRIBE from {tcp_addr}: '{payload}' — {e}")
                    return

                # Form the client's UDP address: TCP source IP + declared UDP port
                client_udp_addr = (tcp_addr[0], udp_port)

                with self._lock:
                    self.subscribers.add(client_udp_addr)
                    self.client_heartbeats[client_udp_addr] = time.time()

                logger.info(f"New subscriber via SSL: UDP addr = {client_udp_addr} "
                            f"[TLS: {client_ssl.version()}] "
                            f"(Active: {len(self.subscribers)})")

        except ConnectionError as e:
            # Client disconnected before finishing the auth handshake
            logger.warning(f"SSL auth connection dropped by {tcp_addr}: {e}")

        except ssl.SSLError as e:
            # ─── Edge Case: SSL Error During Auth ────────────────────────────
            logger.error(f"SSL error during auth from {tcp_addr}: {e}")

        except Exception as e:
            logger.error(f"Unexpected error in SSL auth from {tcp_addr}: {e}")

        finally:
            # Always close the SSL connection — auth is a one-shot operation
            try:
                client_ssl.close()
            except Exception:
                pass

    # ────────────────────────────────────────────────────────────────────────
    # UDP DATA CHANNEL — ACK / HEARTBEAT / UNSUBSCRIBE
    # ────────────────────────────────────────────────────────────────────────

    def listen_udp(self):
        """
        UDP receive loop — runs on a dedicated background thread.

        Handles all incoming UDP packets from subscribed clients:
          - TYPE_ACK         : Remove the (seq, addr) entry from the unacked tracker.
          - TYPE_HEARTBEAT   : Update the client's last-seen timestamp (keep-alive).
          - TYPE_UNSUBSCRIBE : Gracefully remove the client from all tracking structures.

        Note: TYPE_SUBSCRIBE is NOT handled here — it comes in over the SSL channel.
        Note: TYPE_NOTIFY    is NOT received by the server — it sends, not receives it.
        """
        while self.running:
            try:
                # Block until a UDP datagram arrives (up to 4096 bytes)
                # addr = (IP, port) of the sending client's UDP socket
                data, addr = self.udp_socket.recvfrom(4096)

                # Decode the binary packet into our structured fields
                seq, msg_type, payload, valid = decode_packet(data)

                if not valid:
                    # Checksum mismatch = packet was corrupted in transit → discard
                    continue

                if msg_type == TYPE_ACK:
                    # Client confirms it received a specific notification.
                    # Remove this (seq, addr) from the unacked tracker so the
                    # retransmission thread stops waiting for it.
                    with self._lock:
                        if (seq, addr) in self.unacked:
                            del self.unacked[(seq, addr)]
                            logger.info(f"ACK received for seq {seq} from {addr}")

                elif msg_type == TYPE_HEARTBEAT:
                    # Client is still alive — refresh its last-seen timestamp.
                    # If this timestamp goes stale for 5+ seconds, eviction triggers.
                    with self._lock:
                        if addr in self.subscribers:
                            self.client_heartbeats[addr] = time.time()

                elif msg_type == TYPE_UNSUBSCRIBE:
                    # Client is gracefully leaving — immediately remove from all state.
                    # This is faster than waiting for the 5-second heartbeat timeout.
                    self._remove_client(addr)
                    logger.info(f"Client {addr} unsubscribed gracefully via UDP")

            except OSError:
                # UDP socket closed (server shutdown) → exit loop cleanly
                break
            except Exception as e:
                if self.running:
                    logger.error(f"UDP receive error: {e}")

    # ────────────────────────────────────────────────────────────────────────
    # CLIENT MANAGEMENT
    # ────────────────────────────────────────────────────────────────────────

    def _remove_client(self, addr):
        """
        Centralized removal of a client from ALL internal tracking structures.

        Cleans up:
          - subscribers       : so no more broadcasts are sent to this address
          - client_heartbeats : so heartbeat eviction doesn't fire on stale data
          - unacked           : so retransmission doesn't attempt to reach this client

        Protected by self._lock to prevent race conditions with other threads.
        """
        with self._lock:
            self.subscribers.discard(addr)
            self.client_heartbeats.pop(addr, None)

            # Purge all pending retransmit entries for this client
            keys_to_remove = [k for k in self.unacked if k[1] == addr]
            for k in keys_to_remove:
                del self.unacked[k]

        logger.info(f"Client {addr} removed. Active subscribers: {len(self.subscribers)}")

    # ────────────────────────────────────────────────────────────────────────
    # UDP BROADCAST & SENDING
    # ────────────────────────────────────────────────────────────────────────

    def send_with_loss(self, packet, addr):
        """
        Sends a UDP datagram to a specific client address.

        Uses sendto() because UDP is connectionless — we specify the
        destination address with every single datagram we send.

        Includes simulated packet loss for testing reliability.

        Returns:
            True  — datagram was transmitted (or simulatedly dropped)
            False — a real OS-level send error occurred
        """
        # Simulated packet loss — only active when loss_rate > 0 (testing only)
        if random.random() < self.loss_rate:
            logger.warning(f"Simulated DROP to {addr}")
            return False

        try:
            self.udp_socket.sendto(packet, addr)
            return True
        except OSError as e:
            # ─── Edge Case: UDP Send Failure ─────────────────────────────────
            # Can occur if the client's OS has already recycled their UDP port.
            # We log the error but don't crash — other clients still get their packets.
            logger.warning(f"UDP send error to {addr}: {e}")
            return False

    def broadcast(self, message):
        """
        Validates then sends a notification to ALL active subscribers via UDP.

        Embeds the current Unix timestamp in the payload so clients can measure
        end-to-end latency upon receipt.
        Payload format: "1712345678.123456|<actual message text>"

        After sending, each delivered packet is registered in 'unacked' so the
        retransmission_thread() can follow up if no ACK arrives in 2 seconds.

        ── Input Validation ─────────────────────────────────────────────────────
        Rejects: non-string types, empty messages (after stripping whitespace),
                 and messages exceeding MAX_MESSAGE_LENGTH characters.
        """
        # ─── Input Validation ─────────────────────────────────────────────────
        if not isinstance(message, str):
            logger.warning(f"Broadcast rejected: expected string, got {type(message).__name__}")
            return

        message = message.strip()   # Remove leading/trailing whitespace

        if not message:
            logger.warning("Broadcast rejected: message is empty")
            return

        if len(message) > MAX_MESSAGE_LENGTH:
            logger.warning(f"Broadcast rejected: {len(message)} chars exceeds limit of {MAX_MESSAGE_LENGTH}")
            return

        # ─── Build the Packet ─────────────────────────────────────────────────
        with self._lock:
            self.seq_num += 1
            current_seq = self.seq_num      # Local copy so we release the lock quickly

        # Prefix with Unix timestamp for latency calculation by clients
        payload = f"{time.time()}|{message}"
        packet  = encode_packet(current_seq, TYPE_NOTIFY, payload)

        # ─── Send to Each Subscriber via UDP ──────────────────────────────────
        # Take a snapshot to avoid dict-size-change errors if a client disconnects
        # during the broadcast loop.
        with self._lock:
            subscriber_snapshot = set(self.subscribers)

        for addr in subscriber_snapshot:
            sent = self.send_with_loss(packet, addr)    # UDP sendto
            if sent:
                # Track in unacked — retransmission thread will check in 2 seconds
                with self._lock:
                    self.unacked[(current_seq, addr)] = {
                        "addr":      addr,       # Client's UDP (IP, port)
                        "packet":    packet,     # Raw binary packet (for retransmission)
                        "timestamp": time.time(),# When we last sent it (for timeout calc)
                        "retries":   0           # How many times we've retransmitted so far
                    }

        logger.info(f"Broadcast seq {current_seq}: '{message}' → {len(subscriber_snapshot)} client(s)")

    # ────────────────────────────────────────────────────────────────────────
    # RELIABILITY & KEEP-ALIVE — BACKGROUND THREAD
    # ────────────────────────────────────────────────────────────────────────

    def retransmission_thread(self):
        """
        Background loop that runs every second and handles two responsibilities:

        ── 1. ACK Timeout & Retransmission ──────────────────────────────────────
        If a notification hasn't been ACK'd within 2 seconds, we retransmit it
        over UDP (exactly the same binary packet — same seq, same payload).
        After 3 retransmissions with no response, we give up and remove the entry.

        Why retransmit over SSL/TCP too? We don't — only UDP data is retransmitted.
        SSL was only for the one-shot SUBSCRIBE auth.

        ── 2. Heartbeat Eviction (Keep-Alive) ───────────────────────────────────
        Clients send a UDP HEARTBEAT ping every 2 seconds.
        If a client hasn't sent a heartbeat in more than 5 seconds (2.5x the ping rate),
        we assume they are offline (crash, network drop, laptop lid closed) and evict them.
        This cleans up the subscriber list without waiting for explicit UNSUBSCRIBE.
        """
        while self.running:
            current_time = time.time()

            # ─── Retransmission Check ──────────────────────────────────────────
            # Snapshot to avoid dict-changed-during-iteration errors
            with self._lock:
                unacked_snapshot = dict(self.unacked)

            for key, entry in unacked_snapshot.items():
                seq, addr = key

                # Wait 2 seconds before retransmitting (give client time to ACK)
                if current_time - entry["timestamp"] > 2:

                    if entry["retries"] >= 3:
                        # Gave up after 3 retries — client is likely offline
                        logger.warning(f"Giving up on seq {seq} for {addr} after 3 retries")
                        with self._lock:
                            self.unacked.pop(key, None)
                        continue

                    # Retransmit: send the exact same UDP packet again
                    sent = self.send_with_loss(entry["packet"], entry["addr"])
                    if sent:
                        with self._lock:
                            if key in self.unacked:
                                self.unacked[key]["timestamp"] = current_time  # Reset timer
                                self.unacked[key]["retries"]  += 1
                        self.retransmission_count += 1
                        logger.info(f"Retransmitting seq {seq} to {addr} "
                                    f"(retry #{self.unacked.get(key, {}).get('retries', '?')})")

            # ─── Heartbeat Eviction ────────────────────────────────────────────
            with self._lock:
                heartbeat_snapshot = dict(self.client_heartbeats)

            for addr, last_beat in heartbeat_snapshot.items():
                # 5 seconds of silence = ~2.5 missed heartbeats = client is offline
                if current_time - last_beat > 5.0:
                    logger.warning(f"Client {addr} timed out (no heartbeat for 5s). Evicting.")
                    self._remove_client(addr)

            time.sleep(1)   # Check every second


if __name__ == "__main__":
    # Runs when server.py is executed directly (not when imported by test_system.py)
    server = NotificationServer()

    # Thread 1: SSL/TCP auth — accepts SUBSCRIBE connections, registers UDP addresses
    ssl_thread    = threading.Thread(target=server.accept_ssl_clients, daemon=True)

    # Thread 2: UDP data — receives ACKs, HEARTBEATs, UNSUBSCRIBEs from clients
    udp_thread    = threading.Thread(target=server.listen_udp, daemon=True)

    # Thread 3: Reliability — checks for unACK'd packets and evicts dead clients
    retrans_thread = threading.Thread(target=server.retransmission_thread, daemon=True)

    ssl_thread.start()
    udp_thread.start()
    retrans_thread.start()

    print("\n Hybrid SSL/UDP Server is active!")
    print(f"  SSL/TCP auth : port {SERVER_SSL_PORT} (for client SUBSCRIBE)")
    print(f"  UDP data     : port {SERVER_UDP_PORT} (for NOTIFY, ACK, HEARTBEAT)")
    print("\nType any message to broadcast to all subscribers. (Ctrl+C to stop)\n")

    try:
        while True:
            msg = input()
            if msg:
                server.broadcast(msg)   # Validate + send via UDP to all subscribers
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        server.running = False
        try:
            server.udp_socket.close()
            server.ssl_server_socket.close()
        except Exception:
            pass