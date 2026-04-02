# ============================================================================
# SERVER.PY - Reliable UDP Notification Server
# ============================================================================
# This module implements a reliable multicast notification server that:
# - Manages subscriptions from multiple clients
# - Broadcasts notifications with guaranteed delivery (ACK-based)
# - Retransmits unacknowledged packets (up to 3 times)
# - Detects and evicts dead clients using heartbeat timeouts
# - Maintains state tracking: subscribers, unacked packets, heartbeats
# ============================================================================

import socket
import threading
import time
import logging
import random

from protocol import (
    TYPE_SUBSCRIBE, TYPE_NOTIFY, TYPE_ACK,
    TYPE_UNSUBSCRIBE, TYPE_HEARTBEAT,
    encode_packet, decode_packet
)

# Server configuration
SERVER_IP = "0.0.0.0"  # Listen on all interfaces
SERVER_PORT = 5000

# Configure logging for server debugging and monitoring
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("UDP_Server")


class NotificationServer:
    """
    NotificationServer: Reliable group notification server using UDP.
    
    Features:
    - ACK-based reliability: waits for client acknowledgments
    - Automatic retransmission: retries 3 times if no ACK received
    - Heartbeat-based client detection: evicts clients that don't heartbeat
    - Duplicate-free delivery: sequence numbers ensure exactly-once semantics
    - Simulated loss: for testing reliability mechanisms
    """
    
    def __init__(self, host=SERVER_IP, port=SERVER_PORT, loss_rate=0.0):
        """
        Initialize the notification server.
        
        Args:
            host: IP address to bind to (0.0.0.0 = all interfaces)
            port: UDP port to listen on
            loss_rate: Simulated packet loss rate (0.0 to 1.0) for testing
        """
        self.server_addr = (host, port)
        # Create UDP socket for receiving and sending
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind socket to the specified address and port
        self.server_socket.bind(self.server_addr)

        # Set of client addresses currently subscribed
        self.subscribers = set()
        # Dictionary tracking when each client last sent a heartbeat
        # Used to detect dead/crashed clients
        self.client_heartbeats = {}
        # Flag to control server operation
        self.running = True
        # Simulated packet loss rate for testing reliability mechanisms
        self.loss_rate = loss_rate

        # Notification sequence number (incremented for each broadcast)
        self.seq_num = 0
        # Dictionary of unacknowledged packets awaiting client ACKs
        # Key: (seq_num, client_addr), Value: {packet, timestamp, retries, ...}
        self.unacked = {}
        # Counter for total retransmissions (for performance metrics)
        self.retransmission_count = 0

        logger.info(f"Server started on {host}:{port}")

    def send_with_loss(self, packet, addr):
        """
        Send packet with optional simulated packet loss.
        
        Purpose: Allows testing of reliability mechanisms by simulating
        real-world network conditions (dropped packets).
        
        Args:
            packet: Binary packet data to send
            addr: Destination client address (host, port)
        """
        # Simulate packet loss based on configured loss_rate
        if random.random() < self.loss_rate:
            logger.warning(f"Simulated DROP to {addr}")
            return  # Packet dropped, not sent
        # Send packet to destination address
        self.server_socket.sendto(packet, addr)

    def listen(self):
        """
        Listen for incoming packets from clients.
        
        Handles:
        - SUBSCRIBE: Register new client for notifications
        - UNSUBSCRIBE: Gracefully remove client from subscriber list
        - HEARTBEAT: Update last seen time for client (keep-alive)
        - ACK: Mark packet as successfully delivered to client
        
        This runs in a separate thread to handle client traffic while
        other threads handle retransmissions and evictions.
        """
        while self.running:
            try:
                # Receive packet and source address
                data, addr = self.server_socket.recvfrom(4096)

                # Decode packet: extract sequence, message type, payload
                seq, msg_type, payload, valid = decode_packet(data)

                # Ignore packets with corrupted data (invalid checksum)
                if not valid:
                    logger.warning(f"Rejected packet from {addr}: invalid checksum")
                    continue

                # ===== SUBSCRIBE =====
                if msg_type == TYPE_SUBSCRIBE:
                    # Add new client to subscriber set
                    self.subscribers.add(addr)
                    # Record heartbeat timestamp (crucial for client alive detection)
                    self.client_heartbeats[addr] = time.time()
                    logger.info(f"New subscriber: {addr}")

                # ===== UNSUBSCRIBE =====
                elif msg_type == TYPE_UNSUBSCRIBE:
                    if addr in self.subscribers:
                        # Graceful removal: client explicitly unsubscribed
                        self.subscribers.remove(addr)
                        # Clean up heartbeat tracking
                        self.client_heartbeats.pop(addr, None)
                        logger.info(f"Subscriber removed (graceful unsubscribe): {addr}")

                # ===== HEARTBEAT =====
                elif msg_type == TYPE_HEARTBEAT:
                    if addr in self.subscribers:
                        # Update timestamp: client is alive
                        # Prevents eviction (which occurs after 5 sec of no heartbeat)
                        self.client_heartbeats[addr] = time.time()

                # ===== ACK (Reliability Mechanism) =====
                elif msg_type == TYPE_ACK:
                    if (seq, addr) in self.unacked:
                        # Client successfully received packet with this seq_num
                        # Remove from unacked dict (no more retransmits needed)
                        del self.unacked[(seq, addr)]
                        logger.info(f"ACK received for seq {seq} from {addr}")

            # Windows UDP socket quirk: error 10022 can be safely ignored
            except OSError as e:
                if e.errno == 10022:
                    continue
                if self.running:
                    logger.error(f"Socket error: {e}")

            except Exception as e:
                if self.running:
                    logger.error(f"Error in listen loop: {e}")

    def broadcast(self, message):
        """
        Broadcast a notification to all subscribed clients.
        
        Reliability Protocol:
        1. Increment sequence number (for duplicate detection)
        2. Encode packet with TYPE_NOTIFY
        3. Send to each subscriber
        4. Add to unacked dict for tracking (retransmit if no ACK)
        5. Retransmission thread will resend after 2s timeout
        6. After 3 retries, mark as delivered or client dead
        
        Args:
            message: Notification message to broadcast
        """
        # Increment sequence number for this notification
        self.seq_num += 1
        
        # Embed timestamp in payload for latency measurement
        # Format: "<timestamp>|<message>"
        # Clients extract timestamp to calculate end-to-end delay
        payload = f"{time.time()}|{message}"
        # Encode packet with sequence number, notification type, and payload
        packet = encode_packet(self.seq_num, TYPE_NOTIFY, payload)

        # Send to all subscribers
        for addr in self.subscribers:
            # Send packet (may be lost in simulation)
            self.send_with_loss(packet, addr)

            # Track this packet for reliability
            # Key: (seq_num, client_addr), Value: metadata for retransmission
            self.unacked[(self.seq_num, addr)] = {
                "addr": addr,
                "packet": packet,  # Store packet for retransmission
                "timestamp": time.time(),  # Time packet was sent
                "retries": 0  # Number of retransmission attempts so far
            }

    def retransmission_thread(self):
        """
        Retransmit unacknowledged packets and detect dead clients.
        
        Responsibilities:
        1. RETRANSMISSION: Resend packets not yet acknowledged by clients
           - After 2 seconds: if no ACK received, retransmit
           - Max 3 retransmissions per packet
           - Then give up (assume client crash or permanent loss)
        
        2. HEARTBEAT DETECTION: Evict clients that stop sending heartbeats
           - If no heartbeat for 5 seconds: client is dead
           - Remove from subscribers and free resources
        
        This runs in a separate thread (1-second cycle) independent of
        listen() and broadcast() operations.
        """
        while self.running:
            current_time = time.time()

            # ===== RETRANSMISSION LOGIC =====
            # Iterate over copy of keys (list) to safely modify dict during iteration
            for key in list(self.unacked.keys()):
                entry = self.unacked[key]
                seq, addr = key

                # Check if timeout has occurred (2 seconds since last send/retransmit)
                if current_time - entry["timestamp"] > 2:
                    # Give up after 3 retransmission attempts
                    if entry["retries"] >= 3:
                        logger.info(f"Gave up on seq {seq} to {addr} after 3 retries")
                        del self.unacked[key]
                        continue

                    # Retransmit packet to client
                    self.send_with_loss(entry["packet"], entry["addr"])
                    # Update timestamp (for next timeout check)
                    entry["timestamp"] = current_time
                    # Increment retry counter
                    entry["retries"] += 1
                    # Increment metric counter
                    self.retransmission_count += 1

                    logger.info(f"Retransmitting seq {seq} (attempt {entry['retries']})")

            # ===== HEARTBEAT TIMEOUT DETECTION =====
            # Check each subscriber's last heartbeat time
            for addr in list(self.subscribers):
                last_beat = self.client_heartbeats.get(addr, 0)
                # If no heartbeat for more than 5 seconds: client is likely dead
                if current_time - last_beat > 5.0:
                    logger.warning(f"Subscriber {addr} timed out (no heartbeat). Evicting.")
                    # Remove from active subscribers
                    self.subscribers.remove(addr)
                    # Clean up tracking data
                    del self.client_heartbeats[addr]

            # Sleep for 1 second before next check cycle
            time.sleep(1)

# Entry point for running the server
if __name__ == "__main__":
    # Create server with default settings (no simulated packet loss)
    server = NotificationServer()
    
    # Start background threads for handling client traffic and retransmissions
    # Listen Thread: Receives SUBSCRIBE, HEARTBEAT, ACK from clients
    listen_thread = threading.Thread(target=server.listen, daemon=True)
    # Retransmission Thread: Resends unacked packets, detects dead clients
    retrans_thread = threading.Thread(target=server.retransmission_thread, daemon=True)
    listen_thread.start()
    retrans_thread.start()
    
    print("Server is active! Type any message to broadcast to all subscribers:")
    try:
        # Main thread: read messages from user input and broadcast
        while True:
            msg = input()  # Block until user enters text
            if msg:
                # Broadcast to all subscribed clients
                server.broadcast(msg)
    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C
        logger.info("Server shutting down...")
        server.running = False