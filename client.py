# ============================================================================
# CLIENT.PY - Reliable UDP Notification Client
# ============================================================================
# This module implements a reliable notification client that:
# - Subscribes to a notification server over UDP
# - Receives notifications and sends ACKs for reliability
# - Maintains connection via periodic heartbeats
# - Detects and filters duplicate messages
# - Measures end-to-end latency
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
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

# Configure logging for debugging and monitoring
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("UDP_Client")


class NotificationClient:
    """
    NotificationClient: Subscribes to reliable group notifications.
    
    Features:
    - UDP-based reliable communication with the server
    - Automatic heartbeat mechanism to maintain subscription
    - ACK-based reliability (confirms receipt of notifications)
    - Duplicate detection using sequence numbers
    - Latency measurement for performance analysis
    """
    
    def __init__(self, server_host=SERVER_IP, server_port=SERVER_PORT, loss_rate=0.0, verbose=True):
        """
        Initialize the notification client.
        
        Args:
            server_host: IP address of the notification server
            server_port: Port number of the notification server
            loss_rate: Simulated packet loss rate (0.0 to 1.0) for testing
            verbose: Whether to print received notifications to console
        """
        self.server_addr = (server_host, server_port)

        # Use connected UDP socket to prevent "WinError 10022" on Windows
        # This allows using send() instead of sendto() and recv() instead of recvfrom()
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.connect(self.server_addr)

        # Track received sequence numbers to detect and filter duplicates
        self.received_seqs = set()
        # Flag to control client operation
        self.running = True
        # Simulated packet loss rate for testing reliability mechanisms
        self.loss_rate = loss_rate
        # Whether to print notifications to console
        self.verbose = verbose
        # Store latency measurements for performance analysis
        self.latencies = []

    def subscribe(self):
        """
        Send a SUBSCRIBE message to the server.
        
        This message signals the server that this client wants to receive
        notifications broadcast to the group.
        """
        logger.info(f"Subscribing to server at {self.server_addr}...")
        # Encode subscription packet with sequence number 0 (not used for control messages)
        packet = encode_packet(0, TYPE_SUBSCRIBE, "")

        # Send packet (may be dropped if simulated loss occurs)
        self.send_with_loss(packet)

    def unsubscribe(self):
        """
        Send an UNSUBSCRIBE message to the server.
        
        This performs a graceful shutdown, informing the server that
        we no longer want to receive notifications.
        """
        logger.info(f"Unsubscribing from server at {self.server_addr}...")
        # Encode unsubscription packet
        packet = encode_packet(0, TYPE_UNSUBSCRIBE, "")
        self.send_with_loss(packet)

    def heartbeat_loop(self):
        """
        Send periodic heartbeats to maintain active subscription.
        
        Purpose:
        - Keeps the subscription alive on the server
        - Server uses heartbeats to detect dead/crashed clients
        - If a client stops sending heartbeats, server evicts it after timeout
        
        This runs in a separate thread to allow continuous heartbeating
        even while the client processes notifications.
        """
        while self.running:
            try:
                # Create and send a heartbeat packet
                packet = encode_packet(0, TYPE_HEARTBEAT, "")
                self.send_with_loss(packet)  # May be simulated as lost
            except Exception:
                # Silently ignore errors (server may be down temporarily)
                pass
            # Send heartbeat every 2 seconds
            time.sleep(2.0)

    def send_with_loss(self, packet):
        """
        Send packet with optional simulated packet loss.
        
        Purpose: Allows testing of reliability mechanisms by simulating
        real-world network conditions (dropped packets).
        
        Args:
            packet: Binary packet data to send
        """
        # Simulate packet loss based on configured loss_rate
        if random.random() < self.loss_rate:
            logger.warning("Simulated DROP packet")
            return  # Packet dropped, not sent
        # Send packet using connected socket
        self.client_socket.send(packet)

    def listen(self):
        """
        Listen for notifications from the server.
        
        This runs in a separate thread (daemon) to continuously receive
        messages from the server while the main thread can handle other tasks.
        
        Process:
        1. Receive binary packet from server
        2. Decode and validate packet using checksum
        3. Handle notifications (send ACK, detect duplicates)
        """
        while self.running:
            try:
                # Receive up to 4096 bytes from the server
                # Using recv() instead of recvfrom() due to connected socket
                data = self.client_socket.recv(4096)

                # Decode packet: extract sequence number, type, payload, and validate checksum
                seq_num, msg_type, payload, is_valid = decode_packet(data)

                # Ignore packets with invalid checksum (corrupted data)
                if not is_valid:
                    logger.warning(f"Discarding packet with invalid checksum")
                    continue

                # Process notifications and send ACK
                if msg_type == TYPE_NOTIFY:
                    self.handle_notification(seq_num, payload)

            except OSError as e:
                # Windows UDP socket quirk: error 10022 can be safely ignored
                if e.errno == 10022:
                    continue
                if self.running:
                    logger.error(f"Socket error: {e}")
                continue

            except Exception as e:
                if self.running:
                    logger.error(f"Error in listen loop: {e}")
                continue

    def handle_notification(self, seq_num, message):
        """
        Process notification and send ACK.
        
        Reliability Mechanism:
        - Send ACK immediately to acknowledge receipt
        - Server uses ACKs to mark packets as successfully delivered
        - Server retransmits unacked packets after timeout (2 seconds)
        - Server gives up after 3 retries
        
        Duplicate Detection:
        - Uses sequence numbers to detect duplicate deliveries
        - Only processes each message once, even if received multiple times
        - Prevents duplicate notifications from reaching the application
        
        Latency Measurement:
        - Extracts embedded timestamp from payload
        - Measures end-to-end time from server send to client receive
        
        Args:
            seq_num: Sequence number of the notification
            message: Payload message (may include timestamp)
        """

        # Send ACK immediately to inform server of successful receipt
        logger.info(f"Received notification {seq_num}. Sending ACK...")
        ack_packet = encode_packet(seq_num, TYPE_ACK, "")

        # Send ACK (may be lost in simulation)
        self.send_with_loss(ack_packet)

        # Check for duplicate message using sequence number
        if seq_num in self.received_seqs:
            logger.info(f"Duplicate packet {seq_num} ignored.")
            return  # Already processed this message, ignore duplicate

        # Mark this sequence number as received
        self.received_seqs.add(seq_num)

        # Extract latency measurement from timestamp embedded in payload
        actual_message = message
        if isinstance(message, str) and "|" in message:
            parts = message.split("|", 1)
            if len(parts) == 2:
                try:
                    # First part is timestamp inserted by server
                    sent_ts = float(parts[0])
                    # Calculate latency: current time - sent time
                    latency = time.time() - sent_ts
                    self.latencies.append(latency)
                    # Second part is the actual message content
                    actual_message = parts[1]
                except ValueError:
                    pass  # Timestamp parsing failed, use entire message

        # Display notification to user if verbose mode enabled
        if self.verbose:
            print(f"\n>>> NOTIFICATION [{seq_num}]: {actual_message}\n")

    def start(self):
        """
        Start the client listener and heartbeat threads.
        
        Thread Architecture:
        1. Listener Thread (daemon): Continuously receives notifications
        2. Heartbeat Thread (daemon): Periodically sends heartbeats
        3. Main Thread: Handles user input for graceful shutdown
        
        All threads work concurrently to maintain subscription and
        receive notifications without blocking.
        """
        # First, send subscription request to server
        self.subscribe()

        # Start listener thread to receive notifications
        # Daemon thread = exits automatically when main thread exits
        listener_thread = threading.Thread(target=self.listen, daemon=True)
        listener_thread.start()

        # Start heartbeat thread to maintain subscription
        # Runs every 2 seconds independent of notification processing
        heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        heartbeat_thread.start()

        # Main thread: wait for user input to shutdown
        try:
            while self.running:
                msg = input()  # Block until user enters text
                if msg.lower() == 'quit':
                    # Graceful shutdown: unsubscribe first
                    self.unsubscribe()
                    self.running = False
        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            logger.info("Keyboard interrupt received")
            self.unsubscribe()
            self.running = False


# Entry point for running the client
if __name__ == "__main__":
    # Create client with default settings (no simulated packet loss)
    client = NotificationClient()
    # Start subscription and listening threads
    client.start()