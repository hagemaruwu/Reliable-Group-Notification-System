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

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("UDP_Client")


class NotificationClient:
    def __init__(self, server_host=SERVER_IP, server_port=SERVER_PORT, loss_rate=0.0, verbose=True):
        self.server_addr = (server_host, server_port)

        # 🔥 FIX: use connected UDP socket (prevents WinError 10022)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.connect(self.server_addr)

        self.received_seqs = set()
        self.running = True
        self.loss_rate = loss_rate
        self.verbose = verbose
        self.latencies = []

    def subscribe(self):
        """Send a SUBSCRIBE message to the server."""
        logger.info(f"Subscribing to server at {self.server_addr}...")
        packet = encode_packet(0, TYPE_SUBSCRIBE, "")

        # Connected socket → use send()
        self.send_with_loss(packet)

    def unsubscribe(self):
        """Send an UNSUBSCRIBE message to the server."""
        logger.info(f"Unsubscribing from server at {self.server_addr}...")
        packet = encode_packet(0, TYPE_UNSUBSCRIBE, "")
        self.send_with_loss(packet)

    def heartbeat_loop(self):
        """Send periodic heartbeats to maintain active subscription."""
        while self.running:
            try:
                packet = encode_packet(0, TYPE_HEARTBEAT, "")
                self.send_with_loss(packet)
            except Exception:
                pass
            time.sleep(2.0)

    def send_with_loss(self, packet):
        """Send packet with simulated loss."""
        if random.random() < self.loss_rate:
            logger.warning("Simulated DROP packet")
            return
        self.client_socket.send(packet)

    def listen(self):
        """Listen for notifications from the server."""
        while self.running:
            try:
                # 🔥 FIX: use recv() instead of recvfrom()
                data = self.client_socket.recv(4096)

                seq_num, msg_type, payload, is_valid = decode_packet(data)

                if not is_valid:
                    continue

                if msg_type == TYPE_NOTIFY:
                    self.handle_notification(seq_num, payload)

            except OSError as e:
                # Ignore Windows UDP invalid argument issue
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
        """Process notification and send ACK."""

        # Send ACK first
        logger.info(f"Received notification {seq_num}. Sending ACK...")
        ack_packet = encode_packet(seq_num, TYPE_ACK, "")

        # Connected socket → use send()
        self.send_with_loss(ack_packet)

        # Duplicate detection
        if seq_num in self.received_seqs:
            logger.info(f"Duplicate packet {seq_num} ignored.")
            return

        self.received_seqs.add(seq_num)

        actual_message = message
        # Extract timestamp if present to measure latency
        if isinstance(message, str) and "|" in message:
            parts = message.split("|", 1)
            if len(parts) == 2:
                try:
                    sent_ts = float(parts[0])
                    latency = time.time() - sent_ts
                    self.latencies.append(latency)
                    actual_message = parts[1]
                except ValueError:
                    pass

        if self.verbose:
            print(f"\n>>> NOTIFICATION [{seq_num}]: {actual_message}\n")

    def start(self):
        """Start the client listener and heartbeat threads."""
        self.subscribe()

        listener_thread = threading.Thread(target=self.listen, daemon=True)
        listener_thread.start()

        heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        heartbeat_thread.start()

        try:
            while self.running:
                msg = input()
                if msg.lower() == 'quit':
                    self.unsubscribe()
                    self.running = False
        except KeyboardInterrupt:
            self.unsubscribe()
            self.running = False


if __name__ == "__main__":
    client = NotificationClient()
    client.start()