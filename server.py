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

SERVER_IP = "0.0.0.0"
SERVER_PORT = 5000

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("UDP_Server")


class NotificationServer:
    def __init__(self, host=SERVER_IP, port=SERVER_PORT, loss_rate=0.0):
        self.server_addr = (host, port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind socket
        self.server_socket.bind(self.server_addr)

        self.subscribers = set()
        self.client_heartbeats = {} # Track heartbeat timestamps
        self.running = True
        self.loss_rate = loss_rate

        self.seq_num = 0
        self.unacked = {}
        self.retransmission_count = 0

        logger.info(f"Server started on {host}:{port}")

    def send_with_loss(self, packet, addr):
        if random.random() < self.loss_rate:
            logger.warning(f"Simulated DROP to {addr}")
            return
        self.server_socket.sendto(packet, addr)

    def listen(self):
        while self.running:
            try:
                data, addr = self.server_socket.recvfrom(4096)

                seq, msg_type, payload, valid = decode_packet(data)

                if not valid:
                    continue

                if msg_type == TYPE_SUBSCRIBE:
                    self.subscribers.add(addr)
                    self.client_heartbeats[addr] = time.time()
                    logger.info(f"New subscriber: {addr}")

                elif msg_type == TYPE_UNSUBSCRIBE:
                    if addr in self.subscribers:
                        self.subscribers.remove(addr)
                        self.client_heartbeats.pop(addr, None)
                        logger.info(f"Subscriber removed (graceful unsubscribe): {addr}")

                elif msg_type == TYPE_HEARTBEAT:
                    if addr in self.subscribers:
                        self.client_heartbeats[addr] = time.time()

                elif msg_type == TYPE_ACK:
                    if (seq, addr) in self.unacked:
                        del self.unacked[(seq, addr)]
                        logger.info(f"ACK received for seq {seq} from {addr}")

            # ✅ FIX for WinError 10022
            except OSError as e:
                if e.errno == 10022:
                    continue
                if self.running:
                    logger.error(f"Socket error: {e}")

            except Exception as e:
                if self.running:
                    logger.error(f"Error in listen loop: {e}")

    def broadcast(self, message):
        self.seq_num += 1
        
        # Embed timestamp to measure latency
        payload = f"{time.time()}|{message}"
        packet = encode_packet(self.seq_num, TYPE_NOTIFY, payload)

        for addr in self.subscribers:
            self.send_with_loss(packet, addr)

            self.unacked[(self.seq_num, addr)] = {
                "addr": addr,
                "packet": packet,
                "timestamp": time.time(),
                "retries": 0
            }

    def retransmission_thread(self):
        while self.running:
            current_time = time.time()

            for key in list(self.unacked.keys()):
                entry = self.unacked[key]
                seq, addr = key

                if current_time - entry["timestamp"] > 2:
                    if entry["retries"] >= 3:
                        del self.unacked[key]
                        continue

                    self.send_with_loss(entry["packet"], entry["addr"])
                    entry["timestamp"] = current_time
                    entry["retries"] += 1
                    self.retransmission_count += 1

                    logger.info(f"Retransmitting seq {seq}")

            # Evict clients that haven't sent a heartbeat for 5 seconds
            for addr in list(self.subscribers):
                last_beat = self.client_heartbeats.get(addr, 0)
                if current_time - last_beat > 5.0:
                    logger.warning(f"Subscriber {addr} timed out (no heartbeat). Evicting.")
                    self.subscribers.remove(addr)
                    del self.client_heartbeats[addr]

            time.sleep(1)

if __name__ == "__main__":
    server = NotificationServer()
    
    # Start server threads
    listen_thread = threading.Thread(target=server.listen, daemon=True)
    retrans_thread = threading.Thread(target=server.retransmission_thread, daemon=True)
    listen_thread.start()
    retrans_thread.start()
    
    print("Server is active! Type any message to broadcast to all subscribers:")
    try:
        while True:
            msg = input()
            if msg:
                server.broadcast(msg)
    except KeyboardInterrupt:
        server.running = False