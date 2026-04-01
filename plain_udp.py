import socket
import threading
import time
import logging
import random
from protocol import TYPE_SUBSCRIBE, TYPE_NOTIFY, encode_packet, decode_packet

logger = logging.getLogger("Plain_UDP")

class PlainNotificationServer:
    def __init__(self, host="0.0.0.0", port=5000, loss_rate=0.0):
        self.server_addr = (host, port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(self.server_addr)
        
        self.subscribers = set()
        self.running = True
        self.loss_rate = loss_rate
        self.seq_num = 0

    def send_with_loss(self, packet, addr):
        if random.random() < self.loss_rate:
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
            except Exception:
                pass

    def broadcast(self, message):
        self.seq_num += 1
        
        # Embed timestamp for latency measurement
        payload = f"{time.time()}|{message}"
        packet = encode_packet(self.seq_num, TYPE_NOTIFY, payload)
        
        # Best-effort: send once and immediately forget
        for addr in self.subscribers:
            self.send_with_loss(packet, addr)

class PlainNotificationClient:
    def __init__(self, server_host="127.0.0.1", server_port=5000, loss_rate=0.0):
        self.server_addr = (server_host, server_port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.connect(self.server_addr)
        
        self.received_seqs = set()
        self.running = True
        self.loss_rate = loss_rate
        self.latencies = []

    def subscribe(self):
        packet = encode_packet(0, TYPE_SUBSCRIBE, "")
        self.send_with_loss(packet)

    def send_with_loss(self, packet):
        if random.random() < self.loss_rate:
            return
        self.client_socket.send(packet)

    def listen(self):
        while self.running:
            try:
                data = self.client_socket.recv(4096)
                seq, msg_type, payload, valid = decode_packet(data)
                
                if not valid or msg_type != TYPE_NOTIFY:
                    continue
                
                # NO ACK IS SENT for Best-Effort Plain UDP
                
                if seq not in self.received_seqs:
                    self.received_seqs.add(seq)
                    
                    # Extract timestamp if present to measure latency
                    if isinstance(payload, str) and "|" in payload:
                        parts = payload.split("|", 1)
                        if len(parts) == 2:
                            try:
                                sent_ts = float(parts[0])
                                latency = time.time() - sent_ts
                                self.latencies.append(latency)
                            except ValueError:
                                pass
            except Exception:
                pass
