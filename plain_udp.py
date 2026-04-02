# ============================================================================
# PLAIN_UDP.PY - Best-Effort UDP Baseline (No Reliability)
# ============================================================================
# This module implements a simple best-effort UDP notification system
# WITHOUT reliability features. Used as a baseline for comparison:
# - No ACKs required from clients
# - No retransmissions
# - No duplicate detection
# - Fire-and-forget delivery
#
# Purpose: Compare performance against Reliable UDP to demonstrate
# the cost/benefit tradeoff of reliability mechanisms.
# ============================================================================

import socket
import threading
import time
import logging
import random
from protocol import TYPE_SUBSCRIBE, TYPE_NOTIFY, encode_packet, decode_packet

# Configure logging
logger = logging.getLogger("Plain_UDP")

class PlainNotificationServer:
    """
    PlainNotificationServer: Best-effort group notification (no reliability).
    
    Simplified compared to NotificationServer:
    - No ACK handling (fire-and-forget)
    - No retransmission mechanism
    - No heartbeat tracking (no client eviction)
    - Only tracks subscribers
    
    Used for baseline performance comparison.
    """
    
    def __init__(self, host="0.0.0.0", port=5000, loss_rate=0.0):
        """
        Initialize best-effort server.
        
        Args:
            host: IP address to bind to
            port: UDP port
            loss_rate: Simulated packet loss rate (0.0 to 1.0)
        """
        self.server_addr = (host, port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(self.server_addr)
        
        # Set of subscribed client addresses
        self.subscribers = set()
        self.running = True
        self.loss_rate = loss_rate
        # Sequence number for notifications
        self.seq_num = 0

    def send_with_loss(self, packet, addr):
        """
        Send packet with optional simulated loss (same as reliable server).
        
        Args:
            packet: Binary packet data
            addr: Destination address
        """
        if random.random() < self.loss_rate:
            # Simulated drop
            return
        self.server_socket.sendto(packet, addr)

    def listen(self):
        """
        Listen for SUBSCRIBE messages from clients.
        
        Much simpler than reliable version:
        - Only handles SUBSCRIBE (no heartbeat, no ACK)
        - No need to track live clients
        - No retransmission thread needed
        """
        while self.running:
            try:
                data, addr = self.server_socket.recvfrom(4096)
                seq, msg_type, payload, valid = decode_packet(data)
                
                if not valid:
                    continue
                
                # Simply add to subscribers, don't track heartbeat
                if msg_type == TYPE_SUBSCRIBE:
                    self.subscribers.add(addr)
            except Exception:
                pass  # Silently ignore errors

    def broadcast(self, message):
        """
        Broadcast notification using best-effort (fire-and-forget).
        
        Key Difference from Reliable:
        - Send packet ONCE to each subscriber
        - Do NOT track unacked packets
        - Do NOT retransmit if packet is lost
        - Higher throughput but lower reliability
        
        Args:
            message: Notification to broadcast
        """
        self.seq_num += 1
        
        # Embed timestamp for latency measurement (same as reliable)
        payload = f"{time.time()}|{message}"
        packet = encode_packet(self.seq_num, TYPE_NOTIFY, payload)
        
        # Best-effort: send once and immediately forget (no ACK tracking)
        for addr in self.subscribers:
            self.send_with_loss(packet, addr)
        # NOTE: No unacked tracking, no retransmissions

class PlainNotificationClient:
    """
    PlainNotificationClient: Best-effort client (receives without ACKing).
    
    Simplified compared to NotificationClient:
    - Does NOT send ACKs (no reliability handshake)
    - Does NOT send heartbeats (server won't track it)
    - Detects duplicates but doesn't report to server
    - No keep-alive mechanism
    
    Used for baseline performance comparison.
    """
    
    def __init__(self, server_host="127.0.0.1", server_port=5000, loss_rate=0.0):
        """
        Initialize best-effort client.
        
        Args:
            server_host: Server IP address
            server_port: Server port
            loss_rate: Simulated packet loss (0.0 to 1.0)
        """
        self.server_addr = (server_host, server_port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.connect(self.server_addr)
        
        # Track received sequence numbers (for duplicate detection)
        self.received_seqs = set()
        self.running = True
        self.loss_rate = loss_rate
        # Store latency measurements (for comparison)
        self.latencies = []

    def subscribe(self):
        """
        Send subscription message to server (simple, no retry).
        
        Note: Unlike reliable client, we don't retry if packet is lost.
        If SUBSCRIBE gets dropped, we simply don't receive notifications.
        """
        packet = encode_packet(0, TYPE_SUBSCRIBE, "")
        self.send_with_loss(packet)  # Send once, no retry

    def send_with_loss(self, packet):
        """
        Send packet with optional simulated loss.
        
        Args:
            packet: Binary packet data
        """
        if random.random() < self.loss_rate:
            return  # Simulated drop
        self.client_socket.send(packet)

    def listen(self):
        """
        Listen for notifications (without sending ACKs).
        
        Key Difference from Reliable:
        - Receive notifications but NEVER send ACK
        - Server has no way to know packet was received
        - Server won't retransmit if packet was lost
        - Duplicate detection happens locally but not reported
        
        This is the "fire-and-forget" pattern.
        """
        while self.running:
            try:
                # Receive notification from server
                data = self.client_socket.recv(4096)
                seq, msg_type, payload, valid = decode_packet(data)
                
                # Skip invalid packets and non-notification messages
                if not valid or msg_type != TYPE_NOTIFY:
                    continue
                
                # ===== KEY DIFFERENCE: NO ACK IS SENT =====
                # Server has no way to know we received this packet!
                # This is why reliability is lost in best-effort delivery
                
                # Detect and count duplicates (but don't report to server)
                if seq not in self.received_seqs:
                    self.received_seqs.add(seq)
                    
                    # Extract timestamp to measure latency (same as reliable)
                    if isinstance(payload, str) and "|" in payload:
                        parts = payload.split("|", 1)
                        if len(parts) == 2:
                            try:
                                sent_ts = float(parts[0])
                                latency = time.time() - sent_ts
                                self.latencies.append(latency)
                            except ValueError:
                                pass  # Timestamp parsing error
            except Exception:
                pass  # Silently ignore errors
