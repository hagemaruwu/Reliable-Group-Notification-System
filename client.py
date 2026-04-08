"""
client.py
Author: Aditya Raj (PES2UG24CS033)
Description:
    Yeh Reliable Group Notification System ka subscriber client hai.

    ── Hybrid Architecture (SSL/TCP + UDP) ──────────────────────────────────────
    Yeh client DO(2) channels use karta hai:

    1. SSL/TCP Authentication Channel (server port 5001 se connect hota hai)
       ───────────────────────────────────────────────────────────────────
       - Sirf ek baar shuru mein use hota hai SUBSCRIBE packet bhejne ke liye.
       - SUBSCRIBE payload ke andar client ka apna UDP port number hota hai.
       - Is connection mein TLS encryption hota hai (jo project ki requirement hai).
       - SUBSCRIBE karne ke turant baad yeh connection close ho jata hai (one-shot auth).

    2. UDP Data Channel (client ek local UDP port bind karta hai, server 5000 use karta hai)
       ───────────────────────────────────────────────────────────────────────────
       - Server se aane wale saare NOTIFY packets yahan receive hote hain.
       - Hum jo ACK (acknowledgement) bhejte hain wo yahan se jata hai.
       - HEARTBEAT pings (har 2 second mein) yahan se bheji jati hain.
       - Project purely "UDP-based" rahe, isliye baki saara data UDP par hai.
"""

import socket     # Python ka built-in networking library
import ssl        # SSL/TLS authentication ke liye (SUBSCRIBE packet encrypt karne)
import threading  # Loops ko background mein ek sath (parallel) chalane ke liye
import time       # Latency calculate karne aur heartbeat mein delay dene ke liye
import logging    # Terminal par clear messages print karne ke liye
import random     # Testing ke time packet drop (loss) simulate karne ke liye
import sys        # Command line arguments read karne ke liye

# Hamara custom binary protocol format import kar rahe hain
from protocol import (
    TYPE_SUBSCRIBE, TYPE_NOTIFY, TYPE_ACK,
    TYPE_UNSUBSCRIBE, TYPE_HEARTBEAT,
    encode_packet, decode_packet
)

# ─── Default Server Addresses ─────────────────────────────────────────────────
SERVER_HOST     = "127.0.0.1"    # Loopback — agar server isi laptop par chal raha ho
SERVER_UDP_PORT = 5000           # Server ka UDP data channel port
SERVER_SSL_PORT = 5001           # Server ka SSL/TCP auth channel port

# Logger configure kar rahe hain taaki output achha dikhe
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("Hybrid_Client")


class NotificationClient:
    def __init__(self, server_host=SERVER_HOST, server_udp_port=SERVER_UDP_PORT,
                 server_ssl_port=SERVER_SSL_PORT, loss_rate=0.0, verbose=True):
        """
        Dono (UDP aur SSL) channels ka setup yahan hota hai.
        """
        self.server_host     = server_host
        self.server_udp_addr = (server_host, server_udp_port)  # Yahan hum ACK aur HEARTBEAT bhejenge
        self.server_ssl_addr = (server_host, server_ssl_port)  # Yahan hum sirf SUBSCRIBE bhejenge

        # ─── UDP Socket (Main Data Channel) ──────────────────────────────────
        # SOCK_DGRAM ka matlab UDP hai (connectionless data)
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Port 0 bind karne se OS apne aap ek free local port de deta hai
        self.udp_socket.bind(("", 0))

        # getsockname() se humein pata chalta hai ki OS ne konsa port assign kiya
        # Is port number ko hum server ko bhejenge taaki wo humein wapas data bhej sake
        self.udp_port = self.udp_socket.getsockname()[1]
        logger.info(f"UDP data channel bound to local port {self.udp_port}")

        # ─── SSL Context (Authentication Channel ke liye) ─────────────────────
        # PROTOCOL_TLS_CLIENT TLS 1.2 ya 1.3 apne aap set kar lega
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Development ke liye hum certificate verification band kar rahe hain
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode    = ssl.CERT_NONE  # Self-signed cert accept kar lega

        # ─── Client Variables ──────────────────────────────────────────────────
        self.received_seqs = set()      # Duplicate message rokne ke liye
        self.running       = True       # Background threads ko control karne ke liye
        self.loss_rate     = loss_rate  # Testing ke time packets drop(lose) karne ke liye
        self.verbose       = verbose    # Notification terminal par dikhana hai ya nahi
        self.latencies     = []         # Data aane mein kitna time laga (metrics ke liye)

    # ────────────────────────────────────────────────────────────────────────
    # SUBSCRIBE / UNSUBSCRIBE
    # ────────────────────────────────────────────────────────────────────────

    def subscribe(self):
        """
        Server ko SUBSCRIBE packet bhejta hai taaki hum notifications receive kar sakein.
        Yeh SSL/TCP ke through securely jata hai.
        """
        try:
            # Step 1: Naya raw TCP socket banao aur server ke SSL port pe connect karo
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.connect(self.server_ssl_addr)

        except ConnectionRefusedError:
            # Agar server on nahi hai toh error dega
            logger.critical(f"Cannot connect to SSL auth server at {self.server_ssl_addr}. Is server.py running?")
            return

        try:
            # Step 2: TCP socket ko SSL se wrap karo (Encryption yahin shuru hota hai)
            ssl_sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=self.server_host)
            logger.info(f"SSL auth connected [{ssl_sock.version()}]. Sending SUBSCRIBE (UDP port: {self.udp_port})...")

            # Step 3: SUBSCRIBE packet encode karo. Payload mein apna UDP port bhej rahe hain
            packet = encode_packet(0, TYPE_SUBSCRIBE, str(self.udp_port))
            ssl_sock.sendall(packet)

            # Step 4: Subscribe hone ke baad connection band kar do. 
            # Aage ka sara kaam UDP par hoga.
            ssl_sock.close()
            logger.info("SSL auth complete. Now receiving on UDP channel.")

        except ssl.SSLError as e:
            logger.critical(f"SSL handshake failed: {e}")
            raw_sock.close()
        except Exception as e:
            logger.error(f"Subscribe failed: {e}")

    def unsubscribe(self):
        """
        Group se bahar aane ke liye UNSUBSCRIBE bhejte hain.
        Yeh UDP ke through jata hai kyunki it is very fast.
        """
        logger.info("Sending UNSUBSCRIBE via UDP...")
        # Server ko batate hain ki hamara port number yeh hai, hum jaa rahe hain
        packet = encode_packet(0, TYPE_UNSUBSCRIBE, str(self.udp_port))
        self.send_udp(packet)

    # ────────────────────────────────────────────────────────────────────────
    # HEARTBEAT — KEEP ALIVE
    # ────────────────────────────────────────────────────────────────────────

    def heartbeat_loop(self):
        """
        Server ko har 2 second mein yaad dilata hai ki main abhi bhi zinda/online hu.
        """
        while self.running:
            try:
                # Sirf TYPE_HEARTBEAT packet bhej rahe hain bina kisi payload ke
                packet = encode_packet(0, TYPE_HEARTBEAT, "")
                self.send_udp(packet)
            except Exception:
                pass  # Ignore error aur next cycle mein try karo
            time.sleep(2.0)  # Har 2 second mein ping karega

    # ────────────────────────────────────────────────────────────────────────
    # UDP SEND API
    # ────────────────────────────────────────────────────────────────────────

    def send_udp(self, packet):
        """
        UDP socket directly server ke port 5000 par packet phek deta (send kar deta) hai.
        """
        # Testing/Demonstration ke time randomly packet drop karne ka logic
        if random.random() < self.loss_rate:
            logger.warning("Simulated DROP (client -> server, UDP)")
            return

        try:
            # Sendto use karte hain kyunki UDP lagatar connected nahi rehta
            self.udp_socket.sendto(packet, self.server_udp_addr)
        except OSError as e:
            logger.error(f"UDP send error: {e}")

    # ────────────────────────────────────────────────────────────────────────
    # UDP LISTENING (DATA RECEIVER)
    # ────────────────────────────────────────────────────────────────────────

    def listen(self):
        """
        Background process jo continuously wait karta hai naye UDP messages aane ka.
        """
        while self.running:
            try:
                # recvfrom(4096) ruk ke wait karta hai data receive hone ka
                data, addr = self.udp_socket.recvfrom(4096)

                # Decode the binary packet
                seq_num, msg_type, payload, is_valid = decode_packet(data)

                # Agar packet network me raste mein corrupt ho gaya, toh reject kardo
                if not is_valid:
                    logger.warning("Corrupted UDP packet received — discarding")
                    continue

                # Agar packet NOTIFY type ka hai toh handle karo
                if msg_type == TYPE_NOTIFY:
                    self.handle_notification(seq_num, payload)

            except OSError as e:
                if self.running:
                    logger.error(f"UDP receive error: {e}")
                continue
            except Exception as e:
                continue

    # ────────────────────────────────────────────────────────────────────────
    # NOTIFICATION PROCESSOR
    # ────────────────────────────────────────────────────────────────────────

    def handle_notification(self, seq_num, message):
        """
        Jab koi naya message aata hai toh:
        1. Usko ACK karte hain taaki server wapas same message na bheje.
        2. Duplicate messages ko filter out karte hain.
        3. Message ko terminal screen par print karte hain.
        """
        # Step 1: Server ko FORAN ACK bhejo warna block ho jaega/dobara retransmit karega
        logger.info(f"Received notification seq {seq_num}. Sending ACK via UDP...")
        ack_packet = encode_packet(seq_num, TYPE_ACK, "")
        self.send_udp(ack_packet)

        # Step 2: Kya yeh message already aa chuka hai pichle send mein?
        if seq_num in self.received_seqs:
            logger.info(f"Duplicate seq {seq_num} — already processed, ignoring")
            return

        # Add kar lo ki yeh sequence humne padh liya hai
        self.received_seqs.add(seq_num)

        actual_message = message

        # Step 3: Payload format aisa hota hai: "1712345678.12|ActualMessage"
        # Yahan hum Timestamp nikaalte hain Latency napaane(calculate) ke liye
        if isinstance(message, str) and "|" in message:
            parts = message.split("|", 1)
            if len(parts) == 2:
                try:
                    sent_ts        = float(parts[0])         # Server ne kab bheja tha
                    latency        = time.time() - sent_ts   # Kitna time laga receive hone mein
                    self.latencies.append(latency)
                    actual_message = parts[1]                # Sirf real message bacha loge
                except ValueError:
                    pass

        # Step 4: Screen par print kar do
        if self.verbose:
            print(f"\n>>> NOTIFICATION [{seq_num}]: {actual_message}\n")

    # ────────────────────────────────────────────────────────────────────────
    # MAIN PROGRAM
    # ────────────────────────────────────────────────────────────────────────

    def start(self):
        """
        Client ko start karne ka function. Pehle subscribe karta hai, phir threads run karta hai.
        """
        self.subscribe()  # Pehle TCP se register karo

        # Naya background worker start karo incoming UDP messages padhne ke liye
        listener_thread = threading.Thread(target=self.listen, daemon=True)
        listener_thread.start()

        # Ek aur worker start karo heartbeat ping karne ke liye
        heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        heartbeat_thread.start()

        print(f"\nConnected! Receiving notifications on UDP port {self.udp_port}.")
        print("Type 'quit' and press Enter to disconnect cleanly.\n")

        try:
            while self.running:
                msg = input()
                if msg.lower() == 'quit':
                    self.unsubscribe()   # User quit type karega toh unsubscribe bhejenge
                    self.running = False # Threads ko kill kar denge
        except KeyboardInterrupt:
            self.unsubscribe()
            self.running = False


if __name__ == "__main__":
    # Yahan sys.argv ka use hota hai command line argument padhne ke liye.
    # Agar user ne command likhi: "python client.py 192.168.1.5"
    # Toh yeh apne aap 192.168.1.5 accept kar lega.
    host = sys.argv[1] if len(sys.argv) > 1 else SERVER_HOST
    client = NotificationClient(server_host=host)
    client.start()