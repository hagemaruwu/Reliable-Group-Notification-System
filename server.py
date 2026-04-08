"""
server.py
Author: Aditya Basavaraj Jambagi (PES2UG24CS030)
Description:
    Yeh Reliable Group Notification System ka main server hai.

    ── Hybrid Architecture (SSL/TCP + UDP) ──────────────────────────────────────
    Yeh server ek sath DO(2) channels chalata hai:

    1. SSL/TCP Authentication Channel (Port 5001)
       ─────────────────────────────────────────────────────
       - TLS 1.3 encryption (server.key + server.crt) ke saath chalta hai.
       - Sirf SUBSCRIBE packet (jo client first time start pe bhejta hai) padhne ke liye.
       - Client is channel pe apna "UDP port number" batata hai.
       - Ek baar SUBSCRIBE ho jaye, toh yeh connection close kar dete hain.

    2. UDP Data Channel (Port 5000)
       ──────────────────────────────────────────
       - Saare NOTIFY messages/broadcast UDP ke through yahan se jate hain.
       - Clients ka ACK (Acknowledgement) wapas yahin receive hota hai.
       - Heartbeats (Keep alive) aur Unsubscribe requests bhi idhar hi aati hain.
       - Kyunki main traffic UDP par hai, yeh project completely "UDP-based" kahlata hai.

    ── Reliability ka Logic ─────────────────────────────────────────────────────
    1. ACK + Retransmission: Agar client ko message bhej diya, par usne 2 seconds 
       ke andar ACK nahi bheja, toh dobara packet bhejenge (maximum 3 baar retry).
    2. Keep-Alive: Agar kisi client ka heartbeat 5 seconds tak nahi aaya, toh 
       samajh lo wo dead/disconnect ho gaya hai, aur usko list se nikaal(evict) do.
"""

import socket     # Python ka built-in network connection library
import ssl        # Encryption provide karne ke liye (TLS wrapper)
import threading  # Ek sath accept TCP aur listen UDP loop chalane ke liye
import time       # Timeouts aur latency trace karne ke liye
import logging    # Prints aur console output properly format karne ke liye
import random     # Packet drop / loss system simulate(test) karne ke liye

# Apne banaye huye (custom) protocol aur message headers ko import kar rahe hain
from protocol import (
    TYPE_SUBSCRIBE, TYPE_NOTIFY, TYPE_ACK,
    TYPE_UNSUBSCRIBE, TYPE_HEARTBEAT,
    encode_packet, decode_packet, recv_packet
)

# ─── Server Port Data ───────────────────────────────────────────────
SERVER_IP       = "0.0.0.0"   # Sabhi network interfaces (IPs) par listen karo
SERVER_UDP_PORT = 5000        # Data, ACK aur heartbeat yahan aayega
SERVER_SSL_PORT = 5001        # Sirf connection verification / SUBSCRIBE idhar aayega

# ─── SSL Certificate Files ───────────────────────────────────────────────────
SSL_CERT = "server.crt"   # Public Certificate (client ko connection par bheja jata hai)
SSL_KEY  = "server.key"   # Private Key (server secret rakhta hai, bahar nahi jata)

# Maximum broadcast message allow karne ki limit
MAX_MESSAGE_LENGTH = 1000

# Logger setup taaki output achhe form mein ho
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("Hybrid_Server")


class NotificationServer:
    def __init__(self, host=SERVER_IP, udp_port=SERVER_UDP_PORT,
                 ssl_port=SERVER_SSL_PORT, loss_rate=0.0):
        self.server_host = host
        self.server_addr = (host, udp_port)

        # ─── UDP Socket ka Creation ──────────────────────────────────
        # AF_INET matlab IPv4, SOCK_DGRAM matlab UDP
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # SO_REUSEADDR port block/stuck hone se bachata hai jab server band or chalu ho
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_socket.bind((host, udp_port))
        logger.info(f"UDP data channel ready on port {udp_port}")

        # ─── SSL/TCP Socket ka Creation ──────────────────────────────
        # PROTOCOL_TLS_SERVER use karne se Python latest version (TLS 1.3) auto-select karega
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            # Apne certificates file load karo
            self.ssl_context.load_cert_chain(certfile=SSL_CERT, keyfile=SSL_KEY)
        except FileNotFoundError:
            logger.critical("SSL keys server.crt ya server.key nahi mili! Openssl command chalayein pehle.")
            raise

        # Asli TCP socket ready karke SSL se bind kar rahe hain
        raw_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_tcp.bind((host, ssl_port))
        raw_tcp.listen(10)  # maximum 10 connection ek sath wait par rakh sakte hain
        
        # Ye magic line plain TCP socket ko completely encrypted socket mein badal deti hai
        self.ssl_server_socket = self.ssl_context.wrap_socket(raw_tcp, server_side=True)
        logger.info(f"SSL/TCP auth channel ready on port {ssl_port}")

        # ─── Memory and State Storage ────────────────────────────────
        self.subscribers       = set()  # Currently connected clients ke UDP address
        self.client_heartbeats = {}     # Client last kab active tha iski Dictionary
        self.running           = True   # Server kab stop karna hai uske liye loop control
        self.loss_rate         = loss_rate

        self.seq_num              = 0   # Track karta hai kitne total messages sent hue
        self.unacked              = {}  # Ek list jo bata rahi hai kaunse message abhi tak ACK nahi hue
        self.retransmission_count = 0 

        # Lock variable data override / race condition hone se bachata hai jab threads ek sath work kar rahe ho
        self._lock = threading.Lock()

    # ────────────────────────────────────────────────────────────────────────
    # ACCEPT CONNECTIONS (SSL Channel)
    # ────────────────────────────────────────────────────────────────────────

    def accept_ssl_clients(self):
        """
        Background process loop - sirf naye client auth connections accept karta hai.
        """
        logger.info("SSL auth channel accepting connections...")
        while self.running:
            try:
                # Jab koi client aata hai toh TLS handshake successfully accept hoga yahan
                client_ssl, tcp_addr = self.ssl_server_socket.accept()

                # Har naye client signup keliye alag thread start hota hai taaki main block free rahe
                t = threading.Thread(
                    target=self._handle_ssl_auth,
                    args=(client_ssl, tcp_addr),
                    daemon=True
                )
                t.start()
            except Exception:
                break

    def _handle_ssl_auth(self, client_ssl, tcp_addr):
        """
        Naya client jab connect hua TCP se, uska SUBSCRIBE packet read karo.
        """
        try:
            # Hum helper function se packet ko correct framing se catch karte hain
            seq, msg_type, payload, valid = recv_packet(client_ssl)

            if valid and msg_type == TYPE_SUBSCRIBE:
                # Client apne data mein bata raha hai, 'Mera UDP receive port ye hai'
                udp_port = int(payload.strip())

                # Hum TCP connect hone waale IP aur user diyai UDP port dono ka joda(pair) set karenge
                client_udp_addr = (tcp_addr[0], udp_port)

                # Thread safe data update
                with self._lock:
                    self.subscribers.add(client_udp_addr)
                    self.client_heartbeats[client_udp_addr] = time.time()

                logger.info(f"New subscriber via SSL: UDP addr = {client_udp_addr} [TLS: {client_ssl.version()}]")

        except Exception as e:
            logger.error(f"Error in SSL auth: {e}")
        finally:
            # Jaise hi IP aur port register uski information li, fauran connection todo
            client_ssl.close()

    # ────────────────────────────────────────────────────────────────────────
    # DATA RECIEVER (UDP Channel)
    # ────────────────────────────────────────────────────────────────────────

    def listen_udp(self):
        """
        Ye UDP server ka background loop hai. Ye idhar wait karega kisi message aane ka.
        Yahan par sirrf ACK, HEARTBEAT ya UNSUBSCRIBE aayega. 
        """
        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(4096)
                seq, msg_type, payload, valid = decode_packet(data)

                if not valid:
                    continue  # Packet corrupt ho gaya raste mein

                if msg_type == TYPE_ACK:
                    # Achha usne ACK bhej diya, matlab message correctly poch gya, ab Unacked tracker se hta do.
                    with self._lock:
                        if (seq, addr) in self.unacked:
                            del self.unacked[(seq, addr)]
                            logger.info(f"ACK received for seq {seq} from {addr}")

                elif msg_type == TYPE_HEARTBEAT:
                    # Oh packet zinda/live hai. Iska time counter update karte hain ab fresh time par.
                    with self._lock:
                        if addr in self.subscribers:
                            self.client_heartbeats[addr] = time.time()

                elif msg_type == TYPE_UNSUBSCRIBE:
                    # Client naturally server quit karna chah rha hai. Data me se clean karo isey.
                    self._remove_client(addr)
                    logger.info(f"Client {addr} unsubscribed gracefully")

            except Exception:
                continue

    def _remove_client(self, addr):
        # Client network list or dictionaries me jahan par bhi store hai usko flush kar do
        with self._lock:
            self.subscribers.discard(addr)
            self.client_heartbeats.pop(addr, None)
            
            keys_to_remove = [k for k in self.unacked if k[1] == addr]
            for k in keys_to_remove:
                del self.unacked[k]

    # ────────────────────────────────────────────────────────────────────────
    # BROADCAST DATA PROCESSOR
    # ────────────────────────────────────────────────────────────────────────

    def broadcast(self, message):
        """
        Jab server screen par user type krke ENTER dabaye, broadcast start hoga.
        """
        message = message.strip()
        if not message: return

        with self._lock:
            self.seq_num += 1
            current_seq = self.seq_num

        # Packet mein exact time jodne hain takke end-point devices speed measure kar le latency kitna laga message pochnemein.
        payload = f"{time.time()}|{message}"
        packet  = encode_packet(current_seq, TYPE_NOTIFY, payload)

        with self._lock:
            subscriber_snapshot = set(self.subscribers)

        # Har subscribed client par UDP data alag alag gola bhejte hain loop me
        for addr in subscriber_snapshot:
            # Agar test me hum packet loss force kar rahe to ye function random packet fhek dega network me nahi bhejte
            if random.random() < self.loss_rate: continue

            try:
                self.udp_socket.sendto(packet, addr)
                
                # Dictionary log maintain kar rahe hain ki us client ko UDP bheja, aur counter zero set karo.
                with self._lock:
                    self.unacked[(current_seq, addr)] = {
                        "addr": addr, "packet": packet,
                        "timestamp": time.time(), "retries": 0
                    }
            except Exception:
                pass

        logger.info(f"Broadcast seq {current_seq} bhej diya gya → {len(subscriber_snapshot)} clients ko")

    # ────────────────────────────────────────────────────────────────────────
    # RELIABILITY (GARBAGE COLLECTOR/RE-TRANSMISSION)
    # ────────────────────────────────────────────────────────────────────────

    def retransmission_thread(self):
        """
        Background cleaner process jo har sekond activate hota hai checking ke liye.
        """
        while self.running:
            current_time = time.time()

            # --- 1) Retransmission / Retry --- # 
            with self._lock:
                unacked_snapshot = dict(self.unacked)

            for key, entry in unacked_snapshot.items():
                seq, addr = key

                # Kya bheje hue do second se jyada guzar gaya bina ACK aaye?
                if current_time - entry["timestamp"] > 2:
                    if entry["retries"] >= 3:
                        # Hum 3 baar push kar chuke, par uska response nai aaya. Leave him out off Unacked.
                        with self._lock:
                            self.unacked.pop(key, None)
                        continue

                    # Packet ko doobara push karna h network mein "Retry".
                    try:
                        self.udp_socket.sendto(entry["packet"], entry["addr"])
                        with self._lock:
                            if key in self.unacked:
                                self.unacked[key]["timestamp"] = current_time 
                                self.unacked[key]["retries"]  += 1
                        logger.info(f"Retransmitting seq {seq} to {addr}")
                    except Exception:
                        pass

            # --- 2) Heartbeat Sweeper Eviction --- # 
            # Agar kisi client ne pichle 5 second me HEARTBEAT nahi dhikaya, isko nikal bahaar karo. Zinda nahi hai connection.
            with self._lock:
                heartbeat_snapshot = dict(self.client_heartbeats)

            for addr, last_beat in heartbeat_snapshot.items():
                if current_time - last_beat > 5.0:
                    logger.warning(f"Timeout Eviction: {addr} offline (5 sec bina heartbeat).")
                    self._remove_client(addr)

            time.sleep(1)

if __name__ == "__main__":
    server = NotificationServer()
    
    # 3 processes ko parallel chala dalo
    threading.Thread(target=server.accept_ssl_clients, daemon=True).start()
    threading.Thread(target=server.listen_udp, daemon=True).start()
    threading.Thread(target=server.retransmission_thread, daemon=True).start()

    print("\n Hybrid SSL/UDP Server tayyar (shuru) hai!")
    print("\n Koi message type karo jisko broadcast krna hai sab subscribers tak. (Ctrl+C cancel)\n")

    try:
        while True:
            msg = input()
            server.broadcast(msg)
    except KeyboardInterrupt:
        server.running = False