"""
protocol.py
Author: Aditya Raj (PES2UG24CS033)
Description:
    Yeh hamara custom networking binary protocol format hai.
    Dono Server aur Client isi message format me baat karenge ek doosre se.

    UDP ek datagram based packet protocol hai, par hum connection authentication ke
    liye TCP ka istemal kar rahe hain. TCP ek "stream" protocol hota hai.
    TCP mein data stream hoke chalata hai isliye messages chipti rehte 
    hain aaps mein (boundary blur hoti hai).
    Is file me hum 2 extra help functions bhi banate hain jo packet structure ko TCP
    streams se safely catch kar lete hain.
"""

import struct  # Python ki dictionary / data ko 0s1s raw binary me convert krne wali library
import zlib    # Data loss calculate karne ki math library (CRC Checksum calculation)

# ─────────────────────────────────────────────
# Message Types Const Variables
# In labels se recipient ko immediately samajh aayega konsa action leny hai process.
# ─────────────────────────────────────────────
TYPE_SUBSCRIBE   = 1    # "Add me to the subscriber list" (Sirf SSL se aayega)
TYPE_NOTIFY      = 2    # "Naya Data/Notification aaya hai"
TYPE_ACK         = 3    # "Ha notification perfectly mil gya mujhe"
TYPE_UNSUBSCRIBE = 4    # "Mujhe message list se ab hata de/logout"
TYPE_HEARTBEAT   = 5    # "Main software abhi on karke rakha hun/Zinda hu"

# ─────────────────────────────────────────────
# Packet Header Format Design
# Format string "!IBHH" mein:
#   ! = Network byte order (Big-Endian standard)
#   I = Sequence Number       (4 bytes space - Konsa sequence message chal raha hai?)
#   B = Message Type         (1 byte  space - Subscribe, notify etc.)
#   H = Payload Length        (2 bytes space - Data message original kitna lamba hai)
#   H = Checksum Number       (2 bytes space - Error match/detect karne keliye checksum)
# Total size header ka mila kr = 9 bytes hota hai
# ─────────────────────────────────────────────
HEADER_FORMAT = "!IBHH"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)  # = 9 bytes. Ye auto calculate kar dega


def calculate_checksum(data):
    """
    Ek mathematical fingerprint / chhaap banata hai pure packet ka. 
    Agar safar(transit) ke doraan is data me ek bhi character (bit flip) change ho gya 
    toh dono taraf fingerprint alag ho jaegi.. matlab Data Raste me Corrupt Hua. Aage pass mat kaaro!
    """
    return zlib.crc32(data) & 0xFFFF  # Mathematical mask lagaya to chop inside 16-bits. Fits into H header bytes.


def encode_packet(seq_num, msg_type, payload):
    """
    Insani data aur parameters le kar usko network pe phekne kelia binary capsule packet ready karta hai.

    Kaam ka process:
      1. Message text ko pure UTF-8 computer-readable bytes me badalo.
      2. Half header (sequence, type) encode karo.. abi checksum piche ka chorkar!
      3. Poore payload or uske half banaye heder par math hash fingerprint formula apply karo..
      4. Ek Full 9 bytes kapsul (header) banao wapas seal kar ke and ab usme fingerprint ghusado end me!
      5. Dono Header (capsule) + Undar Ka data (payload bytes) attach karke output bhej do.
    """
    payload_bytes = payload.encode('utf-8') if isinstance(payload, str) else payload
    payload_len = len(payload_bytes)

    # Temporary chhota wala box(packet) pack karo (binay fingerprint number laye)
    header_partial = struct.pack("!IBH", seq_num, msg_type, payload_len)

    # Chhote heder or total data ko ek range mein fingerprint karo
    checksum = calculate_checksum(header_partial + payload_bytes)

    # Complete Seal pack final package (full structure box with fingerprint inserted inside)
    full_header = struct.pack(HEADER_FORMAT, seq_num, msg_type, payload_len, checksum)

    return full_header + payload_bytes


def decode_packet(packet_bytes):
    """
    Aaya hua seal pack (binary packet) receive krke faro(kholo)!

    Decode process output: (SequenceNumber, MsgType, ActualDataMessage, isPayloadCorruptValid)
    'is_valid' false set hoga agar:
      - Raw data lamba hone k bjaye small he jiska matlab adha kachra packet he.
      - Received data ki math fingerprint aane k bar mismatch kar rahi hy! Data chori/corrupt hua
    """
    # Reject: 9 hi se jyada packet bada nahi hy.. ye toh valid kapsul ho nai skta.
    if len(packet_bytes) < HEADER_SIZE:
        return None, None, None, False

    # First kapade(9 bytes chunk) nikal ke box ko todo.
    header_bytes  = packet_bytes[:HEADER_SIZE]   
    payload_bytes = packet_bytes[HEADER_SIZE:]  

    # Variables mein uski position format nikal do read karo
    seq_num, msg_type, payload_len, received_checksum = struct.unpack(HEADER_FORMAT, header_bytes)

    # Same ussi raw string pe local hash formula re-run karein checking/verification purpose se
    header_partial       = struct.pack("!IBH", seq_num, msg_type, payload_len)
    calculated_checksum  = calculate_checksum(header_partial + payload_bytes)

    # Talli Karo (Kya bheja gya hash yhana calculated match hote hen?)
    is_valid = (received_checksum == calculated_checksum)

    try:
        payload = payload_bytes.decode('utf-8')  # Insani bhasa padne wala word string dobara bnado
    except UnicodeDecodeError:
        payload = payload_bytes

    return seq_num, msg_type, payload, is_valid


# ─────────────────────────────────────────────
# TCP STREAM HANDLING FUNCS (VERY IMP) 
# TCP messages ek gunde paani (stream) tarah chalate hn to kab ek packet end or shuru
# ho kisi kom ni pta! In help functions ko TCP streams read kelie mandatory hi bnana parta hai
# verna recv(4000) pure data ek sath mix le aayega stream format ke wajah se.
# ─────────────────────────────────────────────

def recv_exact(sock, n):
    """
    TCP Socket ko strictly wait par hold rakho until fixed n bytes count collect na ho pure.
    """
    data = b""              
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection bich beech dropped..")
        data += chunk       
    return data


def recv_packet(sock):
    """
    Pehle EXACTLY 9 bytes par wait and filter kre.. or read krke "size of next packet string" 
    number read kro then phir uthi hi strict read stream line set kro as packet body!
    Safe mechanism without data leakage on TCP Streams.
    """
    # Read the 9 byte header explicitly stop/hold hokar
    header_bytes = recv_exact(sock, HEADER_SIZE)

    # Usko extract krte time bs uski packet size note kia tuple 2 me
    _, _, payload_len, _ = struct.unpack(HEADER_FORMAT, header_bytes)

    # Ab Exact wo lambai measure (payload) len() ke size exact pull krlo, bs yhin pe rok di socket ko! TCP Stream safety!
    payload_bytes = recv_exact(sock, payload_len) if payload_len > 0 else b""

    # Full perfectly extract pack mila. Chalo kholo decode file call karo
    return decode_packet(header_bytes + payload_bytes)
