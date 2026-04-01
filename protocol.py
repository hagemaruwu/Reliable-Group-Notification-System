import struct
import zlib

# Message Types
TYPE_SUBSCRIBE = 1
TYPE_NOTIFY = 2
TYPE_ACK = 3
TYPE_UNSUBSCRIBE = 4
TYPE_HEARTBEAT = 5

# Header Format: Sequence Number (4B, I), Type (1B, B), Payload Length (2B, H), Checksum (2B, H)
HEADER_FORMAT = "!IBHH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def calculate_checksum(data):
    """Calculate 16-bit CRC checksum."""
    return zlib.crc32(data) & 0xFFFF

def encode_packet(seq_num, msg_type, payload):
    """
    Encodes a packet into binary format.
    """
    payload_bytes = payload.encode('utf-8') if isinstance(payload, str) else payload
    payload_len = len(payload_bytes)
    
    # Header without checksum first to calculate it
    header_partial = struct.pack("!IBH", seq_num, msg_type, payload_len)
    checksum = calculate_checksum(header_partial + payload_bytes)
    
    # Final packet
    full_header = struct.pack(HEADER_FORMAT, seq_num, msg_type, payload_len, checksum)
    return full_header + payload_bytes

def decode_packet(packet_bytes):
    """
    Decodes binary packet. Returns (seq_num, msg_type, payload, is_valid).
    """
    if len(packet_bytes) < HEADER_SIZE:
        return None, None, None, False
    
    header_bytes = packet_bytes[:HEADER_SIZE]
    payload_bytes = packet_bytes[HEADER_SIZE:]
    
    seq_num, msg_type, payload_len, received_checksum = struct.unpack(HEADER_FORMAT, header_bytes)
    
    # Verify checksum
    header_partial = struct.pack("!IBH", seq_num, msg_type, payload_len)
    calculated_checksum = calculate_checksum(header_partial + payload_bytes)
    
    is_valid = (received_checksum == calculated_checksum)
    
    try:
        payload = payload_bytes.decode('utf-8')
    except UnicodeDecodeError:
        payload = payload_bytes
        
    return seq_num, msg_type, payload, is_valid
