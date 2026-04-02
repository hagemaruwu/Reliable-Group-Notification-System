# ============================================================================
# PROTOCOL.PY - Packet Encoding/Decoding and Checksum Verification
# ============================================================================
# This module defines the custom protocol for reliable UDP communication:
# - Message type constants for control and data packets
# - Binary packet structure with CRC32 checksum for error detection
# - Encoding function: Python objects → binary packets
# - Decoding function: binary packets → Python objects with validation
# ============================================================================

import struct
import zlib

# ===== MESSAGE TYPE CONSTANTS =====
# Used to identify the purpose of each packet
TYPE_SUBSCRIBE = 1      # Client request to receive notifications
TYPE_NOTIFY = 2         # Server broadcasts notification to clients
TYPE_ACK = 3            # Client acknowledges receipt of notification
TYPE_UNSUBSCRIBE = 4    # Client request to stop receiving notifications
TYPE_HEARTBEAT = 5      # Client keep-alive signal (no data)

# ===== PACKET HEADER STRUCTURE =====
# Binary format: (sequence_num: 4 bytes, type: 1 byte, payload_len: 2 bytes, checksum: 2 bytes)
# Network byte order (big-endian): ! = network, I = unsigned int, B = unsigned byte, H = unsigned short
# Total header size: 4 + 1 + 2 + 2 = 9 bytes
HEADER_FORMAT = "!IBHH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def calculate_checksum(data):
    """
    Calculate 16-bit CRC checksum for error detection.
    
    Purpose: Detect corrupted packets (single bit errors, etc.)
    
    Algorithm: CRC32 masked to 16-bit value
    - zlib.crc32() produces 32-bit checksum
    - 0xFFFF mask reduces to 16-bit value (fits in 2 bytes)
    
    Args:
        data: Binary data to checksum
    
    Returns:
        16-bit checksum value
    """
    # Apply CRC32 and mask to 16 bits
    return zlib.crc32(data) & 0xFFFF

def encode_packet(seq_num, msg_type, payload):
    """
    Encode a packet into binary format suitable for UDP transmission.
    
    Packet Structure:
    [Header: 9 bytes][Payload: variable]
    
    Header:
    - Sequence Number (4 bytes): unique ID for duplicate detection
    - Message Type (1 byte): SUBSCRIBE, NOTIFY, ACK, etc.
    - Payload Length (2 bytes): size of payload in bytes
    - Checksum (2 bytes): CRC32 for error detection
    
    Algorithm:
    1. Convert payload to UTF-8 bytes (if string)
    2. Calculate checksum of header + payload
    3. Pack header with checksum into binary format
    4. Return: binary_header + binary_payload
    
    Args:
        seq_num: Sequence number (4-byte unsigned int)
        msg_type: Message type constant (1 byte)
        payload: Message content (string or bytes)
    
    Returns:
        Binary packet data (bytes) ready to send over UDP
    """
    # Convert payload to bytes if it's a string
    payload_bytes = payload.encode('utf-8') if isinstance(payload, str) else payload
    payload_len = len(payload_bytes)
    
    # Pack header without checksum field (needed to calculate checksum)
    # Format: sequence (4), type (1), length (2) = 7 bytes
    header_partial = struct.pack("!IBH", seq_num, msg_type, payload_len)
    # Calculate checksum over header + payload
    checksum = calculate_checksum(header_partial + payload_bytes)
    
    # Pack complete header with checksum
    # Format: sequence (4), type (1), length (2), checksum (2) = 9 bytes
    full_header = struct.pack(HEADER_FORMAT, seq_num, msg_type, payload_len, checksum)
    # Return complete packet: header + payload
    return full_header + payload_bytes

def decode_packet(packet_bytes):
    """
    Decode binary packet back to components with validation.
    
    Packet Structure:
    [Header: 9 bytes][Payload: variable]
    
    Validation:
    - Check packet length >= 9 bytes (minimum for header only)
    - Verify checksum matches (error detection)
    
    Error Handling:
    - Return (None, None, None, False) if packet too short
    - Return (None, None, payload, False) if checksum invalid
    - Try to decode payload as UTF-8, fallback to raw bytes
    
    Args:
        packet_bytes: Binary packet data received from UDP socket
    
    Returns:
        Tuple: (seq_num, msg_type, payload, is_valid)
        - seq_num: Packet sequence number (0-4294967295)
        - msg_type: Type constant (1-5)
        - payload: Message content (string or bytes)
        - is_valid: bool, True if checksum matches
    """
    # Check minimum packet length (header only, no payload)
    if len(packet_bytes) < HEADER_SIZE:
        # Packet too short, cannot unpack header
        return None, None, None, False
    
    # Extract header and payload sections
    header_bytes = packet_bytes[:HEADER_SIZE]
    payload_bytes = packet_bytes[HEADER_SIZE:]
    
    # Unpack header fields from binary format
    seq_num, msg_type, payload_len, received_checksum = struct.unpack(HEADER_FORMAT, header_bytes)
    
    # ===== CHECKSUM VERIFICATION (Error Detection) =====
    # Recalculate checksum over same data
    header_partial = struct.pack("!IBH", seq_num, msg_type, payload_len)
    calculated_checksum = calculate_checksum(header_partial + payload_bytes)
    
    # Verify: received checksum == calculated checksum
    is_valid = (received_checksum == calculated_checksum)
    
    # ===== PAYLOAD DECODING =====
    # Try to decode payload as UTF-8 string, fallback to raw bytes
    try:
        payload = payload_bytes.decode('utf-8')
    except UnicodeDecodeError:
        # Not valid UTF-8, return as bytes
        payload = payload_bytes
        
    return seq_num, msg_type, payload, is_valid
