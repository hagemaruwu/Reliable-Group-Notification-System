"""
protocol.py
Author: Aditya Raj (PES2UG24CS033)
Description:
    Defines the custom binary packet format used for communication between
    the server and all clients. Every packet has a structured header with
    a sequence number, a message type, a payload length, and a checksum.

    Also provides two TCP stream helper functions (recv_exact, recv_packet)
    that correctly read one complete packet over a TCP connection.
    These are necessary because TCP is a STREAM protocol — it does not
    preserve message boundaries the way UDP datagrams do.
    Without these helpers, a single recv() call might return half a packet
    or two packets merged together, causing corrupt decoding.

    This file is the foundation — all other files import from it.
"""

import struct  # Python library to pack/unpack binary data into raw bytes
import zlib    # Python library for computing checksums (used for CRC32)

# ─────────────────────────────────────────────
# Message Type Constants
# These are single-byte labels embedded in every packet header so the
# receiver immediately knows what kind of message it just got.
# ─────────────────────────────────────────────
TYPE_SUBSCRIBE   = 1    # Client → Server: "Add me to the subscriber list"
TYPE_NOTIFY      = 2    # Server → Client: "Here is a new notification for you"
TYPE_ACK         = 3    # Client → Server: "I received your notification successfully"
TYPE_UNSUBSCRIBE = 4    # Client → Server: "Remove me from the subscriber list"
TYPE_HEARTBEAT   = 5    # Client → Server: "I'm still alive and connected"

# ─────────────────────────────────────────────
# Packet Header Format
# Each packet starts with a fixed-size binary header before the payload.
# Format string "!IBHH" means:
#   ! = Network byte order (Big-Endian — the universal standard for network data)
#   I = Unsigned Int     (4 bytes) → Sequence Number  (which message number is this?)
#   B = Unsigned Byte    (1 byte)  → Message Type      (SUBSCRIBE, ACK, NOTIFY, etc.)
#   H = Unsigned Short   (2 bytes) → Payload Length    (how many bytes is the message?)
#   H = Unsigned Short   (2 bytes) → Checksum          (to detect packet corruption)
# Total header size = 4 + 1 + 2 + 2 = 9 bytes
# ─────────────────────────────────────────────
HEADER_FORMAT = "!IBHH"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)  # Automatically calculates = 9 bytes


def calculate_checksum(data):
    """
    Computes a 16-bit CRC (Cyclic Redundancy Check) checksum for a block of data.
    A checksum is a mathematical fingerprint of the data. If even 1 bit flips
    during transmission (due to noise or corruption), the checksum will differ,
    and the receiver will discard the packet as corrupted.

    zlib.crc32 returns a 32-bit CRC. We use '& 0xFFFF' to trim it to 16 bits
    so it fits inside our 'H' (2-byte Unsigned Short) header field.
    """
    return zlib.crc32(data) & 0xFFFF  # Mask to lower 16 bits


def encode_packet(seq_num, msg_type, payload):
    """
    Packs a message into our custom binary packet format, ready to send
    over the network (works for both TCP and UDP).

    Steps:
      1. Convert the payload string to raw UTF-8 bytes.
      2. Pack a partial header (seq, type, length) — WITHOUT the checksum.
      3. Compute CRC32 checksum over the partial header + payload bytes.
      4. Build the full header including the checksum.
      5. Return: full_header (9 bytes) + payload_bytes.
    """
    # Convert payload to bytes if it's a plain string; leave it if already bytes
    payload_bytes = payload.encode('utf-8') if isinstance(payload, str) else payload

    # Number of bytes in the payload (stored in header so receiver knows how much to read)
    payload_len = len(payload_bytes)

    # Step 2: Pack 3 of the 4 header fields — checksum is excluded for now
    # "!IBH" = big-endian (unsigned int, unsigned byte, unsigned short)
    header_partial = struct.pack("!IBH", seq_num, msg_type, payload_len)

    # Step 3: Compute checksum over partial header + full payload
    checksum = calculate_checksum(header_partial + payload_bytes)

    # Step 4: Build the complete 9-byte header including the checksum
    full_header = struct.pack(HEADER_FORMAT, seq_num, msg_type, payload_len, checksum)

    # Step 5: Return the complete binary packet = 9-byte header + payload bytes
    return full_header + payload_bytes


def decode_packet(packet_bytes):
    """
    Unpacks a received binary packet back into its individual fields.
    Returns: (seq_num, msg_type, payload, is_valid)

    'is_valid' is False if:
      - The raw bytes are shorter than the minimum header size (truncated packet)
      - The computed checksum doesn't match the received checksum (corrupted packet)
    In either case, the caller should discard the packet.
    """
    # Guard: if fewer bytes than a full header, it's definitely invalid
    if len(packet_bytes) < HEADER_SIZE:
        return None, None, None, False

    # Split the raw bytes into header and payload sections
    header_bytes  = packet_bytes[:HEADER_SIZE]   # First 9 bytes = header
    payload_bytes = packet_bytes[HEADER_SIZE:]   # The rest = payload

    # Unpack the 4 header fields from the binary header
    seq_num, msg_type, payload_len, received_checksum = struct.unpack(HEADER_FORMAT, header_bytes)

    # Re-compute the checksum locally to verify integrity
    # We recreate the partial header (same 3 fields used during encode) and hash it
    header_partial       = struct.pack("!IBH", seq_num, msg_type, payload_len)
    calculated_checksum  = calculate_checksum(header_partial + payload_bytes)

    # Compare: if they match → packet arrived intact; if not → corrupted in transit
    is_valid = (received_checksum == calculated_checksum)

    # Attempt to decode payload bytes back into a human-readable string
    try:
        payload = payload_bytes.decode('utf-8')
    except UnicodeDecodeError:
        # If UTF-8 decoding fails (binary payload), keep it as raw bytes
        payload = payload_bytes

    return seq_num, msg_type, payload, is_valid


# ─────────────────────────────────────────────
# TCP Stream Helpers
#
# WHY THESE ARE NEEDED:
#   UDP is a datagram protocol — every send() corresponds to exactly one recv().
#   TCP is a stream protocol — the OS may split or merge packets arbitrarily.
#
#   Example problem with raw TCP recv(4096):
#     - We send a 50-byte packet and a 20-byte packet.
#     - recv(4096) might return all 70 bytes at once (two packets merged).
#     - Or it might return only 30 bytes (half of the first packet).
#     - In either case, decode_packet() would fail silently with corrupt data.
#
#   Solution: always read the fixed-size header first (9 bytes), extract
#   payload_len from it, then read exactly payload_len more bytes.
#   This guarantees we always get exactly one complete, correctly-framed packet.
# ─────────────────────────────────────────────

def recv_exact(sock, n):
    """
    Reads EXACTLY 'n' bytes from a TCP socket, blocking until all bytes arrive.

    A single TCP recv() call may return fewer bytes than requested if:
      - The data is fragmented across multiple network packets.
      - The OS hasn't buffered all data yet.

    This function loops until our buffer has exactly 'n' bytes before returning.

    Args:
        sock: An open, connected TCP socket (may be SSL-wrapped).
        n:    The exact number of bytes to read.

    Returns:
        bytes: A buffer of exactly n bytes.

    Raises:
        ConnectionError: If the connection is closed before n bytes arrive.
                         (recv() returning an empty bytes object signals closure.)
    """
    data = b""              # Accumulation buffer
    while len(data) < n:
        # Ask for only the remaining bytes we still need (not more)
        chunk = sock.recv(n - len(data))
        if not chunk:
            # Empty recv() = the peer closed the connection
            raise ConnectionError("Connection closed before all bytes were received")
        data += chunk       # Append the received chunk to our buffer
    return data


def recv_packet(sock):
    """
    Reads exactly ONE complete packet from a TCP socket using our custom protocol.

    Steps:
      1. Read exactly HEADER_SIZE (9) bytes to get the fixed-size header.
      2. Parse the 'payload_len' field from the header to know how many more bytes to read.
      3. Read exactly 'payload_len' bytes to get the complete payload.
      4. Combine header + payload and pass to decode_packet() for full parsing.

    This is the correct way to read our custom protocol over TCP.
    Always use this instead of raw recv(4096) for TCP connections.

    Args:
        sock: An open, connected TCP socket (plain or SSL-wrapped).

    Returns:
        (seq_num, msg_type, payload, is_valid) — same as decode_packet().

    Raises:
        ConnectionError: If the connection drops mid-packet.
    """
    # Step 1: Read the 9-byte fixed header
    header_bytes = recv_exact(sock, HEADER_SIZE)

    # Step 2: Peek at the payload_len field (index 2 in the unpacked tuple)
    # We don't need the other fields yet — just the length to know what to read next
    _, _, payload_len, _ = struct.unpack(HEADER_FORMAT, header_bytes)

    # Step 3: Read the payload (may be 0 bytes for control packets like ACK, HEARTBEAT)
    payload_bytes = recv_exact(sock, payload_len) if payload_len > 0 else b""

    # Step 4: Combine and decode the full packet
    return decode_packet(header_bytes + payload_bytes)
