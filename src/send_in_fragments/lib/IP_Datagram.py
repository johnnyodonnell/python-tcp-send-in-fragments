import random
import socket
import struct

from send_in_fragments.lib.checksum import calculate_checksum
from send_in_fragments.lib.IP_Flags import IP_Flags


class IP_Datagram():
    def __init__(
            self, src_addr, dst_addr, data, flags = None, offset = 0):
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.data = data
        self.flags = flags
        self.offset = offset
        self.identification = random.randbytes(2)

    @classmethod
    def from_bytes(klass, byte_str):
        version = (byte_str[0] & 0xF0) >> 4
        IHL = (byte_str[0] & 0xF)
        total_length = int.from_bytes(byte_str[2:4])
        src_addr = int.from_bytes(byte_str[12:16])
        dst_addr = int.from_bytes(byte_str[16:20])
        data = byte_str[(IHL * 4):]
        return klass(src_addr, dst_addr, data)

    def get_identification(self):
        return self.identification

    def get_data(self):
        return self.data

    def set_identification(self, identification):
        self.identification = identification

    def set_flags(self, flags):
        self.flags = flags

    def set_offset(self, offset):
        self.offset = offset

    def get_bytes(self):
        # Version and IHL
        version = 4
        IHL = 5
        ip_header_top = struct.pack(">B", (version << 4) + IHL)
        
        # DSCP and ECN
        ip_header_top += struct.pack(">B", 0)

        # Total Length
        ip_header_top += struct.pack(">H", (IHL * 5) + len(self.data))

        # Identification
        ip_header_top += self.identification

        # Flags and offset
        flags = 0
        if not self.flags is None:
            flags = self.flags.get_integer()
        ip_header_top += struct.pack(">H", ((flags << 13) | self.offset))

        # Time to live
        ip_header_top += struct.pack(">B", 0x40)

        # Protocol
        ip_header_top += struct.pack(">B", 6)

        # Checksum would go here

        # Source address
        ip_header_addrs = socket.inet_aton(self.src_addr)

        # Destination address
        ip_header_addrs += socket.inet_aton(self.dst_addr)

        checksum = calculate_checksum(
                ip_header_top + struct.pack(">H", 0) + ip_header_addrs)
        ip_header = ip_header_top + struct.pack(">H", checksum) + ip_header_addrs

        return ip_header + self.data


