#!/usr/bin/env python3
import sys
import binascii
import hashlib
import struct

ZERO_BLOCK = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF"
TCPA_BLOCK_LEN = 39
TCPA_HEADER_LEN = 29

def find_tcpa_block(data):
    ibmsecur = data.find(b"IBMSECUR")
    if not ibmsecur:
        return None
    tcpa_temp = data[ibmsecur-100:ibmsecur+(16*1024)]
    tcpa_start = tcpa_temp.find(b"TCPA")
    tcpa_end = tcpa_temp.find(ZERO_BLOCK)
    if not (tcpa_start and tcpa_end):
        return None
    return tcpa_temp[tcpa_start:tcpa_end + 1]

class TCPABlock:
    def __init__(self, data):
        # Get struct length and block ID
        cut_data = data[:3]
        self.block_num, self.block_id, self.block_len = struct.unpack("<BBB",
                                                                      cut_data)
        if self.block_id == 0x00:
            # Ignore zero block
            return
        elif self.block_id in (0xFD, 0xFF, 0x42):
            # TCPABIOS or zero block
            assert(self.block_len == 0x27)
            cut_data = data[:0x27]
            self.block_num, self.block_id, self.block_len, self.sha1sum, self.offset, \
            self.length, self.flags, self.fragmentno = struct.unpack("<BBB20sIIII",
                                                                     cut_data)
        elif self.block_id == 0x43:
            # TCPACPUH, CPU microcode. Can't handle properly yet.
            assert(self.block_len == 0xA3)
            cut_data = data[:0xA3]
            print(len(cut_data))
            self.block_num, self.block_id, self.block_len, self.sha1sum, self.date, \
            self.cpuid, self.unknown1 = struct.unpack("<BBB20sII132s",
                                                      cut_data)
        else:
            print("Unknown ID {:x}".format(self.block_id))

if len(sys.argv) <= 1:
    print("USAGE: ", sys.argv[0], "FILE")
    sys.exit(1)

ifile = open(sys.argv[1], "rb")
# Skip 0x520000 zero bytes
assert(ifile.seek(0x520000) == 0x520000)
ifile = ifile.read()

data = ifile

while find_tcpa_block(data):
    tcpa_block = find_tcpa_block(data)
    tcpa_block_name = tcpa_block[:8].decode()
    print("Found", tcpa_block_name, "block")
    if tcpa_block_name == 'TCPACPUH':
        print("Can't handle", tcpa_block_name, "yet, skipping")
        next_ibmsecur = data.find(b"IBMSECUR")
        data = data[next_ibmsecur + TCPA_HEADER_LEN:]
        continue
    # Cutting out header
    tcpa_block = tcpa_block[TCPA_HEADER_LEN:]
    for tcpa_offset in range(0, len(tcpa_block), TCPA_BLOCK_LEN):
        tcpa_current = tcpa_block[tcpa_offset:tcpa_offset+1024]
        tcpa_data = TCPABlock(tcpa_current)
        if not hasattr(tcpa_data, 'sha1sum'):
            print("End reached")
            continue
        tcpa_data_sha1 = binascii.hexlify(tcpa_data.sha1sum).decode()
        error_str = ''
        if hasattr(tcpa_data, 'offset') and hasattr(tcpa_data, 'length') and \
                                tcpa_data.offset and tcpa_data.length:
            tcpa_data_raw = ifile[tcpa_data.offset:tcpa_data.offset+tcpa_data.length]
            sha1 = hashlib.sha1()
            sha1.update(tcpa_data_raw)
            sha1_current = sha1.hexdigest()
            if tcpa_data_sha1 != sha1_current:
                error_str = "| Hash mismatch!! Valid: {}".format(sha1_current)
        else:
            error_str = "| offset={}, length={}, flags={}, frag={}".format(tcpa_data.offset,
                                                                 tcpa_data.length,
                                                                 tcpa_data.flags,
                                                                 tcpa_data.fragmentno)
        print("{:>8}".format(tcpa_data.block_num),
              binascii.hexlify(tcpa_data.sha1sum).decode(), error_str)
        error_str = ''
    next_ibmsecur = data.find(b"IBMSECUR")
    data = data[next_ibmsecur + TCPA_HEADER_LEN:]
