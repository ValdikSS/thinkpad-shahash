#!/usr/bin/env python3
import sys
import os
import binascii
import hashlib
import struct
import argparse
from subprocess import Popen, PIPE

ZERO_BLOCK = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF"
PUBKEY = b"\xFF\x12\x04\x00"
TCPA_BLOCK_LEN = 39
TCPA_HEADER_LEN = 29
PUBKEY_FILE = "my_key_pub"
PRIVKEY_FILE = "my_key.pem"
OPENSSL = "openssl"

sig_replacements = []

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

def replace_pubkey(data, newpubkey):
    pubkey = data.find(PUBKEY)
    if not pubkey:
        return None
    pubkey = pubkey-1+len(PUBKEY)
    assert(len(newpubkey) == 129)
    return data[:pubkey] + newpubkey + data[pubkey+129:]

def replace_checksum(data, oldsum, newsum):
    oldsum_offset = data.find(oldsum)
    if not oldsum:
        return None
    assert(len(newsum) == 20)
    assert(len(oldsum) == 20)
    return data[:oldsum_offset] + newsum + data[oldsum_offset+20:]

def replace_data(data, offset, replacewith):
    return data[:offset] + replacewith + data[offset+len(replacewith):]

def save_data(name, data):
    with open(name, 'wb') as f:
        f.write(data)

def sign_data(input_data):
    out = Popen([OPENSSL,"rsautl","-inkey",os.path.join(os.path.dirname(os.path.realpath(__file__)), PRIVKEY_FILE),"-sign","-raw"],
                stdout=PIPE, stdin=PIPE)
    out = out.communicate(input=input_data)[0]
    return out

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Lenovo Thinkpad *220 firmware hash calculator.')
    parser.add_argument('fw_file', help='Firmware FL1 file')
    parser.add_argument('--output', help='Update checksums in the firmware file and re-sign them with my_key_pub')
    args = parser.parse_args()

    ifile = open(args.fw_file, "rb")
    fullfile = ifile.read()
    # Skip 0x520000 zero bytes
    assert(ifile.seek(0x520000) == 0x520000)
    ifile = ifile.read()

    data = ifile

    if args.output:
        fullfile = replace_pubkey(fullfile, open(os.path.join(os.path.dirname(os.path.realpath(__file__)), PUBKEY_FILE), "rb").read())

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
                    if args.output:
                        sig_replacements.append([tcpa_data.sha1sum, sha1.digest()])
            else:
                error_str = "| offset={}, length={}, flags={}, frag={}".format(tcpa_data.offset,
                                                                    tcpa_data.length,
                                                                    tcpa_data.flags,
                                                                    tcpa_data.fragmentno)
            print("{:>8}".format(tcpa_data.block_num),
                binascii.hexlify(tcpa_data.sha1sum).decode(), error_str)
            error_str = ''
        if args.output:
            # Search for tcpa_block in fullfile.
            # tcpa_offset points to the latest non-zero block right now
            fullfile_tcpablock_offset = fullfile.find(tcpa_block)
            assert(fullfile_tcpablock_offset != -1)
            fullfile_tcpablock_offset -= TCPA_HEADER_LEN
            # check if we're really reached TCPA header
            assert(fullfile[fullfile_tcpablock_offset:fullfile_tcpablock_offset+4] ==\
                b"TCPA")
            fullfile_tcpablock_signature_offset = fullfile_tcpablock_offset + TCPA_HEADER_LEN +\
                tcpa_offset + TCPA_BLOCK_LEN # skip zero block

            # replace checksums from the queue
            for replacement in sig_replacements:
                fullfile = replace_checksum(fullfile, replacement[0], replacement[1])
            sig_replacements = []

            # are we really reached signature offset?
            assert(fullfile[fullfile_tcpablock_signature_offset:fullfile_tcpablock_signature_offset+3] ==\
                b"\xFF\xFF\x83")
            # if so, let's recompute TCPA block hash and re-sign it
            newhash = hashlib.sha1()
            newhash.update(fullfile[fullfile_tcpablock_offset:fullfile_tcpablock_signature_offset])
            newhash = newhash.digest()
            fullfile_tcpablock_signature_offset += 3 # skip FF FF 83
            data_to_sign = bytearray(108) + newhash # 128 bytes
            signed_data = sign_data(data_to_sign)
            assert(len(signed_data) == 128)
            fullfile = replace_data(fullfile, fullfile_tcpablock_signature_offset, signed_data)
            print("Re-signed hash", binascii.hexlify(newhash).decode())

        next_ibmsecur = data.find(b"IBMSECUR")
        data = data[next_ibmsecur + TCPA_HEADER_LEN:]

    if args.output:
        save_data(args.output, fullfile)
