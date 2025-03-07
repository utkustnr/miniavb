#!/usr/bin/env python3
import struct
import hashlib
import sys

class AvbVBMetaHeader:
    SIZE = 256
    FORMAT = (
        '!4s'    # magic (4)
        '2L'     # required versions (4+4)
        '2Q'     # auth/aux block sizes (8+8)
        'L'      # algorithm type (4)
        '2Q'     # hash offset/size (8+8)
        '2Q'     # signature offset/size (8+8)
        '2Q'     # public_key offset/size (8+8)
        '2Q'     # public_key_metadata offset/size (8+8)
        '2Q'     # descriptors offset/size (8+8)  # THIS WAS MISSING
        'Q'      # rollback index (8)
        'L'      # flags (4)
        'L'      # rollback index location (4)
        '47s'    # release string (47)
        'x'      # padding (1)
        '80x'    # reserved (80)
    )

    def __init__(self, data):
        fields = struct.unpack(self.FORMAT, data)
        self.magic = fields[0]
        self.version_major = fields[1]
        self.version_minor = fields[2]
        self.auth_size = fields[3]
        self.aux_size = fields[4]
        self.algorithm = fields[5]
        self.pubkey_offset = fields[10]
        self.pubkey_size = fields[11]
        self.descriptors_offset = fields[14]
        self.descriptors_size = fields[15]
        self.rollback_index = fields[16]
        self.flags = fields[17]
        self.rollback_location = fields[18]
        self.release_str = fields[19].split(b'\x00')[0].decode()

ALGORITHMS = {
    1: 'SHA256_RSA2048',
    2: 'SHA256_RSA4096',
    3: 'SHA256_RSA8192',
    4: 'SHA512_RSA2048',
    5: 'SHA512_RSA4096',
    6: 'SHA512_RSA8192'}

def parse_vbmeta(file_path):
    with open(file_path, 'rb') as f:
        header_data = f.read(256)
        header = AvbVBMetaHeader(header_data)
        f.seek(256 + header.auth_size) # Read auxiliary data
        aux_data = f.read(header.aux_size)
        pubkey = aux_data[header.pubkey_offset:header.pubkey_offset+header.pubkey_size] # Extract public key
        # Parse descriptors
        props = []
        if header.descriptors_size > 0:
            desc_data = aux_data[header.descriptors_offset:header.descriptors_offset+header.descriptors_size]
            pos = 0
            while pos + 16 <= len(desc_data):
                tag, size = struct.unpack_from('!QQ', desc_data, pos)
                pos += 16
                if tag != 0:  # Only handle property descriptors
                    pos += size
                    continue
                key_size, val_size = struct.unpack_from('!QQ', desc_data, pos)
                key = desc_data[pos+16:pos+16+key_size].decode()
                val = desc_data[pos+16+key_size+1:pos+16+key_size+1+val_size].decode()
                props.append((key, val))
                pos += size
        return header, pubkey, props

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <vbmeta.img / path/to/block>")
        sys.exit(1)
    try:
        h, key, props = parse_vbmeta(sys.argv[1])
        print(f"Minimum libavb version:   {h.version_major}.{h.version_minor}")
        print(f"Header Block:             {h.SIZE} bytes")
        print(f"Authentication Block:     {h.auth_size} bytes")
        print(f"Auxiliary Block:          {h.aux_size} bytes")
        print(f"Total Block Size:         {h.SIZE + h.auth_size + h.aux_size} bytes")
        print(f"Public key (sha1):        {hashlib.sha1(key).hexdigest()}")
        print(f"Algorithm:                {ALGORITHMS.get(h.algorithm, 'UNKNOWN')}")
        print(f"Rollback Index:           {h.rollback_index}")
        print(f"Flags:                    {h.flags}")
        print(f"Rollback Index Location:  {h.rollback_location}")
        print(f"Release String:           {h.release_str}")
        for k, v in props:
            print(f"    Props: {k} -> '{v}'")
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
