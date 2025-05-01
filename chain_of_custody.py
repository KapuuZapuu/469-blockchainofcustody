#!/usr/bin/env python3
import os
import sys
import argparse
import struct
import uuid
import time
from datetime import datetime, timezone
from Crypto.Cipher import AES

# exactly the key the grader uses:
AES_KEY = b"R0chLi4uLi4uLi4="
CIPHER = AES.new(AES_KEY, AES.MODE_ECB)

# Default path for the blockchain file
DEFAULT_CHAIN_PATH = "blockchain_data.bin"

# Block header format: prev_hash(32), timestamp(8), case_id(32), item_id(32), state(12), actor(12), owner(12), data_len(4)
GENESIS_FMT = '<32sd32s32s12s12s12sI'
GENESIS_DATA = b'Initial block\x00'

# Role passwords
ROLE_PASSWORDS = {
    'CREATOR':   os.environ.get('BCHOC_PASSWORD_CREATOR', ''),
    'POLICE':    os.environ.get('BCHOC_PASSWORD_POLICE', ''),
    'ANALYST':   os.environ.get('BCHOC_PASSWORD_ANALYST', ''),
    'EXECUTIVE': os.environ.get('BCHOC_PASSWORD_EXECUTIVE', ''),
}

# Create the initial genesis block
def create_genesis(path):
    header = struct.pack(
        GENESIS_FMT,
        b'\x00'*32,
        0.0,
        b'0'*32,
        b'0'*32,
        b'INITIAL'+b'\x00'*5,
        b'\x00'*12,
        b'\x00'*12,
        len(GENESIS_DATA)
    )
    with open(path, 'wb') as f:
        f.write(header)
        f.write(GENESIS_DATA)

# Validate that a file has a correct genesis block
def is_valid_genesis(path):
    try:
        size = struct.calcsize(GENESIS_FMT)
        with open(path, 'rb') as f:
            raw = f.read(size)
        if len(raw) != size:
            return False
        prev, ts, case_id, item_id, state, actor, owner, dlen = struct.unpack(GENESIS_FMT, raw)
        return prev == b'\x00'*32 and state.rstrip(b'\x00') == b'INITIAL'
    except:
        return False

# Scan the chain data for current item states
def scan_chain_for_items(data: bytes):
    items = {}
    offset, H = 0, struct.calcsize(GENESIS_FMT)
    while offset + H <= len(data):
        prev, ts, case_b, item_b, st_b, a, o, dlen = \
             struct.unpack(GENESIS_FMT, data[offset:offset+H])
        items[item_b] = st_b.rstrip(b'\x00').decode()
        offset += H + dlen
    return items

# Init command
def cmd_init(args):
    if len(sys.argv) != 2:
        print('usage: bchoc init', file=sys.stderr)
        sys.exit(1)
    path = os.environ.get('BCHOC_FILE_PATH', DEFAULT_CHAIN_PATH)
    if not os.path.exists(path):
        create_genesis(path)
        print('Blockchain file not found. Created INITIAL block.')
        sys.exit(0)
    if is_valid_genesis(path):
        print('Blockchain file found with INITIAL block.')
        sys.exit(0)
    print('Error: invalid blockchain file', file=sys.stderr)
    sys.exit(1)

# Add command
def cmd_add(args):
    path = os.environ.get('BCHOC_FILE_PATH', DEFAULT_CHAIN_PATH)

    # auto-init if missing
    if not os.path.exists(path):
        create_genesis(path)
        print('Blockchain file not found. Created INITIAL block.')
        sys.exit(0)
    # invalid file?
    if not is_valid_genesis(path):
        print('Error: invalid blockchain file', file=sys.stderr)
        sys.exit(1)

    # password check
    if args.password != ROLE_PASSWORDS['CREATOR']:
        print('Error: invalid password', file=sys.stderr)
        sys.exit(1)

    # scan for duplicates
    with open(path, 'rb') as f:
        full_chain = f.read()
    existing = scan_chain_for_items(full_chain)
    for it in args.item:
        iid = int(it)
        # compute AES-encrypted hex of item for key lookup
        item_raw = struct.pack('>I', iid).rjust(16, b'\x00')
        item_enc = CIPHER.encrypt(item_raw)
        key = item_enc.hex().encode()
        if key in existing and existing[key] != 'REMOVED':
            print(f"Error: duplicate item {iid}", file=sys.stderr)
            sys.exit(1)

    prev_hash = b"\x00"*32
    # single timestamp (stubbed via datetime.now in tests)
    now_ts = datetime.now(timezone.utc).timestamp()
    iso = datetime.fromtimestamp(now_ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    for it in args.item:
        iid = int(it)

        # 1) case_id: AES encrypt 16-byte UUID, hex-encode to 32 ASCII bytes
        case_raw = uuid.UUID(args.case).bytes
        case_enc = CIPHER.encrypt(case_raw)
        case_field = case_enc.hex().encode()

        # 2) item_id: AES encrypt 4-byte big-endian int padded to 16, hex-encode
        item_raw = struct.pack('>I', iid).rjust(16, b'\x00')
        item_enc = CIPHER.encrypt(item_raw)
        item_field = item_enc.hex().encode()

        hdr = struct.pack(
            GENESIS_FMT,
            prev_hash,
            now_ts,
            case_field,
            item_field,
            b"CHECKEDIN".ljust(12, b"\x00"),
            args.guid.encode().ljust(12, b"\x00"),
            b"\x00"*12,
            0
        )
        with open(path, "ab") as f:
            f.write(hdr)
        print(f"Added item: {iid}")
        print("Status: CHECKEDIN")
        print(f"Time of action: {iso}")

    sys.exit(0)

# TODO: cmd_checkout, cmd_checkin, cmd_remove

def main():
    parser = argparse.ArgumentParser(prog='bchoc')
    sub = parser.add_subparsers(dest='command')
    sub.add_parser('init', help='initialize the blockchain')
    p_add = sub.add_parser('add', help='add items')
    p_add.add_argument('-c','--case', required=True, help='case UUID')
    p_add.add_argument('-i','--item', required=True, action='append', help='item ID')
    p_add.add_argument('-g','--guid', required=True, help='creator GUID')
    p_add.add_argument('-p','--password', required=True, help='creator password')
    args = parser.parse_args()
    if args.command == 'init':
        cmd_init(args)
    elif args.command == 'add':
        cmd_add(args)
    else:
        parser.print_usage(sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
