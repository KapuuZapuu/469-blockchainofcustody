#!/usr/bin/env python3
import os
import sys
import argparse
import struct
import time
import uuid
from datetime import datetime, timezone

# Default path, overridden by BCHOC_FILE_PATH
DEFAULT_CHAIN_PATH = "blockchain_data.bin"

# Block header format: prev_hash, timestamp, case_id, item_id, state, creator, owner, data_length
GENESIS_FMT = '<32sd32s32s12s12s12sI'
GENESIS_DATA = b'Initial block\x00'  # 14-byte payload for genesis

# Map roles to environment-stored passwords
ROLE_PASSWORDS = {
    'POLICE':    os.environ.get('BCHOC_PASSWORD_POLICE',''),
    'ANALYST':   os.environ.get('BCHOC_PASSWORD_ANALYST',''),
    'EXECUTIVE': os.environ.get('BCHOC_PASSWORD_EXECUTIVE',''),
    'CREATOR':   os.environ.get('BCHOC_PASSWORD_CREATOR',''),
}

# Create the genesis block
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

# Validate that the file contains a proper genesis block
def is_valid_genesis(path):
    try:
        size = struct.calcsize(GENESIS_FMT)
        with open(path, 'rb') as f:
            raw = f.read(size)
        if len(raw) != size:
            return False
        prev, ts, case_id, item_id, state, creator, owner, dlen = struct.unpack(GENESIS_FMT, raw)
        if prev != b'\x00'*32:
            return False
        if state.rstrip(b'\x00') != b'INITIAL':
            return False
        return True
    except:
        return False

# Read all blocks and track last state per item_id
def scan_chain_for_items(data: bytes):
    items = {}
    offset = 0
    size = struct.calcsize(GENESIS_FMT)
    while offset + size <= len(data):
        header = data[offset:offset+size]
        prev, ts, case_bytes, item_bytes, state_bytes, creator_bytes, owner_bytes, dlen = struct.unpack(GENESIS_FMT, header)
        iid = struct.unpack('<I', item_bytes[:4])[0]
        state = state_bytes.rstrip(b'\x00').decode()
        items[iid] = state
        offset += size + dlen
    return items

# Build a new block header (no payload) storing plaintext IDs
def build_block_header(prev_hash: bytes, timestamp: float, case_uuid: uuid.UUID, item_id: int, state: str, actor: str) -> bytes:
    case_field = case_uuid.bytes.ljust(32, b'\x00')
    item_field = struct.pack('<I', item_id).ljust(32, b'\x00')
    state_field = state.encode().ljust(12, b'\x00')
    actor_field = actor.encode().ljust(12, b'\x00')
    owner_field = b'\x00'*12
    return struct.pack(
        GENESIS_FMT,
        prev_hash,
        float(timestamp),
        case_field,
        item_field,
        state_field,
        actor_field,
        owner_field,
        0
    )

# Get prev_hash as SHA-256 of the last block's bytes
def hash_last_block(data: bytes) -> bytes:
    # For simplicity, hash the entire chain up to this point
    from hashlib import sha256
    return sha256(data).digest()

# Handle `init` command
def cmd_init(args):
    if len(sys.argv) != 2:
        print("usage: bchoc init", file=sys.stderr)
        sys.exit(1)
    path = os.environ.get('BCHOC_FILE_PATH', DEFAULT_CHAIN_PATH)
    if not os.path.exists(path):
        create_genesis(path)
        print("Blockchain file not found. Created INITIAL block.")
        sys.exit(0)
    if is_valid_genesis(path):
        print("Blockchain file found with INITIAL block.")
        sys.exit(0)
    print("Error: invalid blockchain file", file=sys.stderr)
    sys.exit(1)

# Handle `add` command
def cmd_add(args):
    path = os.environ.get('BCHOC_FILE_PATH', DEFAULT_CHAIN_PATH)
    # auto-init if missing
    if not os.path.exists(path):
        create_genesis(path)
        print("Blockchain file not found. Created INITIAL block.")
        sys.exit(0)
    # verify genesis
    if not is_valid_genesis(path):
        print("Error: invalid blockchain file", file=sys.stderr)
        sys.exit(1)
    # password check
    if args.password != ROLE_PASSWORDS['CREATOR']:
        print("Error: invalid password", file=sys.stderr)
        sys.exit(1)
    # load chain and scan items
    with open(path, 'rb') as f:
        data = f.read()
    existing = scan_chain_for_items(data)
    # detect duplicates
    for it in args.item:
        iid = int(it)
        if iid in existing and existing[iid] != 'REMOVED':
            print(f"Error: duplicate item {iid}", file=sys.stderr)
            sys.exit(1)
    # append blocks
    prev = hash_last_block(data)
    for it in args.item:
        iid = int(it)
        hdr = build_block_header(prev, time.time(), uuid.UUID(args.case), iid, 'CHECKEDIN', 'CREATOR')
        with open(path, 'ab') as f:
            f.write(hdr)
        print(f"> Added item: {iid}")
        print(f"> Status: CHECKEDIN")
        # timestamp in UTC with Z
        now = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
        print(f"> Time of action: {now}")
        prev = hash_last_block(hdr)
    sys.exit(0)

# Handle `checkout` command (scaffold)
def cmd_checkout(args):
    # TODO: implement checkout logic
    sys.exit(0)

# Handle `checkin` command (scaffold)
def cmd_checkin(args):
    # TODO: implement checkin logic
    sys.exit(0)

# Handle `remove` command (scaffold)
def cmd_remove(args):
    # TODO: implement remove logic
    sys.exit(0)

# CLI entry point
def main():
    parser = argparse.ArgumentParser(prog="bchoc")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser('init', help='initialize the blockchain')
    p =     sub.add_parser('init', help='initialize the blockchain')
    # --- ADD ---
    p_add = sub.add_parser('add', help='add one or more items to a case')
    p_add.add_argument('-c','--case', required=True, help='case UUID')
    p_add.add_argument('-i','--item', required=True, action='append', help='item ID (can be repeated)')
    p_add.add_argument('-p','--password','-g', required=True, dest='password', help='creator password')

    # --- CHECKOUT ---
    p_co = sub.add_parser('checkout', help='check out an item')
    p_co.add_argument('-i','--item', required=True, help='item ID')
    p_co.add_argument('-p','--password', required=True, help='police password')

    # --- CHECKIN ---
    p_ci = sub.add_parser('checkin', help='check in an item')
    p_ci.add_argument('-i','--item', required=True, help='item ID')
    p_ci.add_argument('-p','--password', required=True, help='analyst/lawyer/executive password')

    # --- REMOVE ---
    p_rm = sub.add_parser('remove', help='remove an item from chain')
    p_rm.add_argument('-i','--item', required=True, help='item ID')
    p_rm.add_argument('-p','--password', required=True, help='creator password')

    args = parser.parse_args()
    if args.command == 'init':
        cmd_init(args)
    elif args.command == 'add':
        cmd_add(args)
    elif args.command == 'checkout':
        cmd_checkout(args)
    elif args.command == 'checkin':
        cmd_checkin(args)
    elif args.command == 'remove':
        cmd_remove(args)
    else:
        parser.print_usage(sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
