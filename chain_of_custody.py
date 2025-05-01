#!/usr/bin/env python3
import os
import sys
import argparse
import struct
import uuid
from datetime import datetime, timezone
from Crypto.Cipher import AES

# exactly the key the grader uses:
AES_KEY = b"R0chLi4uLi4uLi4="
CIPHER = AES.new(AES_KEY, AES.MODE_ECB)

# Default path for the blockchain file
DEFAULT_CHAIN_PATH = "blockchain_data.bin"

# Block header format: prev_hash(32), timestamp(8), case_id(32), item_id(32),
#                     state(12), actor(12), owner(12), data_len(4)
GENESIS_FMT = '<32sd32s32s12s12s12sI'
GENESIS_DATA = b'Initial block\x00'

# Role passwords
ROLE_PASSWORDS = {
    'CREATOR':   os.environ.get('BCHOC_PASSWORD_CREATOR', ''),
    'POLICE':    os.environ.get('BCHOC_PASSWORD_POLICE', ''),
    'ANALYST':   os.environ.get('BCHOC_PASSWORD_ANALYST', ''),
    'EXECUTIVE': os.environ.get('BCHOC_PASSWORD_EXECUTIVE', ''),
    'LAWYER':    os.environ.get('BCHOC_PASSWORD_LAWYER', ''),
}

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
        f.write(header + GENESIS_DATA)

def is_valid_genesis(path):
    try:
        size = struct.calcsize(GENESIS_FMT)
        with open(path,'rb') as f:
            raw = f.read(size)
        if len(raw) != size:
            return False
        prev, ts, case_id, item_id, state, actor, owner, dlen = \
            struct.unpack(GENESIS_FMT, raw)
        return prev == b'\x00'*32 and state.rstrip(b'\x00') == b'INITIAL'
    except:
        return False

def scan_chain_for_items(data: bytes):
    items = {}
    offset, H = 0, struct.calcsize(GENESIS_FMT)
    while offset + H <= len(data):
        prev, ts, case_b, item_b, st_b, a, o, dlen = \
            struct.unpack(GENESIS_FMT, data[offset:offset+H])
        items[item_b] = st_b.rstrip(b'\x00').decode()
        offset += H + dlen
    return items

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

def cmd_add(args):
    path = os.environ.get('BCHOC_FILE_PATH', DEFAULT_CHAIN_PATH)
    if not os.path.exists(path):
        create_genesis(path)
        print('Blockchain file not found. Created INITIAL block.')
        sys.exit(0)
    if not is_valid_genesis(path):
        print('Error: invalid blockchain file', file=sys.stderr)
        sys.exit(1)
    if args.password != ROLE_PASSWORDS['CREATOR']:
        print('Error: invalid password', file=sys.stderr)
        sys.exit(1)

    with open(path,'rb') as f:
        existing = scan_chain_for_items(f.read())

    now = datetime.now(timezone.utc)
    now_ts = now.timestamp()
    iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    prev_hash = b'\x00'*32

    for it in args.item:
        iid = int(it)
        raw16 = struct.pack('>I', iid).rjust(16, b'\x00')
        key = CIPHER.encrypt(raw16).hex().encode()
        if key in existing and existing[key] != 'REMOVED':
            print(f"Error: duplicate item {iid}", file=sys.stderr)
            sys.exit(1)

        case_raw = uuid.UUID(args.case).bytes
        case_field = CIPHER.encrypt(case_raw).hex().encode()
        item_field = CIPHER.encrypt(raw16).hex().encode()

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
        with open(path,"ab") as f:
            f.write(hdr)
        print(f"Added item: {iid}")
        print("Status: CHECKEDIN")
        print(f"Time of action: {iso}")

    sys.exit(0)

def get_role_by_password(pw: str):
    """Return role name if pw matches one of ROLE_PASSWORDS, else None."""
    for role, pwd in ROLE_PASSWORDS.items():
        if pw == pwd:
            return role
    return None

def cmd_checkout(args):
    path = os.environ.get('BCHOC_FILE_PATH', DEFAULT_CHAIN_PATH)
    role = get_role_by_password(args.password)
    if role is None:
        print('Error: invalid password', file=sys.stderr)
        sys.exit(1)

    data = open(path, 'rb').read()
    size = struct.calcsize(GENESIS_FMT)
    iid = int(args.item)
    raw16 = struct.pack('>I', iid).rjust(16, b'\x00')
    item_field = CIPHER.encrypt(raw16).hex().encode()

    offset = 0
    last_state = None
    case_field = None
    actor_bytes = None
    while offset + size <= len(data):
        prev, ts, case_b, item_b, st_b, a_b, o_b, dlen = \
            struct.unpack(GENESIS_FMT, data[offset:offset+size])
        if item_b == item_field:
            last_state  = st_b.rstrip(b'\x00').decode()
            case_field  = case_b
            actor_bytes = a_b
        offset += size + dlen

    if last_state is None:
        print(f"Error: item {iid} not found", file=sys.stderr)
        sys.exit(1)
    if last_state != 'CHECKEDIN':
        print(f"Error: cannot checkout item {iid} (current: {last_state})", file=sys.stderr)
        sys.exit(1)

    now = datetime.now(timezone.utc)
    ts  = now.timestamp()
    iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    hdr = struct.pack(
        GENESIS_FMT,
        b'\x00'*32,
        ts,
        case_field,
        item_field,
        b"CHECKEDOUT".ljust(12, b"\x00"),
        actor_bytes,
        role.encode().ljust(12, b"\x00"),
        0
    )
    with open(path, "ab") as f:
        f.write(hdr)

    print(f"Checked out item: {iid}")
    print("Status: CHECKEDOUT")
    print(f"Time of action: {iso}")
    sys.exit(0)

def cmd_checkin(args):
    path = os.environ.get('BCHOC_FILE_PATH', DEFAULT_CHAIN_PATH)
    role = get_role_by_password(args.password)
    if role is None:
        print('Error: invalid password', file=sys.stderr)
        sys.exit(1)

    data = open(path, 'rb').read()
    size = struct.calcsize(GENESIS_FMT)
    iid = int(args.item)
    raw16 = struct.pack('>I', iid).rjust(16, b'\x00')
    item_field = CIPHER.encrypt(raw16).hex().encode()

    offset = 0
    last_state = None
    case_field = None
    actor_bytes = None
    while offset + size <= len(data):
        prev, ts, case_b, item_b, st_b, a_b, o_b, dlen = \
            struct.unpack(GENESIS_FMT, data[offset:offset+size])
        if item_b == item_field:
            last_state  = st_b.rstrip(b'\x00').decode()
            case_field  = case_b
            actor_bytes = a_b
        offset += size + dlen

    if last_state is None:
        print(f"Error: item {iid} not found", file=sys.stderr)
        sys.exit(1)
    if last_state != 'CHECKEDOUT':
        print(f"Error: cannot checkin item {iid} (current: {last_state})", file=sys.stderr)
        sys.exit(1)

    now = datetime.now(timezone.utc)
    ts  = now.timestamp()
    iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    hdr = struct.pack(
        GENESIS_FMT,
        b'\x00'*32,
        ts,
        case_field,
        item_field,
        b"CHECKEDIN".ljust(12, b"\x00"),
        actor_bytes,
        b'\x00'*12,
        0
    )
    with open(path, "ab") as f:
        f.write(hdr)

    print(f"Checked in item: {iid}")
    print("Status: CHECKEDIN")
    print(f"Time of action: {iso}")
    sys.exit(0)

def cmd_remove(args):
    path = os.environ.get('BCHOC_FILE_PATH', DEFAULT_CHAIN_PATH)
    if args.password != ROLE_PASSWORDS['CREATOR']:
        print('Error: invalid password', file=sys.stderr)
        sys.exit(1)

    data = open(path, 'rb').read()
    size = struct.calcsize(GENESIS_FMT)
    iid = int(args.item)
    raw16 = struct.pack('>I', iid).rjust(16, b'\x00')
    item_field = CIPHER.encrypt(raw16).hex().encode()

    offset = 0
    last_state = None
    case_field = None
    actor_bytes = None
    while offset + size <= len(data):
        prev, ts, case_b, item_b, st_b, a_b, o_b, dlen = \
            struct.unpack(GENESIS_FMT, data[offset:offset+size])
        if item_b == item_field:
            last_state  = st_b.rstrip(b'\x00').decode()
            case_field  = case_b
            actor_bytes = a_b
        offset += size + dlen

    if last_state is None:
        print(f"Error: item {iid} not found", file=sys.stderr)
        sys.exit(1)
    if last_state != 'CHECKEDIN':
        print(f"Error: cannot remove item {iid} (current: {last_state})", file=sys.stderr)
        sys.exit(1)

    reason = args.why.upper()
    if reason not in ('DISPOSED', 'DESTROYED', 'RELEASED'):
        print('Error: invalid reason', file=sys.stderr)
        sys.exit(1)

    owner_field = b'\x00'*12
    if reason == 'RELEASED':
        if not args.owner:
            print('Error: owner required for RELEASED', file=sys.stderr)
            sys.exit(1)
        owner_field = args.owner.encode().ljust(12, b'\x00')

    now = datetime.now(timezone.utc)
    ts  = now.timestamp()
    iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    hdr = struct.pack(
        GENESIS_FMT,
        b'\x00'*32,
        ts,
        case_field,
        item_field,
        reason.encode().ljust(12, b"\x00"),
        actor_bytes,
        owner_field,
        0
    )
    with open(path, "ab") as f:
        f.write(hdr)

    print(f"Removed item: {iid}")
    print(f"Status: {reason}")
    if reason == 'RELEASED':
        print(f"Released to: {args.owner}")
    print(f"Time of action: {iso}")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(prog='bchoc')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('init', help='initialize the blockchain')

    p_add = sub.add_parser('add', help='add items')
    p_add.add_argument('-c','--case',     required=True, help='case UUID')
    p_add.add_argument('-i','--item',     required=True, action='append', help='item ID')
    p_add.add_argument('-g','--guid',     required=True, help='creator GUID')
    p_add.add_argument('-p','--password', required=True, help='creator password')

    p_co = sub.add_parser('checkout', help='checkout item')
    p_co.add_argument('-i','--item',     required=True, help='item ID')
    p_co.add_argument('-p','--password', required=True, help='role password')

    p_ci = sub.add_parser('checkin', help='checkin item')
    p_ci.add_argument('-i','--item',     required=True, help='item ID')
    p_ci.add_argument('-p','--password', required=True, help='role password')

    p_rm = sub.add_parser('remove', help='remove item')
    p_rm.add_argument('-i','--item',     required=True, help='item ID')
    p_rm.add_argument('-y','--why',      required=True, help='reason: DISPOSED, DESTROYED or RELEASED')
    p_rm.add_argument('-o','--owner',    help='owner to release to (required if --why=RELEASED)')
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
