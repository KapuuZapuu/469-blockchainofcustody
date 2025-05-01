#!/usr/bin/env python3
import os
import sys
import argparse
import struct
import time
import uuid
from datetime import datetime, timezone
from Crypto.Cipher import AES
from hashlib import sha256

# Map roles to environment-stored passwords
ROLE_PASSWORDS = {
    'POLICE':    os.environ.get('BCHOC_PASSWORD_POLICE',''),
    'ANALYST':   os.environ.get('BCHOC_PASSWORD_ANALYST',''),
    'EXECUTIVE': os.environ.get('BCHOC_PASSWORD_EXECUTIVE',''),
    'CREATOR':   os.environ.get('BCHOC_PASSWORD_CREATOR',''),
}

# Default path, overridden by BCHOC_FILE_PATH
DEFAULT_CHAIN_PATH = "blockchain_data.bin"

# Block header format: prev_hash, timestamp, case_id, item_id, state, creator, owner, data_length
GENESIS_FMT = '<32sd32s32s12s12s12sI'
GENESIS_DATA = b'Initial block\x00'  # 14 bytes

# AES key for encrypting IDs (used in future commands)
AES_KEY = b"R0chLi4uLi4uLi4="

# PKCS#7 padding stub (to be used when encrypting IDs)
def pad_bytes(b: bytes) -> bytes:
    pad_len = AES.block_size - (len(b) % AES.block_size)
    return b + bytes([pad_len]) * pad_len

# Encrypt and pad stub
def encrypt_and_pad(raw: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad_bytes(raw))

# Create the genesis block
def create_genesis(path):
    header = struct.pack(
        GENESIS_FMT,
        b'\x00' * 32,
        0.0,
        b'0' * 32,
        b'0' * 32,
        b'INITIAL' + b'\x00' * 5,
        b'\x00' * 12,
        b'\x00' * 12,
        len(GENESIS_DATA),
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
        prev_hash, ts, case_id, item_id, state, creator, owner, dlen = \
            struct.unpack(GENESIS_FMT, raw)
        if prev_hash != b'\x00' * 32:
            return False
        if state.rstrip(b'\x00') != b'INITIAL':
            return False
        return True
    except Exception:
        return False

# Handle `init` command
def cmd_init(args):
    # disallow any extra args
    if len(sys.argv) != 2:
        print("usage: bchoc init", file=sys.stderr)
        sys.exit(1)

    path = os.environ.get("BCHOC_FILE_PATH", DEFAULT_CHAIN_PATH)

    # no file → create it
    if not os.path.exists(path):
        create_genesis(path)
        print("Blockchain file not found. Created INITIAL block.")
        sys.exit(0)

    # file exists → validate
    if is_valid_genesis(path):
        print("Blockchain file found with INITIAL block.")
        sys.exit(0)

    # invalid file → error
    print("Error: invalid blockchain file", file=sys.stderr)
    sys.exit(1)

# Handle `add` command (scaffold)
def cmd_add(args):
    """
    Add one or more items to a case.
    TODO: implement:
      - auto-init if no chain exists
      - password check against ROLE_PASSWORDS['CREATOR']
      - scan existing items to prevent duplicates
      - append new block(s) with CHECKEDIN state
    """
    # Example scaffold:
    # path = os.environ.get("BCHOC_FILE_PATH", DEFAULT_CHAIN_PATH)
    # if not os.path.exists(path): create_genesis(path); print(...); sys.exit(0)
    # ... password check
    # ... scan chain
    # ... build and append blocks
    sys.exit(0)

# Handle `checkout` command (scaffold)
def cmd_checkout(args):
    """
    Check out an item.
    TODO: implement:
      - validate chain
      - password check ROLE_PASSWORDS['POLICE']
      - ensure item exists and is CHECKEDIN
      - append new block with CHECKEDOUT state
    """
    sys.exit(0)

# Handle `checkin` command (scaffold)
def cmd_checkin(args):
    """
    Check in an item (after checkout).
    TODO: implement:
      - validate chain
      - password check ROLE_PASSWORDS['ANALYST'] or ['LAWYER'] or ['EXECUTIVE']
      - ensure item exists and is CHECKEDOUT
      - append new block with CHECKEDIN state
    """
    sys.exit(0)

# Handle `remove` command (scaffold)
def cmd_remove(args):
    """
    Remove an item from the chain.
    TODO: implement:
      - validate chain
      - password check ROLE_PASSWORDS['CREATOR']
      - ensure item exists
      - append new block with REMOVED state
    """
    sys.exit(0)

# CLI entry point
def main():
    parser = argparse.ArgumentParser(prog="bchoc")
    sub = parser.add_subparsers(dest="command")

    # init
    sub.add_parser("init", help="initialize the blockchain")

    # add
    p_add = sub.add_parser("add", help="add one or more items to a case")
    p_add.add_argument("-c","--case", required=True, help="case UUID")
    p_add.add_argument("-i","--item", required=True, action="append", help="item ID (can be repeated)")
    p_add.add_argument("-p","--password","-g", required=True, dest="password", help="creator password")

    # checkout
    p_co = sub.add_parser("checkout", help="check out an item")
    p_co.add_argument("-i","--item", required=True, help="item ID")
    p_co.add_argument("-p","--password", required=True, help="police password")

    # checkin
    p_ci = sub.add_parser("checkin", help="check in an item")
    p_ci.add_argument("-i","--item", required=True, help="item ID")
    p_ci.add_argument("-p","--password", required=True, help="analyst/lawyer/executive password")

    # remove
    p_rm = sub.add_parser("remove", help="remove an item from chain")
    p_rm.add_argument("-i","--item", required=True, help="item ID")
    p_rm.add_argument("-p","--password", required=True, help="creator password")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "add":
        cmd_add(args)
    elif args.command == "checkout":
        cmd_checkout(args)
    elif args.command == "checkin":
        cmd_checkin(args)
    elif args.command == "remove":
        cmd_remove(args)
    else:
        parser.print_usage(sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
