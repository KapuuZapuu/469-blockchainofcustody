#!/usr/bin/env python3

'''
Group 14
Ryan Leigh - 1224401633
Hassan Khan - 1225282448
Cameron Mendez - 1218669374
'''

import sys
import os
import argparse
import time
import uuid
import struct
from datetime import datetime, timezone
from Crypto.Cipher import AES
from enum import Enum
from struct import pack, unpack, calcsize
from hashlib import sha256

# AES encryption key
AES_KEY = b"R0chLi4uLi4uLi4="

# Map roles to environment-stored passwords
ROLE_PASSWORDS = {
    'POLICE':    os.environ.get('BCHOC_PASSWORD_POLICE', ''),
    'LAWYER':    os.environ.get('BCHOC_PASSWORD_LAWYER', ''),
    'ANALYST':   os.environ.get('BCHOC_PASSWORD_ANALYST', ''),
    'EXECUTIVE': os.environ.get('BCHOC_PASSWORD_EXECUTIVE', ''),
    'CREATOR':   os.environ.get('BCHOC_PASSWORD_CREATOR', ''),
}

# Byte padding utilities (PKCS#7)
def pad_bytes(b: bytes) -> bytes:
    pad_len = AES.block_size - (len(b) % AES.block_size)
    return b + bytes([pad_len]) * pad_len

def unpad_bytes(b: bytes) -> bytes:
    pad_len = b[-1]
    if 1 <= pad_len <= AES.block_size:
        return b[:-pad_len]
    return b

# Encrypt/decrypt using AES-ECB
def encrypt_bytes(raw: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad_bytes(raw))

def decrypt_bytes(enc: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return unpad_bytes(cipher.decrypt(enc))

# Block states
class State(Enum):
    INITIAL    = b"INITIAL"   + b"\0"*5
    CHECKEDIN  = b"CHECKEDIN" + b"\0"*3
    CHECKEDOUT = b"CHECKEDOUT"+ b"\0"*2
    DISPOSED   = b"DISPOSED"  + b"\0"*4
    DESTROYED  = b"DESTROYED" + b"\0"*3
    RELEASED   = b"RELEASED"  + b"\0"*3

# Block owners
class Owner(Enum):
    POLICE    = b"Police"    + b"\0"*7
    LAWYER    = b"Lawyer"    + b"\0"*7
    ANALYST   = b"Analyst"   + b"\0"*6
    EXECUTIVE = b"Executive" + b"\0"*4
    NULL      = b"\0"*12

# Block structure: previous_hash, timestamp, case_id, item_id, state, creator, owner, data_len
class Block:
    HEADER_FMT  = "<32sd32s32s12s12s12sI"
    HEADER_SIZE = calcsize(HEADER_FMT)

    def __init__(self, prev_hash, case_id, item_id, state, creator, owner, data_len, data_bytes):
        self.previous_hash     = prev_hash
        self.timestamp         = time.time()
        self.case_id           = case_id
        self.evidence_item_id  = item_id
        self.state             = state
        self.creator           = creator
        self.owner             = owner
        self.data_len          = data_len
        self.data              = data_bytes

    def serialize(self) -> bytes:
        if isinstance(self.owner, Owner):
            owner_bytes = self.owner.value
        elif isinstance(self.owner, (bytes, bytearray)):
            owner_bytes = self.owner.ljust(12, b'\0')[:12]
        else:
            owner_bytes = str(self.owner).encode('utf-8').ljust(12, b'\0')[:12]
        header = pack(
            self.HEADER_FMT,
            self.previous_hash,
            self.timestamp,
            self.case_id,
            self.evidence_item_id,
            self.state.value,
            self.creator,
            owner_bytes,
            self.data_len,
        )
        return header + self.data

    @classmethod
    def deserialize(cls, raw_bytes: bytes):
        hdr = raw_bytes[:cls.HEADER_SIZE]
        prev_hash, timestamp, case_id, item_id, state_b, creator, owner_b, data_len = unpack(
            cls.HEADER_FMT, hdr)
        data = raw_bytes[cls.HEADER_SIZE:cls.HEADER_SIZE + data_len]
        state = State(state_b)
        owner = None
        for o in Owner:
            if o.value == owner_b:
                owner = o
                break
        if owner is None:
            owner = owner_b.rstrip(b'\0').decode('utf-8')
        blk = cls(prev_hash, case_id, item_id, state, creator, owner, data_len, data)
        blk.timestamp = timestamp
        return blk, cls.HEADER_SIZE + data_len

    def compute_hash(self) -> bytes:
        return sha256(self.serialize()).digest()

class BlockChain:
    def __init__(self, filename=None):
        self.filename = filename or os.environ.get('BCHOC_FILE_PATH', 'blockchain_data.bin')
        self.blocks   = []

    def _create_genesis_block(self):
        raw = b"Initial block\0"
        g = Block(
            prev_hash=b"\0"*32,
            case_id=b"\0"*32,
            item_id=b"\0"*32,
            state=State.INITIAL,
            creator=b"\0"*12,
            owner=Owner.NULL,
            data_len=len(raw),
            data_bytes=raw
        )
        g.timestamp = 0.0
        return g

    def init_chain(self):
        if not os.path.exists(self.filename) or os.path.getsize(self.filename) == 0:
            self._write_block(self._create_genesis_block())
            print("Created INITIAL block.")
            sys.exit(0)

        try:
            with open(self.filename, 'rb') as f:
                hdr = f.read(Block.HEADER_SIZE)
            prev_hash, _, _, _, state_b, *_ = unpack(Block.HEADER_FMT, hdr)
        except (struct.error, ValueError):
            print("Blockchain file found but corrupted.")
            sys.exit(1)

        if prev_hash != b"\0"*32 or state_b != State.INITIAL.value:
            print("Blockchain file found but corrupted.")
            sys.exit(1)

        print("Blockchain file found with INITIAL block.")
        sys.exit(0)

    def load_chain(self):
        self.blocks = []
        with open(self.filename, 'rb') as f:
            buf = f.read()
        offset = 0
        while offset < len(buf):
            blk, size = Block.deserialize(buf[offset:])
            self.blocks.append(blk)
            offset += size

    def _write_block(self, block: Block):
        with open(self.filename, 'ab') as f:
            f.write(block.serialize())

    def add(self, args):
        if args.p != ROLE_PASSWORDS['CREATOR']:
            print("Invalid password"); sys.exit(1)
        if not args.c:
            print("Case ID not provided"); sys.exit(1)
        if not args.i:
            print("Item ID not provided"); sys.exit(1)
        try:
            case_uuid = uuid.UUID(args.c)
        except ValueError:
            print("Invalid case ID format"); sys.exit(1)

        for item_str in args.i:
            for blk in self.blocks[1:]:
                raw = decrypt_bytes(blk.evidence_item_id)
                if unpack("<I", raw[:4])[0] == int(item_str):
                    print("Duplicate item ID"); sys.exit(1)

            prev_hash  = self.blocks[-1].compute_hash()
            item_enc   = encrypt_bytes(pack("<I", int(item_str)))
            case_enc   = encrypt_bytes(case_uuid.bytes)
            creator_f  = args.g.encode('utf-8').ljust(12, b'\0')
            new_blk = Block(
                prev_hash,
                case_enc.ljust(32, b'\0'),
                item_enc.ljust(32, b'\0'),
                State.CHECKEDIN,
                creator_f,
                Owner.NULL,
                0, b""
            )
            self._write_block(new_blk)
            self.blocks.append(new_blk)

            ts_str = datetime.fromtimestamp(new_blk.timestamp, tz=timezone.utc)\
                         .isoformat().replace('+00:00','Z')
            print(f"Added item: {item_str}")
            print(f"Status: {new_blk.state.name}")
            print(f"Time of action: {ts_str}")

    def remove(self, args):
        if args.p != ROLE_PASSWORDS['CREATOR']:
            print("Invalid password")
            sys.exit(1)
        if not args.i:
            print("Item ID not provided")
            sys.exit(1)
        if not args.why:
            print("Reason not provided")
            sys.exit(1)
        reason = args.why.upper()
        if reason not in ("DISPOSED","DESTROYED","RELEASED"):
            print("Invalid reason")
            sys.exit(1)
        item_str = args.i
        last_blk = None
        for blk in self.blocks[1:]:
            raw = decrypt_bytes(blk.evidence_item_id)
            eid = unpack("<I", raw[:4])[0]
            if eid == int(item_str):
                last_blk = blk
        if last_blk is None:
            print("Item not found")
            sys.exit(1)
        if last_blk.state != State.CHECKEDIN:
            print("Cannot remove item in current state")
            sys.exit(1)
        prev_hash = self.blocks[-1].compute_hash()
        case_field = last_blk.case_id
        item_field = last_blk.evidence_item_id
        creator_field = last_blk.creator
        if reason == "RELEASED":
            if not args.o:
                print("Owner not provided")
                sys.exit(1)
            owner_val = args.o.encode('utf-8').ljust(12, b"\0")[:12]
        else:
            owner_val = Owner.NULL.value
        new_blk = Block(prev_hash, case_field, item_field, State[reason], creator_field, owner_val, 0, b"")
        self._write_block(new_blk)
        self.blocks.append(new_blk)
        case_uuid = uuid.UUID(bytes=decrypt_bytes(case_field))
        ts = datetime.fromtimestamp(new_blk.timestamp, tz=timezone.utc)
        ts_str = ts.isoformat().replace('+00:00','Z')
        print(f"Case: {case_uuid}")
        if reason == "RELEASED": print(f"Owner: {args.o}")
        print(f"Removed item: {item_str}")
        print(f"Status: {reason}")
        print(f"Time of action: {ts_str}")

    def checkout(self, args):
        if args.p not in ROLE_PASSWORDS.values():
            print("Invalid password")
            sys.exit(1)
        last_blk = None
        for blk in self.blocks[1:]:
            raw = decrypt_bytes(blk.evidence_item_id)
            if unpack("<I", raw[:4])[0] == int(args.i):
                last_blk = blk
        if last_blk is None or last_blk.state != State.CHECKEDIN:
            print("Cannot checkout item in current state")
            sys.exit(1)
        role = [r for r,p in ROLE_PASSWORDS.items() if p == args.p][0]
        prev_hash = self.blocks[-1].compute_hash()
        new_blk = Block(prev_hash, last_blk.case_id, last_blk.evidence_item_id,
                        State.CHECKEDOUT, last_blk.creator,
                        Owner[role] if role in Owner.__members__ else bytes(role,'utf-8'),
                        0, b"")
        self._write_block(new_blk); self.blocks.append(new_blk)
        case_uuid=uuid.UUID(bytes=decrypt_bytes(new_blk.case_id))
        ts=datetime.fromtimestamp(new_blk.timestamp, tz=timezone.utc).isoformat().replace('+00:00','Z')
        print(f"Case: {case_uuid}")
        print(f"Checked out item: {args.i}")
        print(f"Status: {new_blk.state.name}")
        print(f"Time of action: {ts}")

    def checkin(self, args):
        if args.p not in ROLE_PASSWORDS.values():
            print("Invalid password")
            sys.exit(1)
        last_blk = None
        for blk in self.blocks[1:]:
            raw = decrypt_bytes(blk.evidence_item_id)
            if unpack("<I", raw[:4])[0] == int(args.i):
                last_blk = blk
        if last_blk is None or last_blk.state != State.CHECKEDOUT:
            print("Cannot checkin item in current state")
            sys.exit(1)
        prev_hash = self.blocks[-1].compute_hash()
        new_blk = Block(prev_hash, last_blk.case_id, last_blk.evidence_item_id,
                        State.CHECKEDIN, last_blk.creator,
                        Owner.NULL,
                        0, b"")
        self._write_block(new_blk)
        self.blocks.append(new_blk)
        case_uuid = uuid.UUID(bytes=decrypt_bytes(new_blk.case_id))
        ts = datetime.fromtimestamp(new_blk.timestamp, tz=timezone.utc).isoformat().replace('+00:00','Z')
        print(f"Case: {case_uuid}")
        print(f"Checked in item: {args.i}")
        print(f"Status: {new_blk.state.name}")
        print(f"Time of action: {ts}")

    def show_cases(self, args):
        if args.p not in ROLE_PASSWORDS.values():
            print("Invalid password"); sys.exit(1)
        cases = []
        for blk in self.blocks[1:]:
            cid = uuid.UUID(bytes=decrypt_bytes(blk.case_id))
            if args.c and str(cid) != args.c:
                continue
            # enforce -i filter: only include if this block’s item matches
            if args.i:
                iid = unpack("<I", decrypt_bytes(blk.evidence_item_id)[:4])[0]
                if str(iid) != args.i:
                    continue
            cases.append(cid)
        for c in sorted(set(cases)):
            print(c)

    def show_items(self, args):
        if args.p not in ROLE_PASSWORDS.values():
            print("Invalid password"); sys.exit(1)
        items = []
        for blk in self.blocks[1:]:
            iid = unpack("<I", decrypt_bytes(blk.evidence_item_id)[:4])[0]
            if args.i and str(iid) != args.i:
                continue
            if args.c:
                cid = uuid.UUID(bytes=decrypt_bytes(blk.case_id))
                if str(cid) != args.c:
                    continue
            items.append(iid)
        for i in sorted(set(items)):
            print(i)

    def show_history(self, args):
        if args.p not in ROLE_PASSWORDS.values():
            print("Invalid password"); sys.exit(1)
        entries = []
        for blk in self.blocks[1:]:
            cid = uuid.UUID(bytes=decrypt_bytes(blk.case_id))
            iid = unpack("<I", decrypt_bytes(blk.evidence_item_id)[:4])[0]
            if args.c and str(cid) != args.c:
                continue
            if args.i and str(iid) != args.i:
                continue
            ts = datetime.fromtimestamp(blk.timestamp, tz=timezone.utc).isoformat().replace('+00:00','Z')
            entries.append((ts, cid, iid, blk.state.name))
        if args.reverse:
            entries.reverse()
        for ts, cid, iid, state in entries:
            print(f"{ts} - Case: {cid} Item: {iid} State: {state}")

    def log(self, args):
        if args.p not in ROLE_PASSWORDS.values():
            print("Invalid password"); sys.exit(1)
        self.load_chain()
        entries = []
        for blk in self.blocks[1:]:
            ts  = datetime.fromtimestamp(blk.timestamp, tz=timezone.utc).isoformat().replace('+00:00','Z')
            cid = uuid.UUID(bytes=decrypt_bytes(blk.case_id))
            iid = unpack("<I", decrypt_bytes(blk.evidence_item_id)[:4])[0]
            entries.append((ts, cid, iid, blk.state.name))
        if args.c:
            entries = [e for e in entries if str(e[1]) == args.c]
        if args.i:
            entries = [e for e in entries if str(e[2]) == args.i]
        if args.reverse:
            entries.reverse()
        if args.n is not None:
            if args.reverse:
                entries = entries[:args.n]
            else:
                entries = entries[-args.n:]
        for ts, cid, iid, state in entries:
            print(f"{ts} - Case: {cid} Item: {iid} State: {state}")

    def verify(self, args):
        # Simplified integrity check
        valid = True
        for i in range(1, len(self.blocks)):
            if self.blocks[i].previous_hash != self.blocks[i-1].compute_hash():
                valid = False
                bad = self.blocks[i].compute_hash()
                break
        print(f"Transactions in blockchain: {len(self.blocks)-1}")
        if valid:
            print("State of blockchain: CLEAN")
        else:
            print("State of blockchain: ERROR")
            print(f"Bad block: {bad.hex()}")

    def summary(self, args):
        if args.p not in ROLE_PASSWORDS.values():
            print("Invalid password")
            sys.exit(1)
        case_uuid = uuid.UUID(args.c)
        # build map of each item → its last state
        last_state = {}
        for blk in self.blocks[1:]:
            cid = uuid.UUID(bytes=decrypt_bytes(blk.case_id))
            if cid != case_uuid:
                continue
            iid = unpack("<I", decrypt_bytes(blk.evidence_item_id)[:4])[0]
            last_state[iid] = blk.state.name

        print(f"Case {case_uuid} summary:")
        print(f"Total unique items: {len(last_state)}")
        # count how many items are currently in each state
        for state in State:
            cnt = sum(1 for st in last_state.values() if st == state.name)
            print(f"{state.name}: {cnt}")


# --- CLI parsing and dispatch ---
def main():
    parser = argparse.ArgumentParser(prog='bchoc')
    sub    = parser.add_subparsers(dest='cmd')
    sub.add_parser('init')
    add_p = sub.add_parser('add')
    add_p.add_argument('-c', required=False)
    add_p.add_argument('-i', action='append', required=False)
    add_p.add_argument('-p', required=True)
    add_p.add_argument('-g', default='CREATOR')
    remove_p=sub.add_parser('remove'); remove_p.add_argument('-i',required=False)
    remove_p.add_argument('-y','--why', required=False, help="Reason: DISPOSED, DESTROYED, or RELEASED"); remove_p.add_argument('-o',required=False); remove_p.add_argument('-p',required=True)
    checkin_p=sub.add_parser('checkin'); checkin_p.add_argument('-i',required=True); checkin_p.add_argument('-p',required=True)
    checkout_p=sub.add_parser('checkout'); checkout_p.add_argument('-i',required=True); checkout_p.add_argument('-p',required=True)

    show_p=sub.add_parser('show'); show_sub=show_p.add_subparsers(dest='subcmd')
    
    show_cases_p = show_sub.add_parser('cases')
    show_cases_p.add_argument('-p', required=True)
    show_cases_p.add_argument('-c', required=False)
    show_cases_p.add_argument('-i', required=False)

    show_items_p = show_sub.add_parser('items')
    show_items_p.add_argument('-p', required=True)
    show_items_p.add_argument('-c', required=False)
    show_items_p.add_argument('-i', required=False)

    show_hist=show_sub.add_parser('history'); show_hist.add_argument('-p',required=True); show_hist.add_argument('-c'); show_hist.add_argument('-i')
    show_hist.add_argument('-r','--reverse', action='store_true', help="reverse order")

    verify_p=sub.add_parser('verify'); verify_p.add_argument('-p',required=True)
    summary_p=sub.add_parser('summary'); summary_p.add_argument('-c',required=True); summary_p.add_argument('-p',required=True)

    # New log subcommand
    log_p=sub.add_parser('log')
    log_p.add_argument('-p', required=True)
    log_p.add_argument('-n', type=int, default=None)
    log_p.add_argument('-r', '--reverse',
                   action='store_true',
                   dest='reverse',
                   help="reverse order")
    log_p.add_argument('-c')
    log_p.add_argument('-i')

    args = parser.parse_args()
    bc   = BlockChain()

    if args.cmd == 'init':
        bc.init_chain()

    elif args.cmd == 'add':
        if not os.path.exists(bc.filename) or os.path.getsize(bc.filename) == 0:
            bc.init_chain()
        bc.load_chain()
        bc.add(args)

    else:
        # for all other commands, we require an existing chain file
        if not os.path.exists(bc.filename) or os.path.getsize(bc.filename) == 0:
            # if a password check comes next, they’ll handle it; otherwise we treat
            # "no chain" as an error in each cmd method
            bc.blocks = []
        else:
            bc.load_chain()

        if args.cmd == 'log':
            bc.log(args)
        elif args.cmd == 'show':
            if args.subcmd == 'cases':
                bc.show_cases(args)
            elif args.subcmd == 'items':
                bc.show_items(args)
            elif args.subcmd == 'history':
                bc.show_history(args)
        elif args.cmd == 'remove':
            bc.remove(args)
        elif args.cmd == 'checkout':
            bc.checkout(args)
        elif args.cmd == 'checkin':
            bc.checkin(args)
        elif args.cmd == 'verify':
            bc.verify(args)
        elif args.cmd == 'summary':
            bc.summary(args)
        else:
            parser.print_help()

if __name__=='__main__': main()
