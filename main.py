#!/usr/bin/env python3
# Group 14
# Ryan Leigh - 1224401633
# person 1
# person 2

import sys
import argparse
import time
import os
import re
from datetime import datetime
from Crypto.Cipher import AES
from enum import Enum
from struct import *
from hashlib import sha256
import uuid

AES_KEY = b"R0chLi4uLi4uLi4="

def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len > AES.block_size:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def encrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext))

def encrypt_case_id(case_id_str: str, key: bytes) -> bytes:
    case_uuid = uuid.UUID(case_id_str)
    return encrypt(case_uuid.bytes, key)

def encrypt_item_id(item_id: str | int, key: bytes) -> bytes:
    int_id = int(item_id)
    item_bytes = pack(">I", int_id)
    return encrypt(item_bytes, key)

def decrypt_item_id(enc_item_id: bytes, key: bytes) -> int:
    ciphertext = enc_item_id[:AES.block_size]
    raw = decrypt(ciphertext, key)
    return int.from_bytes(raw[:4], byteorder='big')

def decrypt_case_id(enc_case_id: bytes, key: bytes) -> str:
    ciphertext = enc_case_id[: 2 * AES.block_size ]
    raw = decrypt(ciphertext, key)
    return str(uuid.UUID(bytes=raw[:16]))

class State(Enum):
    INITIAL = b"INITIAL\0\0\0\0\0"
    CHECKEDIN = b"CHECKEDIN\0\0"
    CHECKEDOUT = b"CHECKEDOUT\0"
    DISPOSED = b"DISPOSED\0\0\0\0"
    DESTROYED = b"DESTROYED\0\0\0"
    RELEASED = b"RELEASED\0\0\0\0"

class Owner(Enum):
    POLICE = b"Police\0\0\0\0\0\0"
    LAWYER = b"Lawyer\0\0\0\0\0\0"
    ANALYST = b"Analyst\0\0\0\0\0"
    EXECUTIVE = b"Executive\0\0\0"
    NULL = b"\0\0\0\0\0\0\0\0\0\0"

class Block():
    def __init__(self,
        previous_hash : bytes, case_id : bytes,
        evidence_item_id : bytes, state : State,
        creator : bytes, owner : Owner, # needs to be Police, Lawyer, Analyst, Executive
        data_len : int, data : bytes
        ):
        self.previous_hash = previous_hash
        self.timestamp = time.time() #(datetime.utcnow() - datetime(1970, 1, 1)).total_seconds()
        self.case_id = case_id
        self.evidence_item_id = evidence_item_id
        self.state = state
        self.creator = creator
        self.owner = owner
        self.data_len = data_len
        self.data = data

    def pack_block(self) -> bytes:
        header = pack("32s d 32s 32s 12s 12s 12s I",
            self.previous_hash,
            self.timestamp,
            self.case_id,
            self.evidence_item_id,
            self.state.value,
            self.creator,
            self.owner.value,
            self.data_len
        )
        return header

## NOT IN BLOCK CLASS, THIS IS INTENTIONAL, SOLUTION SUCKS BUT IT IS WHAT IT IS
def unpack_block(block):
    prev_hash, timestamp, case_id, evidence_item_id, state, creator, owner, data_len = unpack("32s d 32s 32s 12s 12s 12s I", block)
    return prev_hash, timestamp, case_id, evidence_item_id, state.strip(b'\x00').decode(), creator.strip(b'\x00').decode(), owner.strip(b'\x00').decode(), data_len

class BlockChain():
    def __init__(self, encryption_key):
        self.blocks : list[Block, bytes] = []
        self.current_transactions = []
        self.encryption_key = encryption_key
        filename = os.environ.get('BCHOC_FILE_PATH', "blockchain_data.dat")
        # if os.environ.get('BCHOC_FILE_PATH') and os.path.getsize(os.environ.get('BCHOC_FILE_PATH')) == 0:
            # sys.exit(1)
        self.filename = filename
        # self.init() ## REMOVE LATER

    def init(self):
        status = False
        if os.path.exists(self.filename):
            print("Blockchain file found. Loading Data")
            status = self.load_blockchain()

        if len(self.blocks) > 0:
            return

        if status == True and len(self.blocks) <= 0:
            status = False
        
        if not status:
            block = Block(
                previous_hash=b"\0" * 32,
                case_id=b"\0" * 32,
                evidence_item_id=b"\0" * 32,
                state=State.INITIAL,
                creator=b"\0" * 12,
                owner=Owner.NULL,
                data_len=0,
                data=b"Initial block\0"
            )
            # print(Owner.NULL.)
            self.blocks = [(block.pack_block(), self.ensure_bytes(block.data))]
            open(self.filename, 'ab').close()
            print("Blockchain file not found. Created INITIAL block.")
        self.save_blockchain()
        # self.print_blockchain()

    def add_block(self, encrypted_case_id: bytes, encrypted_item_id: bytes, state: State, creator: bytes, owner: Owner, data: bytes):
        prev_block_header, _ = self.blocks[-1]
        prev_hash, _, _, _, _, _, _, _ = unpack_block(prev_block_header)
        block = Block(
            previous_hash=prev_hash,
            case_id=encrypted_case_id,
            evidence_item_id=encrypted_item_id,
            state=state,
            creator=creator,
            owner=owner,
            data_len=len(data),
            data=data
        )
        self.blocks.append((block.pack_block(), self.ensure_bytes(data)))

    def add(self, case_id: str, evidence_item_ids: list[str], creator: str, password: str) -> None:
        # self.print_blockchain()
        if len(self.blocks) <= 0:
            self.init()
        ## check creator password
        if not self.verify_password(creator, password):
            print("Invalid password")
            sys.exit(1)

        print(self.blocks)
        ids = set()
        for i, (block_header, _) in enumerate(self.blocks):
            if i == 0:
                continue
            _, _, _, enc_item_id, *rest = unpack_block(block_header)
            existing_id = decrypt_item_id(enc_item_id, self.encryption_key)
            ids.add(existing_id)

        print(ids)
        for raw_id in evidence_item_ids:
            new_id = int(raw_id)
            if new_id in ids:
                print(f"Error: Duplicate item ID {new_id} — already exists in blockchain.")
                return

            enc_case = encrypt_case_id(case_id, self.encryption_key)
            enc_item = encrypt_item_id(new_id, self.encryption_key)
            self.add_block(
                enc_case,
                enc_item,
                State.CHECKEDIN,
                creator.encode(),
                Owner.NULL,
                f"Item {new_id} added and checked in."
            )
            print(f"Added item: {new_id}")
            print("Status: CHECKEDIN")
            print(f"Time of action: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")

        # 4) persist
        self.save_blockchain()

    def print_blockchain(self):
        if not self.blocks:
            print("Blockchain is empty.")
            return

        print("Current Blockchain:\n" + "-" * 50)

        for i, (header, data) in enumerate(self.blocks):
            try:
                prev_hash, timestamp, enc_case_id, enc_item_id, state, creator, owner, data_len = unpack_block(header)
                #case_id = decrypt(enc_case_id, self.encryption_key).decode('utf-8').strip('\0')
                #item_id = decrypt(enc_item_id, self.encryption_key).decode('utf-8').strip('\0')
                if i != 0:
                    case_id = decrypt_case_id(enc_case_id, self.encryption_key)
                    item_id = decrypt_item_id(enc_item_id, self.encryption_key)
                else:
                    case_id = enc_case_id
                    item_id = enc_item_id

                data_str = data.decode('utf-8', errors='ignore').strip('\0')

                print(f"Block {i}:")
                print(f"  Case ID     : {case_id}")
                print(f"  Item ID     : {item_id}")
                print(f"  State       : {state}")
                print(f"  Creator     : {creator.strip()}")
                print(f"  Owner       : {owner.strip()}")
                print(f"  Timestamp   : {datetime.utcfromtimestamp(timestamp).isoformat()}Z")
                print(f"  Data        : {data_str}")
                print("-" * 50)

            except Exception as e:
                print(f"Error reading block {i}: {e}")

    def verify_password(self, creator, password):
        # roles = [Owner.POLICE.strip("\0"), Owner.LAWYER.strip("\0"), Owner.ANALYST.strip("\0"), Owner.EXECUTIVE.strip("\0"), Owner.CREATOR.strip("\0")]
        # for role in roles:
        #     env_var_name = f'BCHOC_PASSWORD_{role}'
        #     if password == os.environ.get(env_var_name, ''):
        #         return True
        # return False
        role = creator.strip('\0')
        env_var_name = f'BCHOC_PASSWORD_{role}'
        if password == os.environ.get(env_var_name, ''):
            return True
        return True


    def save_blockchain(self):
        with open(self.filename, 'wb') as file:
            for block_header, data in self.blocks:
                file.write(block_header)
                file.write(data)

    def load_blockchain(self) -> bool:
        self.blocks = []
        if os.path.getsize(self.filename) == 0:
            return False
        try:
            with open(self.filename, 'rb') as file:
                while True:
                    header = file.read(144)  
                    if not header or len(header) < 144:
                        break
                    unpacked = unpack_block(header)
                    data_len = unpacked[7]  # index of data_len
                    data = file.read(data_len)
                    self.blocks.append((header, self.ensure_bytes(data)))
        except FileNotFoundError:
            print(f"Blockchain file {self.filename} not found. Starting new chain.")
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            sys.exit(1)      
        return True

    def _encode(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, dict):
            return {k: (v.hex() if isinstance(v, bytes) else v) for k, v in obj.items()}
        return obj

    def _decode(self, obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str) and self.is_hex(value):
                    obj[key] = bytes.fromhex(value)
        return obj

    def ensure_bytes(self, value) -> bytes:
        if isinstance(value, str):
            value = value.encode('utf-8')
        return value

def parse_input(blockchain : BlockChain):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')
    # Add Subparser
    parser_add = subparsers.add_parser('add')
    parser_add.add_argument('-c', '--case_id', required=True)
    parser_add.add_argument('-i', '--item_id', nargs='+', required=True)
    parser_add.add_argument('-g', '--creator', required=True)
    parser_add.add_argument('-p', '--password', required=True)
    # Checkout Subparser
    parser_checkout = subparsers.add_parser('checkout')
    parser_checkout.add_argument('-i', '--item_id', required=True)
    parser_checkout.add_argument('-p', '--password', required=True)
    #Checkin Subparser
    parser_checkin = subparsers.add_parser('checkin')
    parser_checkin.add_argument('-i', '--item_id', required=True)
    parser_checkin.add_argument('-p', '--password', required=True)
    #show cases
    parser_show_cases = subparsers.add_parser('show_cases')
    parser_show_cases.add_argument('-p', '--password', required=False)
    # show items
    parser_show_items = subparsers.add_parser('show_items')
    parser_show_items.add_argument('-c', '--case_id', required=True)
    parser_show_items.add_argument('-p', '--password', required=False)
    # show history
    parser_show_history = subparsers.add_parser('show_history')
    parser_show_history.add_argument('-c', '--case_id')
    parser_show_history.add_argument('-i', '--item_id')
    parser_show_history.add_argument('-n', '--num_entries')
    parser_show_history.add_argument('-r', '--reverse', action='store_true')
    parser_show_history.add_argument('-p', '--password', required=True)
    # remove
    parser_remove = subparsers.add_parser('remove')
    parser_remove.add_argument('-i', '--item_id', required=True)
    parser_remove.add_argument('-y', '--reason', required=True)
    parser_remove.add_argument('-p', '--password', required=True)
    subparsers.add_parser('init')
    # verify
    subparsers.add_parser('verify')
    args = parser.parse_args()
    if args.command == 'add':
        blockchain.add(args.case_id, args.item_id, args.creator, args.password)
    elif args.command == 'checkout':
        blockchain.checkout(args.item_id, args.password)    
    elif args.command == 'checkin':
        blockchain.checkin(args.item_id, args.password)
    elif args.command == 'show_cases':
        blockchain.show_cases(args.password)
    elif args.command == 'show_items':
        blockchain.show_items(args.case_id, args.password)
    elif args.command == 'show_history':
        blockchain.show_history(
        case_id=args.case_id,
        item_id=args.item_id,
        num_entries=args.num_entries,
        reverse=args.reverse,
        password=args.password
    )
    elif args.command == 'remove':
        blockchain.remove(args.item_id, args.reason, args.password)
    elif args.command == 'init':
        blockchain.init()
    elif args.command == 'verify':
        blockchain.verify()
    else:
        parser.print_help()



if __name__ == '__main__':
    blockchain = BlockChain(AES_KEY)
    parse_input(blockchain)

