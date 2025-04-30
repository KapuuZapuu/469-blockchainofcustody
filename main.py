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

AES_KEY = b"R0chLi4uLi4uLi4="
os.environ['BCHOC_PASSWORD_POLICE'] = "P80P"
os.environ['BCHOC_PASSWORD_LAWYER'] = "L76L"
os.environ['BCHOC_PASSWORD_ANALYST'] = "A65A"
os.environ['BCHOC_PASSWORD_EXECUTIVE'] = "E69E"
os.environ['BCHOC_PASSWORD_CREATOR'] = "C67C"

def encrypt(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(text).encode())

def decrypt(ciphertext, key):
    decipher = AES.new(key, AES.MODE_ECB)
    decrypted = decipher.decrypt(ciphertext)
    return decrypted

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

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
    NULL = b"NONE\0\0\0\0\0\0\0\0"

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
    def __init__(self, encryption_key, filename='blockchain_data.json'):
        self.blocks : list[Block, bytes] = []
        self.current_transactions = []
        self.encryption_key = encryption_key
        self.filename = filename
        self.init() ## REMOVE LATER

    def init(self):
        if len(self.blocks) > 0:
            print("FAILED")
            return

        if os.path.exists(self.filename):
            self.load_blockchain()
        else:
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
            self.blocks.append((block.pack_block(), block.data))
            print("Blockchain file not found. Created INITIAL block.")

    def add_block(self, case_id : bytes, evidence_item_id : bytes, state : bytes, creator : bytes, owner : bytes, data : bytes):
        if len(self.blocks) <= 0:
            print("FAILED NO INIT")
            sys.exit(1)
    
        encrypted_case_id = encrypt(case_id, self.encryption_key).ljust(32)
        encrypted_evidence_item_id = encrypt(evidence_item_id, self.encryption_key).ljust(32)
        prev_block_header, prev_block_data = self.blocks[-1]
        prev_hash, _, _, _, _, _, _, _ = unpack_block(prev_block_header)
        block = Block(
            previous_hash=prev_hash,
            case_id=encrypted_case_id,
            evidence_item_id=encrypted_evidence_item_id,
            state=state,
            creator=creator,
            owner=owner,
            data_len=len(data),
            data=data
        )
        self.blocks.append((block.pack_block(), data))

    def add(self, case_id : bytes, evidence_item_ids : bytes, creator : str, password : str):
        creator = creator.encode('utf-8').ljust(12, b'\0')
        ## check creator password

        ids = set()
        for block_header, _ in self.blocks:
            _, _, _, evidence_item_id, _, _, _, _ = unpack_block(block_header)
            decrypted_item_id = decrypt(evidence_item_id, self.encryption_key)
            numeric_regex = re.compile(b'\d')
            index = len(decrypted_item_id)
            for i, byte in enumerate(decrypted_item_id):
                if not numeric_regex.match(bytes([byte])):
                    index = i
                    break
            valid_part = decrypted_item_id[:index]
            string_data = valid_part.decode('utf-8')
            ids.add(string_data)

        added_items = []
        for evidence_item_id in evidence_item_ids:
            owner = Owner.NULL
            self.add_block(case_id, str(evidence_item_id), State.CHECKEDIN, creator, owner, f"Item {evidence_item_id} added and checked in.")
            added_items.append(evidence_item_id)
            time_of_action = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()) + 'Z'
            print(f"Added item: {evidence_item_id}")
            print("Status: CHECKEDIN")
            print(f"Time of action: {time_of_action}")

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
        show_history_command(args)
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

