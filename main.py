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
    def __init__(self, encryption_key):
        self.blocks : list[Block, bytes] = []
        self.current_transactions = []
        self.encryption_key = encryption_key
        filename = os.environ.get('BCHOC_FILE_PATH', "blockchain_data.dat")
        self.filename = filename
        self.init() ## REMOVE LATER

    def init(self):
        if len(self.blocks) > 0:
            # print("FAILED")
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
            # open(self.filename, 'ab').close()
            print("Blockchain file not found. Created INITIAL block.")

    def add_block(self, case_id : bytes, evidence_item_id : bytes, state : bytes, creator : bytes, owner : bytes, data : bytes):
        if len(self.blocks) <= 0:
            print("FAILED NO INIT")
            sys.exit(1)
    
        encrypted_case_id = encrypt(str(case_id), self.encryption_key).ljust(32, b'\0')
        encrypted_evidence_item_id = encrypt(str(evidence_item_id), self.encryption_key).ljust(32)
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
        ## check creator password
        if not self.verify_password(creator, password):
            print(f"Invalid password")
            sys.exit(1)
            return

        ids = set()
        for block_header, _ in self.blocks:
            _, _, _, encrypted_item_id, _, _, _, _ = unpack_block(block_header)
            decrypted_item_id = decrypt(encrypted_item_id, self.encryption_key)
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
            if str(evidence_item_id) in ids:
                print(f"Error: Duplicate item ID {evidence_item_id} — already exists in blockchain.")
                # sys.exit(1)
                return
            owner = Owner.NULL
            self.add_block(case_id.encode(), evidence_item_id.encode(), State.CHECKEDIN, creator.encode(), owner, f"Item {evidence_item_id} added and checked in.")
            added_items.append(evidence_item_id)
            time_of_action = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()) + 'Z'
            print(f"Added item: {evidence_item_id}")
            print("Status: CHECKEDIN")
            print(f"Time of action: {time_of_action}")


    def checkout(self, item_id, password):
        item_id_str = str(item_id)
        item_found = False
        last_checked_in = False
        case_id = None

        # Scan blockchain for the item and its last state
        for block in reversed(self.chain):
            block_data = block['data']
            # Decrypt and extract item ID from the block
            header_data = self.unpack_header(block['header'])
            decrypted_item_id = decrypt(header_data['item_id'], self.encryption_key)
            #Byte Examination
            numeric_regex = re.compile(b'\d')  # Matches numeric bytes
            index = len(decrypted_item_id)
            for i, byte in enumerate(decrypted_item_id):
                if not numeric_regex.match(bytes([byte])):  # Check each byte if it's not a digit
                    index = i
                    break
            valid_part = decrypted_item_id[:index]
            string_data = valid_part.decode('utf-8')
            decrypted_item_id = string_data

            if decrypted_item_id == item_id_str:
                item_found = True
                case_id = decrypt(header_data['case_id'], self.encryption_key)
                last_checked_in_owner = header_data['owner'].strip()  
                # Check if the item was last checked in
                if 'CHECKEDIN' in block_data:
                    last_checked_in = True
                    break
                elif 'CHECKEDOUT' in block_data:
                    last_checked_in = False
                    break

        if not item_found:
            print(f"Error: Item ID {item_id} does not exist in the blockchain.")
            sys.exit(1)
            return

        if last_checked_in:
            print(f"Error: Item ID {item_id} is not in a check-in state and cannot be checked out.")
            sys.exit(1)
            return

        
        if self.verify_password(password) == False: 
            print(f"Error: Invalid password for checking out item ID {item_id}.")
            sys.exit(1)
            return

        # Assuming the check passes, we add a checkout block
        creator = last_checked_in_owner if last_checked_in_owner else 'System'  # System or last checked-in user, adjust as needed
        owner = password  # Assuming the checkout is done by the current password owner
        self.add_block(item_id_str, item_id_str, 'CHECKEDOUT', creator, owner, f"Item {item_id} checked out.")
        time_of_action = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()) + 'Z'
        print(f"Case: {case_id}")
        print(f"Checked out item: {item_id}")
        print("Status: CHECKEDOUT")
        print(f"Time of action: {time_of_action}")
        
    def checkin(self, item_id, password):
        item_id_str = str(item_id)
        item_found = False
        last_checked_out = False
        case_id = None  # Initialize case_id for later use
        last_checked_out_owner = None  # To capture the last checked out user
        for block in reversed(self.chain):
            block_data = block['data']
            header_data = self.unpack_header(block['header'])
            decrypted_item_id = decrypt(header_data['item_id'], self.encryption_key)
            #Bytes 
            numeric_regex = re.compile(b'\d')  # Matches numeric bytes
            index = len(decrypted_item_id)
            for i, byte in enumerate(decrypted_item_id):
                if not numeric_regex.match(bytes([byte])):  # Check each byte if it's not a digit
                    index = i
                    break
            valid_part = decrypted_item_id[:index]
            string_data = valid_part.decode('utf-8')
            decrypted_item_id = string_data

            if decrypted_item_id == item_id_str:
                item_found = True
                case_id = decrypt(header_data['case_id'].strip(), self.encryption_key) # Store case_id from the block
                print(block_data)
                # Check the current status of the item
                if 'CHECKEDOUT' in block_data:
                    last_checked_out = True
                    last_checked_out_owner = header_data['owner'].strip().decode()  # Capture the last owner who checked it out
                    break
                elif 'CHECKEDIN' in block_data:
                    last_checked_out = False

        if not item_found:
            print(f"Error: Item ID {item_id} does not exist in the blockchain.")
            sys.exit(1)
            return

        if not last_checked_out:
            print(f"Error: Item ID {item_id} is not in a check-out state and cannot be checked in.")
            sys.exit(1)
            return

        if not self.verify_password(password):
            print(f"Error: Invalid password for checking in item ID {item_id}.")
            sys.exit(1)
            return
        
        creator = last_checked_out_owner if last_checked_out_owner else 'Unknown'  # Use the last checked-out owner if available
        owner = password  # The current user checking in the item
        self.add_block(case_id, item_id_str, 'CHECKEDIN', creator, owner, f"Item {item_id} checked in.")

        time_of_action = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()) + 'Z'
        print(f"Case: {case_id}")
        print(f"Checked in item: {item_id}")
        print("Status: CHECKEDIN")
        print(f"Time of action: {time_of_action}")

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

    def load_blockchain(self):
        self.blocks = []
        if os.path.getsize(self.filename) == 0:
            return
        try:
            with open(self.filename, 'rb') as file:
                while True:
                    header = file.read(144)  
                    if not header or len(header) < 144:
                        break
                    unpacked = unpack_block(header)
                    data_len = unpacked[7]  # index of data_len
                    data = file.read(data_len)
                    self.blocks.append((header, data))
        except FileNotFoundError:
            print(f"Blockchain file {self.filename} not found. Starting new chain.")
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            sys.exit(1)

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

