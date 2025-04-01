'''
Group 14
Ryan Leigh - 1224401633
person 1
person 2
'''

import sys
from ArgumentParser import ArgumentParser
import time
from datetime import datetime
import UUID
from enum import Enum
from struct import *

class State(Enum):
    INITIAL = b"INITIAL\0\0\0\0\0"
    CHECKEDIN = b"CHECKEDIN\0\0"
    CHECKEDOUT = b"CHECKEDOUT\0"
    DISPOSED = b"DISPOSED\0\0\0\0"
    DESTROYED = b"DESTROYED\0\0\0"
    RELEASED = b"RELEASED\0\0\0\0"

class Block():
    def __init__(
        previous_hash : bytes, case_id : bytes, 
        evidence_item_id : bytes, state : State,
        creator : str, owner : str, # needs to be Police, Lawyer, Analyst, Executive
        data_len : int, data : str
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

    def pack_data(self):
        return pack("32s d 32s 32s 12s 12s 12s I",
                    self.previous_hash,
                    self.timestamp,
                    self.case_id,
                    self.state,
                    self.creator,
                    self.owner)


















if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)

