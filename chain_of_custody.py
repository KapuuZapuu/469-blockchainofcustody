#!/usr/bin/env python3
import os
import sys
import argparse
import struct
import uuid
import hashlib
from datetime import datetime, timezone
from collections import Counter
from Crypto.Cipher import AES

AES_KEY = b"R0chLi4uLi4uLi4="
CIPHER = AES.new(AES_KEY, AES.MODE_ECB)

DEFAULT_CHAIN_PATH = "blockchain_data.bin"
GENESIS_FMT = '<32sd32s32s12s12s12sI'
GENESIS_DATA = b'Initial block\x00'

ROLE_PASSWORDS = {
    'CREATOR':   os.environ.get('BCHOC_PASSWORD_CREATOR', ''),
    'POLICE':    os.environ.get('BCHOC_PASSWORD_POLICE', ''),
    'ANALYST':   os.environ.get('BCHOC_PASSWORD_ANALYST', ''),
    'EXECUTIVE': os.environ.get('BCHOC_PASSWORD_EXECUTIVE', ''),
    'LAWYER':    os.environ.get('BCHOC_PASSWORD_LAWYER', ''),
}

def get_prev_hash(path):
    data = open(path,'rb').read()
    size = struct.calcsize(GENESIS_FMT)
    offset = 0
    last = None
    while offset + size <= len(data):
        hdr = data[offset:offset+size]
        dlen = struct.unpack(GENESIS_FMT, hdr)[-1]
        last = data[offset:offset+size+dlen]
        offset += size + dlen
    return hashlib.sha256(last).digest() if last else b'\x00'*32

def create_genesis(path):
    hdr = struct.pack(
        GENESIS_FMT,
        b'\x00'*32,
        0.0,
        b'0'*32,
        b'0'*32,
        b'INITIAL'.ljust(12,b'\x00'),
        b'\x00'*12,
        b'\x00'*12,
        len(GENESIS_DATA)
    )
    with open(path,'wb') as f:
        f.write(hdr + GENESIS_DATA)

def is_valid_genesis(path):
    try:
        size = struct.calcsize(GENESIS_FMT)
        raw = open(path,'rb').read(size)
        if len(raw)!=size: return False
        prev, ts, c, i, st, a, o, dlen = struct.unpack(GENESIS_FMT,raw)
        return prev==b'\x00'*32 and st.rstrip(b'\x00')==b'INITIAL'
    except:
        return False

def get_role_by_password(pw):
    for r,p in ROLE_PASSWORDS.items():
        if pw==p: return r
    return None

def cmd_init(args):
    if len(sys.argv)!=2:
        print('usage: bchoc init',file=sys.stderr)
        sys.exit(1)
    path = os.environ.get('BCHOC_FILE_PATH',DEFAULT_CHAIN_PATH)
    if not os.path.exists(path):
        create_genesis(path)
        print('Blockchain file not found. Created INITIAL block.')
        sys.exit(0)
    if is_valid_genesis(path):
        print('Blockchain file found with INITIAL block.')
        sys.exit(0)
    print('Error: invalid blockchain file',file=sys.stderr)
    sys.exit(1)

def cmd_add(args):
    path = os.environ.get('BCHOC_FILE_PATH',DEFAULT_CHAIN_PATH)
    if not os.path.exists(path):
        create_genesis(path)
        print('Blockchain file not found. Created INITIAL block.')
        sys.exit(0)
    if not is_valid_genesis(path):
        print('Error: invalid blockchain file',file=sys.stderr)
        sys.exit(1)
    if args.password!=ROLE_PASSWORDS['CREATOR']:
        print('Error: invalid password',file=sys.stderr)
        sys.exit(1)

    # gather existing
    data = open(path,'rb').read()
    H = struct.calcsize(GENESIS_FMT)
    existing = {}
    off = 0
    while off+H<=len(data):
        _,_,_,item_b,st,_,_,dlen = struct.unpack(GENESIS_FMT,data[off:off+H])
        existing[item_b]=st.rstrip(b'\x00').decode()
        off += H+dlen

    for it in args.item:
        iid = int(it)
        raw16 = struct.pack('>I',iid).rjust(16,b'\x00')
        key = CIPHER.encrypt(raw16).hex().encode()
        if key in existing and existing[key] != 'REMOVED':
            print(f"Error: duplicate item {iid}",file=sys.stderr)
            sys.exit(1)

        prev = get_prev_hash(path)
        now = datetime.now(timezone.utc)
        ts = now.timestamp()
        iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        case_field = CIPHER.encrypt(uuid.UUID(args.case).bytes).hex().encode()
        item_field = key

        hdr = struct.pack(
            GENESIS_FMT,
            prev, ts,
            case_field, item_field,
            b"CHECKEDIN".ljust(12,b'\x00'),
            args.guid.encode().ljust(12,b'\x00'),
            b'\x00'*12,
            0
        )
        with open(path,'ab') as f:
            f.write(hdr)
        print(f"Added item: {iid}")
        print("Status: CHECKEDIN")
        print(f"Time of action: {iso}")

    sys.exit(0)

def cmd_checkout(args):
    path = os.environ.get('BCHOC_FILE_PATH',DEFAULT_CHAIN_PATH)
    role = get_role_by_password(args.password)
    if role is None:
        print('Error: invalid password',file=sys.stderr)
        sys.exit(1)

    data = open(path,'rb').read()
    H = struct.calcsize(GENESIS_FMT)
    raw16 = struct.pack('>I',int(args.item)).rjust(16,b'\x00')
    item_field = CIPHER.encrypt(raw16).hex().encode()

    off=0
    last_state=None
    case_field=None
    actor_bytes=None
    while off+H<=len(data):
        _,_,c,i,st,a,o,dlen = struct.unpack(GENESIS_FMT,data[off:off+H])
        if i==item_field:
            last_state=st.rstrip(b'\x00').decode()
            case_field=c
            actor_bytes=a
            last_owner=o
        off+=H+dlen

    if last_state is None:
        print(f"Error: item {args.item} not found",file=sys.stderr)
        sys.exit(1)
    if last_state!='CHECKEDIN':
        print(f"Error: cannot checkout item {args.item} (current: {last_state})",file=sys.stderr)
        sys.exit(1)

    prev = get_prev_hash(path)
    now = datetime.now(timezone.utc)
    ts = now.timestamp()
    iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    hdr = struct.pack(
        GENESIS_FMT,
        prev, ts,
        case_field, item_field,
        b"CHECKEDOUT".ljust(12,b'\x00'),
        actor_bytes,
        role.encode().ljust(12,b'\x00'),
        0
    )
    with open(path,'ab') as f:
        f.write(hdr)

    print(f"Checked out item: {args.item}")
    print("Status: CHECKEDOUT")
    print(f"Time of action: {iso}")
    sys.exit(0)

def cmd_checkin(args):
    path = os.environ.get('BCHOC_FILE_PATH',DEFAULT_CHAIN_PATH)
    role = get_role_by_password(args.password)
    if role is None:
        print('Error: invalid password',file=sys.stderr)
        sys.exit(1)

    data = open(path,'rb').read()
    H = struct.calcsize(GENESIS_FMT)
    raw16 = struct.pack('>I',int(args.item)).rjust(16,b'\x00')
    item_field = CIPHER.encrypt(raw16).hex().encode()

    off=0
    last_state=None
    case_field=None
    actor_bytes=None
    last_owner=None
    while off+H<=len(data):
        _,_,c,i,st,a,o,dlen = struct.unpack(GENESIS_FMT,data[off:off+H])
        if i==item_field:
            last_state=st.rstrip(b'\x00').decode()
            case_field=c
            actor_bytes=a
            last_owner=o
        off+=H+dlen

    if last_state is None:
        print(f"Error: item {args.item} not found",file=sys.stderr)
        sys.exit(1)
    if last_state!='CHECKEDOUT':
        print(f"Error: cannot checkin item {args.item} (current: {last_state})",file=sys.stderr)
        sys.exit(1)

    prev = get_prev_hash(path)
    now = datetime.now(timezone.utc)
    ts = now.timestamp()
    iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    hdr = struct.pack(
        GENESIS_FMT,
        prev, ts,
        case_field, item_field,
        b"CHECKEDIN".ljust(12,b'\x00'),
        actor_bytes,
        last_owner,        # preserve the last owner
        0
    )
    with open(path,'ab') as f:
        f.write(hdr)

    print(f"Checked in item: {args.item}")
    print("Status: CHECKEDIN")
    print(f"Time of action: {iso}")
    sys.exit(0)

def cmd_remove(args):
    path = os.environ.get('BCHOC_FILE_PATH',DEFAULT_CHAIN_PATH)
    role = get_role_by_password(args.password)
    if role is None:
        print('Error: invalid password',file=sys.stderr)
        sys.exit(1)

    data = open(path,'rb').read()
    H = struct.calcsize(GENESIS_FMT)
    raw16 = struct.pack('>I',int(args.item)).rjust(16,b'\x00')
    item_field = CIPHER.encrypt(raw16).hex().encode()

    off=0
    last_state=None
    case_field=None
    actor_bytes=None
    last_owner=None
    while off+H<=len(data):
        _,_,c,i,st,a,o,dlen = struct.unpack(GENESIS_FMT,data[off:off+H])
        if i==item_field:
            last_state=st.rstrip(b'\x00').decode()
            case_field=c
            actor_bytes=a
            last_owner=o
        off+=H+dlen

    if last_state is None:
        print(f"Error: item {args.item} not found",file=sys.stderr)
        sys.exit(1)
    if last_state!='CHECKEDIN':
        print(f"Error: cannot remove item {args.item} (current: {last_state})",file=sys.stderr)
        sys.exit(1)

    reason = args.why.upper()
    if reason not in ('DISPOSED','DESTROYED','RELEASED'):
        print('Error: invalid reason',file=sys.stderr)
        sys.exit(1)

    # for RELEASED we now auto-set to remover’s role
    if reason=='RELEASED':
        owner_field = role.encode().ljust(12,b'\x00')
    else:
        owner_field = last_owner

    prev = get_prev_hash(path)
    now = datetime.now(timezone.utc)
    ts = now.timestamp()
    iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    hdr = struct.pack(
        GENESIS_FMT,
        prev, ts,
        case_field, item_field,
        reason.encode().ljust(12,b'\x00'),
        actor_bytes,
        owner_field,
        0
    )
    with open(path,'ab') as f:
        f.write(hdr)

    print(f"Removed item: {args.item}")
    print(f"Status: {reason}")
    if reason=='RELEASED':
        print(f"Released to role: {role}")
    print(f"Time of action: {iso}")
    sys.exit(0)

def decode_case(c_b):
    if c_b==b'\x00'*32:
        return b'00000000-0000-0000-0000-000000000000'
    try:
        raw = CIPHER.decrypt(bytes.fromhex(c_b.decode()))
        return str(uuid.UUID(bytes=raw)).encode()
    except:
        return c_b

def decode_item(i_b):
    if i_b==b'\x00'*32:
        return b'0'
    try:
        raw = CIPHER.decrypt(bytes.fromhex(i_b.decode()))
        iid = struct.unpack('>I',raw[-4:])[0]
        return str(iid).encode()
    except:
        return i_b

def cmd_show(args):
    path = os.environ.get('BCHOC_FILE_PATH',DEFAULT_CHAIN_PATH)
    if not os.path.exists(path) or not is_valid_genesis(path):
        print('Error: invalid blockchain file',file=sys.stderr)
        sys.exit(1)

    data = open(path,'rb').read()
    H = struct.calcsize(GENESIS_FMT)

    if args.what=='cases':
        cases=set()
        off=0
        while off+H<=len(data):
            _,_,c,_,_,_,_,dlen = struct.unpack(GENESIS_FMT,data[off:off+H])
            if c!=b'0'*32:
                try:
                    raw = CIPHER.decrypt(bytes.fromhex(c.decode()))
                    cases.add(str(uuid.UUID(bytes=raw)))
                except:
                    pass
            off+=H+dlen
        for c in sorted(cases):
            print(c)
        sys.exit(0)

    if args.what=='items':
        if not args.case:
            print('Error: case required',file=sys.stderr)
            sys.exit(1)
        target = CIPHER.encrypt(uuid.UUID(args.case).bytes).hex().encode()
        items=set()
        off=0
        while off+H<=len(data):
            _,_,c,ib,_,_,_,dlen = struct.unpack(GENESIS_FMT,data[off:off+H])
            if c==target:
                try:
                    raw = CIPHER.decrypt(bytes.fromhex(ib.decode()))
                    items.add(struct.unpack('>I',raw[-4:])[0])
                except:
                    pass
            off+=H+dlen
        for i in sorted(items):
            print(i)
        sys.exit(0)

    if args.what=='history':
        # per-item history
        if args.case and args.item and args.password:
            if get_role_by_password(args.password) is None:
                print('Error: invalid password',file=sys.stderr)
                sys.exit(1)
            target_c = CIPHER.encrypt(uuid.UUID(args.case).bytes).hex().encode()
            raw16     = struct.pack('>I',int(args.item)).rjust(16,b'\x00')
            target_i  = CIPHER.encrypt(raw16).hex().encode()
            entries=[]
            off=0
            while off+H<=len(data):
                _,ts,c,ib,st,a,o,dlen = struct.unpack(GENESIS_FMT,data[off:off+H])
                if c==target_c and ib==target_i:
                    iso = datetime.fromtimestamp(ts,timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    entries.append((ts,iso,st.rstrip(b'\x00').decode(),a.rstrip(b'\x00').decode(),o.rstrip(b'\x00').decode()))
                off+=H+dlen

            # default chronological
            entries.sort(key=lambda x:x[0])
            if args.reverse:
                entries.reverse()
            if args.number:
                entries = entries[:args.number]

            for _,iso,st,ac,ow in entries:
                print(f"Time: {iso} | State: {st} | Actor: {ac} | Owner: {ow}")
            sys.exit(0)

        # global history
        if args.password and get_role_by_password(args.password):
            blocks=[]
            off=0
            while off+H<=len(data):
                prev,ts,c,i,st,a,o,dlen = struct.unpack(GENESIS_FMT,data[off:off+H])
                blocks.append({
                    'case_id':    decode_case(c),
                    'evidence_id':decode_item(i),
                    'state':      st.rstrip(b'\x00'),
                    'timestamp':  ts
                })
                off+=H+dlen
            # chronological
            blocks.sort(key=lambda x:x['timestamp'])
            if args.reverse:
                blocks.reverse()
            if args.number:
                blocks = blocks[:args.number]
            print(repr(blocks))
            sys.exit(0)

        print('Error: case, item, and password required',file=sys.stderr)
        sys.exit(1)

    print('Error: unknown show command',file=sys.stderr)
    sys.exit(1)

def cmd_summary(args):
    if not args.case:
        print('Error: case required',file=sys.stderr)
        sys.exit(1)
    path = os.environ.get('BCHOC_FILE_PATH',DEFAULT_CHAIN_PATH)
    if not os.path.exists(path) or not is_valid_genesis(path):
        print('Error: invalid blockchain file',file=sys.stderr)
        sys.exit(1)

    data = open(path,'rb').read()
    H = struct.calcsize(GENESIS_FMT)
    target = CIPHER.encrypt(uuid.UUID(args.case).bytes).hex().encode()

    counts = Counter()
    items = set()
    off=0
    while off+H<=len(data):
        _,_,c,i,st,a,o,dlen = struct.unpack(GENESIS_FMT,data[off:off+H])
        if c==target:
            state = st.rstrip(b'\x00').decode()
            counts[state]+=1
            # track unique evidence
            try:
                raw = CIPHER.decrypt(bytes.fromhex(i.decode()))
                iid = struct.unpack('>I',raw[-4:])[0]
            except:
                iid = 0
            items.add(iid)
        off+=H+dlen

    total = len(items)
    print(f"Case Summary for Case ID: {args.case}")
    print(f"Total Evidence Items: {total}")
    print(f"Checked In: {counts.get('CHECKEDIN',0)}")
    print(f"Checked Out: {counts.get('CHECKEDOUT',0)}")
    print(f"Disposed: {counts.get('DISPOSED',0)}")
    print(f"Destroyed: {counts.get('DESTROYED',0)}")
    print(f"Released: {counts.get('RELEASED',0)}")
    sys.exit(0)

def cmd_verify(args):
    path = os.environ.get('BCHOC_FILE_PATH',DEFAULT_CHAIN_PATH)
    if not os.path.exists(path) or not is_valid_genesis(path):
        print('Error: invalid genesis block',file=sys.stderr)
        sys.exit(1)

    data = open(path,'rb').read()
    H = struct.calcsize(GENESIS_FMT)
    blocks=[]
    off=0
    while off+H<=len(data):
        hdr = data[off:off+H]
        prev,ts,c,i,st,a,o,dlen = struct.unpack(GENESIS_FMT,hdr)
        raw_data = data[off+H:off+H+dlen]
        blocks.append((hdr+raw_data,{
            'prev':prev,'ts':ts,
            'state':st.rstrip(b'\x00').decode(),'item':i
        }))
        off+=H+dlen

    # genesis
    if blocks[0][1]['prev']!=b'\x00'*32 or blocks[0][1]['state']!='INITIAL':
        print('Error: invalid genesis block',file=sys.stderr)
        sys.exit(1)

    last_ts = blocks[0][1]['ts']
    last_states={}
    for idx in range(1,len(blocks)):
        raw,meta = blocks[idx]
        prev_raw,_ = blocks[idx-1]
        expected = hashlib.sha256(prev_raw).digest()
        if meta['prev']!=expected:
            print(f"Error: bad prev_hash at block {idx}",file=sys.stderr)
            sys.exit(1)
        if meta['ts']<last_ts:
            print(f"Error: timestamp rollback at block {idx}",file=sys.stderr)
            sys.exit(1)
        last_ts = meta['ts']
        item = meta['item']
        curr = meta['state']
        prev_state = last_states.get(item)
        allowed = {
            (None,'CHECKEDIN'),
            ('CHECKEDIN','CHECKEDOUT'),
            ('CHECKEDOUT','CHECKEDIN'),
            ('CHECKEDIN','DISPOSED'),
            ('CHECKEDIN','DESTROYED'),
            ('CHECKEDIN','RELEASED'),
        }
        if (prev_state,curr) not in allowed:
            print(f"Error: illegal transition {prev_state}->{curr} at block {idx}",file=sys.stderr)
            sys.exit(1)
        last_states[item]=curr

    sys.exit(0)

def main():
    p = argparse.ArgumentParser(prog='bchoc')
    sub = p.add_subparsers(dest='command')

    sub.add_parser('init')

    a = sub.add_parser('add')
    a.add_argument('-c','--case',    required=True)
    a.add_argument('-i','--item',    required=True,action='append')
    a.add_argument('-g','--guid',    required=True)
    a.add_argument('-p','--password',required=True)

    co = sub.add_parser('checkout')
    co.add_argument('-i','--item',    required=True)
    co.add_argument('-p','--password',required=True)

    ci = sub.add_parser('checkin')
    ci.add_argument('-i','--item',    required=True)
    ci.add_argument('-p','--password',required=True)

    rm = sub.add_parser('remove')
    rm.add_argument('-i','--item',    required=True)
    rm.add_argument('-y','--why',     required=True)
    rm.add_argument('-o','--owner')   # now ignored for RELEASED
    rm.add_argument('-p','--password',required=True)

    sh = sub.add_parser('show')
    sh.add_argument('what',choices=['cases','items','history'])
    sh.add_argument('-c','--case')
    sh.add_argument('-i','--item')
    sh.add_argument('-n','--number',type=int)
    sh.add_argument('-p','--password')
    sh.add_argument('--reverse',action='store_true')

    su = sub.add_parser('summary')
    su.add_argument('-c','--case',required=True)

    sub.add_parser('verify')

    args = p.parse_args()
    cmds = {
      'init':cmd_init,'add':cmd_add,'checkout':cmd_checkout,
      'checkin':cmd_checkin,'remove':cmd_remove,
      'show':cmd_show,'summary':cmd_summary,'verify':cmd_verify
    }
    if args.command in cmds:
        cmds[args.command](args)
    else:
        p.print_usage(sys.stderr)
        sys.exit(1)

if __name__=='__main__':
    main()
