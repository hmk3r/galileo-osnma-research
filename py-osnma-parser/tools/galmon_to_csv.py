import sys

from pwn import *
from navmon_pb2 import NavMonMessage
from google.protobuf.message import DecodeError

sock = None

def bytes_to_binstr(b: bytes):
    lst = [bin(byte)[2:].zfill(8) for byte in b]
    return ''.join(lst)

def read_protobuf_from_stdin():
    magic_value = sys.stdin.buffer.raw.read(4)
    
    if magic_value != b'bert':
        print(f'Bad magic value: {magic_value}', file=sys.stderr)
        
        return

    frame_length_bytes = sys.stdin.buffer.raw.read(2)
    frame_length = int.from_bytes(frame_length_bytes, 'big')

    frame_bytes = sys.stdin.buffer.raw.read(frame_length)

    navmon_msg = NavMonMessage()
    navmon_msg.ParseFromString(frame_bytes)

    return navmon_msg

def read_protobuf_from_sock():
    global sock
    data = sock.recvuntil(b'bert')[:-4]
    
    frame_length_bytes = data[:2]
    frame_length = int.from_bytes(frame_length_bytes, 'big')

    frame_bytes = data[2:2 + frame_length]
    navmon_msg = NavMonMessage()
    navmon_msg.ParseFromString(frame_bytes)

    return navmon_msg

def get_page_osnma(navmon_msg):
    if navmon_msg.gi.sigid != 1 or not navmon_msg.gi.HasField('reserved1'):
        return None

    navdata_binstr = bytes_to_binstr(navmon_msg.gi.contents)
    osnma_binstr = bytes_to_binstr(navmon_msg.gi.reserved1)

    res = {
        'prn': navmon_msg.gi.gnssSV,
        'word_type': int(navdata_binstr[:6], 2),
        'hkroot': osnma_binstr[:8],
        'mack': osnma_binstr[8:40],
        'navdata': navdata_binstr,
    }

    return res

def print_in_csv_format(page_dict):
    print(f"osnma,{page_dict['prn']},{page_dict['word_type']},{page_dict['hkroot']},{page_dict['mack']},{page_dict['navdata']}")

def get_one():
    navmon_msg = read_protobuf_from_sock()
    if not navmon_msg or navmon_msg.type != NavMonMessage.Type.GalileoInavType:
        return
    
    page_dict = get_page_osnma(navmon_msg)

    if not page_dict:
        return

    print_in_csv_format(page_dict)


def setup():
    global sock
    context.log_console = sys.stderr
    sock = remote('86.82.68.237', 10000)
    #skip any previous data in order to sync
    sock.recvuntil(b'bert')
    


def main():
    setup()

    while True:
        try:
            get_one()
        except DecodeError as e:
            print(str(e), file=sys.stderr)
            continue
        except KeyboardInterrupt:
            exit(0)


if __name__ == "__main__":
    main()
        
