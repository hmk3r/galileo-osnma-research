from ctypes import Union
from Crypto.Hash import SHA256, SHA512

def binstr_to_bytes(binstr):
    if len(binstr) % 8 != 0:
        raise Exception('Not a valid length')
    
    b = list()
    for x in [binstr[i:i + 8] for i in range(0, len(binstr), 8)]:
        b.append(int(x, 2))
    
    return bytes(b)

def bytes_to_binstr(b: bytes):
    lst = [bin(byte)[2:].zfill(8) for byte in b]
    return ''.join(lst)

def print_separator():
    print()
    print('-' * 20)
    print()

def get_hash_function_for_ECDSA(key_length_bytes):
    d = None
    if key_length_bytes == SHA256.digest_size:
        d = SHA256.new()
    elif key_length_bytes == SHA512.digest_size:
        d = SHA512.new()
    
    return d
