def binstr_to_bytes(binstr):
    if len(binstr) % 8 != 0:
        raise Exception('Not a valid length')
    
    b = list()
    for x in [binstr[i:i + 8] for i in range(0, len(binstr), 8)]:
        b.append(int(x, 2))
    
    return bytes(b)

def print_separator():
    print()
    print('-' * 20)
    print()
