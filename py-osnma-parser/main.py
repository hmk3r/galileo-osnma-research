import csv
import sys
from pprint import pp

from constants import GALILEO_INAV_MESSAGE_SEQUENCE

from osnma import OSNMA
from osnma_verifier import OSNMA_Verifier
from osnma_storage import OSNMA_Storage

from utils import print_separator

try:
    filename = sys.argv[1]
except:
    print('Filename not provided, using default ./data/osnma-capture.csv')
    filename = './data/osnma-capture.csv'

try:
    public_key_dir = sys.argv[2]
except:
    print('Public key directory not provided, using default ./osnma-keys')
    public_key_dir = './osnma-keys'

prn_messages = dict()

verifier = OSNMA_Verifier(public_key_dir)

# Read messages
with open(filename) as f:
    reader = csv.reader(f)
    for row in reader:
        _, prn, msg_type, hk_root, mack, navdata = row
        
        msg_type = int(msg_type)

        if prn not in prn_messages:
            prn_messages[prn] = list()

        prn_messages[prn].append((msg_type, hk_root, mack, navdata))

prn_messages_complete = dict()

# Get only complete messages
for prn, messages in prn_messages.items():
    subframes = []
    default_fields = {
        'hk_root': '',
        'mack': '',
        'GST_SF': ''
    }
    fields = default_fields.copy()
    expected_message_type_index = 0
    for msg_type, hk_root, mack, navdata in messages:

        if msg_type not in GALILEO_INAV_MESSAGE_SEQUENCE[expected_message_type_index]:
            expected_message_type_index = 0
            fields = default_fields.copy()
            continue
        
        if not fields['GST_SF'] and msg_type == 0 and navdata[6:8] == '10':
            fields['GST_SF'] = navdata[-32:]
            

        expected_message_type_index = (expected_message_type_index + 1) % len(GALILEO_INAV_MESSAGE_SEQUENCE) 
        fields['hk_root'] += hk_root
        fields['mack'] += mack

        if expected_message_type_index == 0 and len(fields['hk_root']) == 120 and len(fields['mack']) == 480:
            subframes.append(fields.copy())
            fields = default_fields.copy()

        

    prn_messages_complete[prn] = subframes

storage = OSNMA_Storage()
for prn, subframes in prn_messages_complete.items():
    for subframe in subframes:
        osnma = OSNMA(prn, subframe['hk_root'], subframe['mack'], subframe['GST_SF'])
        if osnma.NMAS == 0:
            continue
        storage.add(osnma)

print_separator()
pp(storage.DSMs)

print_separator()
print('DSM-PKR Verification:') # TODO
print_separator()

for DSM_id, c in storage.get_all():
    verifier.verify_kroot(c['DSMs'], c['header'])

# Maybe received in weird order, try to get the values by re-invoking the constructor 
for i in range(len(storage.osnma_messages)):
    osnma_message = storage.osnma_messages[i]
    
    if not osnma_message.TESLA_key or not osnma_message.tags_and_info:
        print('Missing TESLA key, attempting to repair')
        storage.osnma_messages[i] = osnma_message.copy()
        osnma_message = storage.osnma_messages[i]

print_separator()
print('TESLA Key Verification:')
print()

verifier.TAKE_SHORTCUTS = True
verifier.DEBUG = True
for msg in storage.osnma_messages:
    verifier.verify_TESLA_key(msg)

print('TESLA Key Verification Test:')
print()
print(f'Every key derived correctly? {verifier.test_verify_all()}')


print_separator()
print('MAC Look-up Table Verification:')
for msg in storage.osnma_messages:
    verifier.verify_MACKLT(msg)

print_separator()
print('MACSEQ Verification:')
print()
for msg in storage.osnma_messages:
    verifier.verify_MACSEQ(msg)

print_separator()
print('Tag Verification:') # TODO

for msg in storage.osnma_messages:
    print(msg)
