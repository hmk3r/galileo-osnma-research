from math import ceil
from pathlib import Path
from xml.etree import ElementTree as ET
import os

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

from osnma import OSNMA

from utils import binstr_to_bytes, get_hash_function_for_ECDSA

class OSNMA_Verifier:

    def __init__(self, public_keys_dir) -> None:
        self.public_keys: dict[int, ECC.EccKey] = dict()
        self.__load_keys_from_directory(public_keys_dir)

    def __load_keys_from_directory(self, public_keys_dir):
        for xml_file in Path(public_keys_dir).glob('*.xml'):
            pk_tree = ET.parse(str(xml_file)).getroot().find('body').find('PublicKey')
            pkid = int(pk_tree.find('PKID').text)
            pem_filename = pk_tree.find('File').text
            with open(os.path.join(public_keys_dir, pem_filename)) as f:
                self.public_keys[pkid] = ECC.import_key(f.read())

            print(f'Loaded Public Key - ID: {pkid}, Size: {self.public_keys[pkid].pointQ.size_in_bits()} bits, Curve {self.public_keys[pkid].curve}')

    def _verify_sig(self, m: bytes, s: bytes, public_key: ECC.EccKey):
        valid = False

        verifier = DSS.new(public_key, 'fips-186-3')
        d = get_hash_function_for_ECDSA(public_key.pointQ.size_in_bytes())
        d.update(m)

        try:
            verifier.verify(d, s)
            valid = True
        except ValueError:
            valid = False

        return valid

    def verify_kroot(self, dsm: list, header: OSNMA):
        public_key = self.public_keys[header.PKID]
        L_ds = public_key.pointQ.size_in_bits() * 2

        L_dk = 104 * ceil(1 + (header.KS_Real + L_ds) / 104)
        pad_len = L_dk - 104 - header.KS_Real - L_ds
        
        key_sig_pad = ''.join(dsm[1:])
        root_key = key_sig_pad[:header.KS_Real]
        sig = key_sig_pad[header.KS_Real:header.KS_Real + L_ds]
        pad = key_sig_pad[header.KS_Real + L_ds:header.KS_Real + L_ds + pad_len]

        sig_bytes = binstr_to_bytes(sig)
        root_key_bytes = binstr_to_bytes(root_key)
        pad_bytes = binstr_to_bytes(pad)

        m = header._hk_root_str[:8]
        m += header._hk_root_str[24:120]
        m += root_key

        m_bytes = binstr_to_bytes(m)
        t = SHA256.new(binstr_to_bytes(m + sig)).digest()


        is_valid_sig = self._verify_sig(m_bytes, sig_bytes, public_key)

        print('DSM-KROOT Verification:')
        print()
        print(f'M({len(m_bytes) * 8} bits): 0x{m_bytes.hex()}')
        print(f'Sig({len(sig_bytes) * 8} bits): 0x{sig_bytes.hex()}')
        print(f'Root key({len(root_key_bytes) * 8} bits): 0x{root_key_bytes.hex()}')
        print(f'Pad({len(pad_bytes) * 8} bits): 0x{pad_bytes.hex()}')
        print(f'T({pad_len} bits): 0x{t.hex()[:pad_len // 4]}')
        print(f'Pad == T? {pad_bytes.hex() == t.hex()[:pad_len // 4]}')
        print(f'Signature Correct? {is_valid_sig}')
