from math import ceil
from pathlib import Path
from xml.etree import ElementTree as ET
import os
import binascii

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256, SHA3_256

from osnma import OSNMA, GST

from utils import binstr_to_bytes, get_hash_function_for_ECDSA

class OSNMA_Verifier:
    DEBUG = True
    def __init__(self, public_keys_dir) -> None:
        self.public_keys: dict[int, ECC.EccKey] = dict()
        self.__load_keys_from_directory(public_keys_dir)
        self.chain_per_dsm = dict()

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

        if not header.DSM_ID in self.chain_per_dsm:
            self.chain_per_dsm[header.DSM_ID] = dict()

        if 0 in self.chain_per_dsm[header.DSM_ID]:
            raise RuntimeError('Root key for this DSM already specified')
        else:
            self.chain_per_dsm[header.DSM_ID][0] = root_key_bytes

        print('DSM-KROOT Verification:')
        print()
        print(f'M({len(m_bytes) * 8} bits): 0x{m_bytes.hex()}')
        print(f'Sig({len(sig_bytes) * 8} bits): 0x{sig_bytes.hex()}')
        print(f'Root key({len(root_key_bytes) * 8} bits): 0x{root_key_bytes.hex()}')
        print(f'Pad({len(pad_bytes) * 8} bits): 0x{pad_bytes.hex()}')
        print(f'T({pad_len} bits): 0x{t.hex()[:pad_len // 4]}')
        print(f'Pad == T? {pad_bytes.hex() == t.hex()[:pad_len // 4]}')
        print(f'Signature Correct? {is_valid_sig}')

    def verify_TESLA_key(self, msg: OSNMA, dsm_h: OSNMA):
        if 0 not in self.chain_per_dsm[msg.DSM_ID] or not msg.GST_SF:
            return False
        
        GST_SF_i = msg.GST_SF.add_time(-1)
        key_index = (GST_SF_i.to_seconds() - dsm_h.GST_0.to_seconds()) // 30 + 1
        if self.DEBUG:
            print(key_index)
        root_key_bytes = self.chain_per_dsm[msg.DSM_ID][0]
        alpha_bytes = binstr_to_bytes(dsm_h.alpha)
        
        GST_SF_i = GST_SF_i.add_time(-30)
        GST_SF_i_bytes = binstr_to_bytes(GST_SF_i.to_binstr())
        current_key = binstr_to_bytes(msg.TESLA_key)
        prev_key = current_key

        hash_func = None

        if dsm_h.HF == 0:
            hash_func = SHA256
        elif dsm_h.HF == 2:
            hash_func = SHA3_256
        else:
            raise RuntimeError('Invalid hash type')
        i = key_index
        while i > 0:
            m = prev_key + GST_SF_i_bytes + alpha_bytes
            h = hash_func.new(m).digest()

            prev_key = h[:dsm_h.KS_Real // 8]
            if self.DEBUG:
                print(f'KEY {str(i - 1).zfill(3)}: {m.hex()} ,{prev_key.hex()} =? {root_key_bytes.hex()}')
            i -= 1
            if i == 1:
                GST_SF_i_bytes = binstr_to_bytes(dsm_h.GST_SF_K.to_binstr())
            else:
                GST_SF_i = GST_SF_i.add_time(-30)
                GST_SF_i_bytes = binstr_to_bytes(GST_SF_i.to_binstr())

        if prev_key == root_key_bytes:
            self.chain_per_dsm[msg.DSM_ID][key_index] = prev_key
            return True

    def test_verify(self, test_vector=None):
        MOCK_DSM_ID = 523
        if test_vector is None:
            test_vector = ('DA7A30B12CF716B00BA31C6D9B2D21DA', 1145, 86340)
        
        key_hex, key_WN_SF, key_TOW_SF = test_vector
        kroot_hex = '540A4830D139B710A4951D73C19DA22D'
        kroot_alpha_hex = '25D3964DA3A2'
        kroot_WN_SF = 1144
        kroot_TOW_SF = 604770
        KS = 128
        HF = 0

        tesla_osnma_mock = OSNMA(123, '0' * 120, '0' * 480, '0' * 360)
        kroot_osnma_mock = OSNMA(123, '0' * 120, '0' * 480, '0' * 360)
        
        self.chain_per_dsm[MOCK_DSM_ID] = {0: bytes.fromhex(kroot_hex)}
        
        kroot_osnma_mock.DSM_ID = MOCK_DSM_ID
        kroot_osnma_mock.GST_SF_K = GST(kroot_WN_SF, kroot_TOW_SF)
        kroot_osnma_mock.GST_0 = kroot_osnma_mock.GST_SF_K.add_time(30)
        kroot_osnma_mock.alpha = bin(int(kroot_alpha_hex, 16)).lstrip('0b').zfill(48)
        kroot_osnma_mock.KS_Real = KS
        kroot_osnma_mock.HF = HF

        tesla_osnma_mock.DSM_ID = MOCK_DSM_ID
        tesla_osnma_mock.GST_SF = GST(key_WN_SF, key_TOW_SF).add_time(1)
        tesla_osnma_mock.TESLA_key = bin(int(key_hex, 16)).lstrip('0b').zfill(KS)

        return self.verify_TESLA_key(tesla_osnma_mock, kroot_osnma_mock)

    def test_verify_all(self):
        old_flag = self.DEBUG
        self.DEBUG = False
        test_vectors = [
            ('DA7A30B12CF716B00BA31C6D9B2D21DA', 1145, 86340),
            ('8AC8F29832EE2EB6C6CCF08F6BD416FC', 1145, 86310),
            ('1256B87E98288C7657ACEB9E0291F523', 1145, 43200),
            ('281A4ED883D8CED907A10EDAED595A41', 1145, 43170),
            ('D7DEF915D2863BDEA81A9E2480FD4662', 1145, 330),
            ('E41CD213C9FE2D2E5B4127857FE3912C', 1145, 300),
            ('8A50D8884FD0A6298B380EBDEA7C45F2', 1145, 60),
            ('4235FF797019E2EFD3CB72780E861FED', 1145, 30),
            ('17B98FD42A4AFD0EA36D1DA2DE406B93', 1145, 0),
            ('540A4830D139B710A4951D73C19DA22D', 1144, 604770)
        ]

        res = []
        for t in test_vectors:
            res.append(self.test_verify(t))
        
        self.DEBUG = old_flag
        return all(res)
