from types import ModuleType
from typing import Tuple, Union, Any
from collections import OrderedDict
from math import ceil
from pathlib import Path
from xml.etree import ElementTree as ET
import os
import binascii

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256, SHA3_256, HMAC, CMAC, SHA512
from Crypto.Cipher import AES

from osnma import OSNMA, GST

from utils import binstr_to_bytes, bytes_to_binstr, get_hash_function_for_ECDSA, pad_binstr_to_byte_length
from progress.bar import IncrementalBar


class Chain:
    def __init__(self) -> None:
        self.GST_SF_K: GST = None
        self._HF: ModuleType = None
        self.alpha: bytes = None
        self.keys: dict[int, bytes] = dict()
        # Floating keys, indexed by GST_SF_K, pointing to a tuple of the the key[0] and alpha[1] value
        self.floating_keys: dict[GST, Tuple[bytes, bytes]] = OrderedDict()
        self.MACKLT_SEQ = None
        self._MF_ID: int = None
        self.message_with_header = None

    @property
    def hash_func(self) -> Union[SHA256.SHA256Hash, SHA3_256.SHA3_256_Hash]:
        return self._HF.new()
    
    @hash_func.setter
    def hash_func(self, hf_id: int):
        if hf_id == 0:
            self._HF = SHA256
        elif hf_id == 2:
            self._HF = SHA3_256
        else:
            raise ValueError(f'Invalid value for hash function: {hf_id}')

    def get_mac_func(self, key: bytes) -> Union[HMAC.HMAC, CMAC.CMAC]:
        if self._MF_ID == 0:
            return HMAC.new(key, digestmod=SHA256)
        elif self._MF_ID == 1:
            return CMAC.new(key, ciphermod=AES)
        else:
            raise ValueError(f'Invalid value for mac function: {self._MF_ID}')

    def new_kroot(self, key: bytes, GST_SF_K: GST, hf_id: int, mf_id: int, alpha: bytes, maclt_seq: tuple, message_with_header: OSNMA):
        # if we already have a root key, archive it, along with the alpha value. 
        # Chain parameters are not changed on (floating) hkroot change
        if self.GST_SF_K is not None:
            self.floating_keys[self.GST_SF_K] = (self.keys[0], self.alpha)
        self.keys.clear()
        self.keys[0] = key
        self.hash_func = hf_id
        self.alpha = alpha
        self.GST_SF_K = GST_SF_K
        self.MACKLT_SEQ = maclt_seq
        self._MF_ID = mf_id
        self.message_with_header = message_with_header

class OSNMA_Verifier:
    class _Verification_Data:
        def __init__(self, tag_type: str, tag: bytes, message: bytes, navdata_osnma_ref: OSNMA) -> None:
            self.tag_type = tag_type
            self.tag = tag
            self.message = message
            self.navdata_osnma_ref = navdata_osnma_ref
        
        def __repr__(self) -> str:
            return f'Tag type: {self.tag_type}'
            

    DEBUG = True
    TAKE_SHORTCUTS = True

    ADKD_DATA_INDICES = {
        0: ((10, 6, -2), (0, 6, -2), (11, 6, 128), (1, 6, -2), (12, 6, -55)),
        4: ((2, 6, -3), (4, -42, 128)),
        12: ((10, 6, -2), (0, 6, -2), (11, 6, 128), (1, 6, -2), (12, 6, -55)),
    }

    @staticmethod
    def get_tag_type(adkd_or_str, prn_a, prn_d=None):
        if prn_d is None:
            prn_d = prn_a
        
        auth_type = 'Cross'
        if prn_a == prn_d:
            auth_type = 'Self'
        
        return f'{auth_type}-{str(adkd_or_str)}'


    def __init__(self, public_keys_dir) -> None:
        self.public_keys: dict[int, ECC.EccKey] = dict()
        self.__load_keys_from_directory(public_keys_dir)
        self.chains: dict[int, Chain] = dict()
        self.MACSEQ_verification_queue: dict[int, OSNMA] = dict()
        self.current_GST: GST = None
        # dict[prn, message] 
        self.prev_subframe_osnma: dict[int, OSNMA] = dict()
        self.current_subframe_osnma: dict[int, OSNMA] = dict()
        # dict[GST, dict[prn, (tag, message, osnma)]]
        self.waiting_for_key_at_GST: dict[GST, dict[int, OSNMA_Verifier._Verification_Data]] = dict()

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
        alpha_bytes = binstr_to_bytes(header.alpha)

        m = header._hk_root_str[:8]
        m += header._hk_root_str[24:120]
        m += root_key

        m_bytes = binstr_to_bytes(m)

        t = SHA256.new(binstr_to_bytes(m + sig)).digest()


        is_valid_sig = self._verify_sig(m_bytes, sig_bytes, public_key)

        if header.CIDKR not in self.chains:
            self.chains[header.CIDKR] = Chain()

        self.chains[header.CIDKR].new_kroot(root_key_bytes, header.GST_SF_K, header.HF, header.MF, alpha_bytes, header.CHAIN_MACKLT_SEQ, header)

        print('DSM-KROOT Verification:')
        print()
        print(f'M({len(m_bytes) * 8} bits): 0x{m_bytes.hex()}')
        print(f'Sig({len(sig_bytes) * 8} bits): 0x{sig_bytes.hex()}')
        print(f'Root key({len(root_key_bytes) * 8} bits): 0x{root_key_bytes.hex()}')
        print(f'Pad({len(pad_bytes) * 8} bits): 0x{pad_bytes.hex()}')
        print(f'T({pad_len} bits): 0x{t.hex()[:pad_len // 4]}')
        print(f'Pad == T? {pad_bytes.hex() == t.hex()[:pad_len // 4]}')
        print(f'Signature Correct? {is_valid_sig}')

    def verify_TESLA_key(self, msg: OSNMA):
        if not msg.TESLA_key:
            if self.DEBUG:
                print('No Tesla key in message')
            return False

        if 0 not in self.chains[msg.CID].keys or not msg.GST_SF:
            if self.DEBUG:
                print('No root key in this chain')
            return False
        
        uses_older_key = False

        if msg.GST_SF <= self.chains[msg.CID].GST_SF_K:
            uses_older_key = True

        root_key_bytes: bytes = None
        GST_0: GST = None
        alpha_bytes: bytes = None

        if uses_older_key:
            print(f'Key is associated with older (floating) HKROOT', end='')
            key_found = False
            for o_gst_sf_k, (o_key_bytes, o_alpha_bytes) in reversed(self.chains[msg.CID].floating_keys.items()):
                if o_gst_sf_k < msg.GST_SF:
                    root_key_bytes = o_key_bytes
                    GST_0 = o_gst_sf_k.add_time(30)
                    alpha_bytes = o_alpha_bytes
                    key_found = True
                    break

            if key_found:
                print(f' at GST_SF_K {str(GST_0.add_time(30))}')
            else:
                print(f', but it was not found in the floating HKROOT archive')
                return False
        else:
            root_key_bytes = self.chains[msg.CID].keys[0]
            GST_0 = self.chains[msg.CID].GST_SF_K.add_time(30)
            alpha_bytes = self.chains[msg.CID].alpha

        # The time between the messages has to be a 0 mod 30, which the documentation does not explicitly say
        GST_SF_i = msg.GST_SF
        key_index = (GST_SF_i.to_seconds() - GST_0.to_seconds()) // 30 + 1
        if self.DEBUG:
            print(f'Key index: {key_index}')
            print(f'CID: {msg.CID}')
        
        GST_SF_i = GST_SF_i.add_time(-30)
        GST_SF_i_bytes = binstr_to_bytes(GST_SF_i.to_binstr())
        current_key = binstr_to_bytes(msg.TESLA_key)
        prev_key = current_key

        i = key_index

        while i > 0:
            m = prev_key + GST_SF_i_bytes + alpha_bytes
            hf = self.chains[msg.CID].hash_func
            hf.update(m)
            h = hf.digest()

            prev_key = h[:len(root_key_bytes)]
            if self.DEBUG:
                print(f'KEY {str(i - 1).zfill(3)}: {m.hex()}, {prev_key.hex()} =? {root_key_bytes.hex()}, {str(GST_SF_i)}')
            
            i -= 1

            if i == 1:
                # GST_SF_K
                GST_SF_i = GST_0.add_time(-30)
            else:
                GST_SF_i = GST_SF_i.add_time(-30)
            
            GST_SF_i_bytes = binstr_to_bytes(GST_SF_i.to_binstr())
            
            if self.TAKE_SHORTCUTS and not uses_older_key and i in self.chains[msg.CID].keys and self.chains[msg.CID].keys[i] == prev_key:
                prev_key = root_key_bytes
                if self.DEBUG:
                    print('Chained reached a key that was verified; short-cutting')
                break
        
        msg.TESLA_key_verified = prev_key == root_key_bytes

        # For older HKROOTs, don't store another chain
        if msg.TESLA_key_verified and not uses_older_key:
            self.chains[msg.CID].keys[key_index] = current_key
        
        return msg.TESLA_key_verified
    
    def verify_MACKLT(self, msg: OSNMA):
        if not msg.tags_and_info or msg.CID not in self.chains:
            if self.DEBUG:
                print('Tags and info not available in this subframe')
            return False
    
        sf_macklt_seq = ["00S"]
        for tag, (prn_d, adkd, reserved, _) in msg.tags_and_info:
            auth_type = "S" if prn_d == msg.prn or prn_d == 255 else "E"
            sf_macklt_seq.append(f'{adkd:02d}{auth_type}')

        chain_macklt_seqs = self.chains[msg.CID].MACKLT_SEQ
        chain_macklt_seq = chain_macklt_seqs[0] if msg.TOW % 60 == 0 else chain_macklt_seqs[1]
        sf_macklt_seq = tuple(sf_macklt_seq)

        msg.SF_MACKLT_SEQ_VERIFIED = chain_macklt_seq == sf_macklt_seq

        return msg.SF_MACKLT_SEQ_VERIFIED

    def verify_MACSEQ(self, msg: OSNMA):
        if msg.CID not in self.chains:
            msg.MACSEQ_verified = (False, msg.TESLA_key_verified)
            return False
        
        if msg.prn not in self.MACSEQ_verification_queue:
            self.MACSEQ_verification_queue[msg.prn] = msg
            msg.MACSEQ_verified = (False, msg.TESLA_key_verified)
            return False
        
        subframe_to_verify = self.MACSEQ_verification_queue[msg.prn]

        chain_macklt_seqs = self.chains[subframe_to_verify.CID].MACKLT_SEQ
        chain_macklt_seq = chain_macklt_seqs[0] if subframe_to_verify.TOW % 60 == 0 else chain_macklt_seqs[1]

        m = subframe_to_verify.prn.to_bytes(1, 'big')
        m += binstr_to_bytes(subframe_to_verify.GST_SF.to_binstr())


        for i, slot in enumerate(chain_macklt_seq):
            if slot == 'FLX':
                m += subframe_to_verify.tags_and_info[i - 1][1][3]

        mac_key = binstr_to_bytes(msg.TESLA_key)

        mac_func = self.chains[msg.CID].get_mac_func(mac_key)

        mac_func.update(m)

        tag = mac_func.digest()
        trunc_tag = bytes_to_binstr(tag)[:12]

        verified = trunc_tag == subframe_to_verify.MACSEQ
        if self.DEBUG:
            print(f'PRN: {subframe_to_verify.prn}, {str(subframe_to_verify.GST_SF)}; {trunc_tag} =? {subframe_to_verify.MACSEQ} - {verified}')
            if subframe_to_verify.GST_SF.add_time(30) != msg.GST_SF:
                print(f'Failed because the subframe at time {str(subframe_to_verify.GST_SF.add_time(30))} is missing')

        subframe_to_verify.MACSEQ_verified = (
            verified,
            msg.TESLA_key_verified
        )

        self.MACSEQ_verification_queue[msg.prn] = msg

        return all(subframe_to_verify.MACSEQ_verified)

    def verify_tags(self, msg: OSNMA):
        if self.current_GST is None or msg.GST_SF > self.current_GST:
            self.current_GST = msg.GST_SF
            self.prev_subframe_osnma = self.current_subframe_osnma
            self.current_subframe_osnma = dict()
        
        self.current_subframe_osnma[msg.prn] = msg
        
        if msg.prn not in self.prev_subframe_osnma:
            return

        # Message generation

        # - Common parameters
        GST_SF =  msg.GST_SF.to_binstr()
        CTR = 1
        PRN_A = bytes_to_binstr(msg.prn.to_bytes(1, byteorder='big'))
        NMAS = bytes_to_binstr(msg.NMAS.to_bytes(1, 'big'))[-2:]
        # - Tag 0 message computation

        tag0_bytes = binstr_to_bytes(msg.TAG_0)
        tag0_navdata = ''
        for i, start, end in self.ADKD_DATA_INDICES[0]:
            tag0_navdata += self.prev_subframe_osnma[msg.prn].navdata[i][start:end]

        # - message
        tag0_message = PRN_A + GST_SF + bytes_to_binstr(CTR.to_bytes(1, byteorder='big')) + NMAS + tag0_navdata
        # - message + P
        tag0_message_bytes = binstr_to_bytes(pad_binstr_to_byte_length(tag0_message))

        key_time = msg.GST_SF.add_time(GST.SF_FREQUENCY_SECONDS)
        if key_time not in self.waiting_for_key_at_GST:
            self.waiting_for_key_at_GST[key_time] = dict()
        
        if msg.prn not in self.waiting_for_key_at_GST[key_time]:
            self.waiting_for_key_at_GST[key_time][msg.prn] = list()
        
        verification_data = self._Verification_Data(
            self.get_tag_type('Tag0', msg.prn),
            tag0_bytes,
            tag0_message_bytes,
            self.prev_subframe_osnma[msg.prn]
        )
        self.waiting_for_key_at_GST[key_time][msg.prn].append(verification_data)

        for tag, (prn_d, adkd, reserved, _) in msg.tags_and_info:
            CTR += 1
            if prn_d == 255:
                prn_d = msg.prn
            
            tag_type = self.get_tag_type(adkd, msg.prn, prn_d)
            if prn_d not in self.prev_subframe_osnma:
                if self.DEBUG:
                    print(f'No subframe from PRN {prn_d} at time {str(msg.GST_SF.add_time(-GST.SF_FREQUENCY_SECONDS))} for {tag_type} authentication')
                continue
            
            navdata_subframe = self.prev_subframe_osnma[prn_d]

            tag_bytes = binstr_to_bytes(tag)
            tag_navdata = ''
            for i, start, end in self.ADKD_DATA_INDICES[adkd]:
                tag_navdata += navdata_subframe.navdata[i][start:end]
            
            tag_message = bytes_to_binstr(prn_d.to_bytes(1, byteorder='big')) + \
                PRN_A + GST_SF + \
                bytes_to_binstr(CTR.to_bytes(1, byteorder='big')) + NMAS + tag_navdata
            
            tag_message_bytes = binstr_to_bytes(pad_binstr_to_byte_length(tag_message))
            
            key_time = msg.GST_SF.add_time(GST.SF_FREQUENCY_SECONDS)
            
            if adkd == 12:
                key_time = key_time.add_time(10 * GST.SF_FREQUENCY_SECONDS)

            if key_time not in self.waiting_for_key_at_GST:
                self.waiting_for_key_at_GST[key_time] = dict()
        
            if msg.prn not in self.waiting_for_key_at_GST[key_time]:
                self.waiting_for_key_at_GST[key_time][msg.prn] = list()

            verification_data = self._Verification_Data(
                tag_type,
                tag_bytes,
                tag_message_bytes,
                navdata_subframe
            )

            self.waiting_for_key_at_GST[key_time][msg.prn].append(verification_data)
            
        if msg.GST_SF not in self.waiting_for_key_at_GST:
            return
        
        if msg.prn not in self.waiting_for_key_at_GST[msg.GST_SF]:
            return
        
        for verification_data in self.waiting_for_key_at_GST[msg.GST_SF][msg.prn]:
            verification_data: OSNMA_Verifier._Verification_Data = verification_data
            mac_key = binstr_to_bytes(msg.TESLA_key)

            mac_func = self.chains[msg.CID].get_mac_func(mac_key)

            mac_func.update(verification_data.message)

            tag = mac_func.digest()
            tag_trunc = tag[:self.chains[msg.CID].message_with_header.TS_Real // 8]
            if self.DEBUG:
                print(f'{str(msg.GST_SF)}, Auth {msg.prn}, {verification_data.tag_type} - Computed tag: {tag_trunc.hex()}, Reference: {str(verification_data.tag.hex())} Equal? - {verification_data.tag == tag_trunc}')

            verification_data.navdata_osnma_ref.navdata_verifications.append(
                (verification_data.tag_type, msg.prn, msg.TESLA_key_verified, tag_trunc == verification_data.tag)
            )



    def brute_GST(self, msg: OSNMA):
        old_flag = self.DEBUG
        self.DEBUG = False

        old_gst_sf_k = self.chains[msg.CID].GST_SF_K

        victim = msg.copy()
        victim.GST_SF = self.chains[victim.CID].GST_SF_K.add_time(30)
        secs = pow(2, 20)
        sf_k_delta = 10
        self.chains[msg.CID].GST_SF_K = old_gst_sf_k.add_time((-sf_k_delta // 2) * 30)

        bar = IncrementalBar('BF Progress', suffix = '%(percent)d%% %(index)d/%(max)d [%(elapsed_td)s / %(eta_td)s]')
        for i in bar.iter(range(1, secs * 10 + 1)):
            if i % secs == 0:
                self.chains[msg.CID].GST_SF_K = self.chains[msg.CID].GST_SF_K.add_time(30)
                victim.GST_SF_K = self.chains[msg.CID].GST_SF_K.add_time(30)

            victim.GST_SF_K = victim.GST_SF_K.add_time(1)
            success = self.verify_TESLA_key(victim)
            if success:
                bar.finish()
                print(f'Correct Time Found!: ')
                print(f'SF_K: {str(self.chains[msg.CID].GST_SF_K)}')
                print(f'SF_msg: {str(victim.GST_SF_K)}')
                break
        
        self.chains[msg.CID].GST_SF_K = old_gst_sf_k
        self.DEBUG = old_flag


    def test_verify(self, test_vector=None):
        MOCK_CID = 523
        if test_vector is None:
            test_vector = ('D7DEF915D2863BDEA81A9E2480FD4662', 1145, 330)
        
        key_hex, key_WN_SF, key_TOW_SF = test_vector
        kroot_hex = '540A4830D139B710A4951D73C19DA22D'
        kroot_alpha_hex = '25D3964DA3A2'
        kroot_WN_SF = 1144
        kroot_TOW_SF = 604770
        KS = 128
        HF = 0
        MF = 0

        tesla_osnma_mock = OSNMA(123, '0' * 120, '0' * 480, '0' * 360, [])

        self.chains[MOCK_CID] = Chain()
        self.chains[MOCK_CID].new_kroot(
            bytes.fromhex(kroot_hex),
            GST(kroot_WN_SF, kroot_TOW_SF),
            HF,
            MF,
            bytes.fromhex(kroot_alpha_hex),
            OSNMA.MACKLT_ENUM.get(33, tuple()),
            tesla_osnma_mock
        )


        tesla_osnma_mock.CID = MOCK_CID
        tesla_osnma_mock.GST_SF = GST(key_WN_SF, key_TOW_SF)
        tesla_osnma_mock.TESLA_key = bin(int(key_hex, 16)).lstrip('0b').zfill(KS)

        return self.verify_TESLA_key(tesla_osnma_mock)

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
            ('17B98FD42A4AFD0EA36D1DA2DE406B93', 1145, 0)
        ]

        res = []
        for t in test_vectors:
            res.append(self.test_verify(t))
        
        self.DEBUG = old_flag
        return all(res)
