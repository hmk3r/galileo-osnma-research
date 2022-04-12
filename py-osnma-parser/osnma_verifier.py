from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

from osnma import OSNMA

from utils import binstr_to_bytes

class OSNMA_Verifier:

    def __init__(self, public_key_pem) -> None:
        self.public_key = ECC.import_key(public_key_pem)
        self.verifier = DSS.new(self.public_key, 'fips-186-3')


    def _verify_sig(self, m: bytes, s: bytes):
        valid = False

        try:
            d = SHA256.new(m) 
            self.verifier.verify(d, s)
            valid = True
        except ValueError:
            valid = False

        return valid

    def verify(self, dsm: list, header: OSNMA):
        pad_len = header.L_dk - 104 - header.KS_Real - header.L_ds
        key_sig_pad = ''.join(dsm[1:])
        root_key = key_sig_pad[:header.KS_Real]
        sig = key_sig_pad[header.KS_Real:header.KS_Real + header.L_ds]
        pad = key_sig_pad[header.KS_Real + header.L_ds:header.KS_Real + header.L_ds + pad_len]

        sig_bytes = binstr_to_bytes(sig)
        root_key_bytes = binstr_to_bytes(root_key)
        pad_bytes = binstr_to_bytes(pad)

        m = header._hk_root_str[:8]
        m += header._hk_root_str[24:120]
        m += root_key

        m_bytes = binstr_to_bytes(m)
        t = SHA256.new(binstr_to_bytes(m + sig)).digest()


        is_valid_sig = self._verify_sig(m_bytes, sig_bytes)


        print(f'M({len(m_bytes) * 8} bits): 0x{m_bytes.hex()}')
        print(f'Sig({len(sig_bytes) * 8} bits): 0x{sig_bytes.hex()}')
        print(f'Root key({len(root_key_bytes) * 8} bits): 0x{root_key_bytes.hex()}')
        print(f'Pad({len(pad_bytes) * 8} bits): 0x{pad_bytes.hex()}')
        print(f'T({pad_len} bits): 0x{t.hex()[:pad_len // 4]}')
        print(f'Pad == T? {pad_bytes.hex() == t.hex()[:pad_len // 4]}')
        print(f'Signature Correct? {is_valid_sig}')
