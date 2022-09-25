from functools import total_ordering
from utils import binstr_to_bytes

@total_ordering
class GST:
    SECONDS_IN_HOUR = 3600
    SECONDS_IN_WEEK = 7 * 24 * SECONDS_IN_HOUR
    SF_FREQUENCY_SECONDS = 30

    def __init__(self, wn, tow) -> 'GST':
        self.wn = wn
        self.tow = tow

    def add_time(self, seconds) -> 'GST':
        new_tow = self.tow + seconds
        wn_adj = new_tow // GST.SECONDS_IN_WEEK

        new_wn = self.wn + wn_adj
        new_tow = new_tow % GST.SECONDS_IN_WEEK

        return GST(new_wn, new_tow)

    def normalise_to_SF_multiple(self) -> 'GST':
        return GST(self.wn, (self.tow // GST.SF_FREQUENCY_SECONDS) * GST.SF_FREQUENCY_SECONDS)

    def to_seconds(self) -> int:
        return self.wn * GST.SECONDS_IN_WEEK + self.tow

    def to_binstr(self):
        return f'{self.wn:012b}{self.tow:020b}'

    def __repr__(self) -> str:
        return f'WN: {self.wn}, TOW: {self.tow}'
    
    def __hash__(self) -> int:
        return self.to_seconds()

    def __eq__(self, __o: 'GST') -> bool:
        return self.to_seconds() == __o.to_seconds()
    
    def __gt__(self, __o: 'GST') -> bool:
        return self.to_seconds() > __o.to_seconds()


class OSNMA:
    KROOT_GST_TIME_DELTA = -30
    NMA_STATUS_ENUM = {
        0: "Reserved/Not in use",
        1: "Test",
        2: "Operational",
        3: "Don't use"
    }
    CHAIN_STATUS_ENUM = {
        0: "Reserved/Not in use",
        1: "Nominal",
        2: "End of chain",
        3: "Chain revoked",
        4: "New Public Key",
        5: "Public Key Revoked",
        6: "Reserved",
        7: "Reserved"
    }
    HF_ENUM = {
        0: "SHA-256",
        1: "Reserved",
        2: "SHA3-256",
        3: "Reserved"
    }
    MF_ENUM = {
        0: "HMAC-SHA-256",
        1: "CMAC-AES",
        2: "Reserved",
        3: "Reserved"
    }

    MACKLT_ENUM = {
        27: (
            ("00S", "00E", "00E", "00E", "12S", "00E"),
            ("00S", "00E", "00E", "04S", "12S", "00E")
        ),
        26: (
            ("00S", "00E", "00E", "00E", "00S", "00E", "00E", "12S", "00E", "00E"), 
            ("00S", "00E", "00E", "00S", "00E", "00E", "04S", "12S", "00E", "00E")
        ),
        31: (
            ("00S", "00E", "00E", "12S", "00E"),
            ("00S", "00E", "00E", "12S", "04S")
        ),
        33: (
            ("00S", "00E", "04S", "00E", "12S", "00E"),
            ("00S", "00E", "00E", "12S", "00E", "12E")
        )
    }
    TAG_INFO_SIZE = 16
    NB_OFFSET = 6

    @staticmethod
    def KEY_SIZE_ENUM(value):
        if value <= 4:
            return 96 + 8 * value
        elif value >= 5 or value <= 8:
            return (value - 5) * 32 + 160
        elif value >= 9:
            return "Reserved"

    @staticmethod
    def TS_ENUM(value):
        if value <= 4 or value >= 10:
            return "Reserved"
        elif value == 9:
            return 40
        else:
            return (value - 5) * 4 + 20

    LATEST_VALUES_PER_CHAIN = dict()

    def __init__(self, prn, hk_root_str, mack_str, gst_sf_str, navdata_str_list) -> None:
        self._hk_root_str = hk_root_str
        self._mack_str = mack_str
        self._gst_sf_str = gst_sf_str
        self.navdata = tuple(navdata_str_list)
        self.prn = int(prn)
        self.NMAS = int(hk_root_str[:2], 2)
        WN = int(gst_sf_str[:12], 2)
        TOW = int(gst_sf_str[12:], 2)
        self.GST_SF = GST(WN, TOW).add_time(-1).normalise_to_SF_multiple()
        if self.NMAS == 0:
            return
        self.CID = int(hk_root_str[2:4], 2)
        self.CPKS = int(hk_root_str[4:7], 2)
        self.NMA_header_reserved = int(hk_root_str[7:8], 2)
        self.DSM_ID = int(hk_root_str[8:12], 2)
        self.DSM_block_ID = int(hk_root_str[12:16], 2)
        self.WN = self.GST_SF.wn
        self.TOW = self.GST_SF.tow
        if self.DSM_ID > 11:
            raise NotImplementedError('DSK-PKR not implemented')
        if self.DSM_block_ID == 0:
            self.NB = int(hk_root_str[16:20], 2) + self.NB_OFFSET
            self.PKID = int(hk_root_str[20:24], 2)
            self.CIDKR = int(hk_root_str[24:26], 2)
            self.reserved_dsm_kroot = int(hk_root_str[26:28], 2)
            self.HF = int(hk_root_str[28:30], 2)
            self.MF = int(hk_root_str[30:32], 2)
            self.KS = int(hk_root_str[32:36], 2)
            self.TS = int(hk_root_str[36:40], 2)
            self.MACKLT = int(hk_root_str[40:48], 2)
            self.CHAIN_MACKLT_SEQ = OSNMA.MACKLT_ENUM.get(self.MACKLT, None)
            self.reserved_dsm_kroot_2 = int(hk_root_str[48:52], 2)
            self.WNK = int(hk_root_str[52:64], 2)
            self.TOWHK = int(hk_root_str[64:72], 2)
            self.TOWK = self.TOWHK * GST.SECONDS_IN_HOUR
            self.alpha = hk_root_str[72:120]
            self.GST_0 = GST(self.WNK, self.TOWK)
            self.GST_SF_K = self.GST_0.add_time(OSNMA.KROOT_GST_TIME_DELTA)
            self.KS_Real = self.KEY_SIZE_ENUM(self.KS)
            self.TS_Real = self.TS_ENUM(self.TS)
            self.number_of_tags = (480 - self.KS_Real) // (self.TS_Real + 16)

            if self.CIDKR not in OSNMA.LATEST_VALUES_PER_CHAIN:
                OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR] = dict()
            
            total_tag_size = self.TS_Real + OSNMA.TAG_INFO_SIZE
            OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR]['TS'] = self.TS
            OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR]['TS_Real'] = self.TS_Real
            OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR]['KS'] = self.KS
            OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR]['KS_Real'] = self.KS_Real
            OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR]['N_t'] = self.number_of_tags
            OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR]['TTS'] = total_tag_size
            OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR]['CHAIN_MACKLT_SEQ'] = self.CHAIN_MACKLT_SEQ
            OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR]['Key_Start'] = self.number_of_tags * total_tag_size
            OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR]['GST_0'] = self.GST_0
            OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR]['GST_SF_K'] = self.GST_SF_K
            OSNMA.LATEST_VALUES_PER_CHAIN[self.CIDKR]['alpha'] = self.alpha
        else:
            self.NB = None
            self.PKID = None
            self.CIDKR = None
            self.reserved_dsm_kroot = None
            self.HF = None
            self.MF = None
            self.KS = None
            self.TS = None
            self.MACKLT = None
            self.CHAIN_MACKLT_SEQ = None
            self.reserved_dsm_kroot_2 = None
            self.WNK = None
            self.TOWHK = None
            self.TOWK = None
            self.alpha = None
            self.GST_0 = None
            self.GST_SF_K = None
            self.KS_Real = None
            self.TS_Real = None
            self.number_of_tags = None
        
        if self.CID in OSNMA.LATEST_VALUES_PER_CHAIN:
            l_t = OSNMA.LATEST_VALUES_PER_CHAIN[self.CID]['TS_Real']
            l_k = OSNMA.LATEST_VALUES_PER_CHAIN[self.CID]['KS_Real']
            self.alpha = OSNMA.LATEST_VALUES_PER_CHAIN[self.CID]['alpha']

            self.number_of_tags = OSNMA.LATEST_VALUES_PER_CHAIN[self.CID]['N_t']
            total_tag_size = OSNMA.LATEST_VALUES_PER_CHAIN[self.CID]['TTS']
            ti_start = total_tag_size
            key_start = OSNMA.LATEST_VALUES_PER_CHAIN[self.CID]['Key_Start']

            self.GST_0 = OSNMA.LATEST_VALUES_PER_CHAIN[self.CID]['GST_0']
            self.GST_SF_K = OSNMA.LATEST_VALUES_PER_CHAIN[self.CID]['GST_SF_K']
            self.TAG_0 = mack_str[:l_t]
            self.MACSEQ = mack_str[l_t:l_t + 12]
            self.reserved_mack_2 = mack_str[l_t + 12:ti_start]

            self.CHAIN_MACKLT_SEQ = OSNMA.LATEST_VALUES_PER_CHAIN[self.CID]['CHAIN_MACKLT_SEQ']
            _tags_and_info = list() 
            for i in range(self.number_of_tags - 1):
                tag = mack_str[ti_start + i * total_tag_size:ti_start + i * total_tag_size + l_t]
                info_str = mack_str[ti_start + i * total_tag_size + l_t:ti_start + i * total_tag_size + l_t + OSNMA.TAG_INFO_SIZE]

                PRN_D = int(info_str[:8], 2)
                ADKD = int(info_str[8:12], 2)
                reserved_2 = info_str[12:16]
                _tags_and_info.append((tag, (PRN_D, ADKD, reserved_2, binstr_to_bytes(info_str))))

            self.tags_and_info = tuple(_tags_and_info)

            self.TESLA_key = mack_str[key_start:key_start + l_k]
            self.MACKs_padding = mack_str[key_start + l_k:]
        else:
            self.number_of_tags = None
            self.TAG_0 = None
            self.MACSEQ = None
            self.reserved_mack_2 = None
            self.tags_and_info = tuple()
            self.TESLA_key = None
            self.MACKs_padding = None

        self.TESLA_key_verified = False
        self.SF_MACKLT_SEQ_VERIFIED = False
        self.MACSEQ_verified = (False, False)
        self.navdata_verifications = list()

    def copy(self):
        return OSNMA(self.prn, self._hk_root_str, self._mack_str, self._gst_sf_str, self.navdata)

    def __repr__(self) -> str:
        s = f'-> PRN: {self.prn}\n'
        if self.NMAS == 0:
            return s + "  -> OSNMA Disabled for this satellite"
        s += f'  -> WN: {self.WN}\n'
        s += f'  -> TOW: {self.TOW}\n'
        s += f'  -> GST_SF: {self.GST_SF}\n'
        s += f'  -> HKROOT:\n'
        s += f'    -> NMA Status: {self.NMA_STATUS_ENUM.get(self.NMAS, None)}\n'
        s += f'    -> Chain Status: {self.CHAIN_STATUS_ENUM.get(self.CPKS, None)}\n'
        s += f'    -> Chain ID: {self.CID}\n'
        s += f'    -> Reserved: {self.NMA_header_reserved}\n'
        s += f'    -> DSM ID: {self.DSM_ID}\n'
        s += f'    -> DSM Block ID: {self.DSM_block_ID}\n'
        if self.DSM_block_ID == 0:
            s += f'    -> Nb. of Blocks (NB): {self.NB}\n'
            s += f'    -> Public Key ID (PKID): {self.PKID}\n'
            s += f'    -> Chain ID of KROOT (CIDKR): {self.CIDKR}\n'
            s += f'    -> Hash Function (HF): {self.HF_ENUM[self.HF]}\n'
            s += f'    -> MAC Function (MF): {self.MF_ENUM[self.MF]}\n'
            s += f'    -> Key Size (KS): {self.KEY_SIZE_ENUM(self.KS)}\n'
            s += f'    -> MAC Size (TS): {self.TS_ENUM(self.TS)}\n'
            s += f'    -> MAC Look-up Table (MACLT): {self.MACKLT}\n'
            s += f'    -> WNK: {self.WNK}\n'
            s += f'    -> TOWHK: {self.TOWHK}\n'
            s += f'    -> TOWK: {self.TOWK}\n'
            s += f'    -> GST_0: {str(self.GST_0)}\n'
            s += f'    -> GST_SF_K: {str(self.GST_SF_K)}\n'
            s += f'    -> Alpha(random): {self.alpha}\n'
        s += f'  -> MACK messages: '

        if self.TAG_0 is None:
            s += f'DSM-KROOT not received yet, no key/tag length available'
        else:
            s += '\n'
            s += f'    -> Tag_0: {hex(int(self.TAG_0, 2))}\n'
            s += f'    -> MACSEQ: {self.MACSEQ}, {"NOT " if  not self.MACSEQ_verified[0] else ""}Verified, with{"OUT" if not self.MACSEQ_verified[1] else ""} verified TESLA Key\n'
            s += f'    -> Reserved: {self.reserved_mack_2}\n'
            s += f'    -> Tag&Info\n'
            for tag, info in self.tags_and_info:
                s += f'      -> Tag: {hex(int(tag, 2))}; Info - PRN_D: {info[0]}, ADKD: {info[1]}, Reserved: {info[2]}\n'
            s += f'    -> TESLA Key: {hex(int(self.TESLA_key, 2))}, {"" if self.TESLA_key_verified else "NOT "}verified\n'
            s += f'    -> Padding: {self.MACKs_padding}\n'
            s += f'    -> Subframe MACK Sequence {"NOT " if not self.SF_MACKLT_SEQ_VERIFIED else ""}Verified\n'
        
        s += f'  -> Navdata Authentic: {not not self.navdata_verifications and all([x[-1] for x in self.navdata_verifications])}\n'
        for tag_type, verifier, tesla_key_verified, tag_verified in self.navdata_verifications:
            s += f'    -> Tag Type: {tag_type}, {"NOT " if not tag_verified else ""}Verified by PRN {str(verifier)}, with{"OUT" if not tesla_key_verified else ""} verified TESLA Key\n'
        return s
