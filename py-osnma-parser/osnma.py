from math import ceil

class OSNMA:
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

    @staticmethod
    def NMACK_ENUM(value):
        return 480 // value if value != 0 else "Reserved"

    def __init__(self, prn, hk_root_str, mack_str) -> None:
        self._hk_root_str = hk_root_str
        self._mack_str = mack_str
        self.prn = prn
        self.NMA_status = int(hk_root_str[:2], 2)
        self.CID = int(hk_root_str[2:4], 2)
        self.chain_status = int(hk_root_str[4:7], 2)
        self.NMA_header_reserved = int(hk_root_str[7:8], 2)
        self.DSM_ID = int(hk_root_str[8:12], 2)
        self.DSM_block_ID = int(hk_root_str[12:16], 2)
        if self.DSM_ID > 11:
            raise NotImplementedError('DSK-PKR is not yet specified')
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
            self.reserved_dsm_kroot_2 = int(hk_root_str[48:52], 2)
            self.KROOTWN = int(hk_root_str[52:64], 2)
            self.KROOTDOW = int(hk_root_str[64:72], 2)
            self.alpha = hex(int(hk_root_str[72:120], 2))

            self.KS_Real = self.KEY_SIZE_ENUM(self.KS)
            self.L_ds = 512
            self.L_dk = 104 * ceil(1 + (self.KS_Real + self.L_ds) / 104)

    
    def copy(self):
        return OSNMA(self.prn, self._hk_root_str, self._mack_str)

    def __repr__(self) -> str:
        s = f'-> PRN: {self.prn}\n'
        if self.NMA_status == 0:
            return s + "  -> OSNMA Disabled for this satelite"
        
        s += f'  -> HKROOT:\n'
        s += f'    -> NMA Status: {self.NMA_STATUS_ENUM.get(self.NMA_status, None)}\n'
        s += f'    -> Chain Status: {self.CHAIN_STATUS_ENUM.get(self.chain_status, None)}\n'
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
            s += f'    -> KROOT WN: {self.KROOTWN}\n'
            s += f'    -> KROOT DOW: {self.KROOTDOW}\n'
            s += f'    -> Alpha(random): {self.alpha}\n'

        return s
