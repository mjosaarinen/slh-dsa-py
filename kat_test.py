#   kat_test.py
#   2023-11-24  Markku-Juhani O. Saarinen < mjos@iki.fi>. See LICENSE

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from slh_dsa import *

class NIST_KAT_DRBG:
    """AES-256 CTR to extract "fake" DRBG outputs that are compatible with
        the randombytes() call in the NIST KAT testing suite."""

    def __init__(self, seed):
        self.seed_length = 48
        assert len(seed) == self.seed_length
        self.key = b'\x00'*32
        self.ctr = b'\x00'*16
        update = self.get_bytes(self.seed_length)
        update = bytes(a^b for a,b in zip(update,seed))
        self.key = update[:32]
        self.ctr = update[32:]

    def __increment_ctr(self):
        x = int.from_bytes(self.ctr, 'big') + 1
        self.ctr = x.to_bytes(16, byteorder='big')

    def get_bytes(self, num_bytes):
        tmp = b''
        cipher = AES.new(self.key, AES.MODE_ECB)
        while len(tmp) < num_bytes:
            self.__increment_ctr()
            tmp  += cipher.encrypt(self.ctr)
        return tmp[:num_bytes]

    def random_bytes(self, num_bytes):
        output_bytes = self.get_bytes(num_bytes)
        update = self.get_bytes(48)
        self.key = update[:32]
        self.ctr = update[32:]
        return output_bytes

#   test bench

def test_rsp(iut, katnum=100):
    """Generate NIST-styte KAT response strings."""
    fail    = 0
    drbg    = NIST_KAT_DRBG(bytes([i for i in range(48)]))
    kat     = f'# {iut.algname}\n\n'
    for count in range(katnum):
        print(f'# {count}/{katnum} {iut.stdname}')
        kat += f'count = {count}\n'
        seed = drbg.random_bytes(48)
        iut.set_random(NIST_KAT_DRBG(seed).random_bytes)
        kat += f'seed = {seed.hex().upper()}\n'
        mlen = 33 * (count + 1)
        kat += f'mlen = {mlen}\n'
        msg = drbg.random_bytes(mlen)
        kat += f'msg = {msg.hex().upper()}\n'
        (pk, sk) = iut.keygen()
        kat += f'pk = {pk.hex().upper()}\n'
        kat += f'sk = {sk.hex().upper()}\n'
        sm = iut.sign(msg, sk)
        kat += f'smlen = {len(sm)}\n'
        kat += f'sm = {sm.hex().upper()}\n'
        m2 = iut.open(sm, pk)
        if m2 == None or m2 != msg:
            fail += 1
            kat += f'(verify error)\n'
        kat += '\n'
    return kat

if (__name__ == "__main__"):
    katnum = 1
    for iut in SLH_DSA_ALL:
        kat = test_rsp(iut, katnum=katnum)
        md  = SHA256.new(kat.encode('ASCII')).hexdigest()
        print(f'{md} {iut.stdname} ({katnum})')

