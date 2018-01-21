#pylint: disable=invalid-name

import hashlib
import os

wlfile = open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
              'english.txt'), 'r')
wltxt = wlfile.read()
wordlist_english = wltxt.split('\n')

class Mnemonic(tuple):

    def __new__(cls, *args):
        if not args:
            entropy = os.urandom(20)
            return cls.from_entropy(entropy)
        else:
            return super().__new__(cls, *args)

    def __str__(self):
        return ' '.join(self)

    def to_seed(self, password=b''):
        mnemonic_bytes = str(self).encode()
        return hashlib.pbkdf2_hmac(hash_name='sha512',
                                   password=mnemonic_bytes,
                                   salt=b'mnemonic' + password,
                                   iterations=2048)

    def bin_string(self, wl=wordlist_english):
        return ''.join(bin(wl.index(x))[2:].zfill(11) for x in self)

    @classmethod
    def from_string(cls, string):
        return cls(string.split(' '))

    @classmethod
    def from_entropy(cls, ent, wl=wordlist_english):
        assert len(ent) % 4 == 0 and len(ent) >= 16 and len(ent) <= 32,\
            'entropy lenght must be integer multiple of 32 between 128-256'
        cs = hashlib.sha256(ent).digest()
        csbits = bin(int.from_bytes(cs, 'big'))[2:].zfill(0x100)
        entbits = bin(int.from_bytes(ent, 'big'))[2:].zfill(len(ent) * 8)
        b = entbits + csbits[:len(ent) * 8 // 28]
        l = len(b) // 11
        return cls(wl[int(b[i * 11:(i + 1) * 11], 2)] for i in range(l))

    def check(self, wl=wordlist_english):
        if len(self) % 3 > 0:
            return False
        try:
            b = self.bin_string()
        except:
            return False
        l = len(b)
        d, h = b[:l // 33 * 32], b[-l // 33:]
        nd = int(d, 2).to_bytes(len(d) // 8, 'big')
        hexdig = hashlib.sha256(nd).hexdigest()
        csbits = bin(int(hexdig, 16))[2:].zfill(0x100)[:l // 33]
        return h == csbits
