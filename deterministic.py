#pylint:disable=invalid-name

import hashlib
import hmac
from ecc import Point, G, N
from base58 import b58enc, b58dec

XPRIV_B58 = b'\x04\x88\xAD\xE4'
XPUB_B58 = b'\x04\x88\xB2\x1E'

def hash160(msg):
    shadigest = hashlib.new('sha256', msg).digest()
    return hashlib.new('ripemd160', shadigest).digest()

class BIP32Node:

    __slots__ = 'xkey', 'depth', 'parent_fingerprint', 'index'

    def __init__(self, xkey, depth=0, parent_fingerprint=b'\0' * 4, index=0):
        self.xkey = xkey
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.index = index

    @classmethod
    def from_b58string(cls, b58string):
        'Create and return a BIP32Node from a BIP32 xkey string'
        b = b58dec(b58string, True)
        c, Kbytes = b[-65:-33], b[-33:]
        if b[:4] == XPRIV_B58:
            assert Kbytes[0] == 0
            xkey = XPrivKey(int.from_bytes(Kbytes, 'big'), c)
        elif b[:4] == XPUB_B58:
            K = Point.from_bytes(Kbytes)
            xkey = XPubKey(K, c)
        depth, fingerp, index = b[4], b[5:9], int.from_bytes(b[9:13], 'big')
        return cls(xkey, depth, fingerp, index)

    @classmethod
    def from_entropy(cls, entbyes):
        return cls(XPrivKey.from_entropy(entbyes))

    def __str__(self):
        vbytes = XPRIV_B58 if isinstance(self.xkey, XPrivKey) else XPUB_B58
        depth  = self.depth.to_bytes(1, 'big')
        fingr  = self.parent_fingerprint
        chnum  = self.index.to_bytes(4, 'big')
        ccode  = self.xkey.c
        keydat = self.xkey.keydat
        return b58enc(vbytes + depth + fingr + chnum + ccode + keydat, True)

    def ckd(self, i):
        xkey = self.xkey.ckd(i)
        depth = self.depth + 1
        finger = self.xkey.id[:4]
        return BIP32Node(xkey, depth, finger, i)

    def derive(self, path):
        key = self
        for x in path.split('/'):
            x = int(x) if x[-1] != 'H' else int(x[:-1]) + 0x80000000
            key = key.ckd(int(x))
        return key

class XPubKey:

    __slots__ = '_K', '_c'

    def __init__(self, K, c):
        self._K = K
        self._c = c

    @classmethod
    def from_string(cls, b58string):
        b = b58dec(b58string, True)
        c, Kbytes = b[-65:-33], b[-33:]
        K = Point.from_bytes(Kbytes)
        return cls(K, c)

    @property
    def K(self):
        'Public Key Point'
        return self._K

    @property
    def addr(self):
        'Bitcoin P2PKH address'
        return b58enc(b'\0' + self.id, True)

    @property
    def id(self):
        'key ID. HASH160 of compressed serialized PubKey'
        return hash160(self.K.to_bytes())

    @property
    def c(self):
        'Chain code'
        return self._c

    @property
    def keydat(self):
        return self.K.to_bytes()

    def ckd(self, i):
        'derive child XPubKey'
        assert i < 0x80000000, 'Cannot derive hardend child nodes from xpub'
        pl = self.K.to_bytes() + i.to_bytes(4, 'big')
        I = hmac.new(self.c, pl, 'sha512').digest()
        IL, IR = I[:32], I[-32:]
        k = int.from_bytes(IL, 'big')
        return XPubKey(G * k  + self.K, IR)


class XPrivKey(XPubKey):

    __slots__ = '_k', '_c'

    def __init__(self, k, c):
        self._k = k
        self._c = c

    @classmethod
    def from_string(cls, b58string):
        b = b58dec(b58string, True)
        c, kbytes = b[-65:-33], b[-33:]
        assert kbytes[0] == 0
        return cls(int.from_bytes(kbytes, 'big'), c)

    @classmethod
    def from_entropy(cls, seed):
        'Create and return a BIP32Node from entropy bytes'
        I = hmac.new(b'Bitcoin seed', seed, 'sha512').digest()
        k, c = int.from_bytes(I[:32], 'big'), I[32:]
        assert k and k < N, 'Invalid privkey, use  different entropy'
        return cls(k, c)

    def ckd(self, i):
        plbe = self.keydat if i >= 0x80000000 else (G * self.k).to_bytes()
        I = hmac.new(self.c, plbe + i.to_bytes(4, 'big'), 'sha512').digest()
        IL, IR = I[:32], I[-32:]
        k = (int.from_bytes(IL, 'big') + self.k) % N
        return XPrivKey(k, IR)

    @property
    def wif(self):
        'WIF string privkey'
        return b58enc(b'\x80' + self.k.to_bytes(32, 'big') + b'\x01', True)

    @property
    def k(self):
        'private key'
        return self._k

    @property
    def K(self):
        return G * self._k

    @property
    def keydat(self):
        return b'\0' + self.k.to_bytes(32, 'big')
