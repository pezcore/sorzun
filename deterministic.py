#pylint:disable=invalid-name

import hashlib
import hmac
from ecc import Point, G, N
from base58 import b58enc, b58dec

def hash160(msg):
    shadigest = hashlib.new('sha256', msg).digest()
    return hashlib.new('ripemd160', shadigest).digest()

class XPubKey:

    __slots__ = '_K', '_c'

    def __init__(self, K, c):
        self._K = K
        self._c = c

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
        return hash160(bytes(self.K))

    @property
    def c(self):
        'Chain code'
        return self._c

    @property
    def keydat(self):
        return bytes(self.K)

    def ckd(self, i):
        'derive child XPubKey'
        assert i < 0x80000000, 'Cannot derive hardend child nodes from xpub'
        pl = bytes(self.K) + i.to_bytes(4, 'big')
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
    def from_entropy(cls, seed):
        'Create and return a BIP32Node from entropy bytes'
        I = hmac.new(b'Bitcoin seed', seed, 'sha512').digest()
        k, c = int.from_bytes(I[:32], 'big'), I[32:]
        assert k and k < N, 'Invalid privkey, use  different entropy'
        return cls(k, c)

    def ckd(self, i):
        plbe = self.keydat if i >= 0x80000000 else bytes(G * self.k)
        I = hmac.new(self.c, plbe + i.to_bytes(4, 'big'), 'sha512').digest()
        IL, IR = I[:32], I[-32:]
        k = (int.from_bytes(IL, 'big') + self.k) % N
        return XPrivKey(k, IR)

    def to_pub(self):
        return XPubKey(self.K, self.c)

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

class PubBIP32Node(XPubKey):

    vbytes = b'\x04\x88\xB2\x1E'

    def __init__(self, K, c, depth=0, parent_fingerprint=b'\0' * 4, index=0):
        super().__init__(K, c)
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.index = index

    def _ser(self):
        '''get the bytes serialization of the BIP32 payload serialization. This
        is the serialization format without the version bytes prefix.'''
        depth = self.depth.to_bytes(1, 'big')
        fingr = self.parent_fingerprint
        chnum = self.index.to_bytes(4, 'big')
        ccode = self.c
        keydt = self.keydat
        return depth + fingr + chnum + ccode + keydt

    def __str__(self):
        return b58enc(self.vbytes + self._ser(), True)

    def ckd(self, i):
        xkey = super().ckd(i)
        depth = self.depth + 1
        finger = self.id[:4]
        kdat = xkey.k if isinstance(xkey, XPrivKey) else xkey.K
        return type(self)(kdat, xkey.c, depth, finger, i)

    def derive(self, path):
        key = self
        for x in path.split('/'):
            x = int(x) if x[-1] != 'H' else int(x[:-1]) + 0x80000000
            key = key.ckd(int(x))
        return key

class PrivBIP32Node(PubBIP32Node, XPrivKey):

    vbytes = b'\x04\x88\xAD\xE4'

    def to_pub(self):
        'return PubBIP32Node Counterpart'
        return PubBIP32Node(self.K, self.c, self.depth,
                            self.parent_fingerprint, self.index)

    def __str__(self):
        return super().__str__() + '\n' + str(self.to_pub())
