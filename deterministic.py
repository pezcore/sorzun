#pylint:disable=invalid-name

import hashlib
import hmac
from ecc import Point, G, N
from base58 import b58enc, b58dec

def hash160(msg):
    shadigest = hashlib.new('sha256', msg).digest()
    return hashlib.new('ripemd160', shadigest).digest()

def node_from_str(s):
    'Create and return a BIP32Node from a BIP32 xkey string'
    b = b58dec(s, True)
    c, Kbytes = b[-65:-33], b[-33:]
    depth, fingerp, index = b[4], b[5:9], int.from_bytes(b[9:13], 'big')
    if b[:4] == PrivBIP32Node.vbytes:
        assert Kbytes[0] == 0
        k = int.from_bytes(Kbytes, 'big')
        return PrivBIP32Node(k, c, depth, fingerp, index)
    elif b[:4] == PubBIP32Node.vbytes:
        K = Point.from_bytes(Kbytes)
        return PubBIP32Node(K, c, depth, fingerp, index)

class XPubKey:

    __slots__ = '_key', '_chaincode'

    def __init__(self, key, chaincode):
        self._key = key
        self._chaincode = chaincode

    @property
    def pubkey(self):
        'Public Key Point'
        return self._key

    def addr(self, vbyte=b'\0'):
        'Bitcoin P2PKH address'
        return b58enc(vbyte + self.id, True)

    @property
    def id(self):
        'key ID. HASH160 of compressed serialized PubKey'
        return hash160(bytes(self.pubkey))

    @property
    def chaincode(self):
        'Chain code'
        return self._chaincode

    @property
    def keydat(self):
        "Bytes of pub key"
        return bytes(self.pubkey)

    def ckd(self, i):
        'derive child XPubKey'
        assert i < 0x80000000, 'Cannot derive hardend child nodes from xpub'
        pl = bytes(self._key) + i.to_bytes(4, 'big')
        I = hmac.new(self._chaincode, pl, 'sha512').digest()
        IL, IR = I[:32], I[-32:]
        k = int.from_bytes(IL, 'big')
        return XPubKey(G * k  + self._key, IR)

    def derive(self, path):
        key = self
        for x in path.split('/'):
            x = int(x) if x[-1] != 'H' else int(x[:-1]) + 0x80000000
            key = key.ckd(int(x))
        return key

    def __str__(self):
        return ('chaincode: %s\nkeydata  : %s'
                % (self._chaincode.hex(), self.keydat.hex()))

class XPrivKey(XPubKey):

    @classmethod
    def from_entropy(cls, seed):
        'Create and return a XprivKey from entropy bytes'
        I = hmac.new(b'Bitcoin seed', seed, 'sha512').digest()
        k, c = int.from_bytes(I[:32], 'big'), I[32:]
        assert k and k < N, 'Invalid privkey, use  different entropy'
        return cls(k, c)

    def ckd(self, i):
        plbe = self.keydat if i >= 0x80000000 else bytes(self.pubkey)
        ibytes = i.to_bytes(4, 'big')
        I = hmac.new(self._chaincode, plbe + ibytes, 'sha512').digest()
        IL, IR = I[:32], I[-32:]
        k = (int.from_bytes(IL, 'big') + self._key) % N
        return XPrivKey(k, IR)

    def wif(self, vbyte=b'\x80'):
        'WIF string privkey'
        return b58enc(vbyte + self._key.to_bytes(32, 'big') + b'\x01', True)

    @property
    def pubkey(self):
        return G * self._key

    @property
    def keydat(self):
        return b'\0' + self._key.to_bytes(32, 'big')

class PubBIP32Node(XPubKey):

    vbytes = b'\x04\x88\xB2\x1E'

    def __init__(self, K, c, depth=0, parent_fingerprint=b'\0' * 4, index=0):
        super().__init__(K, c)
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.index = index

    def __bytes__(self):
        '''get the bytes serialization of the BIP32 payload serialization. This
        is the serialization format without the version bytes prefix.'''
        depth = self.depth.to_bytes(1, 'big')
        fingr = self.parent_fingerprint
        chnum = self.index.to_bytes(4, 'big')
        ccode = self._chaincode
        keydt = self.keydat
        return  depth + fingr + chnum + ccode + keydt

    def __str__(self):
        fmt = 'depth    : %d\nindex    : %d\nparent   : %s\n'
        s1 = fmt % (self.depth, self.index, self.parent_fingerprint.hex())
        return s1 + super().__str__() + ('\nBIP32 str: %s' % self.bip32_str())

    def bip32_str(self):
        return b58enc(self.vbytes + bytes(self), True)

    def ckd(self, i):
        xkey = super().ckd(i)
        depth = self.depth + 1
        finger = self.id[:4]
        kdat = xkey._key
        return type(self)(kdat, xkey.chaincode, depth, finger, i)

class PrivBIP32Node(PubBIP32Node, XPrivKey):

    vbytes = b'\x04\x88\xAD\xE4'

    def to_pub(self):
        'return PubBIP32Node Counterpart'
        return PubBIP32Node(self.pubkey, self.chaincode, self.depth,
                            self.parent_fingerprint, self.index)

    def bip32_str(self):
        pub = self.to_pub().bip32_str()
        prv = super().bip32_str()
        return f"{prv}\n           {pub}"
