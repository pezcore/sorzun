"""
BIP32 library module. Provides classes for representing BIP32 key tree nodes.
Each node encapsulates key data and implements key derivation methods used in
BIP32
"""

import hashlib
import hmac
from functools import lru_cache
from collections import namedtuple
from os import urandom

from .ecc import Point, G, N
from .base58 import b58enc, b58dec
from .cashaddr import cashenc

def hash160(msg: bytes) -> bytes:
    """
    Compute standard HASH160 of message bytes. This is the RIPEMD160 hash of
    the SHA256 hash of they message bytes.

    args:
        msg: message bytes to hash

    returns:
        bytes
    """
    shadigest = hashlib.new('sha256', msg).digest()
    return hashlib.new('ripemd160', shadigest).digest()

def node_from_str(s: str):
    """
    Create and return a BIP32 Node from a BIP32 xkey string. This takes an
    string encoded according to the `BIP 32 Serialization Format`_ and returns
    the deserialized BIP32Node instance.  Detection of key type is automatic:
    ``xprv`` strings return :class:`PrivBIP32Node` and xpub strings return
    :class:`PubBIP32Node`. Only Bitcoin style (xpub and xpriv) formats are
    supported.

    .. _BIP 32 Serialization Format: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
    """
    b = b58dec(s, True)
    c, Kbytes = b[-65:-33], b[-33:]
    depth, fingerp, index = b[4], b[5:9], int.from_bytes(b[9:13], 'big')
    if b[:4] == PrivBIP32Node.vbytes:
        assert Kbytes[0] == 0
        k = int.from_bytes(Kbytes, 'big')
        return PrivBIP32Node(k, c, depth, fingerp, index)
    if b[:4] == PubBIP32Node.vbytes:
        K = Point.from_bytes(Kbytes)
        return PubBIP32Node(K, c, depth, fingerp, index)
    raise ValueError("bad BIP32 node encoding")

class ProtocolError(ValueError):
    pass

class XPubKey(namedtuple("XKey", ["keydata", "chaincode"])):

    """
    Representation of an extended public key. This consists of an ECDSA public
    key and a 256 bit chaincode. The primary use of the :class:`XPubKey` is key
    derivation. Each XPubKey can deterministically derive :math:`2^{31}`
    non-hardened child XPubKeys each with their own unique chaincode and ECDSA
    public key making them useful for building key trees. It is not possible to
    derive any hardened child XPubKeys or any :class:`XPrivKey` s from an
    :class:`XPubKey`.
    """
    __slots__ = ()

    def __new__(cls, k, cc=None):
        cc = urandom(32) if cc is None else cc
        return super().__new__(cls, k, cc)

    @property
    def pubkey(self):
        'Public Key Curve Point (ecc.Point)'
        return self.keydata

    def addr(self, vbyte: bytes = b'\0') -> str:
        """
        Bitcoin P2PKH address with version byte `vbyte`. A ``str`` is returned
        using base58check encoding
        """
        return b58enc(vbyte + self.id, True)

    def cashaddr(self):
        "Bitcoin Cash cashaddr string"
        return cashenc(b"\0" + self.id)

    @property
    def id(self):
        'Key ID. HASH160 of compressed serialized PubKey (bytes)'
        return hash160(bytes(self.pubkey))

    def __bytes__(self):
        "SEC1 compressed-form byte encoding of the ECDSA pubkey (bytes)"
        return bytes(self.pubkey)


    def ckd(self, i: int) -> "XPubKey":
        """
        Derive and return the `i`:superscript:`th` indexed child
        :class:`XPubKey`. Since children with index higher than ``0x80000000``
        are hardened, `i` must be less than ``0x80000000`` because XPubs can't
        derive hardened children.
        """
        if not i < 0x80000000:
            raise ProtocolError("It is disallowed to derive a hardend subkey "
                "from public node")
        pl = bytes(self.pubkey) + i.to_bytes(4, 'big')
        I = hmac.new(self.chaincode, pl, 'sha512').digest()
        IL, IR = I[:32], I[-32:]
        k = int.from_bytes(IL, 'big')
        return XPubKey(G * k  + self.keydata, IR)

    def derive(self, path):
        """
        Given a string, `path`, traverse the key tree deriving each subsequent
        node. Path is specified as strings using POSIX-like format:

        .. code-block::

            a[H]/b[H]/c[H]/d[H]/...

        where a,b,c,d.... are positive integers each optionally suffixed with
        'H'. The integers are the child indices at each level and the 'H'
        signifies that a node is hardened.
        """
        if not path:
            return self
        key = self
        for x in path.split('/'):
            x = int(x) if x[-1] != 'H' else int(x[:-1]) + 0x80000000
            key = key.ckd(int(x))
        return key

    def __str__(self):
        cc = self.chaincode.hex().upper()
        keydat = bytes(self).hex().upper()
        return f"chaincode: {cc}\nkeydata  : {keydat}"

class XPrivKey(XPubKey):
    """
    Similar to XPubKey, except that the encapsulated key is an ECDSA private
    key. This extends XPubKey with private key only capabilities such as
    exposing WIF. Also, unlike XPubKey, XPrivKey **is** capable of deriving
    hardened children (so it can derive all :math:`2^{32}` child keys)

    .. warning::
        If this Key is derived from a non-hardened parent node, and the
        non-hardened parent node's chaincode is known, then leaking this node's
        private key also leaks the parent's private key and therefore the
        entire key tree rooted there.
    """

    __slots__ = ()

    @classmethod
    def from_entropy(cls, seed):
        """
        Create and return a XprivKey from entropy bytes using the BIP32
        standard private key derivation protocol.
        """
        I = hmac.new(b'Bitcoin seed', seed, 'sha512').digest()
        k, c = int.from_bytes(I[:32], 'big'), I[32:]
        assert k and k < N, 'Invalid privkey, use  different entropy'
        return cls(k, c)

    def ckd(self, i: int):
        """
        Derive and return the `i`:superscript:`th` child XPrivKey.

        args:
            i: child key index

        returns:
            A new XPrivKey
        Note:
            indices over ``0x80000000`` are hardened children.
        """
        plbe = (XPrivKey.__bytes__(self) if i >= 0x80000000
                else bytes(self.pubkey))
        ibytes = i.to_bytes(4, 'big')
        I = hmac.new(self.chaincode, plbe + ibytes, 'sha512').digest()
        IL, IR = I[:32], I[-32:]
        k = (int.from_bytes(IL, 'big') + self.keydata) % N
        return XPrivKey(k, IR)

    def wif(self, vbyte=b'\x80'):
        'WIF string privkey'
        return b58enc(vbyte + self.keydata.to_bytes(32, 'big') + b'\x01', True)

    @property
    @lru_cache()
    def pubkey(self):
        return G * self.keydata

    def __bytes__(self):
        """
        The byte 0x00 followed by the 32-byte big endian bytes representation
        of the private key
        """
        return b'\0' + self.keydata.to_bytes(32, 'big')

_pubnodebase = namedtuple("PubBIP32",
    "keydata, chaincode, depth, parent_fingerprint, index")
class PubBIP32Node(_pubnodebase, XPubKey):
    """
    Same as a XPubKey but it also tracks some additional tree position data
    during key derivation and implementes BIP32-standardized serialization
    format.
    """

    __slots__ = ()
    vbytes = b'\x04\x88\xB2\x1E'    # bitcoin xpubkey version bytes in BIP32

    def __new__(cls, kd, cc, depth=0, parent_fingerprint=b'\0' * 4, index=0):
        """
        Initialize a new PubBIP32Node with

        Parameters
        ----------
        keydata : pubkey
        depth : int, optional
            tree depth of this node from the master tree root.
        parent_fingerprint : bytes
            first four bytes of the parent nodes id (address)
        index : int, optional
            child index
        """
        return super().__new__(cls, kd, cc, depth, parent_fingerprint, index)

    def __bytes__(self):
        " Return the bytes of the BIP32 extended key serialization."
        depth = self.depth.to_bytes(1, 'big')
        fingr = self.parent_fingerprint
        chnum = self.index.to_bytes(4, 'big')
        ccode = self.chaincode
        keydt = super().__bytes__()
        return  self.vbytes + depth + fingr + chnum + ccode + keydt

    def __str__(self):
        fingr = self.parent_fingerprint.hex().upper()
        cc = self.chaincode.hex().upper()
        keydat = super().__bytes__().hex().upper()
        return (f"depth    : {self.depth:d}\nindex    : {self.index:08X}\n"
                f"parent   : {fingr}\nchaincode: {cc}\nkeydata  : {keydat}\n"
                f"BIP32 str: {self.xpub}")

    @property
    def xpub(self):
        "BIP32 xpub string encoding"
        return b58enc(bytes(self), True)

    def ckd(self, i):
        xkey = super().ckd(i)
        depth = self.depth + 1
        finger = self.id[:4]
        return type(self)(*xkey, depth, finger, i)

class PrivBIP32Node(PubBIP32Node, XPrivKey):
    """
    Same as a XPrivKey but it also tracks some additional tree position data
    during key derivation and implementes BIP32-standardized serialization
    format.

    .. inheritance-diagram:: PrivBIP32Node
       :parts: 1
    """
    __slots__ = ()
    vbytes = b'\x04\x88\xAD\xE4'

    @property
    def xpub(self):
        return PubBIP32Node(self.pubkey, *self[1:]).xpub

    @property
    def xprv(self):
        return b58enc(bytes(self), True)

    def __str__(self):
        return super().__str__() + f"\n         : {self.xprv}"
