"Module for generating, checking, and interpreting BIP39 mnemonics"

import hashlib
import os
from unicodedata import normalize

from .util import convertbits

class WordList(tuple):
    """
    A tuple word list with a compact repr. Useable as a full language word-list
    tuple but doesn't spam the screen when printed in documentation. This must
    be loaded from a text file.
    """

    def __new__(cls, fn):
        """
        Create a WordList from a text file. This is a tuple of each word in the
        file
        """
        fullpath = os.path.join(os.path.dirname(os.path.realpath(__file__)), fn)
        with open(fullpath, "r") as fd:
            return super().__new__(cls, fd.read().split())

    def __init__(self, fn):
        self.filename = fn

    def __repr__(self):
        return '<%s word list>' % self.filename

LANGS = ["english", "japanese", "french", "italian", "korean", "spanish"]
WORDLISTS = {lang : WordList(f"wordlists/{lang}.txt") for lang in LANGS}
WORDLIST_ENGLISH = WORDLISTS["english"]

class Mnemonic(tuple):
    """
    A BIP39 Mnemonic: a tuple of 3N spoken-language words for carrying seed
    entropy for generating deterministic wallets. The word sequence itself
    encodes a checksum for error detection. to_seed() provides the main
    mechanism to extract entropy bytes, optionally encrypted with password,
    from a Mnemonic.

    Mnemonics can be created directly from any tuple of strings, single strings
    of whitespace delimited words, or generated randomly using system entropy
    sources.
    """

    def __new__(cls, data=20, wl=WORDLIST_ENGLISH):
        """
        Create a new Mnemonic. Flexible interface takes 2 optional args.

        Parameters
        ----------
        data : flexible:
            Data to use to initialize the mnemonic.
            - int:      generate random n byte mnemonic (defalut=20)
            - btyes:    generate mnemonic using bytes directly as entropy
                        source
            - string:   interpret as an already-made space-delimited mnemonic
                        phrase
            - iterable: intrepret as iterable of mnemonic words
        wl : WordList
            WordList from used for mnemonic.
        """
        if isinstance(data, int):
            entropy = os.urandom(data)
            return cls.from_entropy(entropy, wl)
        if isinstance(data, bytes):
            return cls.from_entropy(data, wl)
        if isinstance(data, str):
            return cls.from_string(data, wl)
        return super().__new__(cls, data)

    def __init__(self, data=None, wl=WORDLIST_ENGLISH):
        self.wordlist = wl
        self.check()

    def __str__(self):
        return ' '.join(self)

    def to_seed(self, password=b''):
        'Return entropy bytes, optionally encrypted with a bytes password'
        mnemonic_bytes = str(self).encode()
        return hashlib.pbkdf2_hmac(hash_name='sha512',
                                   password=mnemonic_bytes,
                                   salt=b'mnemonic' + password,
                                   iterations=2048)

    def _bin_string(self):
        'return str of binary representation'
        return ''.join(bin(self.wordlist.index(x))[2:].zfill(11) for x in self)

    @classmethod
    def from_string(cls, string, wl=None):
        'Create Mnemonic from space delimited string'
        return cls(normalize("NFKD", string).split(), wl)

    @classmethod
    def from_entropy(cls, ent, wl=WORDLIST_ENGLISH):
        """
        Create a Mnemonic from entropy bytes using given wordlist (default
        English)
        """

        ENT = len(ent) * 8
        assert len(ent) % 4 == 0 and len(ent) >= 16 and len(ent) <= 32,\
            'entropy length must be integer multiple of 32 between 128-256'

        hash_ = hashlib.sha256(ent).digest()
        chk = convertbits(hash_, 8, 1)[:ENT // 32]
        entbits = convertbits(ent, 8, 1)
        full = entbits + chk
        l = convertbits(full, 1, 11)
        return cls(tuple(wl[x] for x in l), wl)

    def check(self):
        """
        Check if a Mnemonic instance is valid. Returns true iff the Mnemonic
        instance passes checksum verification.
        """
        if len(self) not in [12, 15, 18, 21, 24]:
            raise ValueError("Incorrect Mnemonic length. must be 12, 15, 18, "
                             "21, or 24 words"
            )
        l = [self.wordlist.index(x) for x in self]
        fullbits = convertbits(l, 11, 1)
        ENT = 32 * len(fullbits) // 33
        plbits, csbits = fullbits[:ENT], fullbits[ENT:]
        plbytes = bytes(convertbits(plbits, 1, 8))
        hash_ = hashlib.sha256(plbytes).digest()
        if not convertbits(hash_, 8, 1)[:len(csbits)] == csbits:
            raise ValueError("Bad mnemonic checksum")
