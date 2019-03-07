"Module for generating, checking, and interpreting BIP39 mnemonics"

import hashlib
import os
from unicodedata import normalize as _normalize

from .util import convertbits

class _WordList(tuple):
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
        return self.__class__.__name__ + f"(\"{self.filename}\")"

LANGS = ["english", "japanese", "french", "italian", "korean", "spanish"]
WORDLISTS = {lang : _WordList(f"wordlists/{lang}.txt") for lang in LANGS}

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

    def __new__(cls, data=20, lang="english"):
        """
        Create a new Mnemonic. Flexible interface takes 2 optional args.
        Automatically performs validation check, raises Exception describing
        invalidity in any case where a non-valid BIP32 Mnemonic instance
        initialization is attempted.

        A valid BIP32 mnemonic must have 128, 160, 192, 224, or 256 bits of
        entropy and, must contain only words from one the six standard language
        word lists, and must pass the checksum (last word contains checksum
        data that most agree with the sequence of other words

        Parameters
        ----------
        data : flexible:
            Data to use to initialize the mnemonic.
            - int:      generate random n byte mnemonic (default=20)
            - bytes:    generate mnemonic using bytes directly as entropy
                        source
            - str:      interpret as an already-made space-delimited mnemonic
                        phrase
            - iterable: interpret as iterable of mnemonic words
        lang : str
            language to use for wordlist
        """
        if isinstance(data, int):
            entropy = os.urandom(data)
            return cls._from_entropy(entropy, lang)
        if isinstance(data, bytes):
            return cls._from_entropy(data, lang)
        if isinstance(data, str):
            return cls(_normalize("NFKD", data).split(), lang)
        return super().__new__(cls, data)

    def __init__(self, data=None, lang="english"):
        self.language = lang
        self.wordlist = WORDLISTS[lang]
        self._check()

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
    def _from_entropy(cls, ent, lang):
        """
        Create a Mnemonic from entropy bytes using given wordlist (default
        English)
        """

        wl = WORDLISTS[lang]
        ENT = len(ent) * 8
        assert len(ent) % 4 == 0 and len(ent) >= 16 and len(ent) <= 32,\
            'entropy length must be integer multiple of 32 between 128-256'

        hash_ = hashlib.sha256(ent).digest()
        chk = convertbits(hash_, 8, 1)[:ENT // 32]
        entbits = convertbits(ent, 8, 1)
        full = entbits + chk
        l = convertbits(full, 1, 11)
        return cls(tuple(wl[x] for x in l), lang)

    def _check(self):
        """
        Check if a Mnemonic instance is valid. Checks checksum and other
        validity criteria specified by BIP39. Raises descriptive exceptions on
        failure.
        """
        if len(self) not in [12, 15, 18, 21, 24]:
            raise ValueError("Incorrect Mnemonic length. must be 12, 15, 18, "
                             "21, or 24 words"
            )

        if not all(x in self.wordlist for x in self):
            baditems = frozenset(self) - frozenset(self.wordlist)
            raise ValueError(
                "Bad word(s): the following words are not "
                "present in the wordlist: " f"{list(baditems)}"
            )

        l = [self.wordlist.index(x) for x in self]
        fullbits = convertbits(l, 11, 1)
        ENT = 32 * len(fullbits) // 33
        plbits, csbits = fullbits[:ENT], fullbits[ENT:]
        plbytes = bytes(convertbits(plbits, 1, 8))
        hash_ = hashlib.sha256(plbytes).digest()
        if not convertbits(hash_, 8, 1)[:len(csbits)] == csbits:
            raise ValueError("Bad mnemonic checksum")
