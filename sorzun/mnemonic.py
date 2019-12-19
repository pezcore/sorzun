"""
Module for generating, checking, and interpreting BIP39_ mnemonics

.. _BIP39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
"""

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

#: Languages supported by this module
LANGS = ["english", "japanese", "french", "italian", "korean", "spanish"]
WORDLISTS = {lang : _WordList(f"wordlists/{lang}.txt") for lang in LANGS}

class Mnemonic(tuple):
    """
    A BIP39_ Mnemonic: a tuple of :math:`3N` spoken-language words for carrying
    seed entropy for generating deterministic wallets. The word sequence itself
    encodes a checksum for error detection. :meth:`~Mnemonic.to_seed` provides
    the interface to extract the entropy bytes, optionally decrypted with
    password, from a Mnemonic. These bytes comprise the entropy carried by the
    :class:`Mnemonic` instance and are either 128, 160, 192, 224, or 256 bits
    long depending on the length of the mnemonic.

    :class:`Mnemonic` instances can be created directly from an iterable of
    strings, a single string of whitespace-delimited words, an existing entropy
    source, or generated randomly using system entropy sources. When creating a
    new :class:`Mnemonic` instance from an existing string or iterable of
    strings, the source data must be consistent with the BIP39 Mnemonic
    validity requirements, namely that the there must be 12, 15, 18, 21, or 24
    words, each word must be a member of the wordlist specified by `lang`, and
    the checksum must pass check.  All instances of :class:`Mnemonic` are
    automatically validity-checked at construction time for these validity
    critera making it difficult to have an invalid :class:`Mnemonic` instance.
    If :class:`Mnemonic` is called with invalid initialization data, an
    Exception with a descriptive error message is raised.

    args:
        data (flexible): Data to use to initialize the mnemonic.
                         Interpreted according to its type. See below for
                         details.
        lang (str): name of spoken language to use for wordlist


    The `data` argument controls the initialization of the mnemonic data.
    It can be a number of different types, and the type of the argument
    passed in determines the initialization behavior:

    - :class:`int`:   generate random `data`-byte mnemonic (default=20)
    - :class:`bytes`: generate mnemonic using `data` bytes directly as entropy source
    - :class:`str`:   interpret as an already-made space-delimited mnemonic phrase
    - iterable:       interpret as iterable of mnemonic words


    Attributes:
        language (str): name of the language of the wordlist.

    Examples:

    Construct a mnemonic from cryptographically secure random entropy source

    >>> Mnemonic()

    Control the entropy of mnemonic by passing :class:`int` values to the
    `data` argument

    >>> Mnemonic(12)
    >>> Mnemonic(32)

    Construct a mnemonic from a predifed list of words

    >>> words = ('crunch', 'subway', 'patch', 'thrive', 'advice', 'math',
    >>>          'another', 'solid', 'horror', 'wedding', 'dance', 'smart')
    >>> Mnemonic (words)
    >>> # It works with space delimited strings too
    >>> Mnemonic ("crunch subway patch thrive advice math another solid horror"
    >>>           "wedding dance smart")

    Construct a Mnemonic from some given entropy

    """

    def __new__(cls, data=20, lang="english"):
        if isinstance(data, int):
            entropy = os.urandom(data)
            return cls._from_entropy(entropy, lang)
        if isinstance(data, bytes):
            return cls._from_entropy(data, lang)
        if isinstance(data, str):
            return cls(_normalize("NFKD", data).split(), lang)
        return super().__new__(cls, data)

    def __init__(self, data=20, lang="english"):
        self.language = lang
        self.wordlist = WORDLISTS[lang]
        self._check()

    def __str__(self):
        return ' '.join(self)

    def to_seed(self, password: bytes = b'') -> bytes:
        r"""
        Return BIP39 standard seed bytes carrying the entropy of the mnemonic,
        optionally decrypted with a password `password`.  See `Algorithm
        Description Spec`_ for details. Always returns 512-bit (64 byte) seed
        regardless of actual entropy content.

        .. _Algorithm Description Spec:  https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed

        Examples:

        >>> source_entropy = b'\x1d\x12\xbf\xae"\xcc&w\xa2I\xab>\x8d\n\xdfk'
        >>> m = Mnemonic(source_entropy)
        >>> m
        ('brown', 'nominee', 'twist', 'easily', 'second', 'design', 'matrix', 'cube', 'direct', 'hair', 'result', 'stone')

        >>> # The seed is not equal to the initializtion entropy
        >>> m.to_seed()
        b'\r\x9a\xf0\xccq5\xd7>\xf3\xb70 \x7f\xc8\x93M\xcb\x1en+\r\xd4U\xb2\r\x19-\xaa\x99\x93\x17\xfeS\x11\xb6\nB"?\x96\x04\x7f\x8d\xeeC\x06\xcd\xdb\x9fb9\x91\x12C\xf0\xb7\x04[r\xa4H\xef\xeew'

        >>> # seed can be decrypted with a password.
        >>> m.to_seed(b"some_password")
        b'?\xb8\x18\x8a\xd5meE\x89\x08~\xfd_d\xcc6\x00\xe0\xb2(\xab\xd4\x1a\xb6\xb9ky\x93>\xe1\x9a~\x05e\xb0\xc1(R\xd6\xf6|\xab\x1a\x06\xd9j\xf7Wp,\xe5>\xa5$\xc6\xb6\xc5\x1f\xf3k\xa2F\x8a\xcb'
        """
        mnemonic_bytes = str(self).encode()
        return hashlib.pbkdf2_hmac(hash_name='sha512',
                                   password=mnemonic_bytes,
                                   salt=b'mnemonic' + password,
                                   iterations=2048)

    def _bin_string(self) -> str:
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
