r"""
This module provides the `base58 and base58check`_ codecs used in bitcoin and
similar cryptocurrency systems. The module provides codec functionality via 2
functions which implement base58 encoding and decoding respectively, each with
optional capability to use checksum generation/validation (base58check).

.. _base58 and base58check: https://en.bitcoin.it/wiki/Base58Check_encoding
"""

import math
from hashlib import sha256

#: Base58 Alphabet
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58enc(b: bytes, check: bool = False) -> str:
    r"""
    Encode :class:`bytes` `b` to a base58 string. If `check` is set, use
    base58check encoding (includes checksum generation). If `b` is a
    :class:`str`, first encode it to :class:`bytes` with UTF-8 text codec
    before applying base58 encoding.

    **Examples**:

    Encoding string data can be performed for both base58 and base58check.
    Function returns base58[check] encoded string of the UTF-8 encoded input
    string.

    .. code-block:: python

        # Encode some Text data
        >>> txt = "The quick brown fox jumps over the lazy dog"
        >>> b58enc(txt) # no checksum
        '7DdiPPYtxLjCD3wA1po2rvZHTDYjkZYiEtazrfiwJcwnKCizhGFhBGHeRdx'
        >>> b58enc(txt, True) # with checksum
        'hgrbmYjTAB9gMSwZ6bUP86rvvhPkJzRkcqkmdZXXPyQCbXzuSLGmEDgmK4iSfhDR'

    :func:`b58enc` can also be used directly on arbitrary binary data
    represented as :class:`bytes` in the same way.

    .. code-block::

        # Encode some Binary data
        >>> bindata = b"\xf0\xfcw\x99\xc0j\xadAN\xf6\x18\xcfT\x94\x91\x1f1\xf2\x17"
        >>> b58enc(bindata)
        'm7pYpwS26hYeGtKjSWJnwSjVVp'
        >>> b58enc(bindata, True)
        '5yh1rWBFpZFGWaRyxxaZYsKsGfr1TFHc'
    """
    if isinstance(b, str):
        b = b.encode()
    if check:
        digest = sha256(sha256(b).digest()).digest()
        b += digest[:4]
    i = int.from_bytes(b, 'big')
    leading_nulls = len(b) - len(b.lstrip(b'\0'))

    string = ''
    while i:
        i, idx = divmod(i, 58)
        string += ALPHABET[idx]
    string += ALPHABET[0] * leading_nulls
    return string[::-1]

def b58dec(s: str, check: bool = False) -> bytes:
    """
    Decode a base58 or base58check-encoded string `s` and return decoded
    :class:`bytes` payload. If `check` is ``True``, input string is interpreted
    as a base58check encoded string and the checksum is checked, raising
    :class:`AssertionError` in the event of a checksum validation failure.

    **Examples**:


    The base58[check]-encoded strings can be decoded with :func:`b58dec`. This
    should return the original encoded payload as :class:`bytes`.

    .. code-block::

        # Decode
        >>> b58dec("7DdiPPYtxLjCD3wA1po2rvZHTDYjkZYiEtazrfiwJcwnKCizhGFhBGHeRdx")
        b'The quick brown fox jumps over the lazy dog'
        >>> b58dec("hgrbmYjTAB9gMSwZ6bUP86rvvhPkJzRkcqkmdZXXPyQCbXzuSLGmEDgmK4iSfhDR", True)
        b'The quick brown fox jumps over the lazy dog'
        >>> b58dec("m7pYpwS26hYeGtKjSWJnwSjVVp") == bindata
        True
        >>> b58dec("5yh1rWBFpZFGWaRyxxaZYsKsGfr1TFHc", True) == bindata
        True

    When decoding with ``check == True`` (base58check), :class:`AssertionError`
    is raised indicating a checksum validation failure if the checksum does not
    match.

    .. code-block::

        # Changing a charactar Raises Exception if using base58check
        # This char is wrong
        >>> b58dec("5yh1rWBFZZFGWaRyxxaZYsKsGfr1TFHc", True) == bindata
        Traceback (most recent call last):
          ...
        AssertionError: Checksum Failed
    """
    i = 0
    for char in s.rstrip('\n'):
        i = i * 58 + ALPHABET.index(char)
    leading_ones = len(s) - len(s.lstrip(ALPHABET[0]))
    n = math.ceil(i.bit_length() / 8)
    pl = b'\0' * leading_ones + i.to_bytes(n, 'big')
    if check:
        pl, cs = pl[:-4], pl[-4:]
        digest = sha256(sha256(pl).digest()).digest()
        assert digest[:4] == cs, 'Checksum Failed'
    return pl

def main():
    import argparse
    import sys
    from textwrap import fill

    parser = argparse.ArgumentParser(
        description='Encode/decode data using base58 or base58check encoding'
    )
    parser.add_argument(
        '-d', '--decode',
        action='store_true',
        help='Decode input base58 string to binary payload'
    )
    parser.add_argument(
        '-c', '--check',
        action='store_true',
        help='Use base58check (generate/verify checksums)'
    )
    parser.add_argument(
        "-w", default=None,
        help="Wrap width"
    )
    args = parser.parse_args()

    data = sys.stdin.buffer.read()

    if args.decode:
        sys.stdout.buffer.write(b58dec(data.decode(), args.check))
    else:
        print(fill(b58enc(data, args.check), args.w or 70))
