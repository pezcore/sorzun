"""
This module provides a set of functions for implementing the cashaddr_ codec, a
codec used to format Bitcoin Cash Addresses.

The main purpose of this module is to provide cashaddr encoding and decoding
via the :func:`cashenc` and :func:`cashdec` functions. These functions
implement the full cashaddr codec. They can encode arbitrary binary data
payloads (represented as :class:`bytes`) to cashaddr strings and decode
cashaddr strings back to the original raw :class:`bytes` payload, each with
support for arbitrary user-defined cashaddr prefixes_ and checksum_
generation/validation.

The :func:`cashdec` and :func:`cashenc` functions completely provide the codec,
and while these two functions alone can probably support most useful
application development, all the other "ingredients" are also exposed by this
module to support other implementations of the codec if it is desired.

About the Codec
...............

The cashaddr codec is a base-32 ASCII-encoded format for arbitrary binary data,
with some specific design features that make it particularly suitable for
encoding cryptocurrency addresses in a secure way. The format encodes the
payload using a 32-element alphabet (:data:`ALPHABET`) designed for easy human
readability and is is completely like-cased to aid spoken communication of hash
digests by supporting case insensitive decoding. It also includes a `BCH
code`_ checksum and an arbitrary user-defined prefix which is under the
checksum to ensure proper application use during checksum validation.

The cashaddr string consists of 2 parts separated by a colon ``:``. The first
part is the human-readable prefix which can be any arbitrary string chosen by
the user. The second part is the payload and checksum_ which are encoded using
the 32-element cashaddr alphabet. This part encodes the payload data and has a
BCH checksum which is computed over both the payload data and the
human-readable prefix to ensure proper application use of the cashaddr string.

.. _cashaddr: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
.. _BCH code: https://en.wikipedia.org/wiki/BCH_code
.. _prefixes: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md#prefix
.. _checksum: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md#checksum
"""
import re

from .util import convertbits

#: cashaddr alphabet
ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

_GEN = [0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470]


def polymod(data: bytes) -> int:
    "Return the polymod of input byte sequence `data` over :math:`GF(2^5)`"
    c = 1
    for d in data:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        for i in range(5):
            c ^= _GEN[i] if ((c0 >> i) & 1) else 0
    return c ^ 1

def b32decode(l: str) -> list:
    """
    Decode base32-encoded string `l` into list of integers indicating the
    indices into the alphabet of the corresponding characters. Equivalent to

    .. code-block:: python

        [ALPHABET.find(x) for x in l]

    Mainly used as helper to :func:`cashdec`
    """
    return [ALPHABET.find(x) for x in l]

def b32encode(data: bytes) -> str:
    r"""
    Encode `data` as base32-encoded :class:`str` using the cashaddr alphabet.
    Returns a :class:`str` of the same length as `data` such that

    .. code-block:: python

        output[i] == ALPHABET[input[i]]

    All bytes in `data` must be less than 32. Mainly used as helper to
    :func:`cashenc`

    **Examples:**

    Encode some random bytes

    >>> payload_bytes = b"\x0f\x02\x18\x02\n\x13\r\x02\x0f\x01"
    >>> # [15, 2, 24, 2, 10, 19, 13, 2, 15,  1]
    >>> b32encode(payload_bytes)
    '0zcz2ndz0p'

    It also works on the :class:`list`-of-:class:`int` form

    >>> payload_int_list = list(payload_bytes)
    >>> b32encode(payload_int_list)
    '0zcz2ndz0p'
    """
    return "".join([ALPHABET[x] for x in data])

def prefix_expand(prefix: str) -> bytes:
    """
    Return a :class:`bytes` representation of the UTF-8-encoded bytes of
    `prefix` but with the leading three bits of each byte cleared and a zero
    byte appended at the end. This is used in the calculation of the `cashaddr
    checksum`_

    .. _cashaddr checksum: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md#checksum
    """
    return bytes([ord(x) & 0x1f for x in prefix] + [0])

def calculate_checksum(prefix: str, payload: bytes) -> bytes:
    """
    With a given prefix string `prefix`, and B32 payload bytes `payload`,
    return the cashaddr checksum bytes. The B32 payload bytes are the payload
    message octets expanded with :func:`sorzun.util.convertbits` to 5-bit
    symbols represented as bytes.
    """
    poly = polymod(prefix_expand(prefix) + payload + b"\0"* 8)
    return bytes([((poly >> 5 * (7 - i)) & 0x1f) for i in range(8)])

def verify_checksum(prefix: str, payload: bytes) -> bool:
    """
    With a given prefix string, `prefix` and a payload bytes `payload`, verify
    that the checksum (at the end of the payload) is valid. Returns ``True``
    if the checksum is valid and ``False`` otherwise.
    """
    return polymod(prefix_expand(prefix) + payload) == 0

def cashenc(pl: bytes, prefix: str = "bitcoincash") -> str:
    r"""
    Return the cashaddr :class:`str` representation of the binary payload
    :class:`bytes` `pl` using human-readable prefix `prefix`.

    **Examples**:

    Encode binary payload

    >>> pl = b'\x00z#M\xdf\xf0\xaeh\x1fe\xc4\x99\x9d\xad9\x9e\xae\xa2\x92\xca\t'
    >>> cashenc(pl)
    'bitcoincash:qpazxnwl7zhxs8m9cjvemtfen6h29yk2pyucpwmjvj'

    Use a custom human-readable prefix

    >>> cashenc(pl, "myprefix")
    'myprefix:qpazxnwl7zhxs8m9cjvemtfen6h29yk2py5arywdw5'

    Both decode to the same original binary payload

    >>> cashdec('myprefix:qpazxnwl7zhxs8m9cjvemtfen6h29yk2py5arywdw5') == pl
    True
    >>> cashdec('bitcoincash:qpazxnwl7zhxs8m9cjvemtfen6h29yk2pyucpwmjvj') == pl
    True
    """
    pl32 = bytes(convertbits(pl, 8, 5))
    checksum = calculate_checksum(prefix, pl32)
    return prefix + ":" + b32encode(pl32 + checksum)

def cashdec(s: str) -> bytes:
    r"""
    Decode cashaddr encoded string and return :class:`bytes` payload. Decoding
    is case insensitive in the payload part. Raises :class:`AssertionError` if
    checksum validation fails. Raises :class:`ValueError` with message
    describing value and position of the first bad character if characters not
    in the base32 :data:`ALPHABET` are used.

    **Examples**:

    Decode a cashaddr string

    >>> cashdec("bitcoincash:qpazxnwl7zhxs8m9cjvemtfen6h29yk2pyucpwmjvj")
    b'\x00z#M\xdf\xf0\xaeh\x1fe\xc4\x99\x9d\xad9\x9e\xae\xa2\x92\xca\t'
    >>> # case insensitive in the payload part
    >>> cashdec("bitcoincash:qpAzXnwL7zHXs8m9cJVemtFEn6h29YK2pyUcpwmJvj")
    b'\x00z#M\xdf\xf0\xaeh\x1fe\xc4\x99\x9d\xad9\x9e\xae\xa2\x92\xca\t'

    Raises :class:`AssertionError` if checksum fails

    >>> # Bad Character---------------------↓
    >>> cashdec("bitcoincash:qpazxnwl7zhxs8mncjvemtfen6h29yk2pyucpwmjvj")
    Traceback (most recent call last):
      ...
    AssertionError: Bad checksum

    Raises :class:`ValueError` if charactars not in the :data:`ALPHABET` are
    used

    >>> cashdec("bitcoincash:alphabetsoup")
    Traceback (most recent call last):
      ...
    ValueError: invalid base32 symbol 'b' at position 5
    """
    prefix, pltxt = s.split(":")
    pltxt = pltxt.lower() # to support case insensitive input
    dec = b32decode(pltxt)
    if -1 in dec:
        badloc = dec.index(-1)
        raise ValueError(
            f"invalid base32 symbol '{pltxt[badloc]}' at position {badloc}"
        )
    pl32 = bytes(dec)
    assert verify_checksum(prefix, pl32), "Bad checksum"
    return bytes(convertbits(pl32[:-8], 5, 8, False))

def is_cashaddr(s: str) -> bool:
    """
    Return ``True`` if and only if string `s` is a cashaddr encoded string.
    Does not perform checksum validation or decoding, only checks syntax format
    and that all characters are taken from the cashaddr alphabet.
    """
    return bool(re.match(f"[a-zA-Z0-9]*:[{ALPHABET}]+$", s))
