"""
base58 codec module

This module implements the base58 and base58check codecs used in bitcoin and
similar cryptocurrency systems. This module provides 2 functions which
implement base58 encoding and decoding, each with optional capability to use
checksums.
"""

import math
from hashlib import sha256

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58enc(b, check=False):
    '''Encode a bytes to a base58 string. If check is set, use base58check
    encoding
    '''
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

def b58dec(s, check=False):
    '''Decode a base58 or base58check encoded string to bytes. If check is set,
    input string is interpreted as a base58check encoded string and the
    checksum is checked, Raises assertion failure exception in the event of a
    checksum failure. Returns binary payload.
    '''
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

    parser = argparse.ArgumentParser(
        description='Encode/decode data using base58 or base58check encoding')
    parser.add_argument('-d', '--decode', action='store_true',
                        help='Decode input base58 string to binary payload')
    parser.add_argument('-c', '--check', action='store_true',
                        help='Use base58check (generate/verify checksums)')
    parser.add_argument('file',
                        metavar='FILE', nargs='?',
                        type=argparse.FileType('r'),
                        default='-',
                        help='Input file to process or stdin if omitted')
    args = parser.parse_args()

    data = args.file.buffer.read()

    if args.decode:
        sys.stdout.buffer.write(b58dec(data.decode(), args.check))
    else:
        print(b58enc(data, args.check), end='')
