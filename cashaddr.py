from util import convertbits

ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
GEN = [0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470]

def polymod(data):
    "Find the polymod of input byte stream over GF(2^5)"
    c = 1
    for d in data:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        for i in range(5):
            c ^= GEN[i] if ((c0 >> i) & 1) else 0
    return c ^ 1

def b32decode(l):
    return [ALPHABET.find(x) for x in l]

def b32encode(data):
    return "".join([ALPHABET[x] for x in data])

def prefix_expand(prefix):
    "Expand prefix string to bytes by taking the lowest 5 bits of each char"
    return bytes([ord(x) & 0x1f for x in prefix] + [0])

def calculate_checksum(prefix, payload):
    """
    Given prefix string and B32 payload bytes, return the checksum bytes. The
    B32 payload bytes are the payload message octets expanded with convertbits
    to 5 bit symbols represented as bytes
    """
    poly = polymod(prefix_expand(prefix) + payload + b"\0"* 8)
    return bytes([((poly >> 5 * (7 - i)) & 0x1f) for i in range(8)])

def verify_checksum(prefix, payload):
    """
    Given a prefix string and a payload bytes, verify that checksum (at the end
    of the payload) is valid.
    """
    return polymod(prefix_expand(prefix) + payload) == 0

def cashenc(pl, prefix="bitcoincash"):
    "Encode bytes data as cashaddr using human readable prefix `prefix`"
    pl32 = bytes(convertbits(pl, 8, 5))
    checksum = calculate_checksum(prefix, pl32)
    return prefix + ":" + b32encode(pl32 + checksum)

def cashdec(s):
    "Decode cashaddr encoded string to bytes"
    prefix, pltxt = s.split(":")
    pl32 = bytes(b32decode(pltxt))
    assert verify_checksum(prefix, pl32), "Bad checksum"
    return bytes(convertbits(pl32[:-8], 5, 8, False))

def is_cashaddr(s):
    "Test is a string is a cashaddr formated address"
    return ":" in s or all((x in ALPHABET) for x in s)
