"""
Test module for testing cashaddr codec. requires pytest
"""

import pytest

# pylint: disable=invalid-name
from ..cashaddr import cashenc, cashdec, SIZE_CODE
from ..cashaddrconv import convert_word

#=========================== Load Test Vectors ===============================#

# loaded from testvec file
with open("vectors/cashaddr_testvec.txt", "r") as fd:
    sp = (l.split() for l in fd)
    test_vec = {x[2] : (int(x[1]), x[3]) for x in sp}

@pytest.fixture(scope="module")
def legacy_pairs():
    return [
        ("1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu",
         "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
        ("1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR",
         "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy"),
        ("16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb",
         "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r"),
        ("3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC",
         "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"),
        ("3LDsS579y7sruadqu11beEJoTjdFiFCdX4",
         "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e"),
        ("31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw",
         "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37")
    ]

#============================= TEST FUNCTIONS ================================#

def test_cashenc():
    for cashstr, (typeno, hexstr) in test_vec.items():
        prefix, _ = cashstr.split(":")
        pl = bytes.fromhex(hexstr)
        vb = ((typeno << 3) | SIZE_CODE[len(pl) * 8]).to_bytes(1, "big")
        test = cashenc(vb + pl, prefix)
        assert (0xF8 & vb[0]) >> 3 == typeno
        assert cashstr == test

def test_cashdec():
    for cashstr, (typeno, hexstr) in test_vec.items():
        rawpl = cashdec(cashstr)
        vb, pl = rawpl[0], rawpl[1:]
        assert pl == bytes.fromhex(hexstr)
        assert SIZE_CODE[len(pl) * 8] == 7 & vb
        assert (0xF8 & vb) >> 3 == typeno

def test_checksum():
    """
    Test that cashdec() successfully decodes cashaddr strings with known
    correct checksums, and that cashdec() raises a bad checksum error for
    strngs with known bad checksums. The string with known good checksums are
    provided by upstream spec
    """
    cashdec("prefix:x64nx6hz")
    cashdec("p:gpf8m4h7")
    cashdec("bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn")
    cashdec("bchreg:555555555555555555555555555555555555555555555udxmlmrz")
    with pytest.raises(AssertionError, match="Bad checksum"):
        cashdec("bchreg:555555555555555555555555555555555555555555555udxmlmrr")

def test_convert_word_to_cash(legacy_pairs):
    """
    Test that cashaddr addresses are properly converted to legacy addresses via
    convert_word()
    """
    for leg, cash in legacy_pairs:
        *_, cashtest = convert_word(leg)
        assert cashtest == cash

def test_convert_word_to_leg(legacy_pairs):
    """
    Test that legacy addresses are properly converted to cashaddr via
    convert_word()
    """
    for leg, cash in legacy_pairs:
        *_, legtest, _ = convert_word(cash)
        assert legtest == leg

def test_bad_char():
    """
    Test that the correct ValueError is raised when attempting to decode a
    cashaddr string containing a character not present in the base32 alphabet.
    The raised exception must accurately specify both the value of the bad
    character and its position in the cashaddr string.
    """
    estr = "invalid base32 symbol 'i' at position 2"
    with pytest.raises(ValueError, match=estr):
        cashdec("bitcoincash:thisismyaddressstring")
    estr = "invalid base32 symbol 'b' at position 19"
    with pytest.raises(ValueError, match=estr):
        cashdec("bitcoincash:qz42g6m8d4p7u6zkvxgbf5583h4rz8dlsypzjp7zd0")
