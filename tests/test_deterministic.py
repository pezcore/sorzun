import os.path
import json

import pytest

from ..deterministic import XPubKey, XPrivKey, PrivBIP32Node, PubBIP32Node, ProtocolError
from ..ecc import Point

test_dir = os.path.dirname(os.path.realpath(__file__))

def test_derive():
    ffn = os.path.join(test_dir, "vectors", "deterministic.json")
    with open(ffn, "r") as fd:
        l = json.load(fd)

    for testvec in l:
        prv = PrivBIP32Node.from_entropy(bytes.fromhex(testvec["seed"]))
        for leaf in testvec["leaves"]:
            der = prv.derive(leaf["path"])
            assert der.xpub == leaf["xpub"]
            assert der.xprv == leaf["xprv"]

def test_xpub_ctor_arglim():
    with pytest.raises(TypeError, match="positional arguments but"):
        k, cc = 123123, os.urandom(32)
        XPubKey(k, cc, "extra arg")

def test_xpub_ctor_autocc():
    k, cc = 123123, os.urandom(32)
    xpub = XPubKey(k, cc)
    assert xpub[0] is xpub.pubkey
    assert xpub[1] is xpub.chaincode
    assert xpub.pubkey is k
    assert xpub.chaincode is cc

    xpub = XPubKey(k)
    assert xpub.pubkey is k

# xpub661MyMwAqRbcFcThV86HtqwDepp7p2NLhsUuVEiTLcmTCfqLv6Fdp5YVNwsBwWhS93foQgVCR5H5ZAFvg9yRZb7xCpm3eUGgJsBiVm6RnCX
key = Point.from_bytes(bytes.fromhex(
    "02d253e2552d249ae7e36d18374953196"
    "ec554319b99d1b653b854dfa9b4a295a2")
)
cc = bytes.fromhex(
    "6b6a4e1f98b1d5e8261f85827e6c379f11f2e73cd5dfd88cf85e97ec8dbe9f61"
)


def test_xpub_addr():
    xpub = XPubKey(key, cc)
    assert xpub.addr() == "1A7gUzu8SZR7wBkSWFHY6Q6JXc2tGtBVQw"

def test_xpub_casharddr():
    xpub = XPubKey(key, cc)
    assert xpub.cashaddr() == ( "bitcoincash:"
        "qp3le9s66xma3svpr3at440jazfk7s8rpq6yqapn67"
    )

def test_xpub_id():
    xpub = XPubKey(key, cc)
    assert xpub.id == bytes.fromhex("63fc961ad1b7d8c1811c7abad5f2e8936f40e308")

def test_xpub_bytes():
    xpub = XPubKey(key, cc)
    assert bytes(xpub) == bytes.fromhex(
        "02d253e2552d249ae7e36d18374953196"
        "ec554319b99d1b653b854dfa9b4a295a2"
    )

def test_xpub_ckd():
    xpub = XPubKey(key, cc)
    der = xpub.ckd(44)
    assert der.addr() == "18ENWVy17pZQ1iKLwhM77XcWYHPamUvwbB"
    assert der.id == bytes.fromhex("4f503e12beb6bd7665c1e8a98d0227e41c600e32")
    assert der.cashaddr() == ("bitcoincash:"
        "qp84q0sjh6mt6an9c852nrgzyljpccqwxg294e8elf"
    )
    assert bytes(der) == bytes.fromhex(
        "02419d361302c210232b86291bd323921"
        "ef6afa9d2e2bb32c608e760ae84b95d0f"
    )

def test_xpub_ckd_disallow_harddev():
    xpub = XPubKey(key, cc)
    with pytest.raises(ProtocolError, match="It is disallowed to derive a"):
        der = xpub.ckd(2 ** 31)
