import os.path
import json

import pytest

from sorzun.deterministic import (
    XPubKey, XPrivKey, PrivBIP32Node, PubBIP32Node, ProtocolError)
from sorzun.ecc import Point

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

with open(os.path.join(test_dir, "vectors", "ku_det.json"), "r") as fd:
    ku_testvec = json.load(fd)

@pytest.fixture(scope="module")
def xpub():
    pubkey_bytes = bytes.fromhex(ku_testvec["key_pair_as_sec"])
    pubkey = Point.from_bytes(pubkey_bytes)
    cc = bytes.fromhex(ku_testvec["chain_code"])
    return XPubKey(pubkey, cc)

def test_xpub_addr(xpub):
    assert xpub.addr() == ku_testvec["BTC_address"]

def test_xpub_casharddr(xpub):
    assert xpub.cashaddr() == ("bitcoincash:"
        "qr6hv2medj2c0yvpqdpr7vz25slwt0vmuywvkgjuvr"
    )

def test_xpub_id(xpub):
    assert xpub.id == bytes.fromhex(ku_testvec["hash160"])

def test_xpub_bytes(xpub):
    assert bytes(xpub) == bytes.fromhex(ku_testvec["key_pair_as_sec"])

def test_xpub_ckd(xpub):
    for leaf in ku_testvec["leaves"]:
        if "H" in leaf["path"]:
            continue # dont attempt hardened derivation from XPubKey
        der = xpub.derive(leaf["path"].split()[0])
        print(f"XPubKey:\n{xpub}")
        print("Derivation path ", leaf["path"].split()[0])
        print(f"derived keys\n{der}")
        assert der.addr() == leaf["BTC_address"]
        assert der.id == bytes.fromhex(leaf["hash160"])
        assert bytes(der) == bytes.fromhex(leaf["key_pair_as_sec"])

def test_xpub_ckd_disallow_harddev(xpub):
    with pytest.raises(ProtocolError, match="It is disallowed to derive a"):
        der = xpub.ckd(2 ** 31)
