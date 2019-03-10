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

with open(os.path.join(test_dir, "vectors", "ku_det.json"), "r") as fd:
    ku_testvec = json.load(fd)

def test_xpub_addr():
    xpub = XPubKey(
        bytes.fromhex(ku_testvec["key_pair_as_sec"]),
        bytes.fromhex(ku_testvec["chain_code"])
    )
    assert xpub.addr() == ku_testvec["BTC_address"]

def test_xpub_casharddr():
    xpub = XPubKey(
        bytes.fromhex(ku_testvec["key_pair_as_sec"]),
        bytes.fromhex(ku_testvec["chain_code"])
    )
    assert xpub.cashaddr() == ("bitcoincash:"
        "qr6hv2medj2c0yvpqdpr7vz25slwt0vmuywvkgjuvr"
    )

def test_xpub_id():
    xpub = XPubKey(
        bytes.fromhex(ku_testvec["key_pair_as_sec"]),
        bytes.fromhex(ku_testvec["chain_code"])
    )
    assert xpub.id == bytes.fromhex(ku_testvec["hash160"])

def test_xpub_bytes():
    xpub = XPubKey(
        bytes.fromhex(ku_testvec["key_pair_as_sec"]),
        bytes.fromhex(ku_testvec["chain_code"])
    )
    assert bytes(xpub) == bytes.fromhex(ku_testvec["key_pair_as_sec"])

def test_xpub_ckd():
    xpub = XPubKey(
        bytes.fromhex(ku_testvec["key_pair_as_sec"]),
        bytes.fromhex(ku_testvec["chain_code"])
    )
    for leaf in ku_testvec["leaves"]:
        if "H" in leaf["child_index"]:
            continue # dont attempt hardened derivation from XPubKey
        der = xpub.derive(leaf["child_index"].split()[0])
        assert der.addr() == leaf["BTC_address"]
        assert der.id == bytes.fromhex(leaf["hash16"])
        assert der.cashaddr() == ("bitcoincash:"
            "qp84q0sjh6mt6an9c852nrgzyljpccqwxg294e8elf"
        )
        assert bytes(der) == bytes.fromhex(leaf["key_pair_as_sec"])
        print("leaf derivation path : ", leaf["child_index"])

def test_xpub_ckd_disallow_harddev():
    xpub = XPubKey(key, cc)
    with pytest.raises(ProtocolError, match="It is disallowed to derive a"):
        der = xpub.ckd(2 ** 31)
