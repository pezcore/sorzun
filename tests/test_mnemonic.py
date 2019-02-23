import os.path
import json
from unicodedata import normalize

import pytest

from ..mnemonic import Mnemonic, WORDLIST_JAPANESE

test_dir = os.path.dirname(os.path.realpath(__file__))

@pytest.fixture(scope="module")
def trezorvec():
    fn = os.path.join(test_dir, "vectors", "trezor_bip32.json")
    with open(fn, "r") as fd:
        return json.load(fd)["english"]

@pytest.fixture(scope="module")
def japvecs():
    fn = os.path.join(test_dir, "vectors", "japaneese_bip32.json")
    with open(fn, "r") as fd:
        return json.load(fd)


def test_construction():
    m = Mnemonic("become keen dog whip federal dice column cat fly".split())
    assert m.to_seed().hex() == (
        "e78890ff55949e0d93d62b96aedb2bcce87c2f44bbbe6ff0f6646fb6eaf7644e"
        "09b87ba81504d37d32089d131502b6a68f4f3541f545317ac69476894abc6b61"
    )

def test_from_string():
    m = Mnemonic.from_string("become keen dog whip federal dice column cat fly")
    assert m.to_seed().hex() == (
        "e78890ff55949e0d93d62b96aedb2bcce87c2f44bbbe6ff0f6646fb6eaf7644e"
        "09b87ba81504d37d32089d131502b6a68f4f3541f545317ac69476894abc6b61"
    )

def test_default():
    m = Mnemonic()

def test_from_entropy():
    m = Mnemonic.from_entropy(bytes.fromhex("f49fccd1abc419181c1206d1005c4ae0"))
    assert m == tuple("virus wrist crucial fiscal dose metal icon dolphin "
                      "speed actual bargain scrub".split())
    assert m.to_seed().hex() == (
        "e260dbc427ce11fed7913e5c7d68e317aa3f5db7ab20c8a14bde1c3c8b9da3b2"
        "71f7d2e90dedac9aadd645082c2d06b2619d742463e0f4140eb201a71efa325d"
    )

def test_trezorvectors(trezorvec):
    for entstr, mstr, seedstr, _ in trezorvec:
        m = Mnemonic.from_entropy(bytes.fromhex(entstr))
        assert m == tuple(mstr.split())
        assert m.to_seed(b"TREZOR").hex() == seedstr

def test_japaneese_vectors(japvecs):
    for tv in japvecs:
        ent = bytes.fromhex(tv["entropy"])
        passwd = normalize("NFKD", tv["passphrase"])
        expected_seed = bytes.fromhex(tv["seed"])
        m = Mnemonic.from_entropy(ent, WORDLIST_JAPANESE)
        assert m == tuple(normalize("NFKD", x) for x in tv["mnemonic"].split())
        assert m.to_seed(passwd.encode("utf8")) == expected_seed
