import os.path
import json
from unicodedata import normalize

import pytest

from ..mnemonic import Mnemonic, WORDLIST_JAPANESE
from .. import mnemonic

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

def test_from_entropy(trezorvec):
    for entstr, mstr, seedstr, _ in trezorvec:
        m = Mnemonic.from_entropy(bytes.fromhex(entstr))
        assert m == tuple(mstr.split())
        assert m.to_seed(b"TREZOR").hex() == seedstr

def test_construction(trezorvec):
    for entstr, mstr, seedstr, _ in trezorvec:
        m = Mnemonic(mstr.split())
        assert m == tuple(mstr.split())
        assert m.to_seed(b"TREZOR").hex() == seedstr

def test_from_string(trezorvec):
    for entstr, mstr, seedstr, _ in trezorvec:
        m = Mnemonic.from_string(mstr)
        assert m == tuple(mstr.split())
        assert m.to_seed(b"TREZOR").hex() == seedstr

def test_default():
    m = Mnemonic()

def test_consume():
    """
    Test that all words in the wordlist appear at least once in set of 3000
    uniformly distributed random mnemonics. Only as many mnemonics as
    necessary to confirm are actually generated.
    """
    # o look a python algorithm! :O
    seen = set()
    wl = frozenset(mnemonic.WORDLIST_ENGLISH)
    i = 0
    while seen != wl:
        ent = os.urandom(20)
        m = Mnemonic.from_entropy(ent)
        seen |= set(m)
        i += 1
    if i > 3000:
        assert False, "Wordlist consumption timeout"

def test_japaneese_vectors(japvecs):
    for tv in japvecs:
        ent = bytes.fromhex(tv["entropy"])
        passwd = normalize("NFKD", tv["passphrase"])
        expected_seed = bytes.fromhex(tv["seed"])
        m = Mnemonic.from_entropy(ent, WORDLIST_JAPANESE)
        assert m == tuple(normalize("NFKD", x) for x in tv["mnemonic"].split())
        assert m.to_seed(passwd.encode("utf8")) == expected_seed
