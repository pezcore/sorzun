import os.path
import json
from unicodedata import normalize

import pytest

from ..mnemonic import Mnemonic, WORDLIST_JAPANESE
from .. import mnemonic

test_dir = os.path.dirname(os.path.realpath(__file__))

@pytest.fixture(scope="module",
    params=[(mnemonic.WORDLIST_ENGLISH, "test_EN_BIP39.json"),
            (mnemonic.WORDLIST_JAPANESE, "test_JP_BIP39.json")],
    ids=["english", "japanese"])
def testvec(request):
    wl, fn = request.param
    ffn = os.path.join(test_dir, "vectors", fn)
    with open(ffn, "r") as fd:
        d = json.load(fd)
    passphrase = normalize("NFKD", d["passphrase"]).encode("utf8")
    return wl, passphrase, d["vectors"]

def test_from_entropy(testvec):
    wl, passphrase, vectors = testvec
    for tv in vectors:
        m = Mnemonic.from_entropy(bytes.fromhex(tv["entropy"]), wl)
        assert m == tuple(normalize("NFKD", tv["mnemonic"]).split())
        assert m.to_seed(passphrase).hex() == tv["seed"]

def test_construction(testvec):
    wl, passphrase, vectors = testvec
    for tv in vectors:
        m = Mnemonic(normalize("NFKD", tv["mnemonic"]).split())
        assert m == tuple(normalize("NFKD", tv["mnemonic"]).split())
        assert m.to_seed(passphrase).hex() == tv["seed"]

def test_from_string(testvec):
    wl, passphrase, vectors = testvec
    for tv in vectors:
        m = Mnemonic.from_string(tv["mnemonic"])
        assert m == tuple(normalize("NFKD", tv["mnemonic"]).split())
        assert m.to_seed(passphrase).hex() == tv["seed"]

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
