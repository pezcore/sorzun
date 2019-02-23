import os.path
import json
from unicodedata import normalize

import pytest

from ..mnemonic import Mnemonic, WORDLIST_JAPANESE
from .. import mnemonic

test_dir = os.path.dirname(os.path.realpath(__file__))

@pytest.fixture(scope="module",
    params=[(mnemonic.WORDLIST_ENGLISH, "trezor_bip32.json"),
            (mnemonic.WORDLIST_JAPANESE, "japaneese_bip32.json")],
    ids=["english", "japanese"])
def testvec(request):
    wl, fn = request.param
    ffn = os.path.join(test_dir, "vectors", fn)
    with open(ffn, "r") as fd:
        d = json.load(fd)
    # convert test vectors dict into common format for test functions
    if wl is mnemonic.WORDLIST_ENGLISH:
        return wl, [{
            "entropy" : ent,
            "mnemonic": mne,
            "passphrase" : "TREZOR",
            "seed" : seed}
                for ent, mne, seed, _ in d["english"]
            ]
    if wl is mnemonic.WORDLIST_JAPANESE:
        return wl, d

def test_from_entropy(testvec):
    wl, tvl = testvec
    for tv in tvl:
        m = Mnemonic.from_entropy(bytes.fromhex(tv["entropy"]), wl)
        assert m == tuple(normalize("NFKD", tv["mnemonic"]).split())
        passwd = normalize("NFKD", tv["passphrase"]).encode("utf8")
        assert m.to_seed(passwd).hex() == tv["seed"]

def test_construction(testvec):
    wl, tvl = testvec
    for tv in tvl:
        m = Mnemonic(normalize("NFKD", tv["mnemonic"]).split())
        assert m == tuple(normalize("NFKD", tv["mnemonic"]).split())
        passwd = normalize("NFKD", tv["passphrase"]).encode("utf8")
        assert m.to_seed(passwd).hex() == tv["seed"]

def test_from_string(testvec):
    wl, tvl = testvec
    for tv in tvl:
        m = Mnemonic.from_string(tv["mnemonic"])
        assert m == tuple(normalize("NFKD", tv["mnemonic"]).split())
        passwd = normalize("NFKD", tv["passphrase"]).encode("utf8")
        assert m.to_seed(passwd).hex() == tv["seed"]

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
