import os.path
import json
from unicodedata import normalize
import math

import pytest

from ..mnemonic import Mnemonic, WORDLISTS

test_dir = os.path.dirname(os.path.realpath(__file__))

@pytest.fixture(scope="module",
    params=[("english", "test_EN_BIP39.json"),
            ("japanese", "test_JP_BIP39.json")],
    ids=["english", "japanese"])
def testvec(request):
    lang, fn = request.param
    ffn = os.path.join(test_dir, "vectors", fn)
    with open(ffn, "r") as fd:
        d = json.load(fd)
    passphrase = normalize("NFKD", d["passphrase"]).encode("utf8")
    return WORDLISTS[lang], passphrase, d["vectors"]

def test_entropy_constructor(testvec):
    wl, passphrase, vectors = testvec
    for tv in vectors:
        m = Mnemonic(bytes.fromhex(tv["entropy"]), wl)
        assert m == tuple(normalize("NFKD", tv["mnemonic"]).split())
        assert m.to_seed(passphrase).hex() == tv["seed"]

def test_iter_constructor(testvec):
    wl, passphrase, vectors = testvec
    for tv in vectors:
        m = Mnemonic(normalize("NFKD", tv["mnemonic"]).split(), wl)
        assert m == tuple(normalize("NFKD", tv["mnemonic"]).split())
        assert m.to_seed(passphrase).hex() == tv["seed"]

def test_string_constructor(testvec):
    wl, passphrase, vectors = testvec
    for tv in vectors:
        m = Mnemonic(tv["mnemonic"], wl)
        assert m == tuple(normalize("NFKD", tv["mnemonic"]).split())
        assert m.to_seed(passphrase).hex() == tv["seed"]

def test_default_constuctor():
    m = Mnemonic()
    assert all(x in m.wordlist for x in m)
    assert len(m) == 15

def test_int_constructor():
    for n in range(16, 30, 4):
        m = Mnemonic(n)
        assert all(x in m.wordlist for x in m)
        assert len(m) == math.ceil(n * 8 / 11)


def test_consume():
    """
    Test that all words in the wordlist appear at least once in set of 3000
    uniformly distributed random mnemonics. Only as many mnemonics as
    necessary to confirm are actually generated.
    """
    # o look a python algorithm! :O
    seen = set()
    wl = frozenset(WORDLISTS["english"])
    i = 0
    while seen != wl:
        ent = os.urandom(20)
        m = Mnemonic.from_entropy(ent)
        seen |= set(m)
        i += 1
    if i > 3000:
        assert False, "Wordlist consumption timeout"

bad_words = [
    'alien', 'erosion', 'worth', 'minor', 'unusual', 'strike', 'foster',
    'sad', 'item', 'teach', 'century', 'transfer', 'valley', 'ridge',
    'chimney', 'number', 'crazy', 'glass', 'crush', 'canal', 'cloth',
    'seat', 'inmate', 'moon', 'zone', 'laptop', 'inch', 'lecture',
    'become', 'dinner'
]

def test_badlen_fail():
    l = set(range(1, 30)) - {3 * x for x in range(4, 9)}
    for ll in l:
        x = bad_words[:ll]
        with pytest.raises(ValueError, match="Incorrect Mnemonic"):
            Mnemonic(x)

def test_checksum_fail():
    for l in {3 * x for x in range(4, 9)}: # use the correct length
        x = bad_words[:l]
        with pytest.raises(ValueError, match="Bad mnemonic checksum"):
            Mnemonic(x)
