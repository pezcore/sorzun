"Convert bitcoin addresses between legacy and cashaddr format"

import argparse
from .cashaddr import cashenc, cashdec, is_cashaddr
from .base58 import b58enc, b58dec

_b58checkenc = lambda x: b58enc(x, True)
_b58checkdec = lambda x: b58dec(x, True)


def convert_word(word):
    """
    Parse and analyze a string as an address and return version byte info and
    both legacy and cashaddr formatted addresses corresponding to the hash
    """
    intype, decfun, encfun, p2shvbyte = (
        ("CASHAD", cashdec, _b58checkenc, b"\5") if is_cashaddr(word) else
        ("LEGACY", _b58checkdec, cashenc, b"\10")
    )
    pl = decfun(word)
    ivbyte, _hash = pl[:1], pl[1:]
    ovbyte = b"\0" if ivbyte == b"\0" else p2shvbyte
    outaddr = encfun(ovbyte + _hash)
    legaddr, cashaddr = (
        (word, outaddr) if intype == "LEGACY" else (outaddr, word)
    )
    return ivbyte, ovbyte, intype, legaddr, cashaddr

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", default="-",
                        type=argparse.FileType('r'))
    args = parser.parse_args()
    txt = args.file.read()

    for lineno, line in enumerate(txt.split("\n")):
        for wordno, word in enumerate(line.split()):
            try:
                ivbyte, ovbyte, intype, legaddr, cashaddr = convert_word(word)
            except Exception as e:
                print(f"{'':14}ERROR  {word} {type(e).__name__}: {e}")
                continue
            print(
                f"{lineno:4d} {wordno:2d} "
                f"{ivbyte.hex().upper():2} {ovbyte.hex().upper():2} "
                f"{intype:<6} {legaddr:<34} {cashaddr}"
            )

if __name__ == "__main__":
    main()
