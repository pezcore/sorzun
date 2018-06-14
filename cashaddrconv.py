"Convert bitcoin addresses between legacy and cashaddr format"

import argparse
from cashaddr import cashenc, cashdec, is_cashaddr
from base58 import b58enc, b58dec

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", nargs="?", default="-",
                        type=argparse.FileType('r'))
    args = parser.parse_args()

    txt = args.file.read()

    for word in txt.split():
        if is_cashaddr(word):
            addr_type = "CASHAD"
            cashaddr = word
            try:
                pl = cashdec(word)
                ivbyte, _hash = pl[0:1], pl[1:]
            except Exception as e:
                print(f"{'':5} {addr_type} {word} {type(e).__name__}: {e}")
                continue
            ovbyte = b"\0" if ivbyte == b"\0" else b"\5"
            legaddr = b58enc(ovbyte + _hash, True)
        else:
            addr_type = "LEGACY"
            legaddr = word
            try:
                pl = b58dec(word, True)
                ivbyte, _hash = pl[0:1], pl[1:]
            except Exception as e:
                print(f"{'':5} {addr_type} {word} {type(e).__name__}: {e}")
                continue
            ovbyte = b"\0" if ivbyte == b"\0" else b"\10"
            cashaddr = cashenc(ovbyte + _hash)
        print(f"{ivbyte.hex():2} {ovbyte.hex():2} "
              f"{addr_type:<6} {legaddr:<34} {cashaddr}")

if __name__ == "__main__":
    main()
