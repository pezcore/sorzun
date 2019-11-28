import argparse
import math
from .deterministic import node_from_str, PrivBIP32Node
from .mnemonic import Mnemonic

def range_from_str(s):
    'return a arange from a string in x-y format'
    return range(*map(int, s.split('-'))) if '-' in s else range(int(s))

def main():
    parser = argparse.ArgumentParser(description='Key Utility')
    parser.add_argument('-p', '--path', help='derivation path')
    parser.add_argument('-w', '--wif', action='store_true',
                        help='print leaf private keys (compressed WIF format)')

    parser.add_argument('-l', default=range(25),
                        type=range_from_str,
                        help="""
                        Range of leaf indices to compute. Format is x-y. If
                        only one number is given x is assumed to be zero.
                        """)
    parser.add_argument('keydata', nargs='?', default=None,
                        help="""
                        Key specification. This can be a BIP32 standard xpub or
                        xprv key string, a space delimited string of mnemonic
                        words, a hex encoded BIP32 seed, a number of bytes to
                        use as entropy for generating a random mnemonic, or
                        blank which defaults to 20 bytes of entropy for
                        generating a random mnemonic
                        """)
    parser.add_argument('-f', '--format', help='address format', default='BTC',
                        choices=['BTC', 'LTC', "BCH"])
    parser.add_argument("--long-bch-format", action="store_true")
    args = parser.parse_args()

    addrpre = {'BTC' : b'\0', 'LTC' : b'0', "BCH" : b"\0"}
    wifpre = {'BTC' : b'\x80', 'LTC' : b'\xb0', "BCH" : b"\x80"}

    print('Root key info ' + '-' * 97)

    if args.keydata is None:
        m = Mnemonic()
    elif args.keydata.isdigit() and len(args.keydata) < 4:
        m = Mnemonic(int(args.keydata))
    elif ' ' in args.keydata:
        m = Mnemonic(args.keydata)
    elif args.keydata.startswith('xp'):
        r = node_from_str(args.keydata)
    elif set(args.keydata) <= set('1234567890abcdefABCDEF'):
        seed = bytes.fromhex(args.keydata)

    if 'm' in locals():
        print(f"Mnemonic : {m}")
        seed = m.to_seed()

    if 'seed' in locals():
        hexseed = seed.hex().upper()
        print(f"seed     : {hexseed[:64]}\n           {hexseed[64:]}")
        r = PrivBIP32Node.from_entropy(seed)

    print(r)

    if args.path:
        mend = r.derive(args.path) if args.path else r
        print(f"\nDerived Key info {'':-<94}")
        print(f"path     : {args.path}")
        print(mend)
    else:
        mend = r

    ll = math.ceil(math.log10(args.l.stop))     # index text width
    al = 34 if args.format != "BCH" else 42     # address text width
    kl = 52 if args.wif else 66                 # key text width
    # cashaddr abbreveation adjustment.
    ab = 12 if (args.long_bch_format and args.format == "BCH") else 0
    print(f"\n{'leaves':-<{ll + al + kl + ab + 2}}")
    for i in args.l:
        xkey = mend.ckd(i)

        if args.format != "BCH":
            addr = xkey.addr(addrpre[args.format])
        elif args.long_bch_format:
            addr = xkey.cashaddr()
        else:
            addr = xkey.cashaddr()[12:]

        keydat = (xkey.wif(wifpre[args.format]) if args.wif
                  else bytes(xkey.pubkey).hex().upper())
        print(f"{i:{ll}d} {addr:<34} {keydat}")

if __name__ == "__main__":
    main()
