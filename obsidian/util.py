"Small utility module for some common functions"

def convertbits(
        data: bytes, frombits: int, tobits: int, pad: bool=True
    ) -> bytes:
    """
    Convert an iterable of non-negative integers `data` from base
    :math:`2^\mathrm{frombits}` to a list of base :math:`2^\mathrm{tobits}`
    symbols
    """
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret
