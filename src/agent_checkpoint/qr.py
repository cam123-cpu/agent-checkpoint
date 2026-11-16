"""A small QR code encoder for the two-step setup screen: byte mode, error correction M, versions 1-10.

Drawn on the server so the secret never goes to a third-party service or library, and the page
needs no outside script (the strict CSP stays strict). The test suite decodes generated codes
with OpenCV to prove they scan.

Steps: encode bytes → add error correction (Reed-Solomon over GF(256)) → interleave blocks →
place finder, timing and alignment patterns → lay data in the zigzag → try all eight masks and
keep the one with the lowest penalty → write format (and version) bits.
"""

from __future__ import annotations

# version: (ecc codewords per block, [(block count, data codewords per block), ...]) for level M
_M = {
    1: (10, [(1, 16)]), 2: (16, [(1, 28)]), 3: (26, [(1, 44)]), 4: (18, [(2, 32)]), 5: (24, [(2, 43)]),
    6: (16, [(4, 27)]), 7: (18, [(4, 31)]), 8: (22, [(2, 38), (2, 39)]), 9: (22, [(3, 36), (2, 37)]),
    10: (26, [(4, 43), (1, 44)]),
}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42],
          9: [6, 26, 46], 10: [6, 28, 50]}
_REMAINDER = {1: 0, 2: 7, 3: 7, 4: 7, 5: 7, 6: 7, 7: 0, 8: 0, 9: 0, 10: 0}

# GF(256) with primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _rs_ecc(data: list[int], n: int) -> list[int]:
    gen = [1]
    for i in range(n):  # multiply by (x - a^i)
        nxt = [0] * (len(gen) + 1)
        for j, c in enumerate(gen):
            nxt[j] ^= c
            nxt[j + 1] ^= _mul(c, _EXP[i])
        gen = nxt
    rem = [0] * n
    for byte in data:
        factor = byte ^ rem[0]
        rem = rem[1:] + [0]
        for j in range(n):
            rem[j] ^= _mul(gen[j + 1], factor)
    return rem


def _codewords(payload: bytes) -> tuple[int, list[int]]:
    for version in range(1, 11):
        ecc_n, groups = _M[version]
        capacity = sum(c * d for c, d in groups)
        count_bits = 8 if version < 10 else 16
        if 4 + count_bits + 8 * len(payload) <= capacity * 8:
            break
    else:
        raise ValueError("too much data for a version 10 QR code")
    bits = [0, 1, 0, 0] + [(len(payload) >> i) & 1 for i in range(count_bits - 1, -1, -1)]
    for b in payload:
        bits += [(b >> i) & 1 for i in range(7, -1, -1)]
    bits += [0] * min(4, capacity * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    data = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(data) < capacity:
        data.append(pad)
        pad ^= 0xEC ^ 0x11
    blocks, pos = [], 0
    for count, size in groups:
        for _ in range(count):
            blocks.append(data[pos:pos + size])
            pos += size
    eccs = [_rs_ecc(b, ecc_n) for b in blocks]
    out = []
    for i in range(max(len(b) for b in blocks)):
        out += [b[i] for b in blocks if i < len(b)]
    for i in range(ecc_n):
        out += [e[i] for e in eccs]
    return version, out


_MASKS = [
    lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0, lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0, lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0, lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
]


def _penalty(m: list[list[bool]]) -> int:
    n, score = len(m), 0
    for lines in (m, [list(col) for col in zip(*m, strict=True)]):
        for line in lines:  # runs of 5+ same colour
            run, prev = 0, None
            for v in line:
                run = run + 1 if v == prev else 1
                prev = v
                if run == 5:
                    score += 3
                elif run > 5:
                    score += 1
            s = "0000" + "".join("1" if v else "0" for v in line) + "0000"  # finder-like patterns (border is light)
            score += 40 * (s.count("10111010000") + s.count("00001011101"))
    for y in range(n - 1):  # 2x2 blocks
        for x in range(n - 1):
            if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                score += 3
    dark = sum(map(sum, m))
    score += 10 * (abs(dark * 20 - n * n * 10) // (n * n))
    return score


def encode(text: str) -> list[list[bool]]:
    version, data = _codewords(text.encode("utf-8"))
    n = 17 + 4 * version
    mod = [[False] * n for _ in range(n)]
    fn = [[False] * n for _ in range(n)]

    def put(x, y, dark):
        mod[y][x], fn[y][x] = dark, True

    for cx, cy in ((3, 3), (n - 4, 3), (3, n - 4)):  # finders with separators
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < n and 0 <= y < n:
                    d = max(abs(dx), abs(dy))
                    put(x, y, d != 2 and d != 4)
    for i in range(n):  # timing
        if not fn[6][i]:
            put(i, 6, i % 2 == 0)
        if not fn[i][6]:
            put(6, i, i % 2 == 0)
    pos = _ALIGN[version]
    for ay in pos:
        for ax in pos:
            if (ax, ay) in ((6, 6), (6, n - 7), (n - 7, 6)):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    put(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)
    for i in range(9):  # reserve format areas
        for x, y in ((8, i), (i, 8)):
            if not fn[y][x]:
                put(x, y, False)
    for i in range(8):
        put(n - 1 - i, 8, False)
        put(8, n - 1 - i, False)
    put(8, n - 8, True)  # dark module
    if version >= 7:
        rem = version
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        vbits = version << 12 | rem
        for i in range(18):
            bit = (vbits >> i) & 1 == 1
            a, b = n - 11 + i % 3, i // 3
            put(a, b, bit)
            put(b, a, bit)

    bits = [(byte >> (7 - k)) & 1 for byte in data for k in range(8)] + [0] * _REMAINDER[version]
    i, right = 0, n - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(n):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = n - 1 - vert if upward else vert
                if not fn[y][x] and i < len(bits):
                    mod[y][x] = bits[i] == 1
                    i += 1
        right -= 2

    def with_mask(mask: int) -> list[list[bool]]:
        m = [row[:] for row in mod]
        f = _MASKS[mask]
        for y in range(n):
            for x in range(n):
                if not fn[y][x] and f(x, y):
                    m[y][x] = not m[y][x]
        fmt = (0 << 3) | mask  # level M = 00
        rem = fmt
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        fbits = ((fmt << 10) | rem) ^ 0x5412

        def b(k):
            return (fbits >> k) & 1 == 1
        for k in range(6):
            m[k][8] = b(k)
        m[7][8], m[8][8], m[8][7] = b(6), b(7), b(8)
        for k in range(9, 15):
            m[8][14 - k] = b(k)
        for k in range(8):
            m[8][n - 1 - k] = b(k)
        for k in range(8, 15):
            m[n - 15 + k][8] = b(k)
        m[n - 8][8] = True
        return m

    return min((with_mask(k) for k in range(8)), key=_penalty)


def svg(text: str, scale: int = 6, quiet: int = 4) -> str:
    m = encode(text)
    n = len(m)
    size = (n + 2 * quiet) * scale
    path = "".join(f"M{(x + quiet) * scale} {(y + quiet) * scale}h{scale}v{scale}h-{scale}z"
                   for y in range(n) for x in range(n) if m[y][x])
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
            f'shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/>'
            f'<path fill="#000" d="{path}"/></svg>')
