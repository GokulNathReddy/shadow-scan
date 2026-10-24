"""Pure-Python Keccak-512 (the original Keccak padding, as used by XposedOrNot).

Note: this is *not* the same as hashlib.sha3_512 - FIPS-202 SHA-3 changed the
padding byte from 0x01 to 0x06, which produces completely different digests.
Implemented from scratch so the app needs no third-party packages."""

from __future__ import annotations

_MASK = (1 << 64) - 1

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

# Rotation offsets r[x][y] for the rho step.
_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK


def _keccak_f(lanes: list[int]) -> list[int]:
    """The Keccak-f[1600] permutation. Lane (x, y) lives at index x + 5*y."""
    a = lanes
    for rc in _ROUND_CONSTANTS:
        # theta
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(a[x + 5 * y], _ROTATIONS[x][y])
        # chi
        a = [
            b[i] ^ (~b[(i % 5 + 1) % 5 + 5 * (i // 5)] & b[(i % 5 + 2) % 5 + 5 * (i // 5)])
            for i in range(25)
        ]
        # iota
        a[0] ^= rc
    return a


def _sponge(data: bytes, rate: int, out_len: int, pad_byte: int) -> bytes:
    padded = bytearray(data)
    padded.append(pad_byte)
    padded.extend(b"\x00" * (-len(padded) % rate))
    padded[-1] |= 0x80

    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        state = _keccak_f(state)

    out = bytearray()
    while True:
        for i in range(rate // 8):
            out += state[i].to_bytes(8, "little")
        if len(out) >= out_len:
            return bytes(out[:out_len])
        state = _keccak_f(state)


def keccak_512(data: bytes) -> bytes:
    return _sponge(data, rate=72, out_len=64, pad_byte=0x01)


def keccak_512_hex(data: bytes) -> str:
    return keccak_512(data).hex()
