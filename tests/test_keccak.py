import hashlib
import unittest

import support  # noqa: F401
import keccak
from keccak import keccak256, selector, topic


def sha3_256_via_keccak_f(data):
    """NIST SHA3-256 built on keccak._f (domain byte 0x06 instead of 0x01), so the
    permutation and block absorption can be checked against hashlib."""
    rate = 136
    msg = bytearray(data)
    msg.append(0x06)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            A[i % 5][i // 5] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        A = keccak._f(A)
    return b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


class KeccakTest(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(keccak256(b"abc").hex(),
                         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_selectors_and_topics(self):
        self.assertEqual(selector("transfer(address,uint256)"), "0xa9059cbb")
        self.assertEqual(selector("balanceOf(address)"), "0x70a08231")
        self.assertEqual(selector("approve(address,uint256)"), "0x095ea7b3")
        self.assertEqual(topic("Transfer(address,address,uint256)"),
                         "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

    def test_eip1967_slot(self):
        slot = int(topic("eip1967.proxy.implementation"), 16) - 1
        self.assertEqual(hex(slot), "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")

    def test_permutation_matches_hashlib_across_block_boundaries(self):
        # 135/136/137 and 271/272 straddle the 136-byte rate, where padding bugs hide
        for n in (0, 1, 55, 135, 136, 137, 200, 271, 272, 273, 1000):
            data = bytes(range(256)) * 4
            data = data[:n]
            with self.subTest(n=n):
                self.assertEqual(sha3_256_via_keccak_f(data), hashlib.sha3_256(data).digest())

    def test_output_is_32_bytes(self):
        for n in (0, 135, 136, 500):
            self.assertEqual(len(keccak256(b"x" * n)), 32)


if __name__ == "__main__":
    unittest.main()
