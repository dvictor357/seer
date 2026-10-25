import json
import os
import subprocess
import sys
import tempfile
import unittest

import support
import evm


def word(hexstr):
    return hexstr.rjust(64, "0")


class AbiTest(unittest.TestCase):
    def test_words_and_ints(self):
        self.assertEqual(evm.words(None), [])
        self.assertEqual(evm.words("0x"), [])
        self.assertEqual(evm.words("0x" + word("1") + word("2")), [word("1"), word("2")])
        self.assertEqual(evm.w_int(word("ff")), 255)
        self.assertEqual(evm.w_int("f" * 64, signed=True), -1)

    def test_address_round_trip(self):
        a = "0x" + "AbCd" * 10
        self.assertEqual(evm.w_addr(evm.enc_addr(a)), a.lower())
        self.assertEqual(evm.enc_uint(255), word("ff"))

    def test_decode_str(self):
        self.assertIsNone(evm.decode_str(None))
        self.assertIsNone(evm.decode_str("0x"))
        dyn = "0x" + word("20") + word("4") + "53454552".ljust(64, "0")
        self.assertEqual(evm.decode_str(dyn), "SEER")
        b32 = "0x" + "4d4b52".ljust(64, "0")  # MKR-style bytes32 symbol
        self.assertEqual(evm.decode_str(b32), "MKR")

    def test_guess_value(self):
        self.assertEqual(evm.guess_value(None), {"error": "reverted"})
        self.assertEqual(evm.guess_value("0x"), {"raw": "0x"})
        self.assertEqual(evm.guess_value("0x" + word("1")), {"bool/uint": 1})
        addr = "11" * 20
        self.assertEqual(evm.guess_value("0x" + word(addr)), {"address": "0x" + addr})
        self.assertEqual(evm.guess_value("0x" + "f" * 64), {"int": -1})
        self.assertEqual(evm.guess_value("0x" + word("20") + word("2") + "6869".ljust(64, "0")),
                         {"string": "hi"})
        self.assertEqual(evm.guess_value("0x" + word("5") + word("0")), {"tuple": [{"uint": 5}, {"uint": 0}]})


class BytecodeTest(unittest.TestCase):
    def test_disassemble(self):
        ins = evm.disassemble("0x6001600201")
        self.assertEqual(ins, [(0, "PUSH1", "01"), (2, "PUSH1", "02"), (4, "ADD", "")])
        self.assertEqual(evm.disassemble("61aa"), [(0, "PUSH2", "aa")])  # truncated push at end of code
        self.assertEqual(evm.disassemble("0c")[0][1], "UNKNOWN_0x0c")

    def test_analyze_bytecode(self):
        code = ("63a9059cbb14"      # PUSH4 transfer EQ          -> dispatcher
                "631234567860e01b"  # PUSH4 x PUSH1 0xe0 SHL     -> outbound call selector
                "7f" + "ab" * 32 +  # PUSH32                     -> event topic
                "f4ff")             # DELEGATECALL SELFDESTRUCT
        r = evm.analyze_bytecode(code)
        self.assertEqual(r["dispatcher"], {"0xa9059cbb"})
        self.assertEqual(r["outbound_or_errors"], {"0x12345678"})
        self.assertEqual(r["push32"], {"0x" + "ab" * 32})
        self.assertTrue(r["has_selfdestruct"])
        self.assertTrue(r["has_delegatecall"])
        self.assertFalse(evm.analyze_bytecode("6001")["has_selfdestruct"])

    def test_eip7702_target(self):
        target = "22" * 20
        self.assertEqual(evm.eip7702_target("0xEF0100" + target), "0x" + target)
        self.assertIsNone(evm.eip7702_target("0xef0100" + target + "00"))
        self.assertIsNone(evm.eip7702_target("0x6001"))


class SafeJoinTest(unittest.TestCase):
    def test_stays_inside_root(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(evm._safe_join(root, "contracts/A.sol"), os.path.join(root, "contracts", "A.sol"))
            for rel in ("../../etc/passwd", "/etc/passwd", "..\\..\\x.sol", "a/../../b.sol"):
                with self.subTest(rel=rel):
                    p = evm._safe_join(root, rel)
                    self.assertTrue(p.startswith(os.path.join(root, "")), p)
            self.assertEqual(evm._safe_join(root, ""), os.path.join(root, "source.sol"))

    def test_save_sources(self):
        with tempfile.TemporaryDirectory() as root:
            evm.save_sources(root, {"src/T.sol": "contract T {}", "../evil.sol": None})
            with open(os.path.join(root, "src", "T.sol")) as fh:
                self.assertEqual(fh.read(), "contract T {}")
            self.assertTrue(os.path.exists(os.path.join(root, "evil.sol")))


class ConfigTest(unittest.TestCase):
    """evm reads config.json at import, so each case runs in a fresh interpreter."""

    PROBE = ("import os, sys; sys.path.insert(0, sys.argv[1]); import evm; "
             "print(evm.RPCS['base'][0]); print(evm.RPCS['base'].count(evm.RPCS['base'][0])); "
             "print(evm.RPCS.get('mychain')); print(os.environ.get('ETHERSCAN_API_KEY')); "
             "print(evm.DOSSIERS)")

    def run_probe(self, config, **env):
        with tempfile.TemporaryDirectory() as home:
            if config is not None:
                with open(os.path.join(home, "config.json"), "w") as fh:
                    fh.write(config if isinstance(config, str) else json.dumps(config))
            p = subprocess.run([sys.executable, "-I", "-c", self.PROBE, support.SCRIPTS],
                               env=support.clean_env(SEER_HOME=home, **env),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            return p, home

    def test_no_config(self):
        p, home = self.run_probe(None)
        self.assertEqual(p.returncode, 0, p.stderr)
        base, _, mine, key, dossiers = p.stdout.splitlines()
        self.assertEqual(base, evm.RPCS["base"][0])
        self.assertEqual(mine, "None")
        self.assertEqual(key, "None")
        self.assertEqual(dossiers, os.path.join(home, "dossiers"))

    def test_config_rpcs_first_and_key_filled(self):
        cfg = {"rpc": {"base": "https://mine.example", "mychain": ["https://a", "https://b"]},
               "etherscan_api_key": "cfgkey"}
        p, _ = self.run_probe(cfg)
        self.assertEqual(p.returncode, 0, p.stderr)
        base, count, mine, key, _ = p.stdout.splitlines()
        self.assertEqual(base, "https://mine.example")
        self.assertEqual(count, "1")
        self.assertEqual(mine, "['https://a', 'https://b']")
        self.assertEqual(key, "cfgkey")

    def test_config_rpc_already_builtin_not_duplicated(self):
        builtin = evm.RPCS["base"][1]
        p, _ = self.run_probe({"rpc": {"base": [builtin]}})
        base, count, _, _, _ = p.stdout.splitlines()
        self.assertEqual((base, count), (builtin, "1"))

    def test_env_beats_config(self):
        p, _ = self.run_probe({"etherscan_api_key": "cfgkey"}, ETHERSCAN_API_KEY="envkey")
        self.assertEqual(p.stdout.splitlines()[3], "envkey")

    def test_bad_config_fails_with_path(self):
        for cfg, msg in (("{not json", "cannot read"), ("[]", "must be a JSON object"),
                         ('{"rpc": "https://x"}', 'must map chain')):
            with self.subTest(cfg=cfg):
                p, _ = self.run_probe(cfg)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(msg, p.stderr)
                self.assertIn("config.json", p.stderr)


if __name__ == "__main__":
    unittest.main()
