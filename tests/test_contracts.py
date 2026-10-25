"""Pure helpers of the on-chain checker, the dossier builder and the LP fee scan."""
import unittest

import support  # noqa: F401
import contract_dossier as cd
import lp_fees
import onchain_check as oc


class DossierHelpersTest(unittest.TestCase):
    def test_split_args_respects_tuples(self):
        self.assertEqual(cd.split_args(""), [])
        self.assertEqual(cd.split_args("address,uint256"), ["address", "uint256"])
        self.assertEqual(cd.split_args("address,(uint256,(bool,address)),bytes"),
                         ["address", "(uint256,(bool,address))", "bytes"])

    def test_sig_to_abi(self):
        fn = cd.sig_to_abi("transfer(address,uint256)")
        self.assertEqual(fn["name"], "transfer")
        self.assertEqual([i["type"] for i in fn["inputs"]], ["address", "uint256"])
        self.assertEqual(fn["stateMutability"], "nonpayable")
        self.assertEqual(cd.sig_to_abi("pause()")["inputs"], [])
        ev = cd.sig_to_abi("Swap(bytes32,(int128,int128))", kind="event")
        self.assertEqual([i["type"] for i in ev["inputs"]], ["bytes32", "(int128,int128)"])
        self.assertFalse(ev["anonymous"])
        self.assertNotIn("outputs", ev)

    def test_value_str(self):
        self.assertEqual(cd.value_str({"uint": 5}), "5")
        self.assertEqual(cd.value_str({"bool/uint": 1}), "1 (bool/uint)")
        self.assertEqual(cd.value_str({"tuple": [{"uint": 1}, {"address": "0xab"}]}), "(1, 0xab)")
        self.assertEqual(cd.value_str("raw"), "raw")

    def test_safe_dir_name(self):
        self.assertEqual(cd.safe_dir_name("Uni V3/Pool:x"), "Uni_V3_Pool_x")
        self.assertEqual(cd.safe_dir_name("../../etc"), ".._.._etc")
        self.assertEqual(len(cd.safe_dir_name("a" * 100)), 60)


class OnchainHelpersTest(unittest.TestCase):
    def test_amounts_for(self):
        x, y = oc.amounts_for(1000, -100, 100, 1.0)  # tick 0 inside [-100, 100]
        self.assertGreater(x, 0)
        self.assertGreater(y, 0)
        self.assertAlmostEqual(x, y, delta=x * 1e-3)  # symmetric range around price 1
        x, y = oc.amounts_for(1000, -100, 100, 0.5)
        self.assertGreater(x, 0)
        self.assertEqual(y, 0)
        x, y = oc.amounts_for(1000, -100, 100, 2.0)
        self.assertEqual(x, 0)
        self.assertGreater(y, 0)

    def test_verdict(self):
        def label(*sevs):
            return oc.verdict([{"severity": s} for s in sevs])["label"]
        self.assertEqual(label(), "NO MAJOR CONTRACT RED FLAGS")
        self.assertEqual(label("CRITICAL", "OK"), "DANGER")
        self.assertEqual(label("HIGH", "HIGH"), "HIGH RISK")
        self.assertEqual(label("HIGH"), "CAUTION")
        self.assertEqual(label("MEDIUM", "MEDIUM", "MEDIUM"), "CAUTION")
        self.assertEqual(label("MEDIUM", "MEDIUM", "LOW"), "NO MAJOR CONTRACT RED FLAGS")
        self.assertEqual(oc.verdict([{"severity": "HIGH"}, {"severity": "INFO"}])["counts"],
                         {"HIGH": 1, "INFO": 1})

    def test_state_map(self):
        state = [{"fn": "owner()", "arg": None, "value": {"address": "0xab"}},
                 {"fn": "balanceOf(address)", "arg": "0x1", "value": {"uint": 5}},
                 {"fn": "limits()", "arg": None, "value": {"tuple": [{"uint": 1}]}},
                 {"fn": "paused()", "arg": None, "value": {"bool/uint": 0}}]
        self.assertEqual(oc.state_map(state), {"owner": "0xab", "paused": 0})


class LpFeesTest(unittest.TestCase):
    def test_effective_fee_priority(self):
        self.assertEqual(lp_fees.effective_fee({"swap_fee_median": 500, "live_lp_fee": 3000}), (500, "swaps"))
        self.assertEqual(lp_fees.effective_fee({"dynamic": True, "live_lp_fee": 3000}), (None, "dynamic"))
        self.assertEqual(lp_fees.effective_fee({"live_lp_fee": 3000, "fee_tier": 10000}), (3000, "slot0"))
        self.assertEqual(lp_fees.effective_fee({"fee_tier": 10000}), (10000, "tier"))
        self.assertEqual(lp_fees.effective_fee({}), (None, "tier"))

    def test_pairs_from_args_rejects_missing_parts(self):
        for items in ([], ["robinhood"], ["0xabc"]):
            with self.subTest(items=items), self.assertRaises(SystemExit):
                lp_fees.pairs_from_args(items)

    def test_lp_flags(self):
        r = {"flags": ["churn/wash?"], "chg24": 80, "chg6": 0, "age_d": 1, "liq": 10_000}
        s = {"swaps_window": 0, "hook_bits": ["beforeRemoveLiquidity", "afterSwapReturnDelta"]}
        flags = lp_fees.lp_flags(r, s, 0)
        for want in ("ZERO-FEE", "no swaps", "gates remove-liquidity", "cut of swaps", "wash",
                     "high volatility", "< 48h", "thin pool"):
            with self.subTest(want=want):
                self.assertTrue(any(want in f for f in flags), flags)
        self.assertEqual(lp_fees.lp_flags({"flags": [], "chg24": 1, "chg6": 1, "age_d": 30, "liq": 1e6},
                                          {"swaps_window": 9}, 3000), [])


if __name__ == "__main__":
    unittest.main()
