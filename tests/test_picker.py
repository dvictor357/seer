"""Screener row building and the picker's LP / BUY ratings, from a DexScreener-shaped pair."""
import unittest

import support  # noqa: F401
import picker
import screener

NOW_MS = 1_800_000_000_000
DAY_MS = 86_400_000


def pair(liq=300_000, mcap=2_000_000, vol24=600_000, chg=(1, 2, 5), buys=600, sells=400,
         txns1h=50, age_d=30, **extra):
    p = {
        "chainId": "base", "dexId": "uniswap", "labels": ["v3"], "url": "https://dexscreener.com/base/0xpair",
        "pairAddress": "0xpair", "priceUsd": "0.5",
        "baseToken": {"address": "0xtoken", "name": "Test", "symbol": "TST"},
        "quoteToken": {"address": "0xweth", "name": "Wrapped Ether", "symbol": "WETH"},
        "liquidity": {"usd": liq}, "marketCap": mcap, "fdv": mcap * 2,
        "volume": {"h24": vol24, "h1": vol24 / 24},
        "txns": {"h24": {"buys": buys, "sells": sells}, "h1": {"buys": txns1h // 2, "sells": txns1h - txns1h // 2}},
        "priceChange": {"h1": chg[0], "h6": chg[1], "h24": chg[2]},
        "pairCreatedAt": NOW_MS - age_d * DAY_MS,
    }
    p.update(extra)
    return p


def row(totals=None, **kw):
    return screener.row(pair(**kw), NOW_MS, totals)


def with_fees(r, fee_pct=0.3, **extra):
    r = dict(r, lp_fee_pct=fee_pct, fee_apr_pct=fee_pct * r["vol_liq"] * 365, swaps_window=10)
    r.update(extra)
    return r


class ScreenerRowTest(unittest.TestCase):
    def test_fields(self):
        r = row(totals=(400_000, 3, False))
        self.assertEqual(r["symbol"], "TST")
        self.assertEqual(r["dex"], "uniswap v3")
        self.assertAlmostEqual(r["age_d"], 30)
        self.assertEqual(r["vol_liq"], 2)
        self.assertEqual(r["total_liq"], 400_000)
        self.assertEqual(r["liq_mcap_pct"], 20)
        self.assertEqual(r["bs_ratio"], 1.5)
        self.assertEqual(r["txns1h"], 50)
        self.assertEqual(r["flags"], [])

    def test_total_liq_never_below_main_pool(self):
        self.assertEqual(row(totals=(1_000, 1, False))["total_liq"], 300_000)

    def test_fdv_fallback_and_missing_age(self):
        r = row(mcap=0, pairCreatedAt=None)
        self.assertIsNone(r["age_d"])
        self.assertEqual(r["mcap"], 0)  # fdv is 2 * mcap = 0 too
        self.assertEqual(r["liq_mcap_pct"], 0)

    def test_flags(self):
        r = row(liq=10_000, vol24=500_000, buys=3, sells=2, txns1h=0, age_d=1, chg=(0, 0, -60))
        for flag in ("thin-liq", "new<48h", "churn/wash?", "fake-vol?", "dead-1h", "dumped"):
            with self.subTest(flag=flag):
                self.assertIn(flag, r["flags"])
        self.assertLess(r["score"], row()["score"])


class RatingTest(unittest.TestCase):
    def test_healthy_pool(self):
        r = with_fees(row(totals=(400_000, 3, False)))
        lp, _, why = picker.rate_lp(r)
        self.assertEqual(lp, "GOOD LP", why)
        buy, _, why = picker.rate_buy(r)
        self.assertEqual(buy, "CANDIDATE", why)

    def test_lp_hard_fails(self):
        base = row()
        cases = {
            "zero fee": with_fees(base, fee_pct=0),
            "hook controls removal": with_fees(base, hook_bits=["beforeRemoveLiquidity"]),
        }
        for name, r in cases.items():
            with self.subTest(name):
                lab, _, why = picker.rate_lp(r)
                self.assertEqual(lab, "AVOID LP")
                self.assertIn("pool charges ~0% fee" if name == "zero fee" else "exit may be blocked", why[0])

    def test_lp_apr_capped_at_3x_turnover(self):
        r = with_fees(row(vol24=3_000_000))  # vol/liq = 10
        picker.rate_lp(r)
        self.assertAlmostEqual(r["lp_apr_capped"], 0.3 * 3 * 365)

    def test_buy_hard_fail_on_paper_mcap(self):
        for mcap in (100_000_000, 15_000_000):  # liq/mcap 0.3% and 2%
            with self.subTest(mcap=mcap):
                lab, _, why = picker.rate_buy(row(mcap=mcap))
                self.assertEqual(lab, "AVOID")
                self.assertEqual(why[0], "liquidity under 3% of mcap")
        _, _, why = picker.rate_buy(row(mcap=10_000_000))  # exactly 3%: weak, but not a hard fail
        self.assertNotIn("liquidity under 3% of mcap", why)

    def test_candidate_capped_for_young_or_pumped(self):
        young = picker.rate_buy(row(totals=(400_000, 3, False), age_d=3))
        self.assertNotEqual(young[0], "CANDIDATE")
        thin = picker.rate_buy(row(liq=90_000, mcap=500_000, vol24=180_000))
        self.assertNotEqual(thin[0], "CANDIDATE")

    def test_label(self):
        self.assertEqual(picker.label(10, picker.LP_LABELS, "boom"), "AVOID LP")
        self.assertEqual(picker.label(4, picker.LP_LABELS, None), "GOOD LP")
        self.assertEqual(picker.label(1, picker.LP_LABELS, None), "OK LP")
        self.assertEqual(picker.label(0, picker.LP_LABELS, None), "AVOID LP")


if __name__ == "__main__":
    unittest.main()
