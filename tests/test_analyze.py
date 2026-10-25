import unittest

import support  # noqa: F401
import analyze as an


def bar(t, c, h=None, l=None, v=1.0):
    return {"t": t, "o": c, "h": c if h is None else h, "l": c if l is None else l, "c": c, "v": v}


class ParseTargetTest(unittest.TestCase):
    def test_url_and_pair(self):
        self.assertEqual(an.parse_target(["https://dexscreener.com/base/0xAbC123"]), ("base", "0xAbC123"))
        self.assertEqual(an.parse_target(["https://dexscreener.com/solana/7xKXtg2CW?maker=x"]),
                         ("solana", "7xKXtg2CW"))
        self.assertEqual(an.parse_target(["robinhood", "0xabc"]), ("robinhood", "0xabc"))

    def test_bad_input(self):
        for args in ([], ["https://example.com/base/0xabc"], ["a", "b", "c"]):
            with self.subTest(args=args), self.assertRaises(SystemExit):
                an.parse_target(args)


class IndicatorTest(unittest.TestCase):
    def test_f(self):
        self.assertEqual(an.f("1.5"), 1.5)
        self.assertEqual(an.f(None), 0.0)
        self.assertEqual(an.f("x", 7), 7)

    def test_ema(self):
        self.assertEqual(an.ema([], 9), [])
        self.assertEqual(an.ema([2.0] * 5, 3), [2.0] * 5)
        self.assertAlmostEqual(an.ema([0.0, 4.0], 3)[-1], 2.0)  # k = 2/(3+1) = 0.5

    def test_rsi(self):
        self.assertIsNone(an.rsi(list(range(14))))
        self.assertEqual(an.rsi([float(i) for i in range(20)]), 100.0)
        self.assertAlmostEqual(an.rsi([float(20 - i) for i in range(20)]), 0.0)
        self.assertAlmostEqual(an.rsi([1.0, 2.0] * 10, n=2), 50.0, delta=20)

    def test_atr(self):
        self.assertIsNone(an.atr([bar(0, 1)]))
        c = [bar(i, 10, h=11, l=9) for i in range(5)]
        self.assertEqual(an.atr(c), 2)
        # gap up: true range uses the previous close
        self.assertEqual(an.atr([bar(0, 10), bar(1, 20, h=21, l=19)]), 11)

    def test_swings_and_cluster(self):
        closes = [1, 2, 3, 4, 3, 2, 1, 2, 3]
        hi, lo = an.swings([bar(i, c) for i, c in enumerate(closes)])
        self.assertEqual(hi, [4])
        self.assertEqual(lo, [])  # the low at index 6 has only 2 bars after it
        merged = an.cluster([1.0, 1.02, 2.0])
        self.assertAlmostEqual(merged[0][0], 1.01)
        self.assertEqual(merged[0][1], 2)
        self.assertEqual(merged[1], (2.0, 1))

    def test_impact_pct(self):
        self.assertIsNone(an.impact_pct(100, 0))
        self.assertEqual(an.impact_pct(0, 1000), 0)
        self.assertAlmostEqual(an.impact_pct(500, 1000), 75.0)  # trade = one side of the pool

    def test_candles_sorted(self):
        raw = {"data": {"attributes": {"ohlcv_list": [[2, 1, 1, 1, 1, 1], [1, 2, 2, 2, 2, 2]]}}}
        self.assertEqual([c["t"] for c in an.candles(raw)], [1, 2])
        self.assertEqual(an.candles(None), [])
        self.assertEqual(an.candles({}), [])

    def test_tech(self):
        self.assertEqual(an.tech([bar(0, 1)] * 3, "1h")["note"], "insufficient history")
        c = [bar(i, 1 + i * 0.1, v=1 + i) for i in range(30)]
        t = an.tech(c, "1h")
        self.assertEqual(t["ema_trend"], "up")
        self.assertEqual(t["rsi14"], 100.0)
        self.assertAlmostEqual(t["drawdown_from_high_pct"], 0)
        self.assertGreater(t["volume_trend_2nd_half_vs_1st"], 1)


class FlowTest(unittest.TestCase):
    def test_flow(self):
        self.assertIsNone(an.flow(None))
        self.assertIsNone(an.flow({"data": []}))
        raw = {"data": [{"attributes": a} for a in (
            {"kind": "buy", "volume_in_usd": "100", "tx_from_address": "0xa", "block_timestamp": "t2"},
            {"kind": "buy", "volume_in_usd": "50", "tx_from_address": "0xb", "block_timestamp": "t1"},
            {"kind": "sell", "volume_in_usd": "30", "tx_from_address": "0xa", "block_timestamp": "t3"},
        )]}
        fl = an.flow(raw)
        self.assertEqual(fl["sample_trades"], 3)
        self.assertEqual(fl["buy_usd"], 150)
        self.assertEqual(fl["sell_usd"], 30)
        self.assertEqual(fl["net_usd"], 120)
        self.assertEqual(fl["unique_wallets"], 2)
        self.assertEqual(fl["largest_trade_usd"], 100)
        self.assertEqual(fl["window"], "t1 -> t3")
        self.assertEqual(fl["top_net_buyers"][0], ("0xa", 70))

    def test_fmt(self):
        self.assertEqual(an.fmt(None), "n/a")
        self.assertEqual(an.fmt(12345.6), "12,346")
        self.assertEqual(an.fmt(0.000123456789, 3), "0.000123")
        self.assertEqual(an.fmt(7), "7")


if __name__ == "__main__":
    unittest.main()
