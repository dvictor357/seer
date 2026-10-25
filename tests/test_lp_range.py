import math
import unittest

import support  # noqa: F401
import lp_range as lr


class LiquidityMathTest(unittest.TestCase):
    def test_all_token_below_range_all_quote_above(self):
        x, y = lr.amounts(1.0, 0.5, 0.9, 1.2)
        self.assertGreater(x, 0)
        self.assertEqual(y, 0)
        x, y = lr.amounts(1.0, 2.0, 0.9, 1.2)
        self.assertEqual(x, 0)
        self.assertGreater(y, 0)

    def test_liquidity_for_reproduces_deposit(self):
        for p, pa, pb in ((1.0, 0.95, 1.15), (0.00125, 0.001, 0.002), (3000.0, 1500.0, 6000.0)):
            L = lr.liquidity_for(1000, p, pa, pb)
            self.assertAlmostEqual(lr.value(L, p, pa, pb), 1000, places=6)

    def test_capital_efficiency(self):
        # [p/4, 4p]: 2*sqrt(p) / (2*sqrt(p) - sqrt(p)/2 - sqrt(p)/2) = 2
        self.assertAlmostEqual(lr.capital_efficiency(1.0, 0.25, 4.0), 2.0)
        self.assertAlmostEqual(lr.capital_efficiency(1.0, 1e-12, 1e12), 1.0, places=5)
        self.assertGreater(lr.capital_efficiency(1.0, 0.95, 1.15), 10)

    def test_exit_hours(self):
        self.assertAlmostEqual(lr.exit_hours(0.05, 0.1, 0.01, 1), 50.0)
        self.assertAlmostEqual(lr.exit_hours(0.05, 0.1, 0.01, 4), 200.0)
        self.assertIsNone(lr.exit_hours(0.05, 0.1, 0, 1))
        self.assertIsNone(lr.exit_hours(0.05, 0.1, None, 1))


class PlanTest(unittest.TestCase):
    def test_rejects_bad_bounds(self):
        for lo, hi in ((5, 15), (-5, -1), (-100, 10), (-150, 10), (-5, 0)):
            with self.subTest(lo=lo, hi=hi), self.assertRaises(SystemExit):
                lr.plan(1.0, lo, hi, 1000, None, 0, 0)

    def test_deposit_split_and_losses(self):
        m = lr.plan(2.0, -5, 15, 1000, None, 0, 0)
        self.assertAlmostEqual(m["pa"], 1.9)
        self.assertAlmostEqual(m["pb"], 2.3)
        self.assertAlmostEqual(m["token_amount"] * 2.0 + m["quote_usd"], 1000, places=6)
        self.assertTrue(0 < m["token_share_pct"] < 100)
        self.assertGreater(m["lower_loss_usd"], 0)  # below range: worth less than the cash put in
        self.assertGreater(m["upper_loss_usd"], 0)  # above range: gave up gains vs HODL
        self.assertIsNone(m["lower_payback_days"])  # no fee data
        flat = next(g for g in m["grid"] if g["move_pct"] == 0)
        self.assertAlmostEqual(flat["vs_hodl_pct"], 0, places=9)
        self.assertAlmostEqual(flat["vs_cash_pct"], 0, places=9)
        moves = [g["move_pct"] for g in m["grid"]]
        self.assertEqual(moves, sorted(moves))
        self.assertIn(-5, moves)
        self.assertIn(15, moves)
        self.assertEqual(next(g for g in m["grid"] if g["move_pct"] == 50)["in_range"], False)

    def test_fee_upper_bound_caps_turnover(self):
        m = lr.plan(1.0, -5, 15, 1000, 0.3, 1_000_000, 100_000)
        self.assertEqual(m["turnover_used"], lr.TURNOVER_CAP)
        self.assertAlmostEqual(m["full_range_apr_pct"], 0.3 * 3 * 365)
        self.assertAlmostEqual(m["fee_usd_day"], 1000 * 0.3 * 3 / 100 * m["capital_efficiency"])
        self.assertTrue(m["fee_model"].startswith("upper bound"))
        self.assertAlmostEqual(m["lower_payback_days"], m["lower_loss_usd"] / m["fee_usd_day"])

    def test_fee_active_liquidity_share(self):
        m = lr.plan(1.0, -5, 15, 1000, 0.3, 50_000, 100_000, depth_usd=2_000_000)
        mine = 1000 * m["capital_efficiency"]
        share = mine / (2_000_000 + mine)
        self.assertEqual(m["fee_model"], "active liquidity")
        self.assertAlmostEqual(m["fee_share_pct"], share * 100)
        self.assertAlmostEqual(m["fee_usd_day"], 0.3 / 100 * 0.5 * 100_000 * share)

    def test_no_fee_without_liquidity(self):
        m = lr.plan(1.0, -5, 15, 1000, 0.3, 50_000, 0)
        self.assertNotIn("fee_usd_day", m)


class RangeAdviceTest(unittest.TestCase):
    def test_sigma_pct_preference(self):
        self.assertEqual(lr.sigma_pct({"sigma_pct": 2, "atr_pct": 9}), 2)
        self.assertAlmostEqual(lr.sigma_pct({"atr_pct": 3.2}), 3.2 / lr.RANGE_PER_SIGMA)
        self.assertEqual(lr.sigma_pct({"vol_per_bar_stdev_pct": 4}), 4)
        self.assertIsNone(lr.sigma_pct({}))

    def test_vol_fit_range_lasts_hold_hours(self):
        rows = lr.vol_fit({"1h": {"sigma_pct": 2}, "4h": {"sigma_pct": 5}, "1d": {}}, -5, 15, 48)
        self.assertEqual([r["tf"] for r in rows], ["1h", "4h"])
        for r in rows:
            a = -math.log(1 + r["fit_lower_pct"] / 100)
            b = math.log(1 + r["fit_upper_pct"] / 100)
            with self.subTest(tf=r["tf"]):
                self.assertAlmostEqual(lr.exit_hours(a, b, r["sigma_bar_pct"] / 100, lr.TF_HOURS[r["tf"]]), 48)
                a0, b0 = -math.log(0.95), math.log(1.15)
                self.assertAlmostEqual(r["p_exit_up_pct"], a0 / (a0 + b0) * 100)

    def test_sr_range_skips_levels_hugging_price(self):
        tech = {"1h": {"atr_pct": 3, "nearest_support": 0.99, "nearest_resistance": 1.01},
                "4h": {"nearest_support": 0.9, "nearest_resistance": 1.2},
                "1d": {"nearest_support": 0.4, "nearest_resistance": 5}}  # out of [p/2, 3p]
        out = lr.sr_range(tech, 1.0)
        self.assertEqual(out["min_gap_pct"], 3)
        self.assertEqual(out["support"], 0.9)
        self.assertEqual(out["resistance"], 1.2)
        self.assertEqual(lr.sr_range({}, 1.0), {"min_gap_pct": 2})

    def test_verdict_thresholds(self):
        def note(h):
            return lr.verdict({}, [{"tf": "1h", "exit_hours": h}], None)[0]
        self.assertTrue(note(10).startswith("TOO TIGHT"))
        self.assertTrue(note(48).startswith("TIGHT"))
        self.assertTrue(note(96).startswith("FITS"))
        notes = lr.verdict({"range_apr_pct": 5, "fee_pct": 0}, [], "down/down")
        self.assertTrue(any("downtrend" in n for n in notes))
        self.assertIn("low fee APR even concentrated", notes)
        self.assertIn("ZERO-FEE pool: no fee income at all", notes)


if __name__ == "__main__":
    unittest.main()
