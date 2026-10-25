#!/usr/bin/env python3
"""LP range planner: does a concentrated-liquidity range fit this pool?

For a range given as % from the current price (default -5% / +15%) it computes:
  - price bounds and deposit split (token vs quote) for your USD size
  - capital efficiency vs full range, and estimated fee APR / USD per day
    (on-chain fee from lp_fees, turnover capped at 3x liquidity like picker)
  - position value at each bound and on a price grid, vs HODL and vs cash
  - days of fees needed to pay back the loss at each bound
  - expected time in range from realized volatility per timeframe
    (zero-drift Brownian exit time: E[t] = a*b / sigma^2 in log-price)
  - suggested ranges: one from support/resistance, one sized for --hold-h
  - your share of the pool and exit price impact
Math is Uniswap v3/v4 concentrated liquidity in USD terms. If the quote is not
a stable (e.g. WETH), bounds are in USD at today's quote price and drift with it.

Usage:
  lp_range.py "<dexscreener-url>"                          # -5% / +15%, $1000
  lp_range.py "<url>" --lower -10 --upper 30 --usd 500 --hold-h 48
  lp_range.py robinhood <pair> --fee 0.3                   # skip on-chain fee read
  lp_range.py --price 0.00125 --fee 5 --vol24 160000 --liq 65000 --sigma-1h 3.5   # offline calculator
"""
import argparse
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze  # noqa: E402

TURNOVER_CAP = 3.0  # same cap as picker: vol24 above 3x liquidity counts as 3x
GRID = (-30, -20, -10, -5, 0, 5, 10, 15, 25, 50)
TF_HOURS = {"15m": 0.25, "1h": 1, "4h": 4, "1d": 24}
RANGE_PER_SIGMA = math.sqrt(8 / math.pi)  # E[bar high-low] = 1.6 sigma for a random walk (Parkinson)


# ---------- concentrated liquidity math (prices in USD per token) ----------
def amounts(L, p, pa, pb):
    """Token and quote held by liquidity L at price p in range [pa, pb]."""
    sp, sa, sb = math.sqrt(min(max(p, pa), pb)), math.sqrt(pa), math.sqrt(pb)
    return L * (1 / sp - 1 / sb), L * (sp - sa)


def value(L, p, pa, pb):
    x, y = amounts(L, p, pa, pb)
    return x * p + y


def liquidity_for(usd, p, pa, pb):
    return usd / value(1.0, p, pa, pb)


def capital_efficiency(p, pa, pb):
    """Liquidity per $ vs a full-range (v2) position at the same price."""
    sp = math.sqrt(p)
    return 2 * sp / (2 * sp - math.sqrt(pa) - p / math.sqrt(pb))


def exit_hours(a, b, sigma, bar_h):
    """Expected hours until log-price leaves (-a, +b); sigma = per-bar stdev (fraction)."""
    if not sigma:
        return None
    return a * b / sigma ** 2 * bar_h


def plan(p, lo_pct, hi_pct, usd, fee_pct, vol24, liq, depth_usd=None):
    """depth_usd: pool's in-range liquidity as the TVL a full-range pool would need
    for the same depth. With it, your fee share = your depth / (pool + yours);
    without it, fees assume every other LP is full range (an upper bound)."""
    pa, pb = p * (1 + lo_pct / 100), p * (1 + hi_pct / 100)
    if not 0 < pa < p < pb:
        raise SystemExit(f"error: need lower < 0 < upper and lower > -100 (got {lo_pct}, {hi_pct})")
    L = liquidity_for(usd, p, pa, pb)
    x, y = amounts(L, p, pa, pb)
    ce = capital_efficiency(p, pa, pb)
    out = {"price": p, "lower_pct": lo_pct, "upper_pct": hi_pct, "pa": pa, "pb": pb, "usd": usd,
           "token_amount": x, "quote_usd": y, "token_share_pct": x * p / usd * 100,
           "capital_efficiency": ce}
    if fee_pct is not None and liq:
        turnover = min(vol24 / liq, TURNOVER_CAP)
        full_apr = fee_pct * turnover * 365
        out.update(turnover_used=turnover, full_range_apr_pct=full_apr)
        if depth_usd:
            mine = usd * ce
            share = mine / (depth_usd + mine)
            fee_day = fee_pct / 100 * turnover * liq * share
            out.update(fee_model="active liquidity", pool_depth_usd=depth_usd, fee_share_pct=share * 100)
        else:
            fee_day = usd * full_apr * ce / 100 / 365
            out.update(fee_model="upper bound (other LPs assumed full range)")
        out.update(fee_usd_day=fee_day, range_apr_pct=fee_day * 365 / usd * 100)
    grid = []
    for g in sorted(set(GRID) | {lo_pct, hi_pct}):
        q = p * (1 + g / 100)
        if q <= 0:
            continue
        v = value(L, q, pa, pb)
        hodl = x * q + y
        grid.append({"move_pct": g, "price": q, "in_range": pa <= q <= pb, "value": v,
                     "vs_hodl_pct": (v / hodl - 1) * 100, "vs_cash_pct": (v / usd - 1) * 100,
                     "token_share_pct": amounts(L, q, pa, pb)[0] * q / v * 100 if v else 0})
    out["grid"] = grid
    fee_day = out.get("fee_usd_day")
    for side, g in (("lower", lo_pct), ("upper", hi_pct)):
        row = next(r for r in grid if r["move_pct"] == g)
        loss = usd - row["value"] if side == "lower" else (x * row["price"] + y) - row["value"]
        out[f"{side}_loss_usd"] = loss  # lower: vs cash; upper: vs HODL (gain given up)
        out[f"{side}_payback_days"] = loss / fee_day if fee_day else None
    return out


def sigma_pct(t):
    """Per-bar volatility %. ATR covers the last 14 bars, so launch-day spikes in
    the full history do not inflate it; falls back to the all-history stdev."""
    if t.get("sigma_pct"):
        return t["sigma_pct"]
    if t.get("atr_pct"):
        return t["atr_pct"] / RANGE_PER_SIGMA
    return t.get("vol_per_bar_stdev_pct")


def vol_fit(tech, lo_pct, hi_pct, hold_h):
    a, b = -math.log(1 + lo_pct / 100), math.log(1 + hi_pct / 100)
    rows = []
    for tf, t in tech.items():
        s = sigma_pct(t)
        if not s:
            continue
        sig = s / 100
        rows.append({"tf": tf, "sigma_bar_pct": s, "atr_pct": t.get("atr_pct"),
                     "exit_hours": exit_hours(a, b, sig, TF_HOURS[tf]),
                     # zero-drift odds of leaving through the top
                     "p_exit_up_pct": a / (a + b) * 100,
                     # scale both sides by k so a*b/sigma^2 = hold_h
                     "fit_lower_pct": None, "fit_upper_pct": None})
        k = math.sqrt(hold_h / TF_HOURS[tf] * sig ** 2 / (a * b))
        rows[-1]["fit_lower_pct"] = (math.exp(-a * k) - 1) * 100
        rows[-1]["fit_upper_pct"] = (math.exp(b * k) - 1) * 100
    return rows


def sr_range(tech, p):
    """Nearest support / resistance across timeframes that is at least one 1h ATR
    (min 2%) away, so a level hugging the price does not make a useless range."""
    gap = max((tech.get("1h") or {}).get("atr_pct") or 0, 2) / 100
    sup = [t["nearest_support"] for t in tech.values()
           if t.get("nearest_support") and p * 0.5 <= t["nearest_support"] < p]
    res = [t["nearest_resistance"] for t in tech.values()
           if t.get("nearest_resistance") and p < t["nearest_resistance"] <= p * 3]
    out = {"min_gap_pct": gap * 100}
    far = [v for v in sup if v <= p * (1 - gap)]
    if far:
        out["support"] = max(far)
    far = [v for v in res if v >= p * (1 + gap)]
    if far:
        out["resistance"] = min(far)
    return out


def verdict(m, fit, trend):
    notes = []
    one_h = next((r for r in fit if r["tf"] == "1h"), None) or (fit[0] if fit else None)
    if one_h and one_h["exit_hours"] is not None:
        h = one_h["exit_hours"]
        if h < 24:
            notes.append(f"TOO TIGHT: expected ~{h:.0f}h in range ({one_h['tf']} volatility)")
        elif h < 72:
            notes.append(f"TIGHT: expected ~{h:.0f}h in range, plan to rebalance often")
        else:
            notes.append(f"FITS: expected ~{h / 24:.1f}d in range")
    if trend:
        notes.append(f"trend: EMA9/21 {trend} - "
                     + ("long-biased range matches" if trend.count("up") >= trend.count("down")
                        else "downtrend: lower bound likely to break, leaving you 100% token"))
    if m.get("range_apr_pct") is not None and m["range_apr_pct"] < 20:
        notes.append("low fee APR even concentrated")
    if m.get("fee_pct") is not None and m["fee_pct"] <= 0.0001:
        notes.append("ZERO-FEE pool: no fee income at all")
    return notes


def fmt(x, p=6):
    return analyze.fmt(x, p)


def dur(days):
    return f"{days * 24:.1f}h" if days < 1 else f"{days:.1f}d"


def report(r):
    m, h = r["plan"], r["header"]
    q = h.get("quote") or "quote"
    L = [f"# LP range plan: {h.get('symbol', 'token')}/{q} {h.get('chain', '')} {h.get('dex', '')}".rstrip(),
         f"price ${fmt(m['price'])} | pool liq ${fmt(h.get('liq'))} | vol24 ${fmt(h.get('vol24'))} | "
         f"LP fee {fmt(h.get('fee_pct'), 3)}% ({h.get('fee_source', 'n/a')})", "",
         f"## Range {m['lower_pct']:+g}% / {m['upper_pct']:+g}%",
         f"bounds ${fmt(m['pa'])} - ${fmt(m['pb'])}",
         f"deposit ${m['usd']:,.0f}: {fmt(m['token_amount'])} {h.get('symbol', 'token')} "
         f"({m['token_share_pct']:.0f}%) + ${m['quote_usd']:,.2f} {q} ({100 - m['token_share_pct']:.0f}%)",
         f"capital efficiency {m['capital_efficiency']:.1f}x full range"]
    if m.get("range_apr_pct") is not None:
        L.append(f"fee APR full-range avg {m['full_range_apr_pct']:,.0f}% -> your range {m['range_apr_pct']:,.0f}% "
                 f"(~${m['fee_usd_day']:,.2f}/day while in range; turnover used {m['turnover_used']:.2f}x, cap {TURNOVER_CAP:g}x)")
        if m.get("pool_depth_usd"):
            L.append(f"fee model: active liquidity - pool in-range depth ~${m['pool_depth_usd']:,.0f} full-range equivalent, "
                     f"your share {m['fee_share_pct']:.2f}% of swap fees")
        else:
            L.append(f"fee model: {m['fee_model']}")
    else:
        L.append("fee APR: n/a (fee unknown; pass --fee)")
    L += ["", "## At the bounds",
          f"- lower ${fmt(m['pa'])}: 100% {h.get('symbol', 'token')}, worth ${m['usd'] - m['lower_loss_usd']:,.2f} "
          f"(loss ${m['lower_loss_usd']:,.2f} vs cash"
          + (f", ~{dur(m['lower_payback_days'])} in range of fees to recover)" if m.get("lower_payback_days") else ")"),
          f"- upper ${fmt(m['pb'])}: 100% {q}, worth "
          f"${next(g['value'] for g in m['grid'] if g['move_pct'] == m['upper_pct']):,.2f} "
          f"(gives up ${m['upper_loss_usd']:,.2f} vs HODL"
          + (f", ~{dur(m['upper_payback_days'])} in range of fees)" if m.get("upper_payback_days") else ")"),
          "", "## Price grid",
          "| move | price | in range | value | vs HODL | vs cash | token % |",
          "|---|---|---|---|---|---|---|"]
    for g in m["grid"]:
        L.append(f"| {g['move_pct']:+g}% | {fmt(g['price'])} | {'yes' if g['in_range'] else 'no'} | "
                 f"${g['value']:,.2f} | {g['vs_hodl_pct']:+.2f}% | {g['vs_cash_pct']:+.2f}% | {g['token_share_pct']:.0f}% |")
    if r["vol_fit"]:
        L += ["", f"## Time in range (realized volatility, zero drift; fit = same ratio sized for {r['hold_h']:g}h)",
              "| tf | sigma/bar (ATR/1.6) | ATR | expected in range | exit up odds | fit range |",
              "|---|---|---|---|---|---|"]
        for v in r["vol_fit"]:
            eh = v["exit_hours"]
            L.append(f"| {v['tf']} | {v['sigma_bar_pct']:.2f}% | {fmt(v['atr_pct'], 3)}% | "
                     f"{eh:.1f}h ({eh / 24:.1f}d) | {v['p_exit_up_pct']:.0f}% | "
                     f"{v['fit_lower_pct']:+.1f}% / {v['fit_upper_pct']:+.1f}% |")
    sr = r.get("sr")
    if sr:
        L += ["", "## Support / resistance range"]
        for k in ("support", "resistance"):
            if not sr.get(k):
                L.append(f"- no {k} at least {sr['min_gap_pct']:.1f}% (1h ATR) away; use the volatility fit range")
        if sr.get("support"):
            L.append(f"- support ${fmt(sr['support'])} ({(sr['support'] / m['price'] - 1) * 100:+.1f}%)")
        if sr.get("resistance"):
            L.append(f"- resistance ${fmt(sr['resistance'])} ({(sr['resistance'] / m['price'] - 1) * 100:+.1f}%)")
        if sr.get("plan"):
            s = sr["plan"]
            L.append(f"- S/R range {s['lower_pct']:+.1f}% / {s['upper_pct']:+.1f}%: capital efficiency "
                     f"{s['capital_efficiency']:.1f}x"
                     + (f", fee APR ~{s['range_apr_pct']:,.0f}%" if s.get("range_apr_pct") is not None else "")
                     + (f", expected ~{sr['exit_hours']:.0f}h in range (1h vol)" if sr.get("exit_hours") else ""))
    if h.get("liq"):
        L += ["", "## Size vs pool",
              f"your ${m['usd']:,.0f} = {m['usd'] / h['liq'] * 100:.2f}% of pool liquidity | "
              f"selling it at once ~{analyze.impact_pct(m['usd'], h['liq']):.2f}% impact (full-range CPMM estimate)"]
    L += ["", "## Verdict"] + [f"- {n}" for n in r["verdict"] or ["no data for a verdict"]]
    L += ["", "_Model: zero-drift random walk, fees at 24h volume. Real paths trend and volume fades. Not financial advice._"]
    return "\n".join(L)


def pool_depth_usd(s, d, rpc):
    """In-range L as full-range-equivalent TVL: 2 * L * sqrtP (token1 units) in USD."""
    L, sq = s.get("active_liquidity"), s.get("sqrt_price_x96")
    if not (L and sq and d.get("price_native")):
        return None
    import evm

    def decimals(addr):
        return 18 if not addr or int(addr, 16) == 0 else evm.call_uint(rpc, addr, "decimals()")

    db, dq = decimals(d["token"]), decimals(d.get("quote_address"))
    if db is None or dq is None:
        return None
    p_raw = (sq / 2 ** 96) ** 2  # token1 per token0, raw units
    t1 = s.get("token1")
    if t1:
        base_is_1 = t1.lower() == d["token"].lower()
    else:  # Initialize not found: pick the token order whose implied price matches DexScreener's
        as_quote1 = p_raw * 10 ** (db - dq)
        as_base1 = 1 / (p_raw * 10 ** (dq - db))
        base_is_1 = abs(math.log(as_base1 / d["price_native"])) < abs(math.log(as_quote1 / d["price_native"]))
    usd1 = d["price_usd"] if base_is_1 else d["price_usd"] / d["price_native"]  # quote USD = price_usd / price_native
    return 2 * L * math.sqrt(p_raw) / 10 ** (db if base_is_1 else dq) * usd1


def fetch_pool(chain, d, rpc_url):
    """On-chain LP fee and in-range depth. Returns (fee_pct, source, depth_usd)."""
    try:
        import lp_fees
        from evm import RPC, RPCS
        _, rows = lp_fees.pairs_from_args([chain, d["pair"]])
        if not rows:
            return None, "n/a", None
        s = lp_fees.scan(rows, chain, rpc_url)[0]
        depth = None
        try:
            depth = pool_depth_usd(s, d, RPC([rpc_url] if rpc_url else RPCS.get(chain, [])))
        except Exception as e:
            sys.stderr.write(f"warn: active liquidity read failed for {chain}/{d['pair']}: {e}\n")
        return s.get("lp_fee_pct"), s.get("fee_source", "n/a"), depth
    except Exception as e:  # RPC missing / down: still plan without fee
        sys.stderr.write(f"warn: on-chain fee read failed for {chain}/{d['pair']}: {e}; pass --fee\n")
        return None, "n/a", None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="*", help="dexscreener URL, or <chain> <pair>")
    ap.add_argument("--lower", type=float, default=-5, help="lower bound, %% from price (default -5)")
    ap.add_argument("--upper", type=float, default=15, help="upper bound, %% from price (default 15)")
    ap.add_argument("--usd", type=float, default=1000, help="position size in USD (default 1000)")
    ap.add_argument("--hold-h", type=float, default=72, help="hours you want to stay in range (default 72)")
    ap.add_argument("--fee", type=float, help="LP fee %% (skips on-chain read), e.g. 0.3 or 5")
    ap.add_argument("--rpc", default=os.environ.get("RPC_URL"))
    ap.add_argument("--price", type=float, help="offline mode: current price")
    ap.add_argument("--vol24", type=float, default=0, help="offline mode: 24h volume USD")
    ap.add_argument("--liq", type=float, default=0, help="offline mode: pool liquidity USD")
    ap.add_argument("--sigma-1h", type=float, help="offline mode: 1h volatility %% per bar (ATR%% / 1.6)")
    ap.add_argument("--depth", type=float, help="offline mode: pool in-range depth as full-range-equivalent USD")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if a.price:
        header = {"symbol": "token", "quote": "quote", "liq": a.liq or None, "vol24": a.vol24,
                  "fee_pct": a.fee, "fee_source": "manual" if a.fee is not None else "n/a",
                  "depth_usd": a.depth}
        tech = {"1h": {"sigma_pct": a.sigma_1h}} if a.sigma_1h else {}
        p = a.price
    else:
        if not a.target:
            raise SystemExit("error: pass a dexscreener URL, '<chain> <pair>', or --price for offline mode")
        chain, pair = analyze.parse_target(a.target)
        m = analyze.analyze(chain, pair, a.usd)
        d = m["pair"]
        fee, src, depth = fetch_pool(chain, d, a.rpc)
        if a.fee is not None:
            fee, src = a.fee, "manual"
        header = {"symbol": d["symbol"], "quote": d["quote"], "chain": chain, "dex": d["dex"],
                  "liq": d["liq_usd"], "vol24": analyze.f(d["vol"].get("h24")),
                  "fee_pct": fee, "fee_source": src, "depth_usd": depth}
        tech = m["tech"]
        p = d["price_usd"]

    pl = plan(p, a.lower, a.upper, a.usd, header["fee_pct"], header["vol24"], header["liq"],
              header.get("depth_usd"))
    pl["fee_pct"] = header["fee_pct"]
    fit = vol_fit(tech, a.lower, a.upper, a.hold_h)
    sr = sr_range(tech, p) if not a.price else {}
    if sr.get("support") and sr.get("resistance"):
        lo, hi = (sr["support"] / p - 1) * 100, (sr["resistance"] / p - 1) * 100
        sr["plan"] = plan(p, lo, hi, a.usd, header["fee_pct"], header["vol24"], header["liq"],
                          header.get("depth_usd"))
        s1h = sigma_pct(tech.get("1h") or {})
        if s1h:
            sr["exit_hours"] = exit_hours(-math.log(1 + lo / 100), math.log(1 + hi / 100), s1h / 100, 1)
    trend = " ".join(f"{tf}:{t['ema_trend']}" for tf, t in tech.items() if t.get("ema_trend"))
    r = {"header": header, "plan": pl, "vol_fit": fit, "sr": sr, "hold_h": a.hold_h,
         "verdict": verdict(pl, fit, trend)}
    print(json.dumps(r, indent=1, default=str) if a.json else report(r))


if __name__ == "__main__":
    main()
