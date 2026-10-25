#!/usr/bin/env python3
"""Picker: rate screened tokens twice, for providing liquidity and for buying.

Combines the screener (market data, total liquidity across pools) with the
LP fee scan (on-chain fee, hooks, recent swaps) and gives each token:
  LP  : GOOD LP / OK LP / AVOID LP        (does an LP position earn more than it risks?)
  BUY : CANDIDATE / SPECULATIVE / AVOID   (is the market structure healthy enough to enter?)
with the reasons behind each label. --deep N also runs the on-chain safety
check on the N best-rated tokens; DANGER / HIGH RISK overrides both labels.

Usage:
  picker.py --chain robinhood                      # top 20 trending
  picker.py --chain robinhood --source volume --limit 30 --deep 3
  picker.py --chain base --json
Ratings are rule-based triage, not financial advice.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import screener  # noqa: E402
import lp_fees  # noqa: E402
from evm import RPCS  # noqa: E402

LP_LABELS = ((4, "GOOD LP"), (1, "OK LP"), (-99, "AVOID LP"))
BUY_LABELS = ((4, "CANDIDATE"), (1, "SPECULATIVE"), (-99, "AVOID"))


def label(score, table, hard_fail):
    if hard_fail:
        return table[-1][1]
    return next(name for floor, name in table if score >= floor)


def is_wash(r):
    return any(x.startswith(("fake-vol", "churn")) for x in r["flags"])


def rate_lp(r):
    """Score an LP position in the token's main pool. Returns (label, score, reasons)."""
    s, why, hard = 0, [], None
    fee, apr = r.get("lp_fee_pct"), r.get("fee_apr_pct")
    bits = r.get("hook_bits") or []
    if fee is not None and fee <= 0.0001:
        hard = "pool charges ~0% fee: LPs earn nothing"
    elif fee is None:
        s -= 1
        why.append("fee unknown" + (" (dynamic, no recent swaps)" if r.get("dynamic") else ""))
    if "beforeRemoveLiquidity" in bits:
        hard = hard or "hook controls liquidity removal: exit may be blocked"
    if "beforeAddLiquidity" in bits:
        s -= 1
        why.append("hook gates adding liquidity: Krystal add may revert, test small")
    if {"beforeSwapReturnDelta", "afterSwapReturnDelta"} & set(bits):
        why.append("hook takes a cut of swaps")
    if apr is not None and fee:
        # wash volume inflates APR; cap turnover at 3x liquidity for the estimate
        real_apr = apr * min(r["vol_liq"], 3) / r["vol_liq"] if r["vol_liq"] else 0
        r["lp_apr_capped"] = real_apr
        if real_apr >= 50:
            s += 2
            why.append(f"fee APR ~{real_apr:,.0f}% (turnover capped at 3x)")
        elif real_apr >= 15:
            s += 1
            why.append(f"fee APR ~{real_apr:,.0f}%")
        else:
            s -= 2
            why.append(f"low fee APR ~{real_apr:,.0f}%")
    vol = max(abs(r["chg24"]), abs(r["chg6"]) * 2)
    if vol < 20:
        s += 2
        why.append("calm price: low impermanent loss")
    elif vol < 60:
        why.append("moderate volatility: use a wide range")
    else:
        s -= 2
        why.append(f"volatile ({r['chg24']:+.0f}% 24h): high impermanent loss")
    if r["age_d"] is not None:
        if r["age_d"] >= 7:
            s += 1
        elif r["age_d"] < 2:
            s -= 2
            why.append("pool < 48h old")
    if r["liq"] >= 250_000:
        s += 1
    elif r["liq"] < 50_000:
        s -= 2
        why.append("thin pool")
    if is_wash(r):
        s -= 2
        why.append("volume looks washed: fees may not last")
    if r.get("swaps_window") == 0 or r["txns1h"] == 0:
        s -= 2
        why.append("no recent swaps")
    if hard:
        why.insert(0, hard)
    return label(s, LP_LABELS, hard), s, why


def rate_buy(r):
    """Score buying the token. Returns (label, score, reasons)."""
    s, why, hard = 0, [], None
    lm = r["liq_mcap_pct"]
    if lm >= 10:
        s += 2
        why.append(f"total liq {lm:.0f}% of mcap: exits possible")
    elif lm >= 5:
        why.append(f"total liq {lm:.0f}% of mcap")
    else:
        s -= 3
        why.append(f"total liq only {lm:.1f}% of mcap: mcap is mostly paper")
        if lm < 3:
            hard = "liquidity under 3% of mcap"
    if r["total_liq"] >= 250_000:
        s += 1
    elif r["total_liq"] < 50_000:
        s -= 2
        why.append("thin liquidity: big price impact")
    if r["bs_ratio"] >= 1.2:
        s += 1
        why.append(f"buyers lead ({r['buys24']}/{r['sells24']})")
    elif r["bs_ratio"] < 0.8:
        s -= 1
        why.append(f"sellers lead ({r['buys24']}/{r['sells24']})")
    if r["chg24"] > 300:
        s -= 2
        why.append(f"overextended ({r['chg24']:+,.0f}% 24h): late entry")
    elif r["chg24"] < -50:
        s -= 2
        why.append(f"dumped ({r['chg24']:+.0f}% 24h)")
    elif 0 <= r["chg6"] <= 50 and r["chg1"] > -5:
        s += 1
        why.append("steady uptrend")
    if r["chg1"] < -10:
        s -= 1
        why.append(f"selling now ({r['chg1']:+.0f}% 1h)")
    if r["txns1h"] == 0:
        s -= 2
        why.append("no trades in the last hour")
    if r["age_d"] is not None:
        if r["age_d"] >= 7:
            s += 1
        elif r["age_d"] < 2:
            s -= 1
            why.append("< 48h old")
    if is_wash(r):
        s -= 2
        why.append("volume looks washed")
    elif 0.3 <= r["vol_liq"] <= 5:
        s += 1
    if hard:
        why.insert(0, hard)
    lab = label(s, BUY_LABELS, hard)
    if lab == "CANDIDATE":  # thin exits, young tokens and recent pumps cap the rating
        if r["total_liq"] < 100_000:
            why.append("total liquidity under $100k")
        elif r["age_d"] is None or r["age_d"] < 7:
            why.append("younger than 7 days")
        elif r["chg24"] > 100:
            why.append(f"already {r['chg24']:+.0f}% in 24h: chasing")
        elif lm >= 10:
            return lab, s, why
        lab = "SPECULATIVE"
    return lab, s, why


def deep_check(chain, rows, n, rpc):
    """Run the on-chain safety check on the n best-rated rows; risky contracts override labels."""
    import onchain_check
    best = sorted(rows, key=lambda r: -max(r["lp_score"], r["buy_score"]))
    for r in [x for x in best if not (x["lp"].startswith("AVOID") and x["buy"] == "AVOID")][:n]:
        sys.stderr.write(f"on-chain check {r['symbol']}...\n")
        try:
            res = onchain_check.Checker(chain, r["pair"], rpc).run()
        except Exception as e:  # noqa: BLE001 - report and keep going
            r["onchain"] = f"failed: {e}"
            continue
        v = res["verdict"]["label"]
        r["onchain"] = v
        r["onchain_findings"] = [f"[{f['severity']}] {f['msg']}" for f in res["findings"]
                                 if f["severity"] in ("CRITICAL", "HIGH")]
        if v in ("DANGER", "HIGH RISK"):
            r["lp"], r["buy"] = "AVOID LP", "AVOID"
            r["lp_why"].insert(0, f"on-chain: {v}")
            r["buy_why"].insert(0, f"on-chain: {v}")


def report(chain, source, rows):
    L = [f"## Picks | chain: {chain} | source: {source} | {len(rows)} tokens", ""]
    for title, key, order in (("Best for LP", "lp", ("GOOD LP", "OK LP")),
                              ("Best to buy", "buy", ("CANDIDATE", "SPECULATIVE"))):
        picks = sorted([r for r in rows if r[key] in order],
                       key=lambda r: (order.index(r[key]), -r[f"{key}_score"]))
        L += [f"### {title}", ""]
        if not picks:
            L += ["_None passed. Everything screened is rated AVOID for this._", ""]
            continue
        for r in picks:
            extra = f" | on-chain: {r['onchain']}" if r.get("onchain") else " | on-chain: not checked"
            fee = "" if key == "buy" else (f" | fee {r['lp_fee_pct']:.3g}%" if r.get("lp_fee_pct") is not None else "")
            L.append(f"- **{r[key]}** [{r['symbol']}/{r['quote']}]({r['url']}){fee} | liq "
                     f"{screener.fmt_money(r['liq'])} (total {screener.fmt_money(r['total_liq'])}) | mcap "
                     f"{screener.fmt_money(r['mcap'])}{extra}")
            L.append(f"  - {'; '.join(r[f'{key}_why'])}")
        L.append("")
    checked = [r for r in rows if r.get("onchain")]
    if checked:
        L += ["### On-chain checks (--deep)", ""]
        for r in checked:
            L.append(f"- **{r['symbol']}**: {r['onchain']}")
            L += [f"  - {x}" for x in r.get("onchain_findings", [])]
        L.append("")
    L += ["### All tokens", "",
          "| # | token | LP | BUY | fee | liq / total | liq/mc | 24h | age | on-chain |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        age = "?" if r["age_d"] is None else (f"{r['age_d'] * 24:.0f}h" if r["age_d"] < 2 else f"{r['age_d']:.0f}d")
        fee = "?" if r.get("lp_fee_pct") is None else f"{r['lp_fee_pct']:.3g}%"
        L.append(f"| {i} | [{r['symbol']}/{r['quote']}]({r['url']}) | {r['lp']} | {r['buy']} | {fee} | "
                 f"{screener.fmt_money(r['liq'])} / {screener.fmt_money(r['total_liq'])} | {r['liq_mcap_pct']:.0f}% | "
                 f"{r['chg24']:+.0f}% | {age} | {r.get('onchain', '-')} |")
    L += ["", "_Rule-based triage, not financial advice. Before acting: run onchain_check.py on the pool "
          "(or pass --deep N), and analyze.py for entry levels / LP range. Microcaps can go to zero._"]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--chain", required=True, help="DexScreener chain id")
    ap.add_argument("--source", choices=screener.SOURCES, default="trending")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--min-liq", type=float, default=1000)
    ap.add_argument("--deep", type=int, default=0, help="run onchain_check on the N best-rated tokens (1-3 min each)")
    ap.add_argument("--window-h", type=float, default=6, help="hours of swaps sampled for the real fee")
    ap.add_argument("--rpc", default=os.environ.get("RPC_URL"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    chain = a.chain.strip().lower()
    sort = "volume" if a.source == "volume" else "source"
    rows, _, _ = screener.screen(chain, a.source, a.limit, a.min_liq, sort, 10)
    if chain in RPCS or a.rpc:
        rows = lp_fees.scan(rows, chain, a.rpc, a.window_h)
    else:
        sys.stderr.write(f"warn: no RPC for '{chain}' (EVM only); LP fee unknown. Pass --rpc for EVM chains.\n")
        rows = [{**r, "lp_fee_pct": None, "fee_apr_pct": None} for r in rows]
    for r in rows:
        r["lp"], r["lp_score"], r["lp_why"] = rate_lp(r)
        r["buy"], r["buy_score"], r["buy_why"] = rate_buy(r)
    if a.deep:
        deep_check(chain, rows, a.deep, a.rpc)
    if a.json:
        print(json.dumps(rows, indent=1, default=str))
    else:
        print(report(chain, a.source, rows))


if __name__ == "__main__":
    main()
