#!/usr/bin/env python3
"""DEX token analyzer: pulls DexScreener + GeckoTerminal data, computes
liquidity / flow / technical / risk metrics, and emits a scenario-based
outlook. Stdlib only.

Usage:
  analyze.py <dexscreener-url | chain pairAddress> [--json] [--usd 500]
"""
import argparse
import json
import math
import re
import statistics as st
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

UA = {"User-Agent": "seer/0.1", "Accept": "application/json"}
DS = "https://api.dexscreener.com"
GT = "https://api.geckoterminal.com/api/v2"

# DexScreener chain id -> GeckoTerminal network id where they differ.
GT_NET = {"ethereum": "eth", "bsc": "bsc", "polygon": "polygon_pos",
          "avalanche": "avax", "arbitrum": "arbitrum", "optimism": "optimism",
          "base": "base", "solana": "solana", "fantom": "ftm",
          "robinhood": "robinhood"}


def get(url, retries=4):
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429 and i < retries - 1:
                time.sleep(15 * (i + 1))
                continue
            if e.code == 404:
                return None
            sys.stderr.write(f"warn: {url} -> HTTP {e.code}\n")
            return None
        except Exception as e:  # network hiccup
            if i < retries - 1:
                time.sleep(3)
                continue
            sys.stderr.write(f"warn: {url} -> {e}\n")
            return None


def parse_target(args):
    if len(args) == 1:
        m = re.search(r"dexscreener\.com/([^/]+)/([0-9A-Za-z]+)", args[0])
        if not m:
            raise SystemExit("error: expected dexscreener URL or '<chain> <pair>'")
        return m.group(1), m.group(2)
    if len(args) == 2:
        return args[0], args[1]
    raise SystemExit("error: expected dexscreener URL or '<chain> <pair>'")


def f(x, d=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return d


# ---------- technicals ----------
def ema(vals, n):
    if not vals:
        return []
    k = 2 / (n + 1)
    out = [vals[0]]
    for v in vals[1:]:
        out.append(v * k + out[-1] * (1 - k))
    return out


def rsi(closes, n=14):
    if len(closes) <= n:
        return None
    gains = [max(closes[i] - closes[i - 1], 0) for i in range(1, len(closes))]
    losses = [max(closes[i - 1] - closes[i], 0) for i in range(1, len(closes))]
    ag, al = sum(gains[:n]) / n, sum(losses[:n]) / n
    for g, l in zip(gains[n:], losses[n:]):
        ag = (ag * (n - 1) + g) / n
        al = (al * (n - 1) + l) / n
    if al == 0:
        return 100.0
    return 100 - 100 / (1 + ag / al)


def atr(c, n=14):
    if len(c) < 2:
        return None
    trs = [max(c[i]["h"] - c[i]["l"], abs(c[i]["h"] - c[i - 1]["c"]),
               abs(c[i]["l"] - c[i - 1]["c"])) for i in range(1, len(c))]
    return st.mean(trs[-n:])


def swings(c, w=3):
    """Pivot highs/lows: bar extreme vs w bars each side."""
    hi, lo = [], []
    for i in range(w, len(c) - w):
        win = c[i - w:i + w + 1]
        if c[i]["h"] == max(x["h"] for x in win):
            hi.append(c[i]["h"])
        if c[i]["l"] == min(x["l"] for x in win):
            lo.append(c[i]["l"])
    return hi, lo


def cluster(levels, tol=0.04):
    """Merge levels within tol (fractional) and rank by touch count."""
    out = []
    for lv in sorted(levels):
        if out and abs(lv - out[-1][0]) / out[-1][0] <= tol:
            n = out[-1][1] + 1
            out[-1] = ((out[-1][0] * out[-1][1] + lv) / n, n)
        else:
            out.append((lv, 1))
    return out


def candles(raw):
    if not raw:
        return []
    rows = raw.get("data", {}).get("attributes", {}).get("ohlcv_list", [])
    c = [{"t": r[0], "o": r[1], "h": r[2], "l": r[3], "c": r[4], "v": r[5]}
         for r in rows]
    return sorted(c, key=lambda x: x["t"])


def tech(c, label):
    if len(c) < 5:
        return {"tf": label, "bars": len(c), "note": "insufficient history"}
    closes = [x["c"] for x in c]
    rets = [math.log(closes[i] / closes[i - 1]) for i in range(1, len(closes))
            if closes[i - 1] > 0 and closes[i] > 0]
    e9, e21 = ema(closes, 9), ema(closes, 21)
    vw_den = sum(x["v"] for x in c)
    vwap = sum((x["h"] + x["l"] + x["c"]) / 3 * x["v"] for x in c) / vw_den if vw_den else None
    hi, lo = swings(c)
    last = closes[-1]
    res = [lv for lv, _ in cluster(hi) if lv > last]
    period_high = max(x["h"] for x in c)
    if not res and period_high > last * 1.02:
        res = [period_high]  # range high / ATH acts as overhead supply
    sup = [lv for lv, _ in cluster(lo) if lv < last]
    half = len(c) // 2
    v1 = sum(x["v"] for x in c[:half]) or 1e-9
    v2 = sum(x["v"] for x in c[half:])
    a = atr(c)
    return {
        "tf": label, "bars": len(c), "last": last,
        "high": max(x["h"] for x in c), "low": min(x["l"] for x in c),
        "drawdown_from_high_pct": (last / max(x["h"] for x in c) - 1) * 100,
        "rsi14": rsi(closes),
        "ema9": e9[-1], "ema21": e21[-1],
        "ema_trend": "up" if e9[-1] > e21[-1] else "down",
        "vwap": vwap,
        "price_vs_vwap_pct": (last / vwap - 1) * 100 if vwap else None,
        "atr14": a, "atr_pct": a / last * 100 if a and last else None,
        "vol_per_bar_stdev_pct": st.pstdev(rets) * 100 if len(rets) > 2 else None,
        "volume_trend_2nd_half_vs_1st": v2 / v1,
        "nearest_resistance": min(res) if res else None,
        "nearest_support": max(sup) if sup else None,
    }


# ---------- flow ----------
def flow(trades_raw):
    if not trades_raw or not trades_raw.get("data"):
        return None
    ts = [t["attributes"] for t in trades_raw["data"]]
    buys = [t for t in ts if t.get("kind") == "buy"]
    sells = [t for t in ts if t.get("kind") == "sell"]
    usd = lambda arr: sum(f(t.get("volume_in_usd")) for t in arr)
    wallets = {}
    for t in ts:
        w = t.get("tx_from_address")
        sign = 1 if t.get("kind") == "buy" else -1
        wallets[w] = wallets.get(w, 0) + sign * f(t.get("volume_in_usd"))
    sizes = sorted((f(t.get("volume_in_usd")) for t in ts), reverse=True)
    total = sum(sizes) or 1e-9
    stamps = sorted(t["block_timestamp"] for t in ts)
    return {
        "sample_trades": len(ts),
        "window": f"{stamps[0]} -> {stamps[-1]}" if stamps else None,
        "buy_usd": usd(buys), "sell_usd": usd(sells),
        "net_usd": usd(buys) - usd(sells),
        "unique_wallets": len(wallets),
        "top5_trade_share_pct": sum(sizes[:5]) / total * 100,
        "largest_trade_usd": sizes[0] if sizes else 0,
        "top_net_buyers": sorted(wallets.items(), key=lambda x: -x[1])[:3],
        "top_net_sellers": sorted(wallets.items(), key=lambda x: x[1])[:3],
    }


def impact_pct(usd, liq_usd):
    """Constant-product estimate (full-range). Concentrated v3/v4 liquidity
    can be thinner or deeper; treat as order-of-magnitude."""
    side = liq_usd / 2
    if side <= 0:
        return None
    return (1 - (side / (side + usd)) ** 2) * 100


# ---------- scoring ----------
def outlook(m):
    """Rule-based regime + scenario scoring. Not a forecast."""
    s, why = 0, []
    t1h, td = m["tech"].get("1h", {}), m["tech"].get("1d", {})
    p = m["pair"]
    if t1h.get("ema_trend") == "up":
        s += 1; why.append("+1 1h EMA9>EMA21")
    elif t1h.get("ema_trend") == "down":
        s -= 1; why.append("-1 1h EMA9<EMA21")
    r = t1h.get("rsi14")
    if r is not None:
        if r > 75: s -= 1; why.append(f"-1 1h RSI overbought {r:.0f}")
        elif r < 30: s += 1; why.append(f"+1 1h RSI oversold {r:.0f} (mean-revert)")
    pv = t1h.get("price_vs_vwap_pct")
    if pv is not None:
        s += 1 if pv > 0 else -1
        why.append(f"{'+1' if pv > 0 else '-1'} price {'above' if pv > 0 else 'below'} 1h VWAP ({pv:+.1f}%)")
    bs = p["buys_24h"] / max(p["sells_24h"], 1)
    if bs > 1.2: s += 1; why.append(f"+1 24h buy/sell count {bs:.2f}")
    elif bs < 0.8: s -= 1; why.append(f"-1 24h buy/sell count {bs:.2f}")
    fl = m.get("flow")
    if fl:
        if fl["net_usd"] > 0: s += 1; why.append(f"+1 recent net flow +${fl['net_usd']:,.0f}")
        else: s -= 1; why.append(f"-1 recent net flow -${-fl['net_usd']:,.0f}")
    vt = t1h.get("volume_trend_2nd_half_vs_1st")
    if vt is not None and vt < 0.5:
        s -= 1; why.append(f"-1 volume fading ({vt:.2f}x)")
    elif vt is not None and vt > 1.5:
        s += 1; why.append(f"+1 volume expanding ({vt:.2f}x)")
    if p["vol_liq_24h"] < 0.1:
        s -= 1; why.append(f"-1 low turnover vol/liq {p['vol_liq_24h']:.2f}")
    if td.get("drawdown_from_high_pct", 0) < -70:
        why.append(f"note: {td['drawdown_from_high_pct']:.0f}% below ATH (supply overhead)")
    regime = "bullish" if s >= 3 else "bearish" if s <= -3 else "neutral/range"
    return {"score": s, "regime": regime, "reasons": why}


def risk(m):
    p, flags = m["pair"], []
    if p["liq_usd"] < 50_000: flags.append("thin liquidity <$50k")
    if p["liq_mcap_pct"] < 5: flags.append(f"liq/mcap only {p['liq_mcap_pct']:.1f}% (exit risk)")
    if p["age_days"] < 7: flags.append(f"young pair ({p['age_days']:.1f}d)")
    if p["fdv"] and p["mcap"] and p["fdv"] > p["mcap"] * 1.5: flags.append("large locked/unreleased supply (FDV >> MC)")
    if p["txns_1h"] == 0: flags.append("no trades last hour (illiquid / dead tape)")
    if p["boosts"]: flags.append(f"paid DexScreener boosts active ({p['boosts']}) - marketing, not fundamentals")
    ti = m.get("token_info") or {}
    if ti.get("holders_count") is not None and ti["holders_count"] < 500:
        flags.append(f"few holders ({ti['holders_count']})")
    top10 = ti.get("top10_pct")
    if top10 is not None and top10 > 30:
        flags.append(f"top-10 holders {top10:.1f}% (concentration)")
    fl = m.get("flow") or {}
    if fl.get("top5_trade_share_pct", 0) > 50:
        flags.append("flow dominated by few large trades")
    if fl.get("buy_usd"):
        top3 = sum(max(v, 0) for _, v in fl["top_net_buyers"])
        if top3 / fl["buy_usd"] > 0.5:
            flags.append(f"top-3 wallets = {top3 / fl['buy_usd'] * 100:.0f}% of recent buy volume (move not broad-based)")
    gp = m.get("gt_pool") or {}
    if gp and gp.get("locked_liquidity_percentage") in (None, 0, "0"):
        flags.append("LP lock unknown/none per GeckoTerminal - verify LP owner on-chain")
    gres = f(gp.get("reserve_in_usd"))
    if gres and p["liq_usd"] and abs(gres / p["liq_usd"] - 1) > 0.2:
        flags.append(f"liquidity sources disagree (DS ${p['liq_usd']:,.0f} vs GT ${gres:,.0f}) - concentrated-liquidity range effects")
    return flags


def analyze(chain, pair, probe_usd):
    ds = get(f"{DS}/latest/dex/pairs/{chain}/{pair}")
    if not ds or not ds.get("pairs"):
        raise SystemExit(f"error: DexScreener has no pair {chain}/{pair}")
    d = ds["pairs"][0]
    token = d["baseToken"]["address"]
    now = time.time() * 1000
    liq = f(d.get("liquidity", {}).get("usd"))
    mcap = f(d.get("marketCap")) or f(d.get("fdv"))
    tx = d.get("txns", {})
    m = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
         "pair": {
             "chain": chain, "dex": d.get("dexId"), "labels": d.get("labels", []),
             "pair": d["pairAddress"], "token": token,
             "symbol": d["baseToken"]["symbol"], "name": d["baseToken"]["name"],
             "quote": d["quoteToken"]["symbol"], "quote_address": d["quoteToken"].get("address"),
             "price_usd": f(d.get("priceUsd")), "price_native": f(d.get("priceNative")),
             "mcap": mcap, "fdv": f(d.get("fdv")), "liq_usd": liq,
             "liq_mcap_pct": liq / mcap * 100 if mcap else 0,
             "vol": d.get("volume", {}), "chg": d.get("priceChange", {}),
             "vol_liq_24h": f(d.get("volume", {}).get("h24")) / liq if liq else 0,
             "buys_24h": tx.get("h24", {}).get("buys", 0),
             "sells_24h": tx.get("h24", {}).get("sells", 0),
             "txns_1h": sum(tx.get("h1", {}).values()),
             "age_days": (now - d.get("pairCreatedAt", now)) / 86_400_000,
             "boosts": (d.get("boosts") or {}).get("active", 0),
             "links": [w["url"] for w in (d.get("info") or {}).get("websites", [])]
                      + [s["url"] for s in (d.get("info") or {}).get("socials", [])],
         }}
    others = get(f"{DS}/tokens/v1/{chain}/{token}") or []
    m["pair"]["other_pools"] = len(others) - 1 if isinstance(others, list) else None
    m["pair"]["impact_pct"] = {str(u): impact_pct(u, liq) for u in (probe_usd, 1000, 5000)}

    net = GT_NET.get(chain, chain)
    base = f"{GT}/networks/{net}/pools/{pair}"
    gp = get(f"{base}?include=base_token")
    time.sleep(1.5)
    raw = {tf: None for tf in ("1d", "4h", "1h", "15m")}
    raw["1d"] = get(f"{base}/ohlcv/day?limit=180"); time.sleep(1.5)
    raw["4h"] = get(f"{base}/ohlcv/hour?aggregate=4&limit=500"); time.sleep(1.5)
    raw["1h"] = get(f"{base}/ohlcv/hour?limit=500"); time.sleep(1.5)
    raw["15m"] = get(f"{base}/ohlcv/minute?aggregate=15&limit=500"); time.sleep(1.5)
    trades = get(f"{base}/trades"); time.sleep(1.5)
    tinfo = get(f"{GT}/networks/{net}/tokens/{token}/info")

    m["tech"] = {tf: tech(candles(r), tf) for tf, r in raw.items()}
    m["flow"] = flow(trades)
    if gp and gp.get("data"):
        a = gp["data"]["attributes"]
        m["gt_pool"] = {k: a.get(k) for k in (
            "reserve_in_usd", "locked_liquidity_percentage", "pool_created_at",
            "price_change_percentage", "transactions", "volume_usd")}
    if tinfo and tinfo.get("data"):
        a = tinfo["data"]["attributes"]
        h = a.get("holders") or {}
        dist = h.get("distribution_percentage") or {}
        m["token_info"] = {
            "holders_count": h.get("count"),
            "top10_pct": f(dist.get("top_10")) if dist.get("top_10") else None,
            "distribution": dist,
            "gt_score": a.get("gt_score"),
            "is_honeypot": a.get("is_honeypot"),
            "mint_authority": a.get("mint_authority"),
            "freeze_authority": a.get("freeze_authority"),
        }
    m["risk_flags"] = risk(m)
    m["outlook"] = outlook(m)
    return m


def fmt(x, p=6):
    if x is None:
        return "n/a"
    if isinstance(x, float):
        if abs(x) >= 1000:
            return f"{x:,.0f}"
        return f"{x:.{p}g}"
    return str(x)


def report(m, probe):
    p = m["pair"]
    L = [f"# {p['name']} ({p['symbol']}/{p['quote']}) - {p['chain']} {p['dex']} {' '.join(p['labels'])}",
         f"generated {m['generated']}  pair {p['pair']}  token {p['token']}", "",
         "## Snapshot",
         f"price ${fmt(p['price_usd'])} | mcap ${fmt(p['mcap'])} | FDV ${fmt(p['fdv'])} | liq ${fmt(p['liq_usd'])} ({p['liq_mcap_pct']:.1f}% of mcap)",
         f"age {p['age_days']:.1f}d | other pools {p['other_pools']} | boosts {p['boosts']}",
         f"change: {p['chg']} | volume: {p['vol']}",
         f"24h txns {p['buys_24h']}B/{p['sells_24h']}S | 1h txns {p['txns_1h']} | vol/liq 24h {p['vol_liq_24h']:.2f}",
         "price impact (est, full-range CPMM): " + ", ".join(
             f"${k} -> {v:.2f}%" for k, v in p["impact_pct"].items() if v is not None), ""]
    ti = m.get("token_info")
    if ti:
        L += ["## Holders / safety",
              f"holders {ti['holders_count']} | top10 {fmt(ti['top10_pct'])}% | dist {ti['distribution']} | gt_score {fmt(ti['gt_score'])} | honeypot {ti['is_honeypot']}", ""]
    L.append("## Technicals")
    for tf, t in m["tech"].items():
        if "note" in t:
            L.append(f"- {tf}: {t['note']} ({t['bars']} bars)"); continue
        L.append(f"- {tf} ({t['bars']} bars): last {fmt(t['last'])} | range {fmt(t['low'])}-{fmt(t['high'])} | "
                 f"DD from high {t['drawdown_from_high_pct']:.1f}% | RSI {fmt(t['rsi14'], 3)} | "
                 f"EMA9/21 {t['ema_trend']} | vs VWAP {fmt(t['price_vs_vwap_pct'], 3)}% | "
                 f"ATR {fmt(t['atr_pct'], 3)}% | vol trend {t['volume_trend_2nd_half_vs_1st']:.2f}x | "
                 f"S {fmt(t['nearest_support'])} / R {fmt(t['nearest_resistance'])}")
    fl = m.get("flow")
    if fl:
        L += ["", "## Recent flow (last trades sample)",
              f"{fl['sample_trades']} trades, {fl['unique_wallets']} wallets, window {fl['window']}",
              f"buy ${fl['buy_usd']:,.0f} / sell ${fl['sell_usd']:,.0f} / net ${fl['net_usd']:+,.0f} | top5 trades {fl['top5_trade_share_pct']:.0f}% of volume | max ${fl['largest_trade_usd']:,.0f}"]
    o = m["outlook"]
    L += ["", "## Risk flags"] + [f"- {x}" for x in m["risk_flags"] or ["none triggered"]]
    L += ["", f"## Outlook: {o['regime']} (score {o['score']:+d})"] + [f"- {r}" for r in o["reasons"]]
    L += ["", "_Rule-based read of public data. Not financial advice; microcap DEX tokens can go to zero._"]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--usd", type=float, default=500)
    a = ap.parse_args()
    chain, pair = parse_target(a.target)
    m = analyze(chain, pair, a.usd)
    print(json.dumps(m, indent=2, default=str) if a.json else report(m, a.usd))


if __name__ == "__main__":
    main()
