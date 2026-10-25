#!/usr/bin/env python3
"""DEX screener: pull the top coins on one or more chains and rank them.

Sources (all public, no key):
  trending  GeckoTerminal trending pools for the chain        (default)
  volume    GeckoTerminal top pools by 24h volume
  new       GeckoTerminal newest pools
  boosted   DexScreener most-boosted tokens, filtered to the chain
  profiles  DexScreener latest token profiles, filtered to the chain
Every token is enriched with DexScreener pair data (best-liquidity pair).

Usage:
  screener.py --chain robinhood
  screener.py --chain base,solana --source volume --limit 15 --min-liq 25000
  screener.py --chain robinhood --source new --sort score --json
  screener.py --chain solana --source volume --limit 50     # top 50 traded (auto-pages)
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

UA = {"User-Agent": "seer/0.1", "Accept": "application/json"}
DS = "https://api.dexscreener.com"
GT = "https://api.geckoterminal.com/api/v2"
# DexScreener chain id -> GeckoTerminal network id where they differ
GT_NET = {"ethereum": "eth", "polygon": "polygon_pos", "avalanche": "avax", "fantom": "ftm"}
SOURCES = ("trending", "volume", "new", "boosted", "profiles")
# Majors / stables / wrapped assets: hidden unless --include-majors
MAJORS = {"ETH", "WETH", "BTC", "WBTC", "CBBTC", "TBTC", "USDC", "USDT", "USDBC", "DAI", "USDE", "USD1", "PYUSD",
          "FDUSD", "BUSD", "TUSD", "USDS", "USDG", "EURC", "FRAX", "SOL", "WSOL", "JITOSOL", "MSOL", "BNB", "WBNB",
          "MATIC", "WMATIC", "POL", "AVAX", "WAVAX", "ARB", "OP", "STETH", "WSTETH", "WEETH", "CBETH", "RETH",
          "EZETH", "RSETH", "SUI", "TRX", "XRP", "USDT0", "USD₮0", "LBTC", "SOLVBTC", "BTCB", "USDP", "EUSD", "MSUSD", "SUSDX",
          "SUSDE", "CRVUSD", "GHO", "LUSD", "USDX", "USDM", "USDA", "USR", "DOLA"}


def get(url, retries=4):
    for i in range(retries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429 and i < retries - 1:
                time.sleep(15 * (i + 1))
                continue
            if e.code == 404:
                return None
            sys.stderr.write(f"warn: {url} -> HTTP {e.code}\n")
            return None
        except Exception as e:
            if i < retries - 1:
                time.sleep(2)
                continue
            sys.stderr.write(f"warn: {url} -> {e}\n")
            return None


def f(x, d=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return d


def candidate_pages(chain, source, max_pages):
    """Yield token addresses page by page (source order) for the chain."""
    net = GT_NET.get(chain, chain)
    if source in ("trending", "volume", "new"):
        path = {"trending": f"/networks/{net}/trending_pools",
                "volume": f"/networks/{net}/pools",
                "new": f"/networks/{net}/new_pools"}[source]
        for page in range(1, max_pages + 1):
            q = f"?page={page}" + ("&sort=h24_volume_usd_desc" if source == "volume" else "")
            d = get(f"{GT}{path}{q}")
            if d is None and page == 1:
                raise SystemExit(f"error: GeckoTerminal has no network '{net}' (chain '{chain}'). "
                                 "Check the chain id, or use --source boosted/profiles.")
            data = (d or {}).get("data", [])
            if not data:
                return
            toks = []
            for p in data:
                bt = ((p.get("relationships") or {}).get("base_token") or {}).get("data") or {}
                tid = bt.get("id", "")
                if "_" in tid:
                    toks.append(tid.split("_", 1)[1])
            yield toks
            time.sleep(2.1)  # GeckoTerminal free tier ~30 req/min
    else:
        path = "/token-boosts/top/v1" if source == "boosted" else "/token-profiles/latest/v1"
        yield [x["tokenAddress"] for x in get(f"{DS}{path}") or []
               if x.get("chainId") == chain and x.get("tokenAddress")]


def norm(t):
    return t.lower() if t.startswith("0x") else t


def enrich(chain, tokens):
    """Best-liquidity DexScreener pair per token (30 addresses per call)."""
    best = {}
    for k in range(0, len(tokens), 30):
        chunk = tokens[k:k + 30]
        for p in get(f"{DS}/tokens/v1/{chain}/{','.join(chunk)}") or []:
            addr = p["baseToken"]["address"]
            key = norm(addr)
            if not any(norm(t) == key for t in chunk):
                continue  # token appears as quote in this pair
            liq = f((p.get("liquidity") or {}).get("usd"))
            if key not in best or liq > f((best[key].get("liquidity") or {}).get("usd")):
                best[key] = p
    return best


def pool_totals(chain, token):
    """(total liquidity USD, pool count, capped) across every pool holding the token.
    DexScreener's token-pairs endpoint returns at most 30 pools."""
    ps = get(f"{DS}/token-pairs/v1/{chain}/{token}") or []
    return sum(f((x.get("liquidity") or {}).get("usd")) for x in ps), len(ps), len(ps) >= 30


def row(p, now_ms, totals=None):
    liq = f((p.get("liquidity") or {}).get("usd"))
    total_liq, n_pools, capped = totals or (liq, 1, False)
    total_liq = max(total_liq, liq)
    mcap = f(p.get("marketCap")) or f(p.get("fdv"))
    vol = p.get("volume") or {}
    tx = p.get("txns") or {}
    t24 = tx.get("h24") or {}
    ch = p.get("priceChange") or {}
    age_d = (now_ms - p["pairCreatedAt"]) / 86_400_000 if p.get("pairCreatedAt") else None
    buys, sells = t24.get("buys", 0), t24.get("sells", 0)
    r = {
        "symbol": p["baseToken"]["symbol"], "name": p["baseToken"]["name"],
        "token": p["baseToken"]["address"], "pair": p["pairAddress"], "url": p.get("url"),
        "dex": p.get("dexId") + (" " + "/".join(p["labels"]) if p.get("labels") else ""),
        "quote": p["quoteToken"]["symbol"], "price_usd": f(p.get("priceUsd")),
        "liq": liq, "mcap": mcap, "vol24": f(vol.get("h24")), "vol1": f(vol.get("h1")),
        "chg1": f(ch.get("h1")), "chg6": f(ch.get("h6")), "chg24": f(ch.get("h24")),
        "buys24": buys, "sells24": sells, "txns1h": sum((tx.get("h1") or {}).values()),
        "age_d": age_d, "boosts": (p.get("boosts") or {}).get("active", 0),
        "vol_liq": f(vol.get("h24")) / liq if liq else 0,
        "total_liq": total_liq, "pools": n_pools, "pools_capped": capped,
        "liq_mcap_pct": total_liq / mcap * 100 if mcap else 0,  # all pools: what exits can tap
        "bs_ratio": buys / max(sells, 1),
    }
    flags = []
    if liq < 20_000:
        flags.append("thin-liq")
    if mcap and r["liq_mcap_pct"] < 5:
        flags.append("liq<5%mcap")
    if age_d is not None and age_d < 2:
        flags.append("new<48h")
    if r["vol_liq"] > 10:
        flags.append("churn/wash?")
    n24 = buys + sells
    if r["vol24"] > 100_000 and r["vol24"] / max(n24, 1) > 50_000:
        flags.append("fake-vol?")  # huge volume from a handful of trades
    if r["txns1h"] == 0:
        flags.append("dead-1h")
    if r["boosts"]:
        flags.append(f"boost{r['boosts']}")
    if r["chg24"] < -50:
        flags.append("dumped")
    r["flags"] = flags
    # quick score: momentum + participation + health (rough triage, not a signal)
    s = 0.0
    s += max(min(r["chg6"], 50), -50) / 25
    s += max(min(r["chg24"], 100), -100) / 50
    s += (min(r["bs_ratio"], 3) - 1) * 1.5
    s += min(r["vol_liq"], 5) / 2.5 if r["vol_liq"] <= 10 else -1
    s += 1 if total_liq >= 100_000 else 0 if total_liq >= 20_000 else -2
    s += 1 if r["liq_mcap_pct"] >= 10 else -1 if r["liq_mcap_pct"] < 5 else 0
    s -= 1 if r["txns1h"] == 0 else 0
    s -= 3 if "fake-vol?" in flags else 0
    r["score"] = round(s, 2)
    return r


def fmt_money(x):
    if x >= 1e9:
        return f"${x / 1e9:.2f}B"
    if x >= 1e6:
        return f"${x / 1e6:.2f}M"
    if x >= 1e3:
        return f"${x / 1e3:.1f}k"
    return f"${x:.0f}"


def fmt_price(x):
    return f"${x:.3g}" if x < 1 else f"${x:,.2f}"


def table(chain, source, rows, total):
    head = (f"## Chain: {chain}  |  source: {source}  |  {len(rows)} shown of {total} candidates  |  "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    L = [head, "",
         "| # | chain | token | dex | price | mcap | liq (main pool) | total liq (pools) | total liq/mc | vol24 | "
         "vol/liq | 1h | 6h | 24h | B/S 24h | age | score | flags |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        age = "?" if r["age_d"] is None else (f"{r['age_d'] * 24:.0f}h" if r["age_d"] < 2 else f"{r['age_d']:.0f}d")
        L.append(f"| {i} | {chain} | **{r['symbol']}**/{r['quote']} | {r['dex']} | {fmt_price(r['price_usd'])} | "
                 f"{fmt_money(r['mcap'])} | {fmt_money(r['liq'])} | "
                 f"{fmt_money(r['total_liq'])} ({r['pools']}{'+' if r['pools_capped'] else ''}) | {r['liq_mcap_pct']:.0f}% | {fmt_money(r['vol24'])} | "
                 f"{r['vol_liq']:.2f} | {r['chg1']:+.1f}% | {r['chg6']:+.1f}% | {r['chg24']:+.1f}% | "
                 f"{r['buys24']}/{r['sells24']} | {age} | {r['score']:+.1f} | {' '.join(r['flags'])} |")
    L += ["", "_liq (main pool) = the pair shown (price impact, vol/liq). total liq = sum over every pool holding "
          "the token (both sides of each pool; `30+` = DexScreener cap, real total may be higher). "
          "total liq/mc is what exits can tap._", "", "Links / next step (deep dive any row):"]
    for i, r in enumerate(rows, 1):
        L.append(f"{i}. {r['symbol']}: {r['url']}")
    return "\n".join(L)


def screen(chain, source, limit, min_liq, sort, pages, include_majors=False):
    """Fetch source pages until `limit` rows pass the filters (or pages run out)."""
    toks, seen, pairs = [], set(), {}
    now = time.time() * 1000
    keep = lambda r: r["liq"] >= min_liq and (include_majors or r["symbol"].upper() not in MAJORS)
    n_pages = 0
    for page in candidate_pages(chain, source, pages):
        n_pages += 1
        new = [t for t in page if norm(t) not in seen]
        seen.update(norm(t) for t in new)
        toks += new
        pairs.update(enrich(chain, new))
        if sum(keep(row(p, now)) for p in pairs.values()) >= limit:
            break
    rows = [row(p, now) for p in pairs.values()]
    total = len(rows)
    rows = [r for r in rows if keep(r)]
    if sort == "liq":  # rank on total liquidity, so every candidate needs its totals
        rows = [row(pairs[norm(r["token"])], now, pool_totals(chain, r["token"])) for r in rows]
    key = {"score": lambda r: -r["score"], "volume": lambda r: -r["vol24"], "liq": lambda r: -r["total_liq"],
           "mcap": lambda r: -r["mcap"], "change": lambda r: -r["chg24"], "new": lambda r: r["age_d"] or 1e9,
           "source": None}[sort]
    if key:
        rows.sort(key=key)
    else:  # keep the source's own ranking
        order = {norm(t): i for i, t in enumerate(toks)}
        rows.sort(key=lambda r: order.get(norm(r["token"]), 1e9))
    rows = rows[:limit]
    if sort != "liq":  # totals for the shown rows only (one call per token)
        rows = [row(pairs[norm(r["token"])], now, pool_totals(chain, r["token"])) for r in rows]
    return rows, total, n_pages


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--chain", required=True, help="DexScreener chain id(s), comma-separated: robinhood,base,solana,...")
    ap.add_argument("--source", choices=SOURCES, default="trending")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--min-liq", type=float, default=1000, help="min liquidity USD (default 1000 hides broken pairs)")
    ap.add_argument("--sort", choices=("source", "score", "volume", "liq", "mcap", "change", "new"), default=None,
                    help="default: volume for --source volume, else the source's own order")
    ap.add_argument("--pages", type=int, default=10,
                    help="max GeckoTerminal pages (20 pools each); stops early once --limit rows are filled")
    ap.add_argument("--include-majors", action="store_true", help="keep stables / wrapped majors (hidden by default)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    a.sort = a.sort or ("volume" if a.source == "volume" else "source")
    out = {}
    for chain in [c.strip().lower() for c in a.chain.split(",") if c.strip()]:
        rows, total, n_pages = screen(chain, a.source, a.limit, a.min_liq, a.sort, a.pages, a.include_majors)
        out[chain] = {"source": a.source, "candidates": total, "pages": n_pages, "rows": rows}
        if not a.json:
            print(table(chain, a.source, rows, total))
            if len(rows) < a.limit:
                print(f"\n_Only {len(rows)} of {a.limit} requested passed filters after {n_pages} page(s); "
                      "lower --min-liq, add --include-majors, or raise --pages._")
            print()
    if a.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        print("_Score = quick triage (momentum + buy pressure + turnover + liquidity health), not a buy signal. "
              "Run analyze.py / onchain_check.py on anything interesting._")


if __name__ == "__main__":
    main()
