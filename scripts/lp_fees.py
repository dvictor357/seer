#!/usr/bin/env python3
"""LP fee scanner: what a liquidity provider would actually earn per pool.

For each pool (from the screener, or pairs you pass) it reads on-chain:
  v4  fee tier from Initialize, live lpFee from slot0, the fee actually
      charged on recent swaps (Swap events carry it), the hook and its
      permission bits (can it gate adding/removing liquidity? set fees?)
  v3  fee()
  v2  0.30% assumed for Uniswap v2 forks (getReserves present)
and estimates fee APR = fee x 24h volume / liquidity x 365 (full-range
average; a tight in-range position earns more, and pays it back in IL).

Usage:
  lp_fees.py --chain robinhood --limit 50                 # top 50 traded (screener volume source)
  lp_fees.py --chain robinhood --source trending --limit 20
  lp_fees.py "<dexscreener-url>" ["<url>" ...]
  lp_fees.py robinhood <pair> [<pair> ...] --json
"""
import argparse
import json
import os
import re
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evm import RPC, RPCS, RPCError, BudgetExceeded, words, w_int, w_addr, enc_uint  # noqa: E402
from keccak import keccak256, selector, topic  # noqa: E402
import screener  # noqa: E402

# Uniswap v4 PoolManager per chain (fallback: search Initialize without an address filter)
POOL_MANAGERS = {
    "robinhood": "0x8366a39cc670b4001a1121b8f6a443a643e40951",
    "ethereum": "0x000000000004444c5dc75cb358380d2e3de08a90",
    "base": "0x498581ff718922c3f8e6a244956af099b2652b2b",
    "arbitrum": "0x360e68faccca8ca495c1b759fd9eee466db9fb32",
    "optimism": "0x9a13f98cb987694c9f086b1f5eb990eea8264ec3",
    "polygon": "0x67366782805870060151383f4bbff9dab53e5cd6",
    "bsc": "0x28e2ea090877bf75740558f6bfb36a5ffee9e9df",
    "unichain": "0x1f98400000000000000000000000000000000004",
}
T_INIT = topic("Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)")
T_SWAP = topic("Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)")
DYNAMIC = 0x800000
ZERO = "0x" + "0" * 40
# hook address low bits that matter to an LP
HOOK_BITS = [(11, "beforeAddLiquidity"), (9, "beforeRemoveLiquidity"), (7, "beforeSwap"),
             (6, "afterSwap"), (3, "beforeSwapReturnDelta"), (2, "afterSwapReturnDelta"),
             (1, "afterAddLiquidityReturnDelta"), (0, "afterRemoveLiquidityReturnDelta")]


def blocks_per_sec(rpc, head):
    back = min(head - 1, 200_000)
    a, b = rpc.block(head), rpc.block(head - back)
    return back / max(int(a["timestamp"], 16) - int(b["timestamp"], 16), 1)


def find_init(rpc, pm, pid, at, bps):
    """Initialize log for pid near block `at` (pool creation)."""
    for half_h in (1, 6, 48):
        frm, to = at - int(half_h * 3600 * bps), at + int(half_h * 3600 * bps)
        for addr in ([pm] if pm else []) + [None]:
            try:
                logs, _ = rpc.logs(addr, [T_INIT, pid], max(frm, 0), to, budget=40)
            except (BudgetExceeded, RPCError):
                continue
            if logs:
                return logs[0]
    return None


def scan_v4(rpc, r, head, bps, window_h):
    pid = r["pair"].lower()
    at = head - int((r["age_d"] or 0) * 86400 * bps)
    ev = find_init(rpc, POOL_MANAGERS.get(r["chain"]), pid, min(at, head), bps)
    if ev:
        pm = ev["address"].lower()
        w = words(ev["data"])
        fee, spacing, hook = w_int(w[0]), w_int(w[1], True), w_addr(w[2])
        out = {"version": "v4", "pool_manager": pm, "fee_tier": fee, "dynamic": fee == DYNAMIC,
               "tick_spacing": spacing, "hook": None if hook == ZERO else hook,
               "token1": w_addr(ev["topics"][3])}
    elif POOL_MANAGERS.get(r["chain"]):
        # creation block estimate missed (old pool): slot0, liquidity and swaps
        # are keyed by pool id, so read them anyway; tier and hook stay unknown
        pm = POOL_MANAGERS[r["chain"]]
        out = {"version": "v4", "pool_manager": pm, "hook": None, "hook_unknown": True,
               "note": "Initialize not found: hook and fee tier unknown"}
    else:
        return {"version": "v4", "note": "Initialize not found"}
    base = keccak256(bytes.fromhex(pid[2:] + enc_uint(6)))
    s0 = rpc.eth_call(pm, selector("extsload(bytes32)") + base.hex())
    if s0 and len(s0) >= 66:
        raw = w_int(words(s0)[0])
        out["live_lp_fee"] = (raw >> 208) & 0xFFFFFF
        out["protocol_fee"] = (raw >> 184) & 0xFFFFFF
        out["sqrt_price_x96"] = raw & ((1 << 160) - 1)
    # Pool.State: slot0, feeGrowthGlobal0, feeGrowthGlobal1, liquidity (in-range L)
    liq_slot = enc_uint(int.from_bytes(base, "big") + 3)
    lq = rpc.eth_call(pm, selector("extsload(bytes32)") + liq_slot)
    if lq and len(lq) >= 66:
        out["active_liquidity"] = w_int(words(lq)[0]) & ((1 << 128) - 1)
    # fee actually charged on recent swaps
    frm = max(head - int(window_h * 3600 * bps), 0)
    try:
        logs, trunc = rpc.logs(pm, [T_SWAP, pid], frm, head, max_logs=500, budget=30)
    except (BudgetExceeded, RPCError):
        logs, trunc = [], False
    fees = [w_int(words(lg["data"])[5]) for lg in logs]
    out["swaps_window"] = len(logs) if not trunc and len(logs) < 500 else f"{len(logs)}+"
    if fees:
        out["swap_fee_median"] = statistics.median(fees)
        out["swap_fee_min"], out["swap_fee_max"] = min(fees), max(fees)
    if out["hook"]:
        hv = int(out["hook"], 16)
        out["hook_bits"] = [n for b, n in HOOK_BITS if hv >> b & 1]
    return out


def scan_v3_v2(rpc, r):
    p = r["pair"]
    res = rpc.eth_call(p, selector("fee()"))
    if res and len(res) >= 66:
        out = {"version": "v3", "fee_tier": w_int(words(res)[0])}
        s0 = rpc.eth_call(p, selector("slot0()"))
        lq = rpc.eth_call(p, selector("liquidity()"))
        t1 = rpc.eth_call(p, selector("token1()"))
        if s0 and len(s0) >= 66:
            out["sqrt_price_x96"] = w_int(words(s0)[0])
        if lq and len(lq) >= 66:
            out["active_liquidity"] = w_int(words(lq)[0])
        if t1 and len(t1) >= 66:
            out["token1"] = w_addr(words(t1)[0])
        return out
    res = rpc.eth_call(p, selector("getReserves()"))
    if res and len(res) >= 194:
        uni = r["dex"].startswith("uniswap")
        return {"version": "v2", "fee_tier": 3000 if uni else None,
                "note": "0.30% (Uniswap v2 standard)" if uni else "v2 fork: fee not readable on-chain"}
    return {"version": "unknown", "note": "not a v2/v3/v4 pool"}


def effective_fee(s):
    """LP fee in hundredths of a bip (1e-6), best evidence first."""
    if s.get("swap_fee_median") is not None:
        return s["swap_fee_median"], "swaps"
    if s.get("dynamic"):
        return None, "dynamic"
    if s.get("live_lp_fee") is not None:
        return s["live_lp_fee"], "slot0"
    return s.get("fee_tier"), "tier"


def lp_flags(r, s, fee):
    f = []
    if fee is not None and fee <= 1:  # 0 or 1 pip: effectively free swaps
        f.append("ZERO-FEE: LPs earn ~nothing from swaps")
    if s.get("swaps_window") == 0:
        f.append("no swaps in sample window")
    if s.get("dynamic"):
        f.append("dynamic fee (hook sets it per swap)")
    if s.get("hook_unknown"):
        f.append("hook unknown (Initialize event not found): check with onchain_check")
    bits = s.get("hook_bits") or []
    if "beforeAddLiquidity" in bits:
        f.append("hook gates add-liquidity (Krystal/3rd-party adds may revert)")
    if "beforeRemoveLiquidity" in bits:
        f.append("hook gates remove-liquidity (exit may be restricted)")
    if {"beforeSwapReturnDelta", "afterSwapReturnDelta"} & set(bits):
        f.append("hook takes a cut of swaps")
    if any(x.startswith(("fake-vol", "churn")) for x in r["flags"]):
        f.append("volume may be wash: APR overstated")
    if abs(r["chg24"]) > 50 or abs(r["chg6"]) > 30:
        f.append("high volatility: heavy IL / range exits")
    if r["age_d"] is not None and r["age_d"] < 2:
        f.append("pool < 48h old")
    if r["liq"] < 50_000:
        f.append("thin pool")
    return f


def scan(rows, chain, rpc_url=None, window_h=6):
    rpc = RPC([rpc_url] if rpc_url else RPCS.get(chain, []))
    head = int(rpc.call("eth_blockNumber", []), 16)
    bps = blocks_per_sec(rpc, head)
    out = []
    for r in rows:
        r = {**r, "chain": chain}
        s = scan_v4(rpc, r, head, bps, window_h) if len(r["pair"]) == 66 else scan_v3_v2(rpc, r)
        fee, src = effective_fee(s)
        pct = fee / 1e4 if fee is not None and fee < DYNAMIC else None
        apr = pct * r["vol24"] / r["liq"] * 365 if pct is not None and r["liq"] else None
        out.append({**r, **s, "lp_fee_pct": pct, "fee_source": src, "fee_apr_pct": apr,
                    "lp_flags": lp_flags(r, s, fee)})
    return out


def report(chain, rows, window_h):
    L = [f"## LP fees | chain: {chain} | {len(rows)} pools | swap-fee sample: last {window_h}h", "",
         "| # | chain | pool | ver | LP fee | fee src | hook | liq | vol24 | est fee APR | 24h | LP notes |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        fee = "?" if r["lp_fee_pct"] is None else f"{r['lp_fee_pct']:.3g}%"
        if r.get("swap_fee_min") is not None and r["swap_fee_min"] != r["swap_fee_max"]:
            fee += f" ({r['swap_fee_min'] / 1e4:.3g}-{r['swap_fee_max'] / 1e4:.3g}%)"
        apr = "?" if r["fee_apr_pct"] is None else f"{r['fee_apr_pct']:,.0f}%"
        hook = (r["hook"][:10] + "…") if r.get("hook") else "-"
        L.append(f"| {i} | {chain} | [**{r['symbol']}**/{r['quote']}]({r['url']}) | {r['version']} | {fee} | "
                 f"{r['fee_source']} | {hook} | {screener.fmt_money(r['liq'])} | {screener.fmt_money(r['vol24'])} | "
                 f"{apr} | {r['chg24']:+.0f}% | {'; '.join(r['lp_flags']) or r.get('note', '')} |")
    L += ["", "_Fee APR = LP fee x 24h volume / pool liquidity x 365, averaged over all liquidity. A tight range "
          "earns more while in range and suffers more impermanent loss. Wash volume inflates it. Not advice._"]
    return "\n".join(L)


def pairs_from_args(items):
    """URLs or `chain pair...` -> (chain, [screener rows])."""
    import time
    chain, pairs = None, []
    for x in items:
        m = re.search(r"dexscreener\.com/([^/]+)/([0-9a-zA-Z]+)", x)
        if m:
            chain = chain or m.group(1)
            pairs.append(m.group(2))
        elif chain is None and not x.startswith("0x"):
            chain = x
        else:
            pairs.append(x)
    if not chain or not pairs:
        raise SystemExit("error: pass dexscreener URLs, or `<chain> <pair> [<pair> ...]`, or --chain")
    now = time.time() * 1000
    rows = []
    for k in range(0, len(pairs), 30):
        d = screener.get(f"{screener.DS}/latest/dex/pairs/{chain}/{','.join(pairs[k:k + 30])}") or {}
        rows += [screener.row(p, now) for p in d.get("pairs") or []]
    return chain, rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="dexscreener URLs, or <chain> <pair...>")
    ap.add_argument("--chain", help="screen this chain (DexScreener id) instead of passing pairs")
    ap.add_argument("--source", choices=screener.SOURCES, default="volume")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--min-liq", type=float, default=1000)
    ap.add_argument("--window-h", type=float, default=6, help="hours of Swap events to sample (default 6)")
    ap.add_argument("--sort", choices=("source", "apr", "liq", "volume"), default="source")
    ap.add_argument("--rpc", default=os.environ.get("RPC_URL"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.chain:
        chain = a.chain.strip().lower()
        sort = "volume" if a.source == "volume" else "source"
        rows, _, _ = screener.screen(chain, a.source, a.limit, a.min_liq, sort, 10)
    else:
        chain, rows = pairs_from_args(a.targets)
    if chain not in RPCS and not a.rpc:
        raise SystemExit(f"error: no built-in RPC for chain '{chain}'. Pass --rpc <url>. "
                         f"Built in: {', '.join(sorted(RPCS))}")
    out = scan(rows, chain, a.rpc, a.window_h)
    key = {"apr": lambda r: -(r["fee_apr_pct"] or -1), "liq": lambda r: -r["liq"],
           "volume": lambda r: -r["vol24"]}.get(a.sort)
    if key:
        out.sort(key=key)
    print(json.dumps(out, indent=1, default=str) if a.json else report(chain, out, a.window_h))


if __name__ == "__main__":
    main()
