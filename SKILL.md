---
name: seer
description: Screen and analyze DEX-traded tokens. Picker rates each token for LP (fee, IL, hooks) and for buying. Screener pulls top/trending/new/boosted coins per chain (robinhood, base, solana, ethereum, ...). Analyzer takes a DexScreener link or chain + pair and reports liquidity, mcap, holder concentration, buy/sell flow, multi-timeframe technicals, risk flags and a scenario-based outlook. The on-chain checker (EVM) finds who controls the token and its LP (minter/owner roles, LP lock, v4 hooks, honeypot simulation) and builds a contract dossier for study. Use when the user asks "what should I LP / buy on <chain>", "top coins on <chain>", "screen <chain>", "what's trending", pastes a dexscreener.com URL or pool address, or asks to "analyze this token", "is this a rug", "who owns the LP", "predict price movement", "what LP range", "is -5%/+15% too tight", "how much fee will my range earn".
---

# Seer

Pulls public data (DexScreener + GeckoTerminal, no API key), computes metrics, and
produces a rule-based read. Outlook is probabilistic scenarios, never a guarantee.

## Pick: what to LP, what to buy (start here)

```bash
python3 -I <skill-dir>/scripts/picker.py --chain robinhood                     # top 20 trending, both ratings
python3 -I <skill-dir>/scripts/picker.py --chain robinhood --source volume --limit 30 --deep 3
```

Rates every screened token twice, with the reasons for each rating:
- **LP: GOOD LP / OK LP / AVOID LP.** Inputs are the real on-chain fee, fee APR (turnover capped at 3× liquidity so
  wash volume can't inflate it), volatility (impermanent loss), age, pool depth, recent swaps, and hooks.
  AVOID is forced for pools charging ~0% and for hooks that can block liquidity removal. A hook that runs before adding
  liquidity means a Krystal add may revert, so test with a small amount first.
- **BUY: CANDIDATE / SPECULATIVE / AVOID.** Inputs are total liquidity vs mcap (under 3% forces AVOID), buyer/seller
  balance, trend vs overextension, recent activity, age and wash volume. CANDIDATE also needs total liquidity of at least 10% of mcap and $100k,
  an age of 7 days or more, and a 24h move under +100%; otherwise the rating is capped at SPECULATIVE.
- **`--deep N`** runs the on-chain check on the N best-rated tokens (1–3 min each). DANGER or HIGH RISK forces AVOID on both ratings.

Present the "Best for LP" and "Best to buy" lists with their reasons. For any pick, recommend `onchain_check.py`
(if not already deep-checked), `analyze.py` for entry levels and `lp_range.py` for an LP range. Ratings are triage, not advice.

## Screen a chain (find candidates)

```bash
python3 -I <skill-dir>/scripts/screener.py --chain robinhood                        # trending, ranked by source
python3 -I <skill-dir>/scripts/screener.py --chain base,solana --source volume --limit 15
python3 -I <skill-dir>/scripts/screener.py --chain robinhood --source new --sort score --min-liq 20000
python3 -I <skill-dir>/scripts/screener.py --chain robinhood --source boosted --json
python3 -I <skill-dir>/scripts/screener.py --chain solana --source volume --limit 50  # top 50 traded
```

`--chain` takes DexScreener chain ids (comma-separated). Every table header and row names the
chain being screened. Sources: `trending` | `volume` | `new` (GeckoTerminal pools for that chain),
`boosted` | `profiles` (DexScreener, filtered to the chain). Rows are enriched with the token's
best-liquidity DexScreener pair, plus total liquidity across every pool holding the token
(`token-pairs` endpoint, max 30 pools shown as `30+`); liq/mcap, `liq<5%mcap` and the score use the total. Sort options: `source` (default; `volume` when `--source volume`), `score`, `volume`, `liq`, `mcap`,
`change`, `new`. Majors and stables are hidden unless `--include-majors`. Pages (20 pools each) are
fetched until `--limit` rows pass the filters, capped by `--pages` (default 10); top 50 takes ~1-2 min. Flags: `thin-liq`, `liq<5%mcap`, `new<48h`, `churn/wash?`
(volume/liquidity > 10), `fake-vol?` (avg trade > $50k: volume from a few huge trades), `dead-1h`, `boostN`, `dumped`. The score is triage only. Run the
analyzer and the on-chain check on anything picked from the list.

## LP fee scan (before providing liquidity)

```bash
python3 -I <skill-dir>/scripts/lp_fees.py --chain robinhood --limit 50          # top 50 traded pools
python3 -I <skill-dir>/scripts/lp_fees.py --chain base --source trending --sort apr
python3 -I <skill-dir>/scripts/lp_fees.py "<dexscreener-url>" ["<url>" ...] --json
```

For each pool, it reads the LP fee on-chain:
- **v4:** fee tier from `Initialize`, live `lpFee` from slot0, and the fee actually charged on swaps in
  the last `--window-h` hours (Swap events carry it, so this catches dynamic-fee hooks).
- **v3:** `fee()`.
- **v2:** 0.30% is assumed for Uniswap v2 forks.

It also reports the hook's permission bits. Estimated fee APR = fee × 24h volume / liquidity × 365, a
full-range average. LP notes flag:
- zero-fee pools: many Robinhood launch pools charge 0%, so their volume pays LPs nothing
- hooks that gate add or remove liquidity, so adds from Krystal or other front-ends may revert
- hooks that take a cut of swaps
- wash volume, which overstates APR
- high volatility (impermanent loss)
- pools with no swaps in the sample window

It takes about 3 min for 50 pools. Always run `onchain_check.py` on the token before adding liquidity.

## LP range planner (sizing a concentrated range)

```bash
python3 -I <skill-dir>/scripts/lp_range.py "<dexscreener-url>"                       # -5% / +15%, $1000
python3 -I <skill-dir>/scripts/lp_range.py "<url>" --lower -20 --upper 15 --usd 500 --hold-h 48
python3 -I <skill-dir>/scripts/lp_range.py "<url>" --fee 0.3 --json                  # skip on-chain fee read
python3 -I <skill-dir>/scripts/lp_range.py --price 1 --fee 0.3 --vol24 1e5 --liq 5e5 --sigma-1h 1 --depth 8e5  # offline
```

Uniswap v3/v4 math for a range given as % from price. It reports:
- **Bounds and deposit split:** the price bounds, and how much token vs quote your USD size deposits.
- **Capital efficiency:** liquidity per dollar compared with a full-range position.
- **Fee income:** the fee comes from `lp_fees`. Your share is your depth / (pool's in-range depth + yours), where the
  pool's depth is its active `liquidity` read on-chain and expressed as a full-range-equivalent USD figure.
  Turnover is capped at 3× liquidity. If the depth can't be read, the fee figure is an upper bound.
- **Value at each bound and on a price grid**, vs HODL and vs cash. At the lower bound the position is 100% token;
  at the upper bound it is 100% quote.
- **Fee payback:** how long in range it takes for fees to cover the loss at each bound.
- **Expected time in range per timeframe:** a zero-drift random walk, E[t] = a·b/σ², with σ = ATR/1.6 over the last 14 bars.
  It also gives a "fit" range with the same lower:upper ratio, sized to stay in range for `--hold-h`.
- **S/R range:** the nearest support and resistance at least one 1h ATR away.
- **Size vs pool:** your share of the pool and the exit price impact.
- **Verdict:** TOO TIGHT (under 24h in range) / TIGHT (under 72h) / FITS, plus the EMA trend across timeframes.

When reporting, lead with the verdict and the expected time in range. Then give the fit or S/R range as the alternative.
Fee figures assume today's 24h volume continues, so say volume fades. If the quote is not a stable, the bounds move with
the quote's USD price.

## Analyze one token

```bash
python3 -I <skill-dir>/scripts/analyze.py "<dexscreener-url>"          # markdown report
python3 -I <skill-dir>/scripts/analyze.py <chain> <pairAddress> --json  # full metrics JSON
python3 -I <skill-dir>/scripts/analyze.py "<url>" --usd 2000            # custom price-impact probe size
```

`<skill-dir>` = directory containing this SKILL.md. Takes ~15-60s (GeckoTerminal free
tier is ~30 req/min; script spaces calls and backs off on HTTP 429). Stdlib only, Python 3.8+.

Chain ids are DexScreener's (`ethereum`, `base`, `solana`, `bsc`, `robinhood`, ...).
If GeckoTerminal uses a different network id, add it to `GT_NET` in the script.

## Workflow

1. Run the script. If GeckoTerminal sections are missing (404 / rate limit), say so —
   don't invent holder or candle data.
2. Read `references/methodology.md` for how to interpret each metric and thresholds.
3. Write the answer in this order:
   - **Snapshot**: price, mcap/FDV, liquidity, liq/mcap %, age, volume, txn counts.
   - **Structure**: where price sits vs ATH, range, support/resistance per timeframe.
   - **Momentum**: RSI / EMA / VWAP across 1d, 4h, 1h, 15m — call out divergences between timeframes.
   - **Flow**: net buy/sell USD, unique wallets, whether a few wallets drive the move.
   - **Risk flags**: list every flag the script raised; add any you verify yourself.
   - **Outlook**: 2-3 scenarios (bull / base / bear) with trigger levels from the
     support/resistance output and rough likelihood words (likely / possible / unlikely).
     State what would invalidate each.
   - **What to watch**: concrete levels and signals for the next 24-72h.
4. End with: not financial advice; microcaps can go to zero.

## On-chain safety check + contract dossier (EVM chains)

Run this whenever the user asks "is it safe / a rug / honeypot", wants to know who
controls the token or the liquidity, or before giving any buy-side view:

```bash
python3 -I <skill-dir>/scripts/onchain_check.py "<dexscreener-url>"            # report + dossier
python3 -I <skill-dir>/scripts/onchain_check.py <chain> <pair> --json           # machine-readable
python3 -I <skill-dir>/scripts/onchain_check.py "<url>" --dossier ./dossiers/X  # choose dossier dir
python3 -I <skill-dir>/scripts/onchain_check.py "<url>" --no-dossier            # faster
python3 -I <skill-dir>/scripts/contract_dossier.py <chain> <addr> [<addr>...]   # dossier for any contracts
```

RPC-only (public RPCs built in; `--rpc` / `RPC_URL` to override; `ETHERSCAN_API_KEY`
optional; `LOG_BUDGET` caps log requests, default 400). Takes 1-3 min. The pool type is
detected from the pool contract itself (v2 / v3 / v4 / bonding curve posing as v2 / unsupported AMM), not
from DexScreener labels.

RPC history coverage matters. Robinhood's public RPC serves full log history. Free Base,
Ethereum, Arbitrum and OP RPCs cap log ranges at 1k–100k blocks. When a full scan would exceed the
budget, the checker scans the launch window plus a recent window. It flags the result as partial,
uses GeckoTerminal's holder count and distribution, and still traces LP from launch (where LP
burns and locks happen). For complete holder or LP coverage on those chains, pass
`--rpc <archive RPC>` (e.g. a free Alchemy or QuickNode key URL). It checks:

- **Token**: verified source, proxy/upgradeable, live roles (owner, minter, admin…),
  privileged functions from bytecode (mint, blacklist, fee setters, pause, limits),
  remaining mintable supply vs cap and deadline, unknown selectors, DELEGATECALL/SELFDESTRUCT.
- **Transfer simulation**: `eth_call` transfers from top holders to a fresh wallet and into
  the pool. A revert means a possible honeypot or blacklist.
- **Liquidity**: every LP position (v2 LP tokens, v3/v4 NFTs) with owner, USD value and
  whether it is in range; owner type (burned / contract / EOA / 7702-delegated EOA); and a
  **locker audit** that checks whether the holder contract has any withdraw/unlock path.
- **v4 hooks**: permission bits, verification, owner, decoded fee config for known launchpads
  (adapters in `HOOK_ADAPTERS`).
- **Holders**: rebuilt from all Transfer logs, live balances, the creator (from the launchpad
  registry when known; flags a high-nonce relayer that is not the creator), launch snipers.

The **dossier** (default `~/seer-dossiers/<chain>/<SYMBOL>-<token>/`) is for studying the
contracts. `index.md` has a mermaid system map, a contract table and a study order. Each
contract gets a folder with:
`source/` (if verified) or `interface.sol` (reconstructed), `abi.json`, `state.json`
(live getters), `bytecode.hex`, `disassembly.txt`, and a `README.md` with privileged
functions, live state, outbound calls, events, errors and `cast` commands. Related
contracts (owners, minters, factories, implementations) are found from state, up to 2 hops.

When reporting: lead with the verdict and every HIGH/CRITICAL finding. For any flagged role
(minter, owner, LP holder), open its dossier README and explain what it can do, using its
live state. Treat a mint cap as the worst case and say what the minter's state shows is
actually pending. Read `references/methodology.md` → "On-chain checks" for interpretation.

## Extra checks worth doing when tools allow

- Socials: X/Telegram activity vs boost spend. Paid boosts with flat socials are a red flag.
- Re-run after a few hours; the trend of the score matters more than one reading.

## Limits

- Price impact uses full-range constant-product math; Uniswap v3/v4 concentrated
  liquidity can be much thinner outside the active range.
- Trades sample = last ~100-300 swaps only.
- Technicals on thin microcaps are weak signals; one wallet can move price 10%+.
