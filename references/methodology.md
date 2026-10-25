# Metric interpretation

## Liquidity & size
| Metric | Healthy | Caution | Danger |
|---|---|---|---|
| Liquidity USD | > $250k | $50k-250k | < $50k |
| Liq / mcap | > 15% | 5-15% | < 5% (exits crush price) |
| Vol / liq 24h | 0.5-3 | 0.1-0.5 (sleepy) or >5 (churn/wash) | < 0.1 dead |
| Price impact $1k | < 1% | 1-5% | > 5% |
| FDV / mcap | ~1 | 1.5-3 | > 3 (unlock overhang) |

## Holders
- Top-10 > 30% (excluding LP / burn / CEX): one exit dumps price.
- Holders < 500: tiny community; price set by a handful of wallets.
- Growing holder count while price flat = accumulation; falling = distribution.

## Flow
- Net USD flow and buy/sell **count** ratio — both agreeing is stronger.
- Top-3 wallets > 50% of buy volume: move is narrow, fragile; watch those wallets.
- Unique wallets / trades < 0.3: bots or few actors recycling.
- Zero trades last hour on a microcap: rally lacks follow-through.

## Technicals (per timeframe)
- **RSI14**: > 75 overbought (pullback odds up), < 30 oversold. On microcaps
  RSI can stay pinned during real pumps — confirm with flow.
- **EMA9 vs EMA21**: trend direction. Cross on 4h/1d more meaningful than 15m.
- **VWAP**: above = buyers in profit (support); below = trapped buyers (supply).
- **ATR %**: expected per-bar range. Use for stop distance (1.5-2x ATR).
- **Volume trend** (2nd half vs 1st half of window): < 0.5 fading, > 1.5 expanding.
  Price up on fading volume = weak rally.
- **Support/resistance**: clustered swing pivots. Period high/ATH = overhead supply
  (bag holders waiting to break even).
- **Drawdown from ATH** > 70%: lots of underwater holders above.

## Outlook scoring (script)
Each signal +1/-1: 1h EMA trend, 1h RSI extremes, price vs 1h VWAP, 24h buy/sell
count, recent net flow, volume trend, turnover. Sum >= +3 bullish, <= -3 bearish,
else neutral/range. It is a regime label, not a target.

## Building scenarios
1. **Bull**: break + hold above nearest 1h/4h resistance with expanding volume and
   new wallets. Next target = next resistance / prior range high.
2. **Base**: chop between nearest support and resistance; mean-revert toward VWAP.
3. **Bear**: lose nearest support on volume or top wallets sell; target next support
   / prior low. Microcap breakdowns overshoot.
Weight scenarios by: score, flow breadth, liquidity depth, volume trend.

## Classic red flags
Honeypot / sell tax, mint or blacklist authority live, LP not burned/locked,
deployer holds big %, paid boosts + no organic socials, single pool only,
age < 7 days, wash trading (high volume, tiny wallet count).

# On-chain checks

| Signal | Meaning | Severity |
|---|---|---|
| Transfer sim reverts | holders can't move/sell: honeypot or blacklist | CRITICAL |
| One EOA owns > 50% of LP | one key can pull liquidity any time | CRITICAL |
| LP concentrated (top EOA > 25% or top-3 > 60%) | a couple of wallets can drain it | HIGH |
| LP spread over many independent EOAs | normal open pool; not locked, depth can thin | MEDIUM |
| LP in contract with withdraw/unlock fn | depends on its conditions (timelock? owner-only?) | HIGH until read |
| LP in contract, no exit fn, no unknown selectors | effectively locked | OK |
| Live minter/owner + mint() | supply can grow; check cap, deadline, minter rules | HIGH |
| Proxy / upgradeable token or hook | rules can change after you buy | HIGH |
| Fee/tax setter + live owner | sell tax can be raised to 100% | HIGH |
| v4 hook beforeSwap / *ReturnDelta | can block swaps or take a cut; read hook source | MEDIUM-HIGH |
| Dynamic v4 LP fee (0x800000) | hook sets the fee per swap | HIGH |
| Unverified token/hook | can't read rules; rely on bytecode scan + dossier | MEDIUM |
| Creator holds > 5% / snipers still hold > 10% | exit pressure | MEDIUM |
| EOA (7702-delegated) | an EOA running smart-wallet code; still a single owner key | info |

Reading an unverified contract from its dossier:
1. Read `state.json` (what it currently is) and the README's "Privileged functions" (what it can do).
2. Check `interface.sol` for unknown selectors. Run `cast 4byte <sel>`, or find
   `PUSH4 <sel>` in `disassembly.txt` and follow the JUMP to the code: look for `CALLER`
   compared to a stored owner (an access check), then `SSTORE` or `CALL`.
3. Outbound calls show what it can make other contracts do (e.g. `mint`, `transferFrom`, `modifyLiquidities`).
