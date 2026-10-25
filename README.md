# Seer

On-chain due diligence for DEX tokens, run from your own machine.

Paste a DexScreener link and Seer tells you who controls the token and its liquidity,
how buyers and sellers are behaving, and where the risks are. It also builds a
**contract dossier**: a map of every contract in the token's system (factories, hooks,
vaults, multisigs, proxies) with verified source or reconstructed interfaces, live state
and `cast` commands to study each one.

- **No API keys, no dependencies.** Python 3.8+ standard library only.
- **Your RPC, your data.** Public endpoints are built in; pass your own RPC for full history.
- **Works as an agent skill.** `SKILL.md` lets Claude Code and other agents drive it.

## What it does

| Script | Purpose |
|---|---|
| `scripts/onchain_check.py` | Who controls the token and LP: owner/minter roles, proxies, LP owners and locks, Uniswap v4 hooks, honeypot simulation, holders. Builds the dossier. |
| `scripts/analyze.py` | Snapshot, multi-timeframe technicals, buy/sell flow, risk flags, scenario outlook. |
| `scripts/screener.py` | Trending / top-volume / new / boosted tokens per chain. |
| `scripts/picker.py` | Rates screened tokens for LP and for buying, with reasons. |
| `scripts/lp_fees.py` | Real on-chain LP fee (incl. v4 dynamic fees) and fee APR. |
| `scripts/lp_range.py` | Concentrated-liquidity range planner: fees, IL, time in range. |
| `scripts/contract_dossier.py` | Dossier for any list of contract addresses. |

## Quick start

```bash
git clone https://github.com/dvictor357/seer.git
cd seer

# who controls this token and its liquidity? (+ dossier in ~/.config/seer/dossiers)
python3 -I scripts/onchain_check.py "https://dexscreener.com/robinhood/<pair>"

# market read: flow, technicals, risk flags
python3 -I scripts/analyze.py "https://dexscreener.com/robinhood/<pair>"

# what's moving on a chain
python3 -I scripts/screener.py --chain robinhood
```

Every script takes `--help`. Most take `--json` for machine-readable output.

### Config

Seer keeps everything under `~/.config/seer` (set `SEER_HOME` to move it):

```
~/.config/seer/
├── config.json   # optional, see below
├── dossiers/     # contract dossiers
└── cache/        # resolved function signatures
```

`config.json` (every key is optional):

```json
{
  "rpc": {
    "base": "https://your-archive-rpc",
    "ethereum": ["https://primary-rpc", "https://fallback-rpc"]
  },
  "etherscan_api_key": "...",
  "log_budget": 400
}
```

- `rpc`: per-chain RPCs, tried before the built-in public ones.
- `etherscan_api_key`: optional, adds Etherscan to source verification lookups.
- `log_budget`: max log requests per on-chain check (default 400).

Environment variables override the file: `RPC_URL`, `ETHERSCAN_API_KEY`, `LOG_BUDGET`.
`--rpc` on the command line overrides both.

### RPC

Public RPCs are built in. Many free RPCs cap log ranges, so holder and LP history can be
partial; Seer says so in the report. For full coverage, set an archive RPC in
`config.json` or pass one per run:

```bash
python3 -I scripts/onchain_check.py "<url>" --rpc https://your-archive-rpc
```

### As an agent skill

Clone into your agent's skills directory, e.g. for Claude Code:

```bash
git clone https://github.com/dvictor357/seer.git ~/.claude/skills/seer
```

Then ask things like "is this a rug?", "who owns the LP?" or paste a DexScreener link.

## The dossier

`onchain_check.py` writes `~/.config/seer/dossiers/<chain>/<SYMBOL>-<token>/`:

- `index.md` – mermaid system map, contract table, suggested study order
- `contracts/<Name>-<addr>/` – `source/` or `interface.sol`, `abi.json`, `state.json`,
  `bytecode.hex`, `disassembly.txt`, and a `README.md` with privileged functions and live state

Related contracts (owners, factories, implementations, multisigs) are followed up to two hops.

## Data sources

Seer reads public data from chain RPCs, [DexScreener](https://dexscreener.com) and
[GeckoTerminal](https://www.geckoterminal.com) directly from your machine. You are
responsible for complying with those services' terms.

## Disclaimer

Seer is an analysis tool, not financial advice. Automated checks can miss novel tricks,
and a clean report is not a guarantee of safety. Microcaps can go to zero. Do your own
research.

## License

[Apache License 2.0](LICENSE). If you redistribute Seer or build on it, keep the
[`NOTICE`](NOTICE) file and its attribution.
