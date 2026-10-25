#!/usr/bin/env python3
"""On-chain safety checker for EVM DEX tokens. Answers "who can rug this?":

  - token contract: verified?, proxy?, owner / minter / other live roles,
    privileged functions (mint, blacklist, fee setters, pause, limits),
    remaining mintable supply
  - transfer simulation: can holders transfer and send into the pool?
  - LP ownership per position (burned / locker contract / EOA) with USD value,
    locker audit (does it expose any unlock/withdraw path?); v2, v3, v4
  - v4 hook: permissions, verification, owner, decoded fee config
  - holders rebuilt from Transfer logs: top holders, creator, snipers
  - contract dossier (default on): source or reconstructed interface, ABI,
    live state, disassembly and README for every contract in the system

RPC-first; no API key needed. Optional ETHERSCAN_API_KEY, RPC_URL.

Usage:
  onchain_check.py <dexscreener-url | chain pairAddress> [--json] [--rpc URL]
                   [--dossier DIR | --no-dossier] [--max-logs N]
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evm import (BURN, RPC, RPCS, ZERO, BudgetExceeded, RPCError, analyze_bytecode, call_addr,  # noqa: E402
                 call_str, call_uint, eip7702_target, enc_addr, enc_uint, probe_getters,
                 proxy_info, resolve, try_json, verification, w_addr, w_int, words)
from keccak import keccak256, selector, topic  # noqa: E402

GT_NET = {"ethereum": "eth", "polygon": "polygon_pos", "avalanche": "avax"}

T_TRANSFER = topic("Transfer(address,address,uint256)")
T_V4_INIT = topic("Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)")
T_V4_MODLIQ = topic("ModifyLiquidity(bytes32,address,int24,int24,int256,bytes32)")
T_V3_MINT = topic("Mint(address,address,int24,int24,uint128,uint256,uint256)")
T_V3_INCLIQ = topic("IncreaseLiquidity(uint256,uint128,uint256,uint256)")

V4_FLAGS = [
    (13, "beforeInitialize", ""), (12, "afterInitialize", ""),
    (11, "beforeAddLiquidity", "can block adding liquidity"), (10, "afterAddLiquidity", ""),
    (9, "beforeRemoveLiquidity", "can block LP withdrawals"), (8, "afterRemoveLiquidity", ""),
    (7, "beforeSwap", "can revert swaps (block sells) or change fee"), (6, "afterSwap", "runs on every swap"),
    (5, "beforeDonate", ""), (4, "afterDonate", ""),
    (3, "beforeSwapReturnDelta", "can take/alter swap amounts (tax)"),
    (2, "afterSwapReturnDelta", "can take a cut of swap output (tax)"),
    (1, "afterAddLiquidityReturnDelta", "can take from LP deposits"),
    (0, "afterRemoveLiquidityReturnDelta", "can take from LP withdrawals"),
]

RISK_WORDS = [
    (r"^mint\(|^mintTo\(|^issue\(", "HIGH", "can mint new supply"),
    (r"blacklist|blocklist|^setBots?\(|addBots?|^bots\(|isBot|antibot|setSniper", "HIGH",
     "can block addresses from transferring"),
    (r"^(set|update|change).*(fee|tax)", "HIGH", "fee/tax can be changed (sell tax up to 100% = honeypot)"),
    (r"^pause\(|^setPaused", "HIGH", "transfers can be paused"),
    (r"upgradeTo|setImplementation", "HIGH", "contract logic upgradeable"),
    (r"^(set|update|change)max(Tx|Transaction|Wallet|Sell|Buy)|removeLimits|setLimits", "MEDIUM",
     "transaction / wallet size limits can be changed"),
    (r"^max(Tx|Transaction|Wallet|Sell|Buy)", "INFO", "has transaction / wallet size limits"),
    (r"enableTrading|openTrading|setTrading|startTrading|^launch\(", "MEDIUM", "trading on/off switch"),
    (r"exclude.*fee|includeInFee|whitelist|setExempt", "MEDIUM", "selective fee/limit exemptions"),
    (r"^(set)?(router|pair|uniswapV2Pair|marketingWallet|devWallet|taxWallet)\(", "LOW",
     "privileged wallet / router redirection"),
    (r"rescue|^withdraw|clearStuck|recover", "LOW", "can pull tokens/ETH held by the contract"),
    (r"^burnFrom\(", "INFO", "standard allowance-based burn"),
]
ROLE_GETTER = re.compile(r"^(owner|getOwner|admin|minter|operator|governance|controller|manager|"
                         r"pendingOwner|taxWallet|feeRecipient|treasury)\(\)$", re.I)
LOCKER_EXIT = re.compile(r"withdraw|unlock|release|migrat|emergency|retrieve|recover|rescue|^transfer(?!Ownership)|"
                         r"safeTransfer|decreaseLiquidity|burn|execute|^call\(|multicall", re.I)
# v4 callbacks: only the PoolManager calls these, inside an unlock the contract itself started
LOCKER_CALLBACKS = re.compile(r"^(unlockCallback|lockAcquired|uniswapV3MintCallback|uniswapV3SwapCallback)\(", re.I)
LOCKER_FEES = re.compile(r"(collect|claim).*(fee|reward)|fee.*(collect|claim)|feeCollector", re.I)
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"]


def amounts_for(L, tl, tu, sqrt_p):
    sa, sb = 1.0001 ** (tl / 2), 1.0001 ** (tu / 2)
    if sqrt_p <= sa:
        return L * (sb - sa) / (sa * sb), 0.0
    if sqrt_p >= sb:
        return 0.0, L * (sb - sa)
    return L * (sb - sqrt_p) / (sqrt_p * sb), L * (sqrt_p - sa)


def state_map(state):
    """[{fn, arg, value}] -> {fn_name: python value} for zero-arg getters."""
    out = {}
    for s in state:
        if s["arg"] is not None:
            continue
        v = s["value"]
        if isinstance(v, dict) and len(v) == 1 and "tuple" not in v:
            out[s["fn"].split("(")[0]] = next(iter(v.values()))
    return out


class Checker:
    def __init__(self, chain, pair, rpc_url=None, max_logs=300_000):
        self.chain, self.pair = chain, pair.lower()
        urls = [rpc_url] if rpc_url else ([os.environ["RPC_URL"]] if os.environ.get("RPC_URL") else RPCS.get(chain))
        if not urls:
            raise SystemExit(f"error: no RPC known for chain '{chain}'. Pass --rpc <url> or set RPC_URL.")
        self.rpc_url = urls[0]
        self.rpc = RPC(urls)
        self.max_logs = max_logs
        self.findings = []
        self.r = {"chain": chain, "pair": self.pair}
        self.hook = self.pool_manager = None
        self.lp_owner_set = set()
        self.lp_nft_ids = []
        self.creator = None
        self.minter = None
        self.log_budget = int(os.environ.get("LOG_BUDGET", 400))
        self.history = "full"

    def flag(self, sev, area, msg):
        self.findings.append({"severity": sev, "area": area, "msg": msg})

    # ---------- context ----------
    def load_pair(self):
        ds = try_json(f"https://api.dexscreener.com/latest/dex/pairs/{self.chain}/{self.pair}")
        if not ds or not ds.get("pairs"):
            raise SystemExit(f"error: DexScreener has no pair {self.chain}/{self.pair}")
        d = self.ds = ds["pairs"][0]
        self.token = d["baseToken"]["address"].lower()
        self.quote = d["quoteToken"]["address"].lower()
        pu, pn = float(d.get("priceUsd") or 0), float(d.get("priceNative") or 0)
        self.quote_usd = pu / pn if pn else 0
        self.price_usd = pu
        self.chain_id = int(self.rpc.call("eth_chainId", []), 16)
        self.version = self.detect_version([x.lower() for x in d.get("labels", [])])
        self.head = int(self.rpc.call("eth_blockNumber", []), 16)
        self.created_ts = (d.get("pairCreatedAt") or 0) // 1000
        self.r.update({"token": self.token, "symbol": d["baseToken"]["symbol"], "dex": d.get("dexId"),
                       "version": self.version, "chain_id": self.chain_id, "head_block": self.head})
        b_now, b_old = self.rpc.block(self.head), self.rpc.block(max(self.head - 100_000, 1))
        dt = int(b_now["timestamp"], 16) - int(b_old["timestamp"], 16)
        self.bpd = int(86400 * min(100_000, self.head - 1) / max(dt, 1))
        self.pool_block = self.block_at(self.created_ts) if self.created_ts else self.head - 30 * self.bpd

    def detect_version(self, labels):
        """Trust the pool's own interface over DexScreener labels: forks and
        non-Uniswap AMMs are often unlabeled."""
        if len(self.pair) == 66:
            return "v4"
        r = self.rpc.calls_batch([(self.pair, selector("slot0()")), (self.pair, selector("getReserves()")),
                                  (self.pair, selector("token0()"))])
        if r[0] and len(r[0]) >= 130 and r[2]:
            return "v3"
        if r[1] and len(r[1]) >= 130 and r[2]:
            return "v2"
        self.flag("MEDIUM", "pool", f"pool {self.pair} is not a Uniswap v2/v3-style pair "
                  f"(DexScreener labels {labels or 'none'}); LP ownership not analyzed")
        return "unknown"

    def lp_unknown(self):
        self.r["lp"] = {"positions": [], "total_usd": 0, "share_by_kind": {}, "note": "unsupported AMM"}

    def block_at(self, ts):
        # interpolate from head, then binary search a narrow bracket
        now_ts = int(self.rpc.block(self.head)["timestamp"], 16)
        guess = self.head - int((now_ts - ts) * self.bpd / 86400)
        lo, hi = max(guess - self.bpd // 4, 1), min(guess + self.bpd // 4, self.head)
        if int(self.rpc.block(lo)["timestamp"], 16) > ts:
            lo = 1
        if int(self.rpc.block(hi)["timestamp"], 16) < ts:
            hi = self.head
        while lo < hi:
            mid = (lo + hi) // 2
            if int(self.rpc.block(mid)["timestamp"], 16) < ts:
                lo = mid + 1
            else:
                hi = mid
        return lo

    # ---------- token ----------
    def check_token(self):
        rpc, t = self.rpc, self.token
        code = rpc.code(t)
        tok = {"code_bytes": (len(code) - 2) // 2, "name": call_str(rpc, t, "name()"),
               "symbol": call_str(rpc, t, "symbol()"), "decimals": call_uint(rpc, t, "decimals()"),
               "total_supply_raw": call_uint(rpc, t, "totalSupply()")}
        self.decimals = tok["decimals"] if tok["decimals"] is not None else 18
        self.supply = (tok["total_supply_raw"] or 0) / 10 ** self.decimals
        tok["total_supply"] = self.supply

        px = proxy_info(rpc, t, code)
        tok["proxy"] = px
        bc = analyze_bytecode(code)
        disp = set(bc["dispatcher"])
        if px.get("implementation"):
            disp |= analyze_bytecode(rpc.code(px["implementation"]))["dispatcher"]
            if px.get("minimal_proxy"):
                self.flag("INFO", "token", f"EIP-1167 clone of {px['implementation']} (fixed code, not upgradeable; "
                          "same logic as every token from this launcher)")
            else:
                self.flag("HIGH", "token", f"upgradeable proxy -> implementation {px['implementation']}"
                          + (f", admin {px['admin']}" if px.get("admin") else "")
                          + (f", beacon {px['beacon']}" if px.get("beacon") else "")
                          + ": whoever controls it can replace all token rules")
        names, _ = resolve(disp)
        v = verification(self.chain, self.chain_id, t)
        if v["abi"]:
            for it in v["abi"]:
                if it.get("type") == "function":
                    sig = f"{it['name']}({','.join(i['type'] for i in it.get('inputs', []))})"
                    names[selector(sig)] = sig
        tok["functions"] = sorted(names.values())
        tok["unresolved_selectors"] = sorted(s for s in disp if s not in names)
        tok["verified"] = {k: v[k] for k in ("verified", "via", "name")}

        state = probe_getters(rpc, t, names, {"address": [t]})
        st = state_map(state)
        tok["state"] = state
        roles = {}
        for s in state:
            if s["arg"] is None and ROLE_GETTER.match(s["fn"]) and isinstance(s["value"], dict) \
                    and "address" in s["value"]:
                roles[s["fn"].split("(")[0]] = s["value"]["address"]
        for s in state:  # zero address decodes as uint 0
            if s["arg"] is None and ROLE_GETTER.match(s["fn"]) and s["fn"].split("(")[0] not in roles:
                roles[s["fn"].split("(")[0]] = ZERO
        live = {k: a for k, a in roles.items() if a not in BURN}
        tok["roles"] = roles
        for k, a in live.items():
            c = rpc.code(a)
            kind = ("EOA (7702-delegated)" if eip7702_target(c) else "contract") if len(c) > 2 else "EOA"
            tok.setdefault("role_kinds", {})[k] = kind
        if "minter" in live:
            self.minter = live["minter"]

        risky = []
        for n in names.values():
            for pat, sev, why in RISK_WORDS:
                if re.search(pat, n, re.I):
                    risky.append({"fn": n, "severity": sev, "why": why})
                    break
        tok["privileged_functions"] = risky
        gate = (", ".join(f"{k}={a} ({tok['role_kinds'].get(k)})" for k, a in live.items())
                if live else "no live owner/role found")
        grouped = {}
        for x in risky:
            if x["fn"].startswith("mint"):
                self.mint_risk(st, live, tok)
                continue
            sev = x["severity"] if live or x["severity"] == "INFO" else "LOW"
            grouped.setdefault((sev, x["why"]), []).append(x["fn"])
        for (sev, why), fns in grouped.items():
            self.flag(sev, "token", f"{why}: {', '.join(fns)} [{gate}]")
        if "hasRole(bytes32,address)" in names.values():
            self.flag("MEDIUM", "token", "AccessControl roles in use: role holders are not visible via getters; "
                      "check RoleGranted events")
        if not v["verified"]:
            self.flag("MEDIUM", "token", "source not verified; findings come from bytecode + signature DB"
                      + ("" if os.environ.get("ETHERSCAN_API_KEY") else " (set ETHERSCAN_API_KEY to also try Etherscan)"))
        if tok["unresolved_selectors"]:
            self.flag("LOW", "token", f"{len(tok['unresolved_selectors'])} unknown function selector(s): "
                      f"{', '.join(tok['unresolved_selectors'][:6])} — see dossier disassembly")
        if bc["has_delegatecall"] and not px:
            self.flag("MEDIUM", "token", "token bytecode contains DELEGATECALL")
        if bc["has_selfdestruct"]:
            self.flag("HIGH", "token", "token bytecode contains SELFDESTRUCT")
        self.r["token_contract"] = tok

    def mint_risk(self, st, live, tok):
        cap = next((st[k] for k in ("MAX_SUPPLY", "maxSupply", "cap", "MAX_TOTAL_SUPPLY") if k in st), None)
        open_ = next((st[k] for k in ("mintingOpen", "mintingEnabled", "canMint") if k in st), None)
        deadline = next((st[k] for k in ("mintDeadline", "mintingDeadline", "mintEnd") if k in st), None)
        info = {}
        if cap:
            cap_t = cap / 10 ** self.decimals
            info["max_supply"] = cap_t
            info["mintable_remaining"] = max(cap_t - self.supply, 0)
            info["dilution_pct"] = info["mintable_remaining"] / self.supply * 100 if self.supply else None
        if deadline:
            info["deadline"] = datetime.fromtimestamp(deadline, timezone.utc).isoformat(timespec="minutes")
        info["minting_open"] = open_
        tok["mint"] = info
        who = live.get("minter") or live.get("owner") or live.get("admin")
        if not who:
            self.flag("LOW", "token", "mint() exists but no live minter/owner found")
            return
        if open_ == 0 or (deadline and deadline < datetime.now(timezone.utc).timestamp()):
            self.flag("LOW", "token", f"mint() exists but minting closed (open={open_}, deadline {info.get('deadline')})")
            return
        msg = f"live minter {who} ({tok['role_kinds'].get('minter') or tok['role_kinds'].get('owner')}) can mint"
        if info.get("mintable_remaining") is not None:
            msg += (f" up to {info['mintable_remaining']:,.0f} more tokens "
                    f"(+{info['dilution_pct']:.0f}% of current supply, cap {info['max_supply']:,.0f})")
        else:
            msg += " with no visible cap"
        if info.get("deadline"):
            msg += f" until {info['deadline']}"
        self.flag("HIGH", "token", msg + ". Read the minter's rules in the dossier.")

    # ---------- holders ----------
    def find_start_block(self):
        mint_topic = [T_TRANSFER, "0x" + "0" * 64]
        earliest, empty, hi = None, 0, self.pool_block + self.bpd
        lo_limit = max(self.pool_block - 120 * self.bpd, 0)
        while hi > lo_limit and empty < 2:
            lo = max(hi - 7 * self.bpd, lo_limit)
            got, _ = self.rpc.logs(self.token, mint_topic, lo, hi, budget=self.log_budget)
            if got:
                earliest = min(int(x["blockNumber"], 16) for x in got)
                empty = 0
            elif earliest is not None:
                empty += 1
            elif hi < self.pool_block - 14 * self.bpd:
                break
            hi = lo - 1
        return earliest if earliest is not None else max(self.pool_block - self.bpd, 0)

    def holders(self):
        try:
            start = self.find_start_block()
            logs, truncated = self.rpc.logs(self.token, [T_TRANSFER], start, self.head, self.max_logs,
                                            budget=self.log_budget)
            self.history = "full"
        except BudgetExceeded as e:
            # RPC can't serve the whole history cheaply: use the recent window it can
            window = self.rpc.span_hint * max(self.log_budget // 2, 1)
            start = max(self.head - window, 0)
            try:
                logs, truncated = self.rpc.logs(self.token, [T_TRANSFER], start, self.head, self.max_logs,
                                                budget=self.log_budget)
            except (BudgetExceeded, RPCError):
                logs, truncated = [], True
            self.history = "recent"
            self.flag("LOW", "holders", f"RPC log history too costly (~{e.args[0]} requests at "
                      f"{self.rpc.span_hint}-block ranges): holders rebuilt from the last {self.head - start:,} "
                      "blocks only; top-holder list is partial. Pass --rpc <archive RPC> for a full scan")
        except RPCError as e:
            logs, truncated, start = [], True, self.head
            self.history = "none"
            self.flag("LOW", "holders", f"RPC cannot serve logs ({e}); holder analysis skipped. Pass --rpc <archive RPC>")
        logs.sort(key=lambda x: (int(x["blockNumber"], 16), int(x["logIndex"], 16)))
        bal, sc, to_self = {}, 10 ** self.decimals, 0
        for lg in logs:
            if len(lg["topics"]) < 3:
                continue
            fr, to = w_addr(lg["topics"][1][2:]), w_addr(lg["topics"][2][2:])
            v = w_int(words(lg["data"])[0]) / sc if lg["data"] != "0x" else 0
            bal[fr] = bal.get(fr, 0) - v
            bal[to] = bal.get(to, 0) + v
            to_self += to == self.token
        self.transfer_logs = logs
        if logs and self.history == "full":
            first = logs[0]
            tx = self.rpc.call("eth_getTransactionByHash", [first["transactionHash"]]) or {}
            sender = (tx.get("from") or "").lower() or None
            nonce = int(self.rpc.call("eth_getTransactionCount", [sender, "latest"]), 16) if sender else 0
            self.r["creation"] = {"block": int(first["blockNumber"], 16), "tx": first["transactionHash"],
                                  "tx_from": sender, "tx_from_nonce": nonce, "tx_to": tx.get("to"),
                                  "first_mint_to": w_addr(first["topics"][2][2:])}
            self.launch_sender = sender
            if nonce > 500 and tx.get("to"):
                self.r["creation"]["note"] = ("launch tx sent by a high-nonce wallet through a factory: "
                                              "likely launchpad operator/relayer, not the creator")
            elif not self.creator:
                self.creator = sender
        holders = {a: b for a, b in bal.items() if b > 1e-9 and a != ZERO}
        self.top_raw = sorted(holders.items(), key=lambda x: -x[1])[:25]
        self.r["holders"] = {"count": len(holders) if self.history == "full" else None,
                             "active_addresses_seen": len(holders), "transfers_scanned": len(logs),
                             "partial": truncated or self.history != "full", "history": self.history,
                             "from_block": start}
        gt = try_json(f"https://api.geckoterminal.com/api/v2/networks/{GT_NET.get(self.chain, self.chain)}"
                      f"/tokens/{self.token}/info")
        gh = (((gt or {}).get("data") or {}).get("attributes") or {}).get("holders") or {}
        if gh.get("count"):
            self.r["holders"]["geckoterminal"] = {"count": gh.get("count"),
                                                  "distribution_pct": gh.get("distribution_percentage")}
            if self.r["holders"]["count"] is None:
                self.r["holders"]["count"] = gh["count"]
        if truncated:
            self.flag("LOW", "holders", f"holder rebuild truncated at {len(logs)} transfers (raise --max-logs)")
        if logs and to_self / len(logs) > 0.05:
            self.flag("MEDIUM", "token", f"{to_self} transfers go to the token contract itself: tax-collection pattern")

    def balances(self, addrs):
        res = self.rpc.calls_batch([(self.token, selector("balanceOf(address)") + enc_addr(a)) for a in addrs])
        sc = 10 ** self.decimals
        return {a: (w_int(words(r)[0]) / sc if r and len(r) >= 66 else None) for a, r in zip(addrs, res)}

    def label(self, a, code):
        if a in BURN:
            return "burn"
        if a in (self.pair, self.pool_manager):
            return "pool / PoolManager (liquidity)"
        if a == self.hook:
            return "v4 hook"
        if a == self.token:
            return "token contract"
        if a == self.creator:
            return "creator"
        if a == self.minter:
            return "minter contract"
        if a in self.lp_owner_set:
            return "LP owner"
        d = eip7702_target(code)
        if d:
            return f"EOA (7702 → {d[:10]})"
        if len(code) > 2:
            n = call_str(self.rpc, a, "name()")
            return f"contract{(': ' + n) if n else ''}"
        return "EOA"

    def classify_holders(self):
        addrs = [a for a, _ in self.top_raw]
        live = self.balances(addrs)
        codes = self.rpc.codes(addrs)
        out = []
        for a, b in self.top_raw:
            b = live[a] if live.get(a) is not None else b
            out.append({"address": a, "pct": b / self.supply * 100 if self.supply else 0, "amount": b,
                        "label": self.label(a, codes[a])})
        out.sort(key=lambda x: -x["pct"])
        h = self.r["holders"]
        h["top"] = out[:20]
        if getattr(self, "curve", False):
            for x in out:  # launchpad contract holding the curve's unsold supply
                if x["pct"] > 30 and x["label"].startswith("contract") or x["address"] in (self.r["token_contract"].get("roles") or {}).values():
                    x["label"] = "bonding curve / launchpad (unsold supply)"
        ex = [x for x in out if not (x["label"].startswith(("pool", "bonding curve"))
                                     or x["label"] in ("burn", "token contract"))]
        h["top10_ex_pool_burn_pct"] = sum(x["pct"] for x in ex[:10])
        h["burned_pct"] = sum(x["pct"] for x in out if x["label"] == "burn")
        if self.history != "full":
            dist = (h.get("geckoterminal") or {}).get("distribution_pct") or {}
            h["top10_ex_pool_burn_pct"] = float(dist["top_10"]) if dist.get("top_10") else None
            h["top10_source"] = "GeckoTerminal (may include pool)" if dist.get("top_10") else "unavailable"
            h["top_note"] = "top list = wallets active in the scanned recent window only"
        t10 = h["top10_ex_pool_burn_pct"] or 0
        if t10 > 50:
            self.flag("HIGH", "holders", f"top-10 wallets (excl. pool/burn) hold {t10:.1f}%")
        elif t10 > 30:
            self.flag("MEDIUM", "holders", f"top-10 wallets (excl. pool/burn) hold {t10:.1f}%")
        for x in ex:
            if x["pct"] > 5 and x["label"].startswith("EOA"):
                self.flag("MEDIUM", "holders", f"single wallet {x['address']} holds {x['pct']:.1f}%")
        if self.creator:
            c = self.creator
            bal = self.balances([c])[c] or 0
            n, eth = self.rpc.batch([("eth_getTransactionCount", [c, "latest"]), ("eth_getBalance", [c, "latest"])])
            sent = sum(w_int(words(lg["data"])[0]) for lg in self.transfer_logs
                       if w_addr(lg["topics"][1][2:]) == c) / 10 ** self.decimals
            recv = sum(w_int(words(lg["data"])[0]) for lg in self.transfer_logs
                       if w_addr(lg["topics"][2][2:]) == c) / 10 ** self.decimals
            self.r["creator"] = {"address": c, "source": self.creator_source,
                                 "token_pct_now": bal / self.supply * 100 if self.supply else 0,
                                 "tokens_received": recv, "tokens_sent_out": sent,
                                 "nonce": int(n or "0x0", 16), "native_balance": int(eth or "0x0", 16) / 1e18}
            if self.supply and bal / self.supply > 0.05:
                self.flag("MEDIUM", "holders", f"creator holds {bal / self.supply * 100:.1f}%")

    def snipers(self, pool_addr):
        if self.history != "full":
            return
        buys = [lg for lg in self.transfer_logs if w_addr(lg["topics"][1][2:]) == pool_addr]
        if not buys:
            return
        b0 = int(buys[0]["blockNumber"], 16)
        win = max(int(self.bpd / 1440), 3)
        sc, early = 10 ** self.decimals, {}
        for lg in buys:
            if int(lg["blockNumber"], 16) > b0 + win:
                break
            to = w_addr(lg["topics"][2][2:])
            early[to] = early.get(to, 0) + w_int(words(lg["data"])[0]) / sc
        still = sum(v or 0 for v in self.balances(list(early)[:60]).values())
        s = {"window_blocks": win, "wallets": len(early),
             "bought_pct": sum(early.values()) / self.supply * 100 if self.supply else 0,
             "still_hold_pct": still / self.supply * 100 if self.supply else 0}
        self.r["snipers"] = s
        if s["still_hold_pct"] > 10:
            self.flag("MEDIUM", "holders", f"first-minute buyers still hold {s['still_hold_pct']:.1f}% of supply")

    def simulate(self, pool_addr):
        sc = 10 ** self.decimals
        cand = [h for h in self.r["holders"].get("top", []) if h["label"].startswith("EOA") and h["amount"] > 0][:3]
        res = []
        for h in cand:
            amt = int(h["amount"] * sc * 0.01) or 1
            for dest, name in (("0x000000000000000000000000000000000000beef", "to fresh wallet"),
                               (pool_addr, "to pool (sell path)")):
                r = self.rpc.eth_call(self.token, selector("transfer(address,uint256)") + enc_addr(dest)
                                      + enc_uint(amt), frm=h["address"])
                ok = r is not None and (r == "0x" or w_int(words(r)[0]) == 1)
                res.append({"from": h["address"], "dest": name, "ok": ok})
        self.r["transfer_sim"] = res
        bad = [x for x in res if not x["ok"]]
        if bad:
            self.flag("CRITICAL", "token", f"transfer simulation reverted {len(bad)}/{len(res)} "
                      f"(e.g. {bad[0]['dest']} from {bad[0]['from']}): possible honeypot/blacklist")

    # ---------- liquidity ----------
    def lp_v2(self):
        rpc, p = self.rpc, self.pair
        ts = call_uint(rpc, p, "totalSupply()")
        r = rpc.eth_call(p, selector("getReserves()"))
        t0 = call_addr(rpc, p, "token0()")
        if not ts or not r:
            self.flag("MEDIUM", "liquidity", "could not read v2 pair state")
            return
        w = words(r)
        quote_raw = w_int(w[1]) if t0 == self.token else w_int(w[0])
        tok_reserve = w_int(w[0]) if t0 == self.token else w_int(w[1])
        held = call_uint(rpc, self.token, "balanceOf(address)", enc_addr(p)) or 0
        if tok_reserve and held < tok_reserve * 0.5:
            self.curve = True
            self.flag("HIGH", "pool", f"pair reports reserves it does not hold (holds {held / tok_reserve:.0%} of the "
                      "reported token reserve): virtual-reserve bonding curve posing as a v2 pair. Trades settle in "
                      "the launchpad contract; there is no real LP to lock yet (pre-migration)")
            self.r["lp"] = {"positions": [], "total_usd": 0, "share_by_kind": {},
                            "note": "virtual reserves (bonding curve)"}
            return
        qdec = call_uint(rpc, self.quote, "decimals()") or 18
        pool_usd = 2 * quote_raw / 10 ** qdec * self.quote_usd
        logs, partial = self.windowed_logs(p, [T_TRANSFER])
        cands = set(BURN) | {p, self.token}
        for lg in logs:
            cands.add(w_addr(lg["topics"][1][2:]))
            cands.add(w_addr(lg["topics"][2][2:]))
        cands = sorted(cands)
        res = rpc.calls_batch([(p, selector("balanceOf(address)") + enc_addr(a)) for a in cands])
        pos = []
        for a, r in zip(cands, res):
            b = w_int(words(r)[0]) if r and len(r) >= 66 else 0
            if b <= 0 or (a == ZERO and b <= 1000) or b / ts < 0.001:
                continue
            pos.append({"owner": a, "share_pct": b / ts * 100, "usd": pool_usd * b / ts, "tag": "LP tokens"})
        found = sum(x["share_pct"] for x in pos)
        if partial and found < 99:
            self.flag("MEDIUM", "liquidity", f"only {found:.0f}% of LP tokens traced to holders (RPC log history "
                      "limited); unknown holders may be able to remove the rest. Pass --rpc <archive RPC>")
            self.r["lp_untraced_pct"] = 100 - found
        self._lp_verdict(pos, pool_usd)

    def windowed_logs(self, address, topics):
        """Logs from pool creation to head; if the RPC can't afford it, fall
        back to launch window + recent window. Returns (logs, partial)."""
        lo = self.pool_block - max(self.bpd // 24, 1)
        try:
            return self.rpc.logs(address, topics, lo, self.head, budget=self.log_budget)[0], False
        except BudgetExceeded:
            pass
        out = []
        span = self.rpc.span_hint
        for a, b in ((lo, min(self.pool_block + span * 20, self.head)),
                     (max(self.head - span * max(self.log_budget // 4, 1), lo), self.head)):
            try:
                out += self.rpc.logs(address, topics, a, b, budget=self.log_budget // 2)[0]
            except (BudgetExceeded, RPCError):
                pass
        return out, True

    def lp_v3(self):
        rpc, p = self.rpc, self.pair
        s0 = rpc.eth_call(p, selector("slot0()"))
        t0 = call_addr(rpc, p, "token0()")
        if not s0:
            self.flag("MEDIUM", "liquidity", "could not read v3 pool slot0")
            return
        sqrt_p = w_int(words(s0)[0]) / 2 ** 96
        logs, partial = self.windowed_logs(p, [T_V3_MINT])
        if partial:
            self.flag("MEDIUM", "liquidity", "v3 LP positions traced from launch + recent windows only (RPC log "
                      "history limited); older positions may be missing. Pass --rpc <archive RPC>")
        pos = []
        for npm in {w_addr(lg["topics"][1][2:]) for lg in logs}:
            if rpc.eth_call(npm, selector("positions(uint256)") + enc_uint(1)) is None:
                continue  # not an NFT position manager
            mint_txs = {lg["transactionHash"] for lg in logs if w_addr(lg["topics"][1][2:]) == npm}
            # IncreaseLiquidity sits in the same tx as the pool Mint: fetch receipts, not a block range
            inc = []
            for rc in rpc.batch([("eth_getTransactionReceipt", [h]) for h in sorted(mint_txs)]):
                inc += [lg for lg in (rc or {}).get("logs", [])
                        if lg["address"].lower() == npm and lg["topics"][0] == T_V3_INCLIQ]
            for tid in {w_int(lg["topics"][1][2:]) for lg in inc if lg["transactionHash"] in mint_txs}:
                r = rpc.eth_call(npm, selector("positions(uint256)") + enc_uint(tid))
                if not r:
                    continue
                w = words(r)
                tl, tu, L = w_int(w[5], True), w_int(w[6], True), w_int(w[7])
                if L:
                    self.lp_nft_ids.append(tid)
                    pos.append(self._pos(call_addr(rpc, npm, "ownerOf(uint256)", enc_uint(tid)) or npm,
                                         L, tl, tu, sqrt_p, t0 == self.token, f"NFT #{tid}", npm))
        self._lp_verdict(pos, sum(x["usd"] for x in pos))

    def lp_v4(self):
        rpc, pid = self.rpc, self.pair
        init = []
        for half in (self.bpd // 12, self.bpd, 30 * self.bpd):
            try:
                init, _ = rpc.logs(None, [T_V4_INIT, pid], self.pool_block - half,
                                   min(self.pool_block + half, self.head), budget=self.log_budget // 2)
            except BudgetExceeded:
                init = []
            if init:
                break
        if not init:
            self.flag("MEDIUM", "liquidity", "v4 Initialize event not found; cannot map LP owners")
            return
        ev = init[0]
        pm = self.pool_manager = ev["address"].lower()
        c0 = w_addr(ev["topics"][2][2:])
        w = words(ev["data"])
        fee, spacing, hooks = w_int(w[0]), w_int(w[1], True), w_addr(w[2])
        self.hook = hooks if hooks != ZERO else None
        v4 = {"pool_manager": pm, "currency0": c0, "currency1": w_addr(ev["topics"][3][2:]),
              "lp_fee_bps": fee / 100, "tick_spacing": spacing, "hooks": hooks, "init_tx": ev["transactionHash"],
              "init_block": int(ev["blockNumber"], 16)}
        if fee == 0x800000:
            v4["lp_fee_bps"] = "dynamic"
            self.flag("HIGH", "pool", "dynamic LP fee: the hook can change the swap fee at any time")
        self.r["v4_pool"] = v4
        if self.hook:
            self.check_hook(self.hook, pid)
        slot = "0x" + keccak256(bytes.fromhex(pid[2:] + enc_uint(6))).hex()  # StateLibrary POOLS_SLOT = 6
        s0 = rpc.eth_call(pm, selector("extsload(bytes32)") + slot[2:])
        sqrt_p = None
        if s0 and len(s0) >= 66:
            raw = w_int(words(s0)[0])
            sqrt_p = (raw & ((1 << 160) - 1)) / 2 ** 96
            tick = (raw >> 160) & 0xFFFFFF
            v4["tick"] = tick - (1 << 24) if tick >= 1 << 23 else tick
        try:
            logs, _ = rpc.logs(pm, [T_V4_MODLIQ, pid], v4["init_block"], self.head, budget=self.log_budget)
        except BudgetExceeded:
            logs, _ = self.windowed_logs(pm, [T_V4_MODLIQ, pid])
            self.flag("MEDIUM", "liquidity", "v4 positions traced from launch + recent windows only (RPC log "
                      "history limited). Pass --rpc <archive RPC>")
        agg, removed = {}, 0
        for lg in logs:
            d = words(lg["data"])
            tl, tu, dL = w_int(d[0], True), w_int(d[1], True), w_int(d[2], True)
            k = (w_addr(lg["topics"][2][2:]), tl, tu, d[3])
            agg[k] = agg.get(k, 0) + dL
            removed += dL < 0
        v4["liquidity_events"], v4["removals"] = len(logs), removed
        live = [(k, L) for k, L in agg.items() if L > 0]
        owners = rpc.calls_batch([(k[0], selector("ownerOf(uint256)") + k[3]) for k, _ in live])
        pos = []
        for ((sender, tl, tu, salt), L), o in zip(live, owners):
            tid = int(salt, 16)
            if o and len(o) >= 66 and tid:
                owner, tag = w_addr(words(o)[0]), f"PositionManager NFT #{tid}"
                self.position_manager = sender
                self.lp_nft_ids.append(tid)
            else:
                owner, tag = sender, "held directly by contract"
            pos.append(self._pos(owner, L, tl, tu, sqrt_p, c0 == self.token, tag, sender))
        self._lp_verdict(pos, sum(x["usd"] for x in pos))

    def _pos(self, owner, L, tl, tu, sqrt_p, token_is0, tag, via):
        qdec = 18 if self.quote == ZERO else (call_uint(self.rpc, self.quote, "decimals()") or 18)
        a0 = a1 = 0.0
        in_range = None
        if sqrt_p:
            a0, a1 = amounts_for(L, tl, tu, sqrt_p)
            in_range = 1.0001 ** (tl / 2) < sqrt_p < 1.0001 ** (tu / 2)
        tok_raw, q_raw = (a0, a1) if token_is0 else (a1, a0)
        return {"owner": owner.lower(), "tag": tag, "via": via, "ticks": [tl, tu], "liquidity": L,
                "in_range": in_range, "token_amount": tok_raw / 10 ** self.decimals,
                "quote_amount": q_raw / 10 ** qdec,
                "usd": tok_raw / 10 ** self.decimals * self.price_usd + q_raw / 10 ** qdec * self.quote_usd}

    def owner_kind(self, a):
        if a in BURN:
            return "burned"
        if a == self.hook:
            return "hook-held"
        code = self.rpc.code(a)
        if eip7702_target(code):
            return "EOA (7702-delegated)"
        if len(code) <= 2:
            return "EOA"
        v = verification(self.chain, self.chain_id, a)
        n = v["name"] or call_str(self.rpc, a, "name()")
        return f"contract{(' ' + n) if n else ''} ({'verified' if v['verified'] else 'unverified'})"

    def audit_locker(self, a):
        """Does the LP-holding contract expose any exit path?"""
        code = self.rpc.code(a)
        bc = analyze_bytecode(code)
        names, _ = resolve(bc["dispatcher"])
        v = verification(self.chain, self.chain_id, a)
        exits = sorted(n for n in names.values() if LOCKER_EXIT.search(n) and not LOCKER_FEES.search(n)
                       and not LOCKER_CALLBACKS.search(n)
                       and not n.startswith("onERC721"))
        fee_fns = sorted(n for n in names.values() if LOCKER_FEES.search(n))
        unknown = sorted(s for s in bc["dispatcher"] if s not in names)
        state = probe_getters(self.rpc, a, names, {"address": [self.token, self.pool_manager or self.pair],
                                                   "uint256": self.lp_nft_ids[:3]})
        owner = state_map(state).get("owner")
        if fee_fns:
            self.flag("INFO", "liquidity", f"LP holder {a} can collect trading fees ({', '.join(fee_fns)}); "
                      "fee collection does not remove the locked liquidity")
        out = {"address": a, "verified": v["verified"], "name": v["name"], "exit_functions": exits,
               "fee_functions": fee_fns,
               "unknown_selectors": unknown, "owner": owner, "delegatecall": bc["has_delegatecall"],
               "state": [s for s in state if s["arg"] is not None]}
        if exits:
            self.flag("HIGH", "liquidity", f"LP holder {a} exposes possible exit path(s): {', '.join(exits)} "
                      f"(owner {owner}). Read the conditions in its source/disassembly.")
        elif unknown:
            self.flag("MEDIUM", "liquidity", f"LP holder {a}: no unlock/withdraw among known functions, but "
                      f"{len(unknown)} unknown selector(s) {', '.join(unknown)} — could hide an exit")
        else:
            self.flag("OK", "liquidity", f"LP holder {a}: no function that can move the position out")
        if bc["has_delegatecall"]:
            self.flag("MEDIUM", "liquidity", f"LP holder {a} contains DELEGATECALL (could run arbitrary code)")
        return out

    def _lp_verdict(self, pos, total_usd):
        pos.sort(key=lambda x: -x["usd"])
        for p in pos:
            p["share_pct"] = p.get("share_pct") or (p["usd"] / total_usd * 100 if total_usd else 0)
            p["kind"] = self.owner_kind(p["owner"])
        self.lp_owner_set = {p["owner"] for p in pos}
        lp = self.r["lp"] = {"positions": pos[:15], "total_usd": total_usd}
        by = {}
        for p in pos:
            k = "burned" if p["kind"] == "burned" else "EOA" if p["kind"].startswith("EOA") else "contract"
            by[k] = by.get(k, 0) + p["share_pct"]
        lp["share_by_kind"] = by
        if not pos:
            self.flag("MEDIUM", "liquidity", "no live LP positions found")
        eoa = by.get("EOA", 0)
        # rug risk depends on how concentrated the EOA liquidity is, not on its total share:
        # an open pool with many independent LPs is normal (they can leave, but not all at once)
        per_owner = {}
        for p in pos:
            if p["kind"].startswith("EOA"):
                per_owner[p["owner"]] = per_owner.get(p["owner"], 0) + p["share_pct"]
        top = max(per_owner.values(), default=0)
        top3 = sum(sorted(per_owner.values(), reverse=True)[:3])
        lp["eoa_owners"], lp["top_eoa_pct"], lp["top3_eoa_pct"] = len(per_owner), top, top3
        if top > 50:
            self.flag("CRITICAL", "liquidity", f"one EOA owns {top:.0f}% of LP value: can be pulled at any time")
        elif top > 25 or top3 > 60:
            self.flag("HIGH", "liquidity", f"LP concentrated in few EOAs (top {top:.0f}%, top-3 {top3:.0f}%): "
                                           "a couple of wallets can drain most liquidity")
        elif eoa > 50:
            self.flag("MEDIUM", "liquidity", f"{eoa:.0f}% of LP value in {len(per_owner)} independent EOA positions "
                                             f"(largest {top:.0f}%): open community pool, nothing locked, depth "
                                             "can thin out if LPs leave")
        elif eoa > 10:
            self.flag("LOW", "liquidity", f"{eoa:.0f}% of LP value owned by EOAs (removable)")
        if by.get("burned", 0) > 90:
            self.flag("OK", "liquidity", f"{by['burned']:.0f}% of LP burned")
        if self.creator and self.creator in self.lp_owner_set:
            self.flag("HIGH", "liquidity", "creator wallet directly owns LP")
        lockers = {}
        for p in pos:
            if p["kind"].startswith("contract") and p["share_pct"] > 5:
                lockers[p["owner"]] = lockers.get(p["owner"], 0) + p["share_pct"]
        lp["locker_audits"] = [dict(self.audit_locker(a), share_pct=s) for a, s in lockers.items()]

    # ---------- v4 hook ----------
    def check_hook(self, h, pid):
        rpc = self.rpc
        bits = int(h[-4:], 16) & 0x3FFF
        perms = [(n, note) for b, n, note in V4_FLAGS if bits & (1 << b)]
        v = verification(self.chain, self.chain_id, h)
        info = {"address": h, "permissions": [n for n, _ in perms], "code_bytes": (len(rpc.code(h)) - 2) // 2,
                "owner": call_addr(rpc, h, "owner()"),
                "verified": {k: v[k] for k in ("verified", "via", "name")}}
        if info["owner"]:
            info["owner_kind"] = "contract" if len(rpc.code(info["owner"])) > 2 else "EOA"
        px = proxy_info(rpc, h, rpc.code(h))
        if px:
            info["proxy"] = px
            self.flag("HIGH", "hook", f"hook is upgradeable ({px}); swap rules can change")
        for n, note in perms:
            if not note:
                continue
            sev = "HIGH" if n in ("beforeSwap", "beforeRemoveLiquidity", "beforeSwapReturnDelta") else "MEDIUM"
            if n == "afterSwap":
                sev = "INFO"
            if v["verified"]:
                sev = "MEDIUM" if sev == "HIGH" else "INFO"
            self.flag(sev, "hook", f"{n}: {note}")
        if not v["verified"]:
            self.flag("HIGH", "hook", "hook contract is unverified: its swap logic cannot be reviewed")
        adapter = HOOK_ADAPTERS.get(v["name"] or "")
        if adapter:
            info["config"] = adapter(rpc, h, pid, self)
        self.r["hook"] = info

    # ---------- run ----------
    def run(self):
        self.creator_source = None
        self.load_pair()
        self.check_token()
        pool_addr = self.pair
        try:
            getattr(self, f"lp_{self.version}")()
        except RPCError as e:
            self.flag("MEDIUM", "liquidity", f"LP analysis failed: {e}")
        if self.version == "v4" and self.pool_manager:
            pool_addr = self.pool_manager
        if self.creator:
            self.creator_source = "launchpad registry"
        self.holders()
        if self.creator and not self.creator_source:
            self.creator_source = "first mint tx sender"
        self.classify_holders()
        self.snipers(pool_addr)
        self.simulate(pool_addr)
        self.r["findings"] = sorted(self.findings, key=lambda f: SEV_ORDER.index(f["severity"]))
        self.r["verdict"] = verdict(self.findings)
        self.r["generated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return self.r

    def dossier(self, out):
        from contract_dossier import Dossier
        d = Dossier(self.rpc, self.chain, self.chain_id, out, self.rpc_url,
                    {"address": [self.token, self.pool_manager or self.pair],
                     "uint256": self.lp_nft_ids[:3],
                     "bytes32": [self.pair] if self.version == "v4" else [],
                     "title": f"{self.r.get('symbol')} ({self.token}) on {self.chain}"})
        d.add(self.token, "token")
        if self.version != "v4":
            d.add(self.pair, "pool")
        for k, a in (self.r["token_contract"].get("roles") or {}).items():
            if a not in BURN:
                d.add(a, f"token {k}()")
                d.edge(a, self.token, f"{k}")
        if self.hook:
            d.add(self.hook, "v4 hook")
            d.edge(self.pool_manager, self.hook, "calls on swap")
        if self.pool_manager:
            d.add(self.pool_manager, "v4 PoolManager (holds pool funds)")
            d.edge(self.pool_manager, self.token, "holds pool reserves")
        if getattr(self, "position_manager", None):
            d.add(self.position_manager, "LP PositionManager (NFTs)")
        for p in (self.r.get("lp") or {}).get("positions", [])[:4]:
            if p["owner"] not in BURN:
                d.add(p["owner"], f"LP owner {p['share_pct']:.1f}%")
                d.edge(p["owner"], p.get("via") or self.pair, f"owns LP {p['share_pct']:.1f}%")
        if self.creator:
            d.add(self.creator, "creator")
        cr = self.r.get("creation") or {}
        if cr.get("tx_to"):
            d.add(cr["tx_to"], "launch factory (created token)")
            d.edge(cr["tx_to"], self.token, "deployed")
        d.build()
        self.r["dossier"] = os.path.join(out, "index.md")
        return d


def _pons_v2(rpc, h, pid, chk):
    r = rpc.eth_call(h, selector("launches(bytes32)") + pid[2:])
    if not r:
        return None
    w = words(r)
    cfg = {"launchpad": "Pons V2", "registered": bool(w_int(w[0])), "memecoin": w_addr(w[2]),
           "creator": w_addr(w[4]), "buyback_creator_recipient": w_addr(w[5]), "creator_tax_bps": w_int(w[7]),
           "protocol_fee_share_bps": w_int(w[8]), "buyback_burn_bps": w_int(w[9]), "hook_fee_bps": w_int(w[10]),
           "buyback_enabled": bool(w_int(w[12])),
           "note": "fees frozen per pool at registration (hook owner cannot raise them for this pool); "
                   "no beforeSwap permission, so the hook cannot block sells"}
    chk.creator = cfg["creator"]
    total = cfg["creator_tax_bps"] + cfg["hook_fee_bps"]
    chk.flag("INFO", "hook", f"Pons V2 hook takes {total / 100:.2f}% per swap (hook fee {cfg['hook_fee_bps']} bps"
             f" + creator tax {cfg['creator_tax_bps']} bps), on top of the LP fee")
    if total >= 500:
        chk.flag("HIGH", "hook", f"swap tax {total / 100:.1f}%")
    return cfg


HOOK_ADAPTERS = {"PonsV2MemeHook": _pons_v2}


def verdict(findings):
    c = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    if c["CRITICAL"]:
        v = "DANGER"
    elif c["HIGH"] >= 2:
        v = "HIGH RISK"
    elif c["HIGH"] or c["MEDIUM"] >= 3:
        v = "CAUTION"
    else:
        v = "NO MAJOR CONTRACT RED FLAGS"
    return {"label": v, "counts": {k: n for k, n in c.items() if n}}


def report(r):
    usd = lambda x: f"${x:,.0f}"
    L = [f"# On-chain check: {r.get('symbol')} on {r['chain']} ({r.get('dex')} {r.get('version')})",
         f"token {r['token']} | pair {r['pair']} | chain id {r['chain_id']} | {r['generated']}", "",
         f"## Verdict: {r['verdict']['label']}  {r['verdict']['counts']}", ""]
    L += [f"- [{f['severity']}] {f['area']}: {f['msg']}" for f in r["findings"]]
    t = r["token_contract"]
    L += ["", "## Token contract",
          f"name {t['name']} | supply {t['total_supply']:,.0f} | decimals {t['decimals']} | bytecode {t['code_bytes']} B"
          f" | verified {t['verified']['verified']} ({t['verified']['via'] or '-'})",
          f"roles: {t.get('roles') or 'none'} {t.get('role_kinds') or ''}",
          f"proxy: {t['proxy'] or 'no'}"]
    if t.get("mint"):
        L.append(f"mint: {t['mint']}")
    L.append(f"functions: {', '.join(t['functions'])}")
    if r.get("transfer_sim"):
        ok = sum(x["ok"] for x in r["transfer_sim"])
        L.append(f"transfer simulation: {ok}/{len(r['transfer_sim'])} succeeded (incl. transfers into the pool)")
    if r.get("v4_pool"):
        v = r["v4_pool"]
        L += ["", "## Uniswap v4 pool",
              f"PoolManager {v['pool_manager']} | LP fee {v['lp_fee_bps']} bps | tickSpacing {v['tick_spacing']} | "
              f"tick {v.get('tick')} | liquidity events {v.get('liquidity_events')} (removals {v.get('removals')})"]
    if r.get("hook"):
        h = r["hook"]
        L.append(f"hook {h['address']}: {h['verified']['name'] or 'unknown'} | verified {h['verified']['verified']} | "
                 f"owner {h['owner']} ({h.get('owner_kind')}) | permissions {', '.join(h['permissions'])}")
        if h.get("config"):
            L.append(f"hook config: {h['config']}")
    lp = r.get("lp")
    if lp:
        L += ["", f"## Liquidity owners (~{usd(lp['total_usd'])})",
              f"share by kind: { {k: round(x, 1) for k, x in lp['share_by_kind'].items()} }"]
        for p in lp["positions"][:8]:
            rng = "" if p.get("in_range") is None else (" in-range" if p["in_range"] else " OUT of range")
            L.append(f"- {p['owner']} [{p['kind']}] {p['tag']} {p['share_pct']:.1f}% ~{usd(p['usd'])}{rng}" + (f" ticks {p['ticks']}" if p.get("ticks") else ""))
        for a in lp.get("locker_audits", []):
            L.append(f"  locker audit {a['address']}: exits {a['exit_functions'] or 'none'} | unknown selectors "
                     f"{a['unknown_selectors'] or 'none'} | owner {a['owner']} | per-token state {[(s['fn'], s['value']) for s in a['state']][:4]}")
    h = r.get("holders", {})
    L += ["", f"## Holders (rebuilt from {h.get('transfers_scanned')} transfers{', PARTIAL' if h.get('partial') else ''})",
          f"holders {h.get('count')} | top-10 excl. pool/burn "
          f"{'n/a' if h.get('top10_ex_pool_burn_pct') is None else format(h['top10_ex_pool_burn_pct'], '.1f') + '%'}"
          f"{' (' + h['top10_source'] + ')' if h.get('top10_source') else ''} | burned {h.get('burned_pct', 0):.1f}%"
          + (f"\n_{h['top_note']}_" if h.get("top_note") else "")]
    L += [f"- {x['address']} {x['pct']:.2f}% [{x['label']}]" for x in h.get("top", [])[:12]]
    if r.get("creator"):
        c = r["creator"]
        L += ["", "## Creator",
              f"{c['address']} (from {c['source']}) | holds {c['token_pct_now']:.2f}% | received {c['tokens_received']:,.0f}"
              f" / sent {c['tokens_sent_out']:,.0f} tokens | nonce {c['nonce']} | native {c['native_balance']:.4f}"]
    if r.get("creation"):
        cr = r["creation"]
        L.append(f"first mint block {cr['block']} tx {cr['tx']} via {cr['tx_to']} (sender {cr['tx_from']}, nonce "
                 f"{cr['tx_from_nonce']}){' — ' + cr['note'] if cr.get('note') else ''}")
    if r.get("snipers"):
        s = r["snipers"]
        L += ["", f"## Launch snipers: {s['wallets']} wallets bought {s['bought_pct']:.1f}% in first "
              f"{s['window_blocks']} blocks; still hold {s['still_hold_pct']:.1f}%"]
    if r.get("dossier"):
        L += ["", f"## Contract dossier: {r['dossier']}"]
    L += ["", f"_{r.get('rpc_calls')} RPC requests. Automated checks can miss novel tricks; read the dossier for anything flagged._"]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--rpc")
    ap.add_argument("--max-logs", type=int, default=300_000)
    ap.add_argument("--dossier", help="dossier output dir (default ~/seer-dossiers/<chain>/<SYMBOL>-<token>)")
    ap.add_argument("--no-dossier", action="store_true")
    a = ap.parse_args()
    if len(a.target) == 1:
        m = re.search(r"dexscreener\.com/([^/]+)/([0-9A-Za-z]+)", a.target[0])
        if not m:
            raise SystemExit("error: expected dexscreener URL or '<chain> <pairAddress>'")
        chain, pair = m.group(1), m.group(2)
    else:
        chain, pair = a.target[0], a.target[1]
    if chain == "solana" or not pair.startswith("0x"):
        raise SystemExit("error: on-chain checker supports EVM chains only")
    c = Checker(chain, pair, a.rpc, a.max_logs)
    r = c.run()
    if not a.no_dossier:
        out = a.dossier or os.path.join(os.path.expanduser("~/seer-dossiers"), chain,
                                        f"{re.sub(r'[^A-Za-z0-9]', '', r.get('symbol') or 'token')}-{c.token}")
        try:
            c.dossier(out)
        except Exception as e:  # dossier is a bonus; never lose the safety report
            r["dossier_error"] = str(e)
            sys.stderr.write(f"warn: dossier failed: {e}\n")
    r["rpc_calls"] = c.rpc.calls
    print(json.dumps(r, indent=2, default=str) if a.json else report(r))


if __name__ == "__main__":
    main()
