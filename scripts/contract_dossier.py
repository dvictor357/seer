#!/usr/bin/env python3
"""Contract dossier builder: for each contract in a token's system, write a
study folder with source (verified) or a reconstructed interface/ABI
(unverified), live getter state, bytecode + disassembly, events, errors,
outbound calls, and a README with cast commands. Plus an index.md system map.

Standalone usage:
  contract_dossier.py <chain> <address> [<address> ...] [--out DIR] [--rpc URL]
Normally called by onchain_check.py --dossier.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evm import (BURN, DOSSIERS, EXPLORER, RPC, RPCS, analyze_bytecode, disassemble,  # noqa: E402
                 eip7702_target, probe_getters, proxy_info, resolve, save_sources, verification)

RISKY_NAME = re.compile(r"mint|blacklist|bot|fee|tax|pause|upgrade|withdraw|rescue|sweep|recover|emergency|"
                        r"setOwner|transferOwnership|setFactory|migrat|unlock|release|sellTranche|"
                        r"setRouter|exclude|whitelist|limit|trading", re.I)

DEFAULT_OUT = DOSSIERS

# Well-known infrastructure: documented, kept as leaves (not expanded further).
INFRA = {"PoolManager", "PositionManager", "NonfungiblePositionManager", "UniswapV3Factory", "UniswapV2Factory",
         "UniswapV2Router02", "SwapRouter", "UniversalRouter", "aeWETH", "WETH9", "WETH", "PositionDescriptor",
         "NonfungibleTokenPositionDescriptor", "V4FeeAdapter", "TokenJar", "GnosisSafeProxy", "SafeProxy",
         "Permit2", "StateView", "Quoter", "V4Quoter", "TransparentUpgradeableProxy", "ProxyAdmin", "CaliburEntry"}


def split_args(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "," and depth == 0:
            out.append(cur); cur = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        cur += ch
    if cur:
        out.append(cur)
    return out


def sig_to_abi(sig, kind="function", mutability="nonpayable"):
    name = sig.split("(")[0]
    args = split_args(sig[len(name) + 1:-1])
    item = {"type": kind, "name": name,
            "inputs": [{"name": f"arg{i}", "type": t} for i, t in enumerate(args)]}
    if kind == "function":
        item["outputs"] = []
        item["stateMutability"] = mutability
    if kind == "event":
        item["anonymous"] = False
        for x in item["inputs"]:
            x["indexed"] = False  # unknown from bytecode
    return item


def value_str(v):
    if not isinstance(v, dict):
        return str(v)
    if "tuple" in v:
        return "(" + ", ".join(value_str(x) for x in v["tuple"]) + ")"
    k, val = next(iter(v.items()))
    return f"{val}" if k in ("address", "string", "uint", "int") else f"{val} ({k})"


def safe_dir_name(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:60]


class Dossier:
    def __init__(self, rpc, chain, chain_id, out_root, rpc_url, ctx=None):
        self.rpc, self.chain, self.chain_id = rpc, chain, chain_id
        self.out, self.rpc_url = out_root, rpc_url
        self.ctx = ctx or {}
        self.entries = {}   # addr -> summary
        self.roles = {}     # addr -> [role]
        self.edges = []     # (from, to, label)
        self.depth = {}     # addr -> discovery depth (0 = given)

    MAX_DEPTH, MAX_CONTRACTS = 2, 30

    def add(self, addr, role, depth=0):
        if not addr:
            return
        a = addr.lower()
        if a not in self.roles:
            if depth > self.MAX_DEPTH or len(self.roles) >= self.MAX_CONTRACTS:
                return
            self.depth[a] = depth
        self.roles.setdefault(a, [])
        if role not in self.roles[a]:
            self.roles[a].append(role)

    def edge(self, a, b, label):
        if a and b:
            self.edges.append((a.lower(), b.lower(), label))

    def build(self):
        os.makedirs(self.out, exist_ok=True)
        done = set()
        while True:  # analyzing may discover more (impl, 7702 target, owners)
            todo = [a for a in self.roles if a not in done]
            if not todo:
                break
            self.rpc.codes(todo)
            for a in todo:
                done.add(a)
                try:
                    self.entries[a] = self.one(a)
                except Exception as e:  # keep going; record failure
                    self.entries[a] = {"address": a, "error": str(e), "roles": self.roles[a]}
        self.index()
        return self.entries

    def one(self, a):
        rpc = self.rpc
        code = rpc.code(a)
        roles = self.roles[a]
        e = {"address": a, "roles": roles, "code_bytes": max((len(code) - 2) // 2, 0)}
        if a in BURN:
            e["kind"] = "burn address"
            return e
        d7702 = eip7702_target(code)
        if e["code_bytes"] == 0 or d7702:
            e["kind"] = "EOA" + (f" (EIP-7702 delegated to {d7702})" if d7702 else "")
            bal, nonce = rpc.batch([("eth_getBalance", [a, "latest"]), ("eth_getTransactionCount", [a, "latest"])])
            e["native_balance"] = int(bal or "0x0", 16) / 1e18
            e["nonce"] = int(nonce or "0x0", 16)
            if d7702:
                self.add(d7702, f"7702 delegate code for {a[:10]}", self.depth[a] + 1)
                self.edge(a, d7702, "7702 delegate")
            self.write_eoa(e)
            return e
        e["kind"] = "contract"
        px = proxy_info(rpc, a, code)
        if px:
            e["proxy"] = px
            if px.get("implementation"):
                self.add(px["implementation"], f"implementation of {a[:10]}", self.depth[a])
                self.edge(a, px["implementation"], "delegates to (proxy)")
            if px.get("admin"):
                self.add(px["admin"], f"proxy admin of {a[:10]}", self.depth[a] + 1)
                self.edge(px["admin"], a, "can upgrade")
        v = verification(self.chain, self.chain_id, a)
        bc = analyze_bytecode(code)
        fn, ev = resolve(bc["dispatcher"] | bc["outbound_or_errors"], bc["push32"])
        e.update(verified=v["verified"], via=v["via"], name=v["name"], compiler=v["compiler"],
                 delegatecall=bc["has_delegatecall"], selfdestruct=bc["has_selfdestruct"])
        disp = {s: fn.get(s) for s in sorted(bc["dispatcher"])}
        outb = {s: fn.get(s) for s in sorted(bc["outbound_or_errors"])}
        errors = sorted(n for n in outb.values() if n and n[:1].isupper())
        calls_out = sorted(n for n in outb.values() if n and not n[:1].isupper())
        unknown_out = sorted(s for s, n in outb.items() if not n)
        events = sorted(set(ev.values()))
        # prefer verified ABI for function list
        abi = v["abi"]
        if abi:
            from keccak import selector as _sel
            views = {}
            for it in abi:
                if it.get("type") == "function":
                    sig = f"{it['name']}({','.join(i['type'] for i in it.get('inputs', []))})"
                    disp[_sel(sig)] = sig
                    if it.get("stateMutability") in ("view", "pure"):
                        views[_sel(sig)] = sig
            getters = views
        else:
            getters = {s: n for s, n in disp.items() if n}
        state = probe_getters(rpc, a, getters, self.ctx)
        e["infra"] = (v["name"] or "") in INFRA and self.depth.get(a, 0) > 0
        # discover related addresses from state (owners, minters, factories...)
        for st in ([] if e["infra"] else state):
            val = st["value"]
            if isinstance(val, dict) and "address" in val and st["arg"] is None:
                tgt = val["address"]
                if tgt not in BURN and tgt != a:
                    fname = st["fn"].split("(")[0]
                    if re.search(r"owner|admin|minter|factory|operator|governance|controller|manager|"
                                 r"escrow|vault|recipient|locker|hook|router|pool|token|initializer|treasury",
                                 fname, re.I):
                        self.add(tgt, f"{fname}() of {a[:10]}", self.depth[a] + 1)
                        self.edge(a, tgt, f"{fname}()")
        e.update(functions=[n or s for s, n in disp.items()], unresolved=[s for s, n in disp.items() if not n],
                 events=events, errors=errors, calls_out=calls_out, unknown_outbound=unknown_out,
                 state=state, risky=[n for n in disp.values() if n and RISKY_NAME.search(n)])
        self.write_contract(e, code, v, disp, abi)
        return e

    # ---------- writers ----------
    def folder(self, e):
        label = e.get("name") or (e["roles"][0] if e["roles"] else "contract")
        p = os.path.join(self.out, "contracts", f"{safe_dir_name(label)}-{e['address'][:10]}")
        os.makedirs(p, exist_ok=True)
        e["dir"] = p
        return p

    def cast(self, a, sig_ret):
        return f'cast call {a} "{sig_ret}" --rpc-url {self.rpc_url}'

    def write_eoa(self, e):
        p = self.folder(e)
        L = [f"# {e['kind']} {e['address']}", "", f"Roles: {', '.join(e['roles'])}",
             f"Explorer: {EXPLORER.get(self.chain, '')}{e['address']}",
             f"Native balance: {e['native_balance']:.6f} | nonce (txs sent): {e['nonce']}", "",
             "An EOA is a single private key: whatever privileges it holds can be used at any time,"
             " with no timelock or multisig.",
             "", "```bash", f"cast balance {e['address']} --rpc-url {self.rpc_url}",
             f"cast nonce {e['address']} --rpc-url {self.rpc_url}", "```"]
        with open(os.path.join(p, "README.md"), "w") as fh:
            fh.write("\n".join(L) + "\n")

    def write_contract(self, e, code, v, disp, abi):
        p = self.folder(e)
        a = e["address"]
        with open(os.path.join(p, "bytecode.hex"), "w") as fh:
            fh.write(code + "\n")
        with open(os.path.join(p, "disassembly.txt"), "w") as fh:
            for pc, op, arg in disassemble(code):
                fh.write(f"{pc:05x}  {op}{(' 0x' + arg) if arg else ''}\n")
        if v["sources"]:
            save_sources(os.path.join(p, "source"), v["sources"])
        if not abi:
            abi = [sig_to_abi(n) for n in disp.values() if n]
            abi += [sig_to_abi(x, "event") for x in e["events"]]
            abi += [sig_to_abi(x, "error") for x in e["errors"]]
            abi_note = "reconstructed from bytecode selectors (names/arg types from signature DB; outputs & mutability unknown)"
        else:
            abi_note = f"verified ABI ({v['via']})"
        with open(os.path.join(p, "abi.json"), "w") as fh:
            json.dump(abi, fh, indent=2)
        with open(os.path.join(p, "state.json"), "w") as fh:
            json.dump(e["state"], fh, indent=2, default=str)
        iname = "I" + safe_dir_name(e.get("name") or "Unknown").replace("-", "_").replace(".", "_")
        I = [f"// SPDX-License-Identifier: UNLICENSED",
             f"// Interface for {a} on {self.chain} ({'verified: ' + str(e['name']) if e['verified'] else 'UNVERIFIED, reconstructed'}).",
             "// Generated by Seer. Mutability/returns are unknown for reconstructed entries.",
             "pragma solidity ^0.8.0;", "", f"interface {iname} {{"]
        for x in e["events"]:
            I.append(f"    event {x};")
        for x in e["errors"]:
            I.append(f"    error {x};")
        for s, n in disp.items():
            if n:
                I.append(f"    function {n} external; // {s}")
            else:
                I.append(f"    // unknown function selector {s}")
        I.append("}")
        with open(os.path.join(p, "interface.sol"), "w") as fh:
            fh.write("\n".join(I) + "\n")

        L = [f"# {e.get('name') or 'Unverified contract'} `{a}`", "",
             f"**Roles in this token's system:** {', '.join(e['roles'])}  ",
             f"**Explorer:** {EXPLORER.get(self.chain, '')}{a}  ",
             f"**Verified:** {e['verified']}" + (f" via {e['via']}, compiler {e['compiler']}" if e['verified'] else
                                                 " — no published source; everything below is reconstructed from bytecode") + "  ",
             f"**Bytecode:** {e['code_bytes']} bytes | DELEGATECALL: {e['delegatecall']} | SELFDESTRUCT: {e['selfdestruct']}  "]
        if e.get("proxy"):
            L.append(f"**Proxy:** {e['proxy']}  ")
        L += ["", "## Files", "",
              "| file | what |", "|---|---|",
              "| `source/` | verified source code (read this first) |" if v["sources"] else
              "| `interface.sol` | reconstructed Solidity interface (study the function surface) |",
              f"| `abi.json` | {abi_note} |",
              "| `state.json` | live values of getters (read via eth_call) |",
              "| `bytecode.hex` / `disassembly.txt` | runtime code; search the disassembly for SSTORE/CALL/DELEGATECALL near privileged selectors |",
              ""]
        if e["risky"]:
            L += ["## Privileged / sensitive functions", ""] + [f"- `{x}`" for x in e["risky"]] + [
                "", "Check who may call these (owner / role getters below) and whether they still can.", ""]
        if e["state"]:
            L += ["## Live state", "", "| getter | arg | value |", "|---|---|---|"]
            for s in e["state"]:
                L.append(f"| `{s['fn']}` | {s['arg'] if s['arg'] is not None else ''} | {value_str(s['value'])} |")
            L.append("")
        L += ["## Function surface", ""] + [f"- `{x}`" for x in e["functions"]]
        if e["unresolved"]:
            L += ["", f"Unresolved selectors (not in signature DB): {', '.join(e['unresolved'])}. "
                  "Unknown functions are where custom admin logic often hides — trace them in disassembly.txt."]
        if e["calls_out"]:
            L += ["", "## Calls it makes to other contracts", ""] + [f"- `{x}`" for x in e["calls_out"]]
        if e["events"]:
            L += ["", "## Events", ""] + [f"- `{x}`" for x in e["events"]]
        if e["errors"]:
            L += ["", "## Custom errors (hint at rules it enforces)", ""] + [f"- `{x}`" for x in e["errors"]]
        L += ["", "## Explore it yourself", "", "```bash",
              self.cast(a, "owner()(address)"),
              f"cast code {a} --rpc-url {self.rpc_url} | cast disassemble | less",
              f"cast logs --address {a} --from-block <block> --rpc-url {self.rpc_url}",
              f"cast 4byte <selector>   # resolve an unknown selector",
              "```"]
        ex = [s for s in e["state"] if s["arg"] is None][:3]
        if ex:
            L.insert(-1, "# getters seen above, e.g.:")
            for s in ex:
                L.insert(-1, self.cast(a, s["fn"]))
        with open(os.path.join(p, "README.md"), "w") as fh:
            fh.write("\n".join(L) + "\n")

    def index(self):
        es = sorted(self.entries.values(), key=lambda x: (x.get("kind") != "contract", x["address"]))
        def nid(a):
            return "n" + a[2:10]
        L = [f"# Contract dossier: {self.ctx.get('title', '')}", "",
             f"chain {self.chain} (id {self.chain_id}) | generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
             f"RPC: `{self.rpc_url}`", "",
             "## System map", "", "```mermaid", "graph LR"]
        for e in es:
            label = (e.get("name") or (e["roles"][0].split(" of ")[0] + (" (unverified)" if e.get("kind") == "contract" else ""))
                     if e["roles"] else e.get("kind") or "?").replace('"', "'")
            L.append(f'  {nid(e["address"])}["{label}<br/>{e["address"][:10]}…<br/>{", ".join(e["roles"][:2])}"]')
        seen = set()
        for a, b, lab in self.edges:
            if (a, b, lab) in seen or a not in self.entries or b not in self.entries:
                continue
            seen.add((a, b, lab))
            L.append(f'  {nid(a)} -->|"{lab}"| {nid(b)}')
        L += ["```", "", "## Contracts", "", "| address | kind | name | verified | roles | folder |", "|---|---|---|---|---|---|"]
        for e in es:
            rel = os.path.relpath(e["dir"], self.out) if e.get("dir") else ""
            L.append(f"| `{e['address']}` | {e.get('kind', '?')} | {e.get('name') or ''} | "
                     f"{e.get('verified', '')} | {'; '.join(e['roles'])} | [{rel}]({rel}/README.md) |")
        L += ["", "## Suggested study order", "",
              "1. Token contract: supply rules (mint/burn), owner/minter roles, transfer restrictions.",
              "2. Anything holding a privileged role over the token (minter, owner, proxy admin).",
              "3. Pool hook (v4) and the LP owner/locker: can liquidity or swaps be controlled?",
              "4. EOAs with roles: single keys — watch their transactions.",
              "", "Verified contracts: read `source/`. Unverified: start from `README.md` → `state.json` → `interface.sol`,",
              "then trace unknown selectors in `disassembly.txt`."]
        with open(os.path.join(self.out, "index.md"), "w") as fh:
            fh.write("\n".join(L) + "\n")
        with open(os.path.join(self.out, "dossier.json"), "w") as fh:
            json.dump({"chain": self.chain, "chain_id": self.chain_id, "contracts": self.entries,
                       "edges": self.edges}, fh, indent=2, default=str)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("chain")
    ap.add_argument("addresses", nargs="+")
    ap.add_argument("--out")
    ap.add_argument("--rpc")
    a = ap.parse_args()
    urls = [a.rpc] if a.rpc else RPCS.get(a.chain)
    if not urls:
        raise SystemExit(f"error: no RPC known for chain '{a.chain}'; pass --rpc")
    rpc = RPC(urls)
    cid = int(rpc.call("eth_chainId", []), 16)
    out = a.out or os.path.join(DEFAULT_OUT, a.chain, a.addresses[0].lower())
    d = Dossier(rpc, a.chain, cid, out, urls[0], {"address": [x.lower() for x in a.addresses],
                                                 "title": ", ".join(a.addresses)})
    for x in a.addresses:
        d.add(x, "requested")
    d.build()
    print(f"dossier written: {out}/index.md ({len(d.entries)} addresses)")


if __name__ == "__main__":
    main()
