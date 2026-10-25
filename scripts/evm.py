"""Shared EVM helpers: JSON-RPC (with batching), ABI word decoding, bytecode
analysis (disassembly, selector classification, proxy / EIP-7702 detection),
signature resolution, source verification lookup, and generic getter probing.
Stdlib only."""
import json
import os
import re
import time
import urllib.error
import urllib.request

from keccak import keccak256, selector

UA = "seer/0.1"
CACHE = os.path.expanduser("~/.cache/seer")

ZERO = "0x" + "0" * 40
BURN = {ZERO, "0x000000000000000000000000000000000000dead",
        "0xdead000000000000000042069420694206942069"}

RPCS = {
    "robinhood": ["https://rpc.mainnet.chain.robinhood.com",
                  "https://robinhood-rpc.publicnode.com", "https://robinhood.drpc.org"],
    "ethereum": ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org", "https://eth.llamarpc.com"],
    "base": ["https://base.daybreak-rpc.network", "https://mainnet.base.org", "https://base-rpc.publicnode.com",
             "https://base.gateway.tenderly.co"],
    "arbitrum": ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com"],
    "bsc": ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.bnbchain.org"],
    "polygon": ["https://polygon-bor-rpc.publicnode.com"],
    "optimism": ["https://optimism.gateway.tenderly.co", "https://optimism-rpc.publicnode.com",
                 "https://mainnet.optimism.io"],
    "avalanche": ["https://avalanche-c-chain-rpc.publicnode.com"],
}
BLOCKSCOUT = {
    "robinhood": "https://robinhoodchain.blockscout.com", "ethereum": "https://eth.blockscout.com",
    "base": "https://base.blockscout.com", "arbitrum": "https://arbitrum.blockscout.com",
    "optimism": "https://optimism.blockscout.com", "polygon": "https://polygon.blockscout.com",
}
EXPLORER = {
    "robinhood": "https://robinhoodchain.blockscout.com/address/",
    "ethereum": "https://etherscan.io/address/", "base": "https://basescan.org/address/",
    "arbitrum": "https://arbiscan.io/address/", "bsc": "https://bscscan.com/address/",
    "polygon": "https://polygonscan.com/address/", "optimism": "https://optimistic.etherscan.io/address/",
    "avalanche": "https://snowtrace.io/address/",
}


# ---------------- transport ----------------
def http_json(url, data=None, timeout=60):
    h = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        h["Content-Type"] = "application/json"
        data = json.dumps(data).encode()
    req = urllib.request.Request(url, data=data, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def try_json(url, **kw):
    try:
        return http_json(url, **kw)
    except Exception:
        return None


class RPCError(Exception):
    pass


class BudgetExceeded(Exception):
    pass


RANGE_ERR = re.compile(r"block range|range (is )?too (large|wide)|ranges over|query spans|only \d+ are allowed|"
                       r"exceeds? (the )?(max|limit)|too many (results|logs|blocks)|response size|"
                       r"query returned more than|max results", re.I)
CAPABILITY_ERR = re.compile(r"pruned|history|archive|missing trie|not available|not supported|does not exist|"
                            r"method not found|unsupported|limit reached|rate limit|payment|upgrade|"
                            r"recent blocks|not allowed|forbidden", re.I)
RANGE_NUM = re.compile(r"only (\d+) are allowed|limit of (\d+)|max(?:imum)? block range (\d+)|"
                       r"range (?:of )?(\d+)|over (\d+) blocks|(\d+) block range", re.I)


class RPC:
    def __init__(self, urls):
        self.urls = list(urls)
        self.i = 0
        self.calls = 0
        self._code = {}

    def _post(self, payload):
        last = None
        for attempt in range(3 * len(self.urls)):
            url = self.urls[self.i % len(self.urls)]
            try:
                self.calls += 1
                return http_json(url, payload, timeout=90)
            except urllib.error.HTTPError as e:
                last = f"HTTP {e.code} from {url}"
                if e.code == 429:
                    time.sleep(2 + attempt)
            except Exception as e:
                last = f"{e} from {url}"
            self.i += 1
        raise RPCError(f"all RPCs failed: {last}")

    def call(self, method, params):
        """Rotate to the next RPC when an endpoint lacks a capability (pruned
        history, unsupported method, rate cap). Range-limit errors are raised
        unchanged so logs() can shrink its window."""
        msg = None
        for _ in range(len(self.urls)):
            r = self._post({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            if "error" not in r:
                return r["result"]
            msg = r["error"].get("message", str(r["error"]))
            if RANGE_ERR.search(msg) or not CAPABILITY_ERR.search(msg):
                break
            self.i += 1
        raise RPCError(msg)

    def batch(self, reqs, size=40):
        """reqs: [(method, params)] -> results (None where the call errored)."""
        out = []
        for k in range(0, len(reqs), size):
            chunk = reqs[k:k + size]
            payload = [{"jsonrpc": "2.0", "id": i, "method": m, "params": p} for i, (m, p) in enumerate(chunk)]
            try:
                r = self._post(payload)
            except RPCError:
                r = None
            if not isinstance(r, list):  # endpoint without batch support
                for m, p in chunk:
                    try:
                        out.append(self.call(m, p))
                    except RPCError:
                        out.append(None)
                continue
            by_id = {x.get("id"): x for x in r}
            out.extend(by_id.get(i, {}).get("result") for i in range(len(chunk)))
        return out

    def eth_call(self, to, data, frm=None):
        tx = {"to": to, "data": data}
        if frm:
            tx["from"] = frm
        try:
            return self.call("eth_call", [tx, "latest"])
        except RPCError:
            return None

    def calls_batch(self, items):
        """items: [(to, data)] -> raw results."""
        return self.batch([("eth_call", [{"to": t, "data": d}, "latest"]) for t, d in items])

    def code(self, a):
        a = a.lower()
        if a not in self._code:
            self._code[a] = self.call("eth_getCode", [a, "latest"])
        return self._code[a]

    def codes(self, addrs):
        need = [a.lower() for a in addrs if a.lower() not in self._code]
        for a, c in zip(need, self.batch([("eth_getCode", [a, "latest"]) for a in need])):
            self._code[a] = c or "0x"
        return {a.lower(): self._code[a.lower()] for a in addrs}

    def storage(self, a, slot):
        return self.call("eth_getStorageAt", [a, slot, "latest"])

    def block(self, n):
        return self.call("eth_getBlockByNumber", [hex(n) if isinstance(n, int) else n, False])

    # learned max getLogs range, per query shape (RPCs often allow far wider
    # ranges when an address filter is present)
    span_hints = {True: 2_000_000, False: 2_000_000}

    @property
    def span_hint(self):
        return self.span_hints[True]

    def logs(self, address, topics, frm, to, max_logs=10 ** 9, span=None, budget=None):
        """eth_getLogs with adaptive range splitting. Returns (logs, truncated).
        budget: max requests before raising BudgetExceeded (with the projected
        number of requests) so callers can fall back to a cheaper strategy."""
        out, cur, used = [], max(frm, 0), 0
        shape = bool(address)
        span = span or self.span_hints[shape]
        while cur <= to:
            if budget is not None and used >= budget:
                raise BudgetExceeded(used + (to - cur) // max(span, 1) + 1)
            end = min(cur + span - 1, to)
            q = {"fromBlock": hex(cur), "toBlock": hex(end), "topics": topics}
            if address:
                q["address"] = address
            used += 1
            try:
                got = self.call("eth_getLogs", [q])
            except RPCError as e:
                m = None if re.search(r"results|logs|response size", str(e), re.I) else RANGE_NUM.search(str(e))
                n = next((int(g) for g in (m.groups() if m else ()) if g), None)
                if n and n < span:
                    span = max(n - 1, 1)
                elif span > 1:
                    span = max(span // 4, 1)
                else:
                    raise
                self.span_hints[shape] = span
                if budget is not None and (to - cur) // span > budget * 4:
                    raise BudgetExceeded((to - cur) // span)
                continue
            out.extend(got)
            if len(out) >= max_logs:
                return out, True
            cur = end + 1
            if len(got) < 2000 and span < self.span_hints[shape] * 4:
                span = min(span * 2, 10_000_000)
        return out, False


# ---------------- abi helpers ----------------
def words(hexdata):
    h = hexdata[2:] if hexdata and hexdata.startswith("0x") else (hexdata or "")
    return [h[i:i + 64] for i in range(0, len(h), 64)]


def w_int(w, signed=False):
    return int.from_bytes(bytes.fromhex(w), "big", signed=signed)


def w_addr(w):
    return "0x" + w[-40:].lower()


def enc_addr(a):
    return a.lower().replace("0x", "").rjust(64, "0")


def enc_uint(n):
    return hex(n)[2:].rjust(64, "0")


def call_uint(rpc, to, sig, *args, frm=None):
    r = rpc.eth_call(to, selector(sig) + "".join(args), frm)
    if not r or r == "0x" or len(r) < 66:
        return None
    return w_int(words(r)[0])


def call_addr(rpc, to, sig, *args):
    r = rpc.eth_call(to, selector(sig) + "".join(args))
    if not r or r == "0x" or len(r) < 66:
        return None
    return w_addr(words(r)[0])


def decode_str(r):
    if not r or r == "0x":
        return None
    w = words(r)
    try:
        if len(w) >= 3 and w_int(w[0]) == 32:
            n = w_int(w[1])
            return bytes.fromhex("".join(w[2:])[:n * 2]).decode("utf-8", "replace")
        return bytes.fromhex(w[0]).rstrip(b"\0").decode("utf-8", "replace") or None
    except Exception:
        return None


def call_str(rpc, to, sig):
    return decode_str(rpc.eth_call(to, selector(sig)))


def guess_value(r):
    """Best-effort decode of a getter return with unknown type."""
    if r is None:
        return {"error": "reverted"}
    if r == "0x":
        return {"raw": "0x"}
    w = words(r)
    if len(w) >= 3 and w_int(w[0]) == 32 and w_int(w[1]) < 2048:
        s = decode_str(r)
        if s is not None and s.isprintable():
            return {"string": s}
    vals = []
    for x in w[:12]:
        n = w_int(x)
        if n in (0, 1) and len(w) == 1:
            vals.append({"bool/uint": n})
        elif 2 ** 120 < n < 2 ** 160:
            vals.append({"address": w_addr(x)})
        elif n > 2 ** 255:
            vals.append({"int": w_int(x, True)})
        else:
            vals.append({"uint": n})
    return vals[0] if len(vals) == 1 else {"tuple": vals}


# ---------------- bytecode ----------------
OPCODES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV", 0x06: "MOD",
    0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP", 0x0B: "SIGNEXTEND", 0x10: "LT",
    0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR",
    0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR", 0x20: "KECCAK256",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE",
    0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
    0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH", 0x40: "BLOCKHASH",
    0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT",
    0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x49: "BLOBHASH", 0x4A: "BLOBBASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD", 0x55: "SSTORE",
    0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
    0x5C: "TLOAD", 0x5D: "TSTORE", 0x5E: "MCOPY", 0x5F: "PUSH0",
    0xA0: "LOG0", 0xA1: "LOG1", 0xA2: "LOG2", 0xA3: "LOG3", 0xA4: "LOG4",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL",
    0xF5: "CREATE2", 0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}
for _i in range(32):
    OPCODES[0x60 + _i] = f"PUSH{_i + 1}"
for _i in range(16):
    OPCODES[0x80 + _i] = f"DUP{_i + 1}"
    OPCODES[0x90 + _i] = f"SWAP{_i + 1}"


def disassemble(code_hex):
    b = bytes.fromhex(code_hex[2:] if code_hex.startswith("0x") else code_hex)
    out, i = [], 0
    while i < len(b):
        op = b[i]
        name = OPCODES.get(op, f"UNKNOWN_0x{op:02x}")
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            out.append((i, name, b[i + 1:i + 1 + n].hex()))
            i += n + 1
        else:
            out.append((i, name, ""))
            i += 1
    return out


def analyze_bytecode(code_hex):
    """Split PUSH4 constants into dispatcher selectors (followed by EQ/GT/DUP-EQ)
    vs. outbound-call/error selectors (followed by PUSH1 0xe0 SHL), collect
    PUSH32 constants (event topics) and dangerous opcodes."""
    ins = disassemble(code_hex)
    disp, outbound, other, push32 = set(), set(), set(), set()
    ops = {}
    for k, (pc, name, arg) in enumerate(ins):
        ops[name] = ops.get(name, 0) + 1
        if name == "PUSH32":
            push32.add("0x" + arg)
        if name != "PUSH4":
            continue
        s = "0x" + arg
        if arg in ("ffffffff", "00000000"):
            continue
        nxt = [ins[j][1] for j in range(k + 1, min(k + 4, len(ins)))]
        nxt_args = [ins[j][2] for j in range(k + 1, min(k + 4, len(ins)))]
        if nxt[:1] in (["EQ"], ["GT"], ["LT"]) or nxt[:2] in (["DUP2", "EQ"], ["DUP3", "EQ"]):
            disp.add(s)
        elif nxt[:2] == ["PUSH1", "SHL"] and nxt_args[0] == "e0":
            outbound.add(s)
        else:
            other.add(s)
    return {"dispatcher": disp, "outbound_or_errors": outbound | (other - disp), "push32": push32,
            "opcode_counts": ops, "has_selfdestruct": ops.get("SELFDESTRUCT", 0) > 0,
            "has_delegatecall": ops.get("DELEGATECALL", 0) > 0}


def eip7702_target(code_hex):
    c = code_hex.lower()
    if c.startswith("0xef0100") and len(c) == 2 + 46:
        return "0x" + c[8:]
    return None


def proxy_info(rpc, addr, code_hex):
    slots = {
        "implementation": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        "admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
        "beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
    }
    info = {}
    res = rpc.batch([("eth_getStorageAt", [addr, s, "latest"]) for s in slots.values()])
    for k, v in zip(slots, res):
        if v and int(v, 16):
            info[k] = w_addr(v[2:].rjust(64, "0"))
    m = re.match(r"0x363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3", code_hex.lower())
    if m:
        info["implementation"] = "0x" + m.group(1)
        info["minimal_proxy"] = True
    if "beacon" in info and "implementation" not in info:
        impl = call_addr(rpc, info["beacon"], "implementation()")
        if impl:
            info["implementation"] = impl
    return info


# ---------------- signatures ----------------
_SIGCACHE_FILE = os.path.join(CACHE, "signatures.json")


def _load_sigcache():
    try:
        with open(_SIGCACHE_FILE) as fh:
            return json.load(fh)
    except Exception:
        return {"function": {}, "event": {}}


COMMON_SIGS = [
    "owner()", "pendingOwner()", "factory()", "token()", "token0()", "token1()", "WETH()", "WETH9()",
    "poolManager()", "positionManager()", "router()", "pair()", "admin()", "implementation()", "minter()",
    "name()", "symbol()", "decimals()", "totalSupply()", "balanceOf(address)", "transfer(address,uint256)",
    "transferFrom(address,address,uint256)", "approve(address,uint256)", "allowance(address,address)",
    "ownerOf(uint256)", "safeTransferFrom(address,address,uint256)", "safeTransferFrom(address,address,uint256,bytes)",
    "setApprovalForAll(address,bool)", "getApproved(uint256)", "isApprovedForAll(address,address)",
    "transferOwnership(address)", "renounceOwnership()", "acceptOwnership()", "paused()", "pause()", "unpause()",
    "mint(address,uint256)", "burn(uint256)", "multicall(bytes[])", "execute(bytes,bytes[],uint256)",
    "unlock(bytes)", "settle()", "take(address,address,uint256)", "sync(address)", "getReserves()", "slot0()",
    "positions(uint256)", "collect((uint256,address,uint128,uint128))", "modifyLiquidities(bytes,uint256)",
    "extsload(bytes32)", "withdraw()", "withdraw(uint256)", "unlockTime()", "release()", "feeRecipient()",
    "treasury()", "operator()", "governance()", "hasRole(bytes32,address)", "DEFAULT_ADMIN_ROLE()",
]
_LOCAL = {}


def resolve(sels=(), events=()):
    """Look up 4-byte selectors / event topics in the openchain signature DB
    (cached on disk). Returns ({sel: name}, {topic: name})."""
    if not _LOCAL:
        _LOCAL.update({selector(x): x for x in COMMON_SIGS})
    cache = _load_sigcache()
    fn, ev = cache["function"], cache["event"]
    for s_ in sels:
        if not fn.get(s_) and s_ in _LOCAL:
            fn[s_] = _LOCAL[s_]
    todo_f = sorted(s for s in sels if s not in fn)
    todo_e = sorted(t for t in events if t not in ev)
    for kind, todo, store in (("function", todo_f, fn), ("event", todo_e, ev)):
        for k in range(0, len(todo), 60):
            chunk = todo[k:k + 60]
            r = try_json(f"https://api.openchain.xyz/signature-database/v1/lookup?filter=true&{kind}="
                         + ",".join(chunk), timeout=30)
            got = ((r or {}).get("result") or {}).get(kind) or {}
            for s in chunk:
                cands = got.get(s) or []
                cands = sorted(cands, key=lambda c: not c.get("hasVerifiedContract"))
                store[s] = cands[0]["name"] if cands else None
    try:
        os.makedirs(CACHE, exist_ok=True)
        with open(_SIGCACHE_FILE, "w") as fh:
            json.dump(cache, fh)
    except OSError:
        pass
    return ({s: fn.get(s) for s in sels if fn.get(s)}, {t: ev.get(t) for t in events if ev.get(t)})


# ---------------- verification / sources ----------------
def _safe_join(root, rel):
    rel = rel.replace("\\", "/").lstrip("/")
    p = os.path.normpath(os.path.join(root, rel))
    if not p.startswith(os.path.normpath(root) + os.sep):
        p = os.path.join(root, os.path.basename(rel) or "source.sol")
    return p


def save_sources(root, sources):
    for rel, content in sources.items():
        p = _safe_join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content or "")
    return root


_VERIF = {}


def verification(chain, chain_id, addr):
    """Sourcify -> Etherscan v2 (if ETHERSCAN_API_KEY) -> Blockscout.
    Returns {verified, via, name, compiler, abi, sources:{path: content}}."""
    key_ = (chain_id, addr.lower())
    if key_ in _VERIF:
        return _VERIF[key_]
    res = {"verified": False, "via": None, "name": None, "compiler": None, "abi": None, "sources": {}}
    s = try_json(f"https://sourcify.dev/server/v2/contract/{chain_id}/{addr}?fields=compilation,sources,abi",
                 timeout=45)
    if s and s.get("match"):
        comp = s.get("compilation") or {}
        res.update(verified=True, via=f"sourcify ({s.get('match')})", name=comp.get("name"),
                   compiler=comp.get("compilerVersion"), abi=s.get("abi"),
                   sources={k: v.get("content", "") for k, v in (s.get("sources") or {}).items()})
    elif os.environ.get("ETHERSCAN_API_KEY"):
        e = try_json(f"https://api.etherscan.io/v2/api?chainid={chain_id}&module=contract&action=getsourcecode"
                     f"&address={addr}&apikey={os.environ['ETHERSCAN_API_KEY']}", timeout=45)
        r = (e or {}).get("result")
        r = r[0] if isinstance(r, list) and r else {}
        if r.get("SourceCode"):
            src = r["SourceCode"]
            srcs = {f"{r.get('ContractName') or 'Contract'}.sol": src}
            if src.startswith("{{"):
                try:
                    srcs = {k: v["content"] for k, v in json.loads(src[1:-1])["sources"].items()}
                except Exception:
                    pass
            abi = None
            try:
                abi = json.loads(r.get("ABI") or "null")
            except Exception:
                pass
            res.update(verified=True, via="etherscan", name=r.get("ContractName"),
                       compiler=r.get("CompilerVersion"), abi=abi, sources=srcs)
    if not res["verified"] and BLOCKSCOUT.get(chain):
        b = try_json(f"{BLOCKSCOUT[chain]}/api/v2/smart-contracts/{addr}", timeout=30)
        if b and (b.get("is_verified") or b.get("source_code")):
            srcs = {b.get("file_path") or "Contract.sol": b.get("source_code", "")}
            for extra in b.get("additional_sources") or []:
                srcs[extra.get("file_path", "extra.sol")] = extra.get("source_code", "")
            res.update(verified=True, via="blockscout", name=b.get("name"),
                       compiler=b.get("compiler_version"), abi=b.get("abi"), sources=srcs)
    _VERIF[key_] = res
    return res


# ---------------- generic getter probing ----------------
MUTATING = re.compile(r"^(set|renounce|transfer|approve|burn|mint|withdraw|rescue|claim|sweep|lock|unlock|"
                      r"accept|init|initialize|upgrade|execute|swap|add|remove|deposit|register|update|"
                      r"enable|disable|pause|unpause|launch|create|deploy|multicall|permit|sell|buy|seed|"
                      r"commit|settle|collect|harvest|stake|unstake|exit|open|close|start|stop|toggle|"
                      r"grant|revoke|emergency|recover|release|distribute|airdrop|refund|redeem|skim|sync)"
                      r"(?=[A-Z0-9_]|$)")
# getter-like nouns that start with a verb ("mintDeadline", "claimEnd", "lockedPositions")
GETTER_NOUN = re.compile(r"(Deadline|Open|Enabled|Disabled|At|End|Start|Count|Cap|Amount|Bps|Time|Window|"
                         r"Cursor|Info|Of|For|Fee|Rate|Supply|Address|Recipient|Wallet|Id|Ids|Token|Pool|Path|"
                         r"Router|Factory|Status|State|Config|Limit|Duration|Delay|Period|Threshold)$")


def probe_getters(rpc, addr, fn_names, ctx):
    """Call side-effect-free-looking getters. fn_names: {selector: signature}.
    ctx: {"address": [...], "uint256": [...], "bytes32": [...]} sample args."""
    items, meta = [], []
    for sel, sig in fn_names.items():
        name = sig.split("(")[0]
        args = sig[len(name) + 1:-1]
        if not name[:1].isalpha() or (MUTATING.match(name) and not GETTER_NOUN.search(name)):
            continue
        if args == "":
            items.append((addr, sel)); meta.append((sig, None))
        elif args in ("address", "uint256", "bytes32"):
            for v in ctx.get(args, [])[:4]:
                enc = enc_addr(v) if args == "address" else enc_uint(v) if args == "uint256" else v[2:].rjust(64, "0")
                items.append((addr, sel + enc)); meta.append((sig, v))
    out = []
    for (sig, arg), r in zip(meta, rpc.calls_batch(items)):
        if r is None:
            continue
        out.append({"fn": sig, "arg": arg, "value": guess_value(r)})
    return out
