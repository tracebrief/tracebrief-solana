"""Turn a ``jsonParsed`` Solana transaction into transfers and raw facts.

Works on the exact structure returned by ``getTransaction`` with
``encoding=jsonParsed``. Walks outer *and* inner instructions, because most
value on Solana moves inside CPI calls (swaps, drainer programs, routers).
"""

from __future__ import annotations

from typing import Iterator, Optional

from .model import SOL_MINT, Transfer

SYSTEM_PROGRAM = "11111111111111111111111111111111"
TOKEN_PROGRAMS = {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  # Token-2022
}
TOKEN_TRANSFER_TYPES = {"transfer", "transferChecked", "transferCheckedWithFee"}
SYSTEM_TRANSFER_TYPES = {"transfer", "transferWithSeed"}


def account_keys(tx: dict) -> list[str]:
    keys = tx["transaction"]["message"]["accountKeys"]
    out = [k["pubkey"] if isinstance(k, dict) else k for k in keys]
    # Addresses loaded through lookup tables (v0/v1) are appended in this order.
    loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
    for k in loaded.get("writable", []) + loaded.get("readonly", []):
        if k not in out:
            out.append(k)
    return out


def signers(tx: dict) -> set[str]:
    return {k["pubkey"] for k in tx["transaction"]["message"]["accountKeys"] if isinstance(k, dict) and k.get("signer")}


def fee_payer(tx: dict) -> str:
    return account_keys(tx)[0]


def iter_instructions(tx: dict) -> Iterator[tuple[int, Optional[int], dict]]:
    """Yield ``(outer_index, inner_index_or_None, instruction)`` in execution order."""
    inner_by_outer: dict[int, list[dict]] = {}
    for group in (tx.get("meta") or {}).get("innerInstructions") or []:
        inner_by_outer[group["index"]] = group["instructions"]
    for i, ix in enumerate(tx["transaction"]["message"]["instructions"]):
        yield i, None, ix
        for j, inner in enumerate(inner_by_outer.get(i, [])):
            yield i, j, inner


def parsed(ix: dict) -> tuple[Optional[str], Optional[str], dict]:
    """Return ``(program, type, info)`` for parsed instructions, else ``(None, None, {})``."""
    p = ix.get("parsed")
    if isinstance(p, dict):
        return ix.get("program"), p.get("type"), p.get("info") or {}
    return None, None, {}


def token_accounts(tx: dict) -> dict[str, dict]:
    """Map token account -> {owner, pre_owner, post_owner, mint, decimals, pre, post}.

    ``pre_owner`` matters: an ownership change (``setAuthority`` accountOwner)
    leaves a different owner in the post balances. ``owner`` is the owner
    *before* the transaction when known, because that is whose value it was.
    """
    keys = account_keys(tx)
    meta = tx.get("meta") or {}
    out: dict[str, dict] = {}
    for field in ("preTokenBalances", "postTokenBalances"):
        side = "pre" if field == "preTokenBalances" else "post"
        for b in meta.get(field) or []:
            acc = keys[b["accountIndex"]]
            rec = out.setdefault(acc, {"owner": None, "pre_owner": None, "post_owner": None, "mint": None, "decimals": 0, "pre": 0, "post": 0})
            rec[f"{side}_owner"] = b.get("owner")
            rec["mint"] = b.get("mint") or rec["mint"]
            amt = b.get("uiTokenAmount") or {}
            rec["decimals"] = amt.get("decimals", rec["decimals"])
            rec[side] = int(amt.get("amount", "0"))
    for rec in out.values():
        rec["owner"] = rec["pre_owner"] or rec["post_owner"]
    return out


def lamports(tx: dict, account: str, when: str = "pre") -> int:
    keys = account_keys(tx)
    if account not in keys:
        return 0
    arr = (tx.get("meta") or {}).get("preBalances" if when == "pre" else "postBalances") or []
    i = keys.index(account)
    return arr[i] if i < len(arr) else 0


def sol_delta(tx: dict, account: str) -> int:
    """Net lamport change for ``account`` (includes the fee if it paid one)."""
    return lamports(tx, account, "post") - lamports(tx, account, "pre")


def token_deltas_by_owner(tx: dict, owner: str) -> dict[str, int]:
    """Net raw token change per mint for all token accounts owned by ``owner``."""
    out: dict[str, int] = {}
    for rec in token_accounts(tx).values():
        if not rec["mint"]:
            continue
        if rec["post_owner"] == owner:
            out[rec["mint"]] = out.get(rec["mint"], 0) + rec["post"]
        if rec["pre_owner"] == owner:
            out[rec["mint"]] = out.get(rec["mint"], 0) - rec["pre"]
    return {m: d for m, d in out.items() if d}


def sol_spent_explicitly(tx: dict, wallet: str) -> int:
    """Lamports the wallet sent with system instructions (transfers and account creation rent)."""
    total = 0
    for _, _, ix in iter_instructions(tx):
        program, typ, info = parsed(ix)
        if program != "system":
            continue
        if typ in SYSTEM_TRANSFER_TYPES and info.get("source") == wallet:
            total += int(info.get("lamports", 0))
        elif typ in ("createAccount", "createAccountWithSeed") and info.get("source") == wallet:
            total += int(info.get("lamports", 0))
    return total


def extract_transfers(tx: dict, signature: Optional[str] = None) -> list[Transfer]:
    """All explicit value movements in the transaction (SOL and SPL)."""
    sig = signature or tx["transaction"]["signatures"][0]
    slot, bt = tx.get("slot"), tx.get("blockTime")
    tas = token_accounts(tx)
    out: list[Transfer] = []
    for _, _, ix in iter_instructions(tx):
        program, typ, info = parsed(ix)
        if program == "spl-token" and typ in TOKEN_TRANSFER_TYPES:
            src, dst = info.get("source"), info.get("destination")
            s_rec, d_rec = tas.get(src, {}), tas.get(dst, {})
            ta = info.get("tokenAmount") or {}
            amount = int(ta.get("amount") or info.get("amount") or 0)
            mint = info.get("mint") or s_rec.get("mint") or d_rec.get("mint") or "unknown"
            decimals = ta.get("decimals", s_rec.get("decimals", d_rec.get("decimals", 0)))
            out.append(
                Transfer(
                    signature=sig, asset=mint, amount_raw=amount, decimals=decimals,
                    from_owner=s_rec.get("owner"), to_owner=d_rec.get("owner"),
                    from_account=src, to_account=dst,
                    authority=info.get("authority") or info.get("multisigAuthority"),
                    slot=slot, block_time=bt,
                )
            )
        elif program == "system" and typ in SYSTEM_TRANSFER_TYPES:
            src, dst = info.get("source"), info.get("destination")
            # SOL sent into a token account (e.g. wrapping SOL into the owner's own
            # wSOL account) belongs to that token account's owner.
            src_owner = tas.get(src, {}).get("owner") or src
            dst_owner = tas.get(dst, {}).get("owner") or dst
            out.append(
                Transfer(
                    signature=sig, asset=SOL_MINT, amount_raw=int(info.get("lamports", 0)), decimals=9,
                    from_owner=src_owner, to_owner=dst_owner, from_account=src, to_account=dst,
                    authority=info.get("sourceBase") or src, slot=slot, block_time=bt,
                )
            )
        elif program == "spl-token" and typ == "closeAccount":
            acc, dst = info.get("account"), info.get("destination")
            owner = info.get("owner") or info.get("multisigOwner") or tas.get(acc, {}).get("owner")
            rent = lamports(tx, acc, "pre")
            if rent:
                out.append(
                    Transfer(
                        signature=sig, asset=SOL_MINT, amount_raw=rent, decimals=9,
                        from_owner=owner, to_owner=dst, from_account=acc, to_account=dst,
                        authority=owner, kind="close_account_rent", slot=slot, block_time=bt,
                    )
                )
    return out


def burns_by_owner(tx: dict, owner: str) -> dict[str, int]:
    """Raw amounts burned per mint from token accounts owned by ``owner``."""
    tas = token_accounts(tx)
    out: dict[str, int] = {}
    for _, _, ix in iter_instructions(tx):
        program, typ, info = parsed(ix)
        if program == "spl-token" and typ in ("burn", "burnChecked"):
            acc = info.get("account")
            rec = tas.get(acc, {})
            if (rec.get("owner") or info.get("authority")) == owner:
                amt = int((info.get("tokenAmount") or {}).get("amount") or info.get("amount") or 0)
                mint = info.get("mint") or rec.get("mint")
                if mint:
                    out[mint] = out.get(mint, 0) + amt
    return out


def outflows_from(tx: dict, owner: str, signature: Optional[str] = None) -> list[Transfer]:
    """Transfers that move value away from ``owner`` to someone else."""
    res = []
    for t in extract_transfers(tx, signature):
        if t.from_owner == owner and t.to_owner and t.to_owner != owner:
            res.append(t)
    return res
