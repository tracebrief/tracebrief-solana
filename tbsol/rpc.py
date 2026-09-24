"""Minimal Solana JSON-RPC client (stdlib only).

Uses ``jsonParsed`` encoding and ``maxSupportedTransactionVersion: 1`` so that
legacy, v0 and v1 transactions all decode. Retries with backoff on HTTP 429 and
transient network errors, which matters on the public endpoint.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Optional

DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
MAX_TX_VERSION = 1


class RPCError(RuntimeError):
    pass


class SolanaRPC:
    def __init__(self, url: str = DEFAULT_RPC, timeout: float = 30.0, retries: int = 5, min_interval: float = 0.12):
        self.url = url
        self.timeout = timeout
        self.retries = retries
        self.min_interval = min_interval  # simple client-side rate limit
        self._last = 0.0
        self._cache: dict[str, Any] = {}

    def call(self, method: str, params: list) -> Any:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        delay = 0.5
        last_err: Optional[Exception] = None
        for _ in range(self.retries):
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    payload = json.load(r)
            except urllib.error.HTTPError as e:
                last_err = e
                if e.code in (429, 500, 502, 503, 504):
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise RPCError(f"{method}: HTTP {e.code}") from e
            except (urllib.error.URLError, TimeoutError) as e:
                last_err = e
                time.sleep(delay)
                delay *= 2
                continue
            if "error" in payload:
                raise RPCError(f"{method}: {payload['error']}")
            return payload.get("result")
        raise RPCError(f"{method}: gave up after {self.retries} attempts ({last_err})")

    def get_transaction(self, signature: str) -> Optional[dict]:
        if signature in self._cache:
            return self._cache[signature]
        tx = self.call(
            "getTransaction",
            [signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": MAX_TX_VERSION, "commitment": "confirmed"}],
        )
        self._cache[signature] = tx
        return tx

    def get_signatures(self, address: str, limit: int = 100, before: Optional[str] = None) -> list[dict]:
        cfg: dict = {"limit": limit, "commitment": "confirmed"}
        if before:
            cfg["before"] = before
        return self.call("getSignaturesForAddress", [address, cfg]) or []

    def get_account_owner_program(self, address: str) -> Optional[str]:
        """Program that owns ``address`` (System Program for normal wallets)."""
        key = f"owner:{address}"
        if key in self._cache:
            return self._cache[key]
        res = self.call("getAccountInfo", [address, {"encoding": "base64", "commitment": "confirmed"}])
        owner = (res or {}).get("value", {}) or {}
        owner = owner.get("owner") if owner else None
        self._cache[key] = owner
        return owner

    def get_balance(self, address: str) -> int:
        """Current lamports of ``address``."""
        res = self.call("getBalance", [address, {"commitment": "confirmed"}])
        return int((res or {}).get("value", 0))

    def get_token_balance(self, owner: str, mint: str) -> int:
        """Current raw balance of ``mint`` summed over all token accounts owned by ``owner``."""
        res = self.call("getTokenAccountsByOwner", [owner, {"mint": mint}, {"encoding": "jsonParsed", "commitment": "confirmed"}])
        total = 0
        for acc in (res or {}).get("value", []) or []:
            info = (((acc.get("account") or {}).get("data") or {}).get("parsed") or {}).get("info") or {}
            total += int((info.get("tokenAmount") or {}).get("amount", 0))
        return total

    def signatures_after(self, address: str, after_slot: int, max_items: int = 50, page: int = 100, max_pages: int = 10) -> tuple[list[dict], bool]:
        """Successful signatures involving ``address`` with slot > ``after_slot``.

        Returns ``(oldest_first, busy)``. ``busy`` is True when the address has
        more activity since ``after_slot`` than ``max_pages`` pages - typical of
        exchange hot wallets and program vaults, which the tracer treats as an
        endpoint instead of trying to follow.
        """
        out: list[dict] = []
        before = None
        self.last_window = None  # (newest blockTime, oldest blockTime read) when busy - lets callers judge the rate
        for _ in range(max_pages):
            batch = self.get_signatures(address, limit=page, before=before)
            if not batch:
                return list(reversed(out))[:max_items], False
            for s in batch:
                if s.get("slot", 0) <= after_slot:
                    return list(reversed(out))[:max_items], False
                if s.get("err") is None:
                    out.append(s)
            if len(batch) < page:
                return list(reversed(out))[:max_items], False
            before = batch[-1]["signature"]
        if out:
            self.last_window = (out[0].get("blockTime"), out[-1].get("blockTime"))
        return list(reversed(out))[:max_items], True
