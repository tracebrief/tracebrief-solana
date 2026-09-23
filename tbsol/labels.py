"""Endpoint labels.

Rule inherited from TraceBrief: a label is shown only when it rests on a
primary source (an exchange's own proof-of-reserves list, the OFAC SDN list,
or a protocol's own documentation). Labels name companies and protocols,
never private individuals.

This repository ships only program IDs that are documented by the protocols
themselves. Exchange deposit and hot-wallet lists are loaded at runtime from a
CSV (TraceBrief's production list is built from exchanges' published
proof-of-reserves wallets and is not part of this repo).

CSV format (header required)::

    address,label,type,source
    <base58>,Example Exchange hot wallet,EXCHANGE,https://example.com/proof-of-reserves
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Label:
    address: str
    name: str
    type: str  # EXCHANGE | BRIDGE | DEX | MIXER | SANCTIONED | PROGRAM
    source: str


# Program IDs published by the protocols themselves.
BUILTIN_PROGRAMS: dict[str, Label] = {
    a: Label(a, n, t, s)
    for a, n, t, s in [
        ("11111111111111111111111111111111", "System Program", "PROGRAM", "https://docs.solana.com/developing/runtime-facilities/programs"),
        ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "SPL Token Program", "PROGRAM", "https://spl.solana.com/token"),
        ("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "SPL Token-2022 Program", "PROGRAM", "https://spl.solana.com/token-2022"),
        ("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "Associated Token Account Program", "PROGRAM", "https://spl.solana.com/associated-token-account"),
        ("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "Jupiter Aggregator v6", "DEX", "https://dev.jup.ag/"),
        ("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", "Raydium AMM v4", "DEX", "https://docs.raydium.io/raydium/protocol/developers/addresses"),
        ("worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth", "Wormhole Core Bridge", "BRIDGE", "https://wormhole.com/docs/products/reference/contract-addresses/"),
        ("wormDTUJ6AWPNvk59vGQbDvGJmqbDTdgWgAqcLBCgUb", "Wormhole Token Bridge", "BRIDGE", "https://wormhole.com/docs/products/reference/contract-addresses/"),
    ]
}

KNOWN_MINTS = {
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": ("USDC", 6),
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": ("USDT", 6),
    "So11111111111111111111111111111111111111112": ("wSOL", 9),
    "SOL": ("SOL", 9),
}


class LabelStore:
    def __init__(self, labels: Optional[dict[str, Label]] = None):
        self._by_addr: dict[str, Label] = dict(BUILTIN_PROGRAMS)
        if labels:
            self._by_addr.update(labels)

    @classmethod
    def from_csv(cls, path: str) -> "LabelStore":
        labels: dict[str, Label] = {}
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                addr = (row.get("address") or "").strip()
                if not addr:
                    continue
                if not (row.get("source") or "").strip():
                    raise ValueError(f"label for {addr} has no source - primary source is mandatory")
                labels[addr] = Label(addr, row["label"].strip(), row["type"].strip().upper(), row["source"].strip())
        return cls(labels)

    def get(self, address: Optional[str]) -> Optional[Label]:
        return self._by_addr.get(address) if address else None

    def __len__(self) -> int:
        return len(self._by_addr)


def asset_name(mint: str) -> str:
    known = KNOWN_MINTS.get(mint)
    return known[0] if known else f"{mint[:4]}…{mint[-4:]}"
