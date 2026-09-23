"""Plain data types shared by the parser, classifier, tracer and report."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

LAMPORTS_PER_SOL = 1_000_000_000
SOL_MINT = "SOL"  # pseudo-mint used for native SOL movements
U64_MAX = 2**64 - 1


@dataclass
class Transfer:
    """One movement of value inside a transaction.

    ``from_owner``/``to_owner`` are wallets (owners of token accounts, or the
    system accounts themselves for SOL). ``from_account``/``to_account`` are the
    accounts that actually held the value (token accounts for SPL).
    """

    signature: str
    asset: str  # mint address, or SOL_MINT
    amount_raw: int
    decimals: int
    from_owner: Optional[str]
    to_owner: Optional[str]
    from_account: Optional[str] = None
    to_account: Optional[str] = None
    authority: Optional[str] = None  # who signed for the move
    kind: str = "transfer"  # transfer | close_account_rent | balance_delta
    slot: Optional[int] = None
    block_time: Optional[int] = None

    @property
    def amount(self) -> float:
        return self.amount_raw / (10**self.decimals) if self.decimals else float(self.amount_raw)

    @property
    def via_delegate(self) -> bool:
        """True when someone other than the owner authorised the move."""
        return bool(self.authority and self.from_owner and self.authority != self.from_owner)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["amount"] = self.amount
        d["via_delegate"] = self.via_delegate
        return d


@dataclass
class Finding:
    """A plain-language statement about what a transaction did to the victim.

    Every finding carries the signature that proves it, so a reader (police,
    exchange, lawyer) can verify it independently.
    """

    code: str
    severity: str  # critical | high | medium | info
    title: str
    detail: str
    signature: str
    accounts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Hop:
    depth: int
    transfer: Transfer
    endpoint: Optional[str] = None  # label or reason the trail stops here
    endpoint_type: Optional[str] = None  # EXCHANGE | BRIDGE | DEX | PROGRAM | DORMANT | LIMIT | MIXER | SANCTIONED

    def to_dict(self) -> dict:
        d = {"depth": self.depth, "endpoint": self.endpoint, "endpoint_type": self.endpoint_type}
        d.update(self.transfer.to_dict())
        return d


@dataclass
class IncidentReport:
    victim: str
    signature: str
    slot: Optional[int]
    block_time: Optional[int]
    victim_signed: bool
    findings: list[Finding] = field(default_factory=list)
    outflows: list[Transfer] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "victim": self.victim,
            "signature": self.signature,
            "slot": self.slot,
            "block_time": self.block_time,
            "victim_signed": self.victim_signed,
            "findings": [f.to_dict() for f in self.findings],
            "outflows": [t.to_dict() for t in self.outflows],
            "hops": [h.to_dict() for h in self.hops],
            "notes": self.notes,
        }
