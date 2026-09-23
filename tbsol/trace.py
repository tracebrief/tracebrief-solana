"""Follow funds forward from an incident transaction, hop by hop.

Design choices (same as the TraceBrief engine):

* Follow **wallets** (owners), not token accounts: every outgoing move from a
  wallet's token account is signed by that wallet (or its delegate), so the
  wallet's signature history contains all of its outflows.
* Stop at an endpoint and say why: a labelled exchange/bridge/DEX, an account
  controlled by a program (pool, vault, bridge escrow), a high-activity address
  (typical of services), a dormant address (funds still there), or the hop limit.
* Never guess. If the trail cannot be followed with evidence, the report says
  where and why it stops.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .classify import classify, sort_findings
from .labels import LabelStore
from .model import Hop, IncidentReport, Transfer
from .parse import SYSTEM_PROGRAM, extract_transfers, fee_payer, outflows_from, token_accounts
from .poisoning import find_poisoning
from .rpc import SolanaRPC

DUST_LAMPORTS = 100_000  # 0.0001 SOL


@dataclass
class TraceConfig:
    max_hops: int = 4
    fanout: int = 5
    per_node_txs: int = 25
    max_nodes: int = 40
    check_poisoning: bool = True
    history: int = 40


def _ownership_edges(tx: dict, findings) -> list[Transfer]:
    """Turn an ownership change into a traceable edge to the new owner."""
    tas = token_accounts(tx)
    edges = []
    for f in findings:
        if f.code != "OWNER_REASSIGNED":
            continue
        acc = f.accounts["token_account"]
        rec = tas.get(acc, {})
        edges.append(Transfer(
            signature=f.signature, asset=rec.get("mint") or "unknown", amount_raw=rec.get("post", 0),
            decimals=rec.get("decimals", 0), from_owner=f.accounts["old_owner"], to_owner=f.accounts["new_owner"],
            from_account=acc, to_account=acc, authority=f.accounts["old_owner"], kind="ownership_change",
            slot=tx.get("slot"), block_time=tx.get("blockTime"),
        ))
    return edges


def _poisoning(rpc: SolanaRPC, report: IncidentReport, cfg: TraceConfig):
    recipients = {t.to_owner for t in report.outflows if t.to_owner}
    if not recipients:
        return []
    prev, dust = set(), set()
    for s in rpc.get_signatures(report.victim, limit=cfg.history, before=report.signature):
        if s.get("err") is not None:
            continue
        tx = rpc.get_transaction(s["signature"])
        if not tx:
            continue
        for t in extract_transfers(tx, s["signature"]):
            if t.from_owner == report.victim and t.to_owner and t.to_owner != report.victim:
                prev.add(t.to_owner)
            elif t.to_owner == report.victim and t.from_owner and t.from_owner != report.victim:
                if (t.asset == "SOL" and t.amount_raw <= DUST_LAMPORTS) or (t.asset != "SOL" and t.amount < 0.01):
                    dust.add(t.from_owner)
    return find_poisoning(report.signature, recipients, prev, dust)


def explain(
    signature: str,
    victim: Optional[str] = None,
    rpc: Optional[SolanaRPC] = None,
    labels: Optional[LabelStore] = None,
    cfg: Optional[TraceConfig] = None,
) -> IncidentReport:
    rpc = rpc or SolanaRPC()
    labels = labels or LabelStore()
    cfg = cfg or TraceConfig()
    tx = rpc.get_transaction(signature)
    if not tx:
        raise ValueError(f"transaction {signature} not found (wrong network or not yet confirmed?)")
    notes: list[str] = []
    if not victim:
        victim = fee_payer(tx)
        notes.append(f"No victim address given - assumed the fee payer {victim}.")
    findings, outflows = classify(tx, victim)
    report = IncidentReport(
        victim=victim, signature=signature, slot=tx.get("slot"), block_time=tx.get("blockTime"),
        victim_signed=any(f.code == "SIGNED_TRANSFER_OUT" for f in findings) or victim in {k["pubkey"] for k in tx["transaction"]["message"]["accountKeys"] if k.get("signer")},
        findings=findings, outflows=outflows + _ownership_edges(tx, findings), notes=notes,
    )
    if cfg.check_poisoning:
        try:
            report.findings += _poisoning(rpc, report, cfg)
        except Exception as e:  # history lookups are best-effort
            report.notes.append(f"Address-poisoning check skipped: {e}")
    report.findings = sort_findings(report.findings)
    report.hops = trace_forward(rpc, report.outflows, labels, cfg, report.notes)
    return report


def _endpoint(rpc: SolanaRPC, labels: LabelStore, t: Transfer) -> tuple[Optional[str], Optional[str]]:
    for addr in (t.to_owner, t.to_account):
        lab = labels.get(addr)
        if lab:
            return f"{lab.name} (source: {lab.source})", lab.type
    try:
        prog = rpc.get_account_owner_program(t.to_owner) if t.to_owner else None
    except Exception:
        prog = None
    if prog and prog != SYSTEM_PROGRAM:
        lab = labels.get(prog)
        name = lab.name if lab else f"program {prog}"
        return f"Account controlled by {name} - not a normal wallet", (lab.type if lab and lab.type != "PROGRAM" else "PROGRAM")
    return None, None


def trace_forward(rpc: SolanaRPC, start: list[Transfer], labels: LabelStore, cfg: TraceConfig, notes: list[str]) -> list[Hop]:
    hops: list[Hop] = []
    queue: list[tuple[Transfer, int]] = [(t, 1) for t in sorted(start, key=lambda t: -t.amount_raw)[: cfg.fanout]]
    seen: set[tuple[str, str]] = set()
    visited = 0
    while queue:
        t, depth = queue.pop(0)
        node = t.to_owner
        key = (node or "", t.asset)
        if not node or key in seen:
            continue
        seen.add(key)
        hop = Hop(depth=depth, transfer=t)
        hops.append(hop)
        ep, ep_type = _endpoint(rpc, labels, t)
        if ep:
            hop.endpoint, hop.endpoint_type = ep, ep_type
            continue
        if depth >= cfg.max_hops:
            hop.endpoint, hop.endpoint_type = f"Hop limit ({cfg.max_hops}) reached", "LIMIT"
            continue
        if visited >= cfg.max_nodes:
            hop.endpoint, hop.endpoint_type = "Node budget exhausted", "LIMIT"
            notes.append("Trace stopped early: node budget exhausted.")
            continue
        visited += 1
        sigs, busy = rpc.signatures_after(node, after_slot=t.slot or 0, max_items=cfg.per_node_txs)
        if busy:
            hop.endpoint, hop.endpoint_type = "High-activity address - typical of an exchange or service wallet (unlabelled)", "SERVICE"
            continue
        nxt: list[Transfer] = []
        for s in sigs:
            tx = rpc.get_transaction(s["signature"])
            if tx:
                nxt += outflows_from(tx, node, s["signature"])
        if not nxt:
            hop.endpoint, hop.endpoint_type = "No outgoing movement since - funds appear to sit here", "DORMANT"
            continue
        same = sorted([x for x in nxt if x.asset == t.asset], key=lambda x: -x.amount_raw)
        other = [x for x in nxt if x.asset != t.asset]
        for x in (same + other)[: cfg.fanout]:
            queue.append((x, depth + 1))
    return hops
