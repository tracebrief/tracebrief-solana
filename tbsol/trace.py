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
    follow_up: bool = True  # look for later transactions that used a permission granted here
    follow_accounts: int = 8
    follow_txs: int = 10
    collector_txs: int = 100  # keep scanning an address that only receives (a collector) up to this many txs


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


FOLLOW_USE_CODES = {"DELEGATE_SPEND", "PROGRAM_OUTFLOW", "OWNER_REASSIGNED"}


def _follow_up(rpc: SolanaRPC, report: IncidentReport, cfg: TraceConfig) -> int:
    """A permission (delegate approval, wallet assigned to a program) moves nothing in the
    transaction that grants it - the loss comes later, often in transactions that do not
    even list the victim's wallet. Look at the affected accounts after this slot and pull
    in the transactions that used the permission. Returns how many were found."""
    targets: list[str] = []
    for f in report.findings:
        acc = None
        if f.code == "DELEGATE_APPROVED":
            acc = f.accounts.get("token_account")
        elif f.code == "WALLET_ASSIGNED":
            acc = f.accounts.get("wallet") or report.victim
        if acc and acc not in targets:
            targets.append(acc)
    targets = targets[: cfg.follow_accounts]
    if not targets:
        return 0
    seen = {report.signature}
    used = 0
    for acc in targets:
        sigs, _busy = rpc.signatures_after(acc, after_slot=(report.slot or 0) - 1, max_items=cfg.follow_txs)
        for s in sigs:
            sg = s["signature"]
            if sg in seen:
                continue
            seen.add(sg)
            tx = rpc.get_transaction(sg)
            if not tx:
                continue
            f2, out2 = classify(tx, report.victim)
            misuse = [f for f in f2 if f.code in FOLLOW_USE_CODES]
            if not misuse:
                continue
            used += 1
            have_unsigned = any(f.code == "NOT_SIGNED_BY_VICTIM" for f in report.findings)
            report.findings += [f for f in f2 if f.code in FOLLOW_USE_CODES
                                or (f.code == "NOT_SIGNED_BY_VICTIM" and not have_unsigned)]
            report.outflows += out2
    report.notes.append(
        f"Later use of the permission: checked {len(targets)} affected account(s) after this transaction; "
        f"{used} later transaction(s) moved value using it."
        + (" They are included below with their own signatures." if used else "")
    )
    return used


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
    if cfg.follow_up and not report.outflows:
        try:
            _follow_up(rpc, report, cfg)
        except Exception as e:  # best-effort, like the poisoning check
            report.notes.append(f"Later-use check skipped: {e}")
    report.findings = sort_findings(report.findings)
    report.hops = trace_forward(rpc, report.outflows, labels, cfg, report.notes, victim=report.victim)
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


def trace_forward(rpc: SolanaRPC, start: list[Transfer], labels: LabelStore, cfg: TraceConfig, notes: list[str],
                  victim: Optional[str] = None) -> list[Hop]:
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
        if victim and node == victim:
            # e.g. the attacker tops up the victim's SOL to pay fees for the next drain
            hop.endpoint, hop.endpoint_type = "Back to the victim's own wallet - not followed further", "RETURN"
            continue
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
        sigs, busy = rpc.signatures_after(node, after_slot=t.slot or 0, max_items=max(cfg.per_node_txs, cfg.collector_txs))
        if busy:
            hop.endpoint, hop.endpoint_type = "High-activity address - typical of an exchange or service wallet (unlabelled)", "SERVICE"
            continue
        nxt: list[Transfer] = []
        scanned = 0
        for s in sigs:
            # A collector wallet first receives from many victims and only then moves the money on:
            # keep reading past the first page until something leaves, up to collector_txs.
            onward = [x for x in nxt if x.to_owner != victim]  # a fee top-up back to the victim is not "onward"
            if scanned >= cfg.per_node_txs and (onward or scanned >= cfg.collector_txs):
                break
            scanned += 1
            tx = rpc.get_transaction(s["signature"])
            if tx:
                nxt += outflows_from(tx, node, s["signature"])
        if scanned > cfg.per_node_txs:
            notes.append(
                f"{node[:4]}…{node[-4:]} mostly receives from other wallets (a collector); read {scanned} of its transactions "
                "to find where the money went next. From here on the money is pooled with other senders' funds: the next hops "
                "show where the pool went, not only this wallet's share."
            )
        if not nxt:
            hop.endpoint, hop.endpoint_type = "No outgoing movement since - funds appear to sit here", "DORMANT"
            continue
        same = sorted([x for x in nxt if x.asset == t.asset], key=lambda x: -x.amount_raw)
        other = [x for x in nxt if x.asset != t.asset]
        for x in (same + other)[: cfg.fanout]:
            queue.append((x, depth + 1))
    return hops
