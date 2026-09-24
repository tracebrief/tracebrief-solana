"""Render an :class:`IncidentReport` as plain-language Markdown or JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .labels import asset_name
from .model import IncidentReport, fmt_amount

EXPLORER = "https://solscan.io/tx/"
SEV_MARK = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "info": "INFO"}


def _s(a: str | None) -> str:
    return f"`{a[:4]}…{a[-4:]}`" if a and len(a) > 12 else f"`{a}`"


def _when(ts: int | None) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "unknown time"


def to_json(report: IncidentReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def to_markdown(report: IncidentReport) -> str:
    L: list[str] = []
    L.append("# TraceBrief - Solana incident explanation\n")
    L.append(f"- **Transaction:** [{report.signature[:12]}…]({EXPLORER}{report.signature})")
    L.append(f"- **Time:** {_when(report.block_time)} (slot {report.slot})")
    L.append(f"- **Wallet examined:** `{report.victim}`")
    L.append(f"- **Signed by this wallet:** {'yes' if report.victim_signed else 'no'}\n")

    L.append("## What happened\n")
    if not report.findings:
        L.append("No loss-related pattern was found for this wallet in this transaction.\n")
    for f in report.findings:
        L.append(f"**[{SEV_MARK.get(f.severity, f.severity)}] {f.title}**  ")
        L.append(f"{f.detail}  ")
        L.append(f"Evidence: [{f.signature[:12]}…]({EXPLORER}{f.signature})\n")

    L.append("## Where the funds went\n")
    if not report.hops:
        L.append("No outgoing value from this wallet in this transaction.\n")
    else:
        L.append("| Hop | From | To | Amount | Transaction | Stops here because |")
        L.append("|---|---|---|---|---|---|")
        for h in report.hops:
            t = h.transfer
            kind = {"ownership_change": " (ownership change)", "close_account_rent": " (account rent)",
                    "balance_delta": " (moved by a program)"}.get(t.kind, "")
            L.append(
                f"| {h.depth} | {_s(t.from_owner)} | {_s(t.to_owner)} | {fmt_amount(t.amount)} {asset_name(t.asset)}{kind} | "
                f"[{t.signature[:8]}…]({EXPLORER}{t.signature}) | {h.endpoint or '-'} |"
            )
        L.append("")
        exch = [h for h in report.hops if h.endpoint_type == "EXCHANGE"]
        svc = [h for h in report.hops if h.endpoint_type == "SERVICE"]
        if exch or svc:
            L.append("### Who to contact\n")
            for h in exch:
                L.append(f"- {h.endpoint}: deposit address `{h.transfer.to_owner}`, reference transaction `{h.transfer.signature}`.")
            for h in svc:
                L.append(
                    f"- Unlabelled high-activity address `{h.transfer.to_owner}` (reference transaction `{h.transfer.signature}`). "
                    "It behaves like an exchange or service wallet; confirm who operates it before contacting anyone."
                )
            L.append("")
    if report.notes:
        L.append("## Notes\n")
        L.extend(f"- {n}" for n in report.notes)
        L.append("")
    L.append("## Method and limits\n")
    L.append(
        "Read-only analysis of public Solana data (getTransaction, jsonParsed). Every statement links to the "
        "transaction that proves it. Labels come only from primary sources and name companies or protocols, never "
        "private individuals. A trail stops at a labelled endpoint, a program-controlled account, a high-activity "
        "address, a dormant address or the hop limit - the report says which. This is not legal advice and does not "
        "recover funds."
    )
    return "\n".join(L) + "\n"
