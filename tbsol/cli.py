"""Command line: ``python -m tbsol explain <signature> [--victim ADDRESS]``."""

from __future__ import annotations

import argparse
import json
import sys

from .classify import classify, sort_findings
from .labels import LabelStore
from .model import IncidentReport
from .report import to_json, to_markdown
from .rpc import DEFAULT_RPC, SolanaRPC
from .trace import TraceConfig, explain


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tbsol", description="Explain how funds left a Solana wallet and where they went.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("explain", help="explain an incident transaction and trace funds forward")
    e.add_argument("signature")
    e.add_argument("--victim", help="wallet that lost funds (default: fee payer)")
    e.add_argument("--hops", type=int, default=4)
    e.add_argument("--fanout", type=int, default=5)
    e.add_argument("--labels", help="CSV with address,label,type,source")
    e.add_argument("--rpc", default=DEFAULT_RPC)
    e.add_argument("--no-poisoning", action="store_true", help="skip the address-poisoning history check")
    e.add_argument("--no-trace", action="store_true", help="classify only, do not follow funds")
    e.add_argument("--json", action="store_true")

    o = sub.add_parser("offline", help="classify a saved getTransaction JSON (no network)")
    o.add_argument("file")
    o.add_argument("--victim", required=True)
    o.add_argument("--json", action="store_true")

    a = ap.parse_args(argv)
    if a.cmd == "offline":
        tx = json.load(open(a.file))
        findings, outflows = classify(tx, a.victim)
        rep = IncidentReport(victim=a.victim, signature=tx["transaction"]["signatures"][0], slot=tx.get("slot"),
                             block_time=tx.get("blockTime"), victim_signed=any(k.get("signer") and k["pubkey"] == a.victim for k in tx["transaction"]["message"]["accountKeys"]),
                             findings=sort_findings(findings), outflows=outflows)
        print(to_json(rep) if a.json else to_markdown(rep))
        return 0

    labels = LabelStore.from_csv(a.labels) if a.labels else LabelStore()
    cfg = TraceConfig(max_hops=0 if a.no_trace else a.hops, fanout=a.fanout, check_poisoning=not a.no_poisoning)
    rep = explain(a.signature, a.victim, SolanaRPC(a.rpc), labels, cfg)
    if a.no_trace:
        rep.hops = []
    print(to_json(rep) if a.json else to_markdown(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
