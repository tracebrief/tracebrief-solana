"""Tracer, poisoning, labels and report tests with an offline fake RPC."""

import pytest
from conftest import ix, make_tx, tb

from tbsol.labels import Label, LabelStore
from tbsol.poisoning import find_poisoning, lookalike
from tbsol.report import to_json, to_markdown
from tbsol.trace import TraceConfig, explain

V = "VictimWa11et1111111111111111111111111111111"
MULE = "Mu1eWa11et111111111111111111111111111111111"
EXCH = "ExchangeHotWa11et11111111111111111111111111"
SYSTEM = "11111111111111111111111111111111"


class FakeRPC:
    def __init__(self, txs, history, owners=None):
        self.txs, self.history, self.owners = txs, history, owners or {}

    def get_transaction(self, sig):
        return self.txs.get(sig)

    def get_signatures(self, address, limit=100, before=None):
        return []

    def signatures_after(self, address, after_slot, max_items=50, **_):
        return [{"signature": s, "slot": after_slot + 1 + i, "err": None} for i, s in enumerate(self.history.get(address, []))], False

    def get_account_owner_program(self, address):
        return self.owners.get(address, SYSTEM)


def sol(src, dst, lamports, sig, slot=100):
    t = make_tx([ix("system", "transfer", source=src, destination=dst, lamports=lamports)], signers=(src,), keys=[src, dst], sig=sig)
    t["slot"] = slot
    return t


def test_trace_to_labelled_exchange():
    rpc = FakeRPC(
        txs={"inc": sol(V, MULE, 5_000_000_000, "inc"), "h2": sol(MULE, EXCH, 4_900_000_000, "h2", 101)},
        history={MULE: ["h2"]},
    )
    labels = LabelStore({EXCH: Label(EXCH, "Example Exchange hot wallet", "EXCHANGE", "https://example.com/por")})
    rep = explain("inc", V, rpc=rpc, labels=labels, cfg=TraceConfig(check_poisoning=False))
    assert [h.depth for h in rep.hops] == [1, 2]
    assert rep.hops[-1].endpoint_type == "EXCHANGE"
    md = to_markdown(rep)
    assert "Who to contact" in md and "Example Exchange" in md and "h2" in md


def test_trace_stops_at_dormant_and_program_accounts():
    vault = "PoolVau1t11111111111111111111111111111111111"
    rpc = FakeRPC(
        txs={"inc": sol(V, MULE, 1_000_000_000, "inc")},
        history={},
        owners={MULE: SYSTEM},
    )
    rep = explain("inc", V, rpc=rpc, cfg=TraceConfig(check_poisoning=False))
    assert rep.hops[0].endpoint_type == "DORMANT"

    rpc2 = FakeRPC(txs={"inc": sol(V, vault, 1_000_000_000, "inc")}, history={}, owners={vault: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"})
    rep2 = explain("inc", V, rpc=rpc2, cfg=TraceConfig(check_poisoning=False))
    assert rep2.hops[0].endpoint_type == "DEX" and "Jupiter" in rep2.hops[0].endpoint


def test_hop_limit():
    chain = {"inc": sol(V, "A" * 44, 10, "inc")}
    hist = {}
    prev = "A" * 44
    for i, nxt in enumerate(["B" * 44, "C" * 44, "D" * 44]):
        chain[f"s{i}"] = sol(prev, nxt, 10, f"s{i}", 101 + i)
        hist[prev] = [f"s{i}"]
        prev = nxt
    rep = explain("inc", V, rpc=FakeRPC(chain, hist), cfg=TraceConfig(max_hops=2, check_poisoning=False))
    assert rep.hops[-1].endpoint_type == "LIMIT" and rep.hops[-1].depth == 2


def test_ownership_change_becomes_traceable_edge():
    usdc, ata, attacker = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "VictimUsdcAta111111111111111111111111111111", "Attacker1111111111111111111111111111111111"
    t = make_tx([ix("spl-token", "setAuthority", account=ata, authority=V, authorityType="accountOwner", newAuthority=attacker)],
                keys=[V, ata], pre_tokens=[tb(1, usdc, V, 7_000_000)], post_tokens=[tb(1, usdc, attacker, 7_000_000)], sig="own")
    rep = explain("own", V, rpc=FakeRPC({"own": t}, {}), cfg=TraceConfig(check_poisoning=False))
    assert rep.hops and rep.hops[0].transfer.kind == "ownership_change" and rep.hops[0].transfer.to_owner == attacker
    assert "ownership change" in to_markdown(rep)


def test_poisoning_detection():
    genuine = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
    fake = "7xKXzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzgAsU"
    assert lookalike(fake, genuine) and not lookalike(genuine, genuine)
    f = find_poisoning("sig", [fake], [genuine], dust_senders=[fake])
    assert f and f[0].severity == "critical" and f[0].accounts["genuine_counterparty"] == genuine
    assert find_poisoning("sig", [genuine], [genuine]) == []


def test_labels_require_source(tmp_path):
    p = tmp_path / "labels.csv"
    p.write_text("address,label,type,source\nAbc,Some Exchange,exchange,\n")
    with pytest.raises(ValueError):
        LabelStore.from_csv(str(p))
    p.write_text("address,label,type,source\nAbc,Some Exchange,exchange,https://x.example/por\n")
    store = LabelStore.from_csv(str(p))
    assert store.get("Abc").type == "EXCHANGE"


def test_json_output_roundtrip():
    rpc = FakeRPC({"inc": sol(V, MULE, 5, "inc")}, {})
    import json
    d = json.loads(to_json(explain("inc", V, rpc=rpc, cfg=TraceConfig(check_poisoning=False))))
    assert d["signature"] == "inc" and d["hops"][0]["to_owner"] == MULE
