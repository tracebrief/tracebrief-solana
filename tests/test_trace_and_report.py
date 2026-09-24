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


def test_poisoning_prefix_only_real_case():
    """Mainnet, 2024-11-23: 7,000,000 PYTH sent to a look-alike that matched only the
    first four characters of the address the wallet had paid 13 times before. The
    look-alike had sent the wallet 0.000001 SOL two days earlier."""
    genuine = "4yfu48qwim7hGzD3Nphzd2A6ThydzysfKi4wBPFSgnhY"
    fake = "4yfuQCL4fnNfSbBgqFcPTFn5GGZABDaEFQLhGpwjizcY"
    assert lookalike(fake, genuine)
    f = find_poisoning("T3vqZjMEi8MrJ34p", [fake], [genuine], dust_senders=[fake])
    assert f and f[0].severity == "critical"
    assert "first four characters" in f[0].detail


def test_lookalike_is_specific():
    assert not lookalike("4yfuQCL4fnNfSbBgqFcPTFn5GGZABDaEFQLhGpwjizcY", "9w2e3kpt5XUQXLdGb51nRWZoh4JFs6FL7TdEYsvKq6Wb")


def test_amounts_never_scientific():
    from tbsol.model import fmt_amount
    assert fmt_amount(7_000_000) == "7,000,000"
    assert fmt_amount(37_500_000.5) == "37,500,000.5"
    assert fmt_amount(1781.67) == "1,781.67"
    assert fmt_amount(0.000123) == "0.000123"
    assert "e" not in fmt_amount(1e-8) and "e" not in fmt_amount(3.75e7)


def test_follow_up_finds_later_delegate_spend():
    """Real pattern (mainnet, Nov 2025, ~$3M): the approval moves nothing; the drain is a
    later transaction that does not list the victim's wallet at all. The report for the
    approval must still find it and trace it."""
    from conftest import ix, make_tx, tb
    from tbsol.model import U64_MAX
    V_ATA, ATT, A_ATA, USDC = "VictimUsdcAta111111111111111111111111111111", "Attacker1111111111111111111111111111111111", \
        "AttackerUsdcAta1111111111111111111111111111", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    approve = make_tx([ix("spl-token", "approve", source=V_ATA, delegate=ATT, owner=V, amount=str(U64_MAX))],
                      signers=(V,), keys=[V, V_ATA], sig="approve")
    drain = make_tx(
        [ix("spl-token", "transferChecked", source=V_ATA, destination=A_ATA, authority=ATT, mint=USDC,
            tokenAmount={"amount": "2500000000", "decimals": 6})],
        signers=(ATT,), keys=[ATT, V_ATA, A_ATA], sig="drain",
        pre_tokens=[tb(1, USDC, V, 2_500_000_000), tb(2, USDC, ATT, 0)],
        post_tokens=[tb(1, USDC, V, 0), tb(2, USDC, ATT, 2_500_000_000)],
    )
    drain["slot"] = 101
    rep = explain("approve", V, rpc=FakeRPC({"approve": approve, "drain": drain}, {V_ATA: ["drain"]}),
                  cfg=TraceConfig(check_poisoning=False, max_hops=1))
    codes = {f.code for f in rep.findings}
    assert {"DELEGATE_APPROVED", "DELEGATE_SPEND"} <= codes
    assert rep.hops and rep.hops[0].transfer.to_owner == ATT and rep.hops[0].transfer.signature == "drain"
    assert any("Later use of the permission" in n and "1 later transaction" in n for n in rep.notes)


def test_program_moved_sol_names_the_receiver():
    from conftest import ix, make_tx
    DRAINER, SINK = "Dra1nerProgram1111111111111111111111111111", "Sink111111111111111111111111111111111111111"
    t = make_tx([{"programId": DRAINER, "accounts": [V, SINK], "data": "x", "stackHeight": 1}],
                signers=(SINK,), keys=[SINK, V], pre=[1_000_000, 1_773_680_000], post=[1_773_675_000, 1_000_000], sig="pm")
    from tbsol.classify import classify
    findings, outflows = classify(t, V)
    f = next(f for f in findings if f.code == "PROGRAM_OUTFLOW")
    assert "received" in f.detail and f.accounts["receiver"] == SINK
    assert outflows and outflows[0].to_owner == SINK and outflows[0].kind == "balance_delta"


def test_trace_does_not_follow_back_into_victim_and_reads_past_collector_inflows():
    OTHER = "OtherVictim11111111111111111111111111111111"
    txs = {"inc": sol(V, MULE, 5_000_000_000, "inc")}
    hist = []
    for i in range(30):  # the collector first receives from other victims ...
        s = f"in{i}"; txs[s] = sol(OTHER, MULE, 1_000_000_000, s, 101 + i); hist.append(s)
    txs["fee"] = sol(MULE, V, 50_000_000, "fee", 140); hist.append("fee")   # ... tops the victim up for fees ...
    txs["out"] = sol(MULE, EXCH, 30_000_000_000, "out", 141); hist.append("out")  # ... then consolidates
    rpc = FakeRPC(txs, {MULE: hist})
    labels = LabelStore({EXCH: Label(EXCH, "Example Exchange hot wallet", "EXCHANGE", "https://example.com/por")})
    rep = explain("inc", V, rpc=rpc, labels=labels, cfg=TraceConfig(check_poisoning=False, max_hops=3))
    back = [h for h in rep.hops if h.transfer.to_owner == V]
    assert back and back[0].endpoint_type == "RETURN"
    assert any(h.endpoint_type == "EXCHANGE" and h.transfer.signature == "out" for h in rep.hops)
    assert any("collector" in n for n in rep.notes)


def test_program_moved_sol_split_between_two_receivers():
    """Mainnet pattern (Nov 2025): the drainer program split 1.772676109 SOL 75/25."""
    from conftest import make_tx
    from tbsol.classify import classify
    OP, R1, R2 = "Operator11111111111111111111111111111111111", "Receiver75111111111111111111111111111111111", "Receiver25111111111111111111111111111111111"
    t = make_tx([{"programId": "Dra1nerProgram1111111111111111111111111111", "accounts": [V], "data": "x", "stackHeight": 1}],
                signers=(OP,), keys=[OP, V, R1, R2], fee=205000,
                pre=[10_000_000, 1_773_676_109, 0, 0], post=[9_795_000, 1_000_000, 1_329_507_082, 443_169_027])
    findings, outflows = classify(t, V)
    f = next(f for f in findings if f.code == "PROGRAM_OUTFLOW")
    assert set(f.accounts["receivers"]) == {R1, R2}
    assert {o.to_owner for o in outflows} == {R1, R2}
