"""Classifier tests: real mainnet transactions + synthetic attack scenarios."""

from conftest import ix, make_tx, tb

from tbsol.classify import classify
from tbsol.model import U64_MAX
from tbsol.parse import extract_transfers, outflows_from

V = "VictimWa11et1111111111111111111111111111111"
ATTACKER = "Attacker1111111111111111111111111111111111"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
V_ATA = "VictimUsdcAta111111111111111111111111111111"
A_ATA = "AttackerUsdcAta1111111111111111111111111111"


def codes(findings):
    return {f.code for f in findings}


# --- real mainnet transactions ------------------------------------------------

def test_real_unlimited_approve_is_critical(tx):
    t = tx("spl-token_approveChecked")
    findings, _ = classify(t, "D353humRbsSRGXoYpGJE9SFCNLWV5Xs433YcrfiEXrws")
    approve = [f for f in findings if f.code == "DELEGATE_APPROVED"]
    assert approve and approve[0].severity == "critical"
    assert "unlimited" in approve[0].detail
    assert "CLOSE_AUTHORITY_REASSIGNED" in codes(findings)


def test_real_limited_approve_is_high_and_burn_is_not_outflow(tx):
    findings, _ = classify(tx("spl-token_approve"), "ChvTZ5KDn7jCUgtS74yWHazfD3bdGD1NcBx2sfdyKDEy")
    assert codes(findings) == {"DELEGATE_APPROVED"}
    assert findings[0].severity == "high"


def test_real_durable_nonce_detected(tx):
    findings, outflows = classify(tx("system_advanceNonce"), "9nXDunV8eNvYSVys7JSBkm2hz9Q79Q3EYeko19srVeMC")
    assert "DURABLE_NONCE" in codes(findings)
    assert outflows


def test_real_close_account_to_other(tx):
    findings, _ = classify(tx("spl-token_closeAccount"), "BtDPEEogqm2y1szgtwTEYKHRAaZDpr3vW3M2mMCThZ15")
    assert "ACCOUNT_CLOSED_TO_OTHER" in codes(findings)


def test_real_plain_sol_transfer(tx):
    t = tx("system_transfer")
    victim = t["transaction"]["message"]["accountKeys"][0]["pubkey"]
    findings, outflows = classify(t, victim)
    assert codes(findings) == {"SIGNED_TRANSFER_OUT"}
    assert len(outflows) == 1 and outflows[0].asset == "SOL" and outflows[0].amount_raw == 68319365


def test_real_usdc_transfer_checked_owners_resolved(tx):
    t = tx("spl-token_transferChecked")
    transfers = extract_transfers(t)
    assert transfers[0].asset == USDC and transfers[0].decimals == 6
    assert transfers[0].to_owner == "7uTT8Xi5RWXzy7h9XL244GRgEycDYDhLjr3ZyNdXi8pZ"
    assert outflows_from(t, "GLPNCbk9zWeCb9roa7QkRQYipPEcaBQpuG9AZNybmGkZ")


def test_real_assign_of_new_token_account_is_not_wallet_assign(tx):
    t = tx("system_assign")
    victim = t["transaction"]["message"]["accountKeys"][0]["pubkey"]
    findings, _ = classify(t, victim)
    assert "WALLET_ASSIGNED" not in codes(findings)


def test_all_real_fixtures_parse(tx):
    for name in ["spl-token_transfer", "spl-token_transferCheckedWithFee", "system_assign", "spl-token_closeAccount"]:
        t = tx(name)
        for tr in extract_transfers(t):
            assert tr.amount_raw >= 0 and tr.signature == t["transaction"]["signatures"][0]


# --- synthetic attack scenarios ------------------------------------------------

def test_owner_reassigned_without_any_transfer():
    t = make_tx(
        [ix("spl-token", "setAuthority", account=V_ATA, authority=V, authorityType="accountOwner", newAuthority=ATTACKER)],
        keys=[V, V_ATA], pre_tokens=[tb(1, USDC, V, 5_000_000_000)], post_tokens=[tb(1, USDC, ATTACKER, 5_000_000_000)],
    )
    findings, outflows = classify(t, V)
    assert "OWNER_REASSIGNED" in codes(findings)
    assert not outflows  # nothing moved - which is exactly why plain tracers miss it
    f = next(f for f in findings if f.code == "OWNER_REASSIGNED")
    assert f.accounts["new_owner"] == ATTACKER and f.severity == "critical"


def test_delegate_spend_without_victim_signature():
    t = make_tx(
        [ix("spl-token", "transferChecked", source=V_ATA, destination=A_ATA, authority=ATTACKER, mint=USDC,
            tokenAmount={"amount": "2500000000", "decimals": 6})],
        signers=(ATTACKER,), keys=[ATTACKER, V_ATA, A_ATA],
        pre_tokens=[tb(1, USDC, V, 2_500_000_000), tb(2, USDC, ATTACKER, 0)],
        post_tokens=[tb(1, USDC, V, 0), tb(2, USDC, ATTACKER, 2_500_000_000)],
    )
    findings, outflows = classify(t, V)
    assert {"DELEGATE_SPEND", "NOT_SIGNED_BY_VICTIM"} <= codes(findings)
    assert outflows[0].via_delegate and outflows[0].amount == 2500.0


def test_wallet_assigned_to_program():
    t = make_tx([ix("system", "assign", account=V, owner="Ma1iciousProgram11111111111111111111111111")], keys=[V])
    findings, _ = classify(t, V)
    assert "WALLET_ASSIGNED" in codes(findings)


def test_unlimited_plain_approve():
    t = make_tx([ix("spl-token", "approve", source=V_ATA, delegate=ATTACKER, owner=V, amount=str(U64_MAX))], keys=[V, V_ATA])
    findings, _ = classify(t, V)
    assert next(f for f in findings if f.code == "DELEGATE_APPROVED").severity == "critical"


def test_sol_into_own_wsol_account_is_not_an_outflow():
    wsol = "So11111111111111111111111111111111111111112"
    own_wsol_ata = "VictimWsolAta11111111111111111111111111111"
    t = make_tx(
        [ix("system", "transfer", source=V, destination=own_wsol_ata, lamports=1_000_000_000)],
        keys=[V, own_wsol_ata], pre_tokens=[tb(1, wsol, V, 0, 9)], post_tokens=[tb(1, wsol, V, 1_000_000_000, 9)],
        pre=[2_000_000_000, 2_039_280], post=[999_995_000, 1_002_039_280],
    )
    findings, outflows = classify(t, V)
    assert not outflows and "PROGRAM_OUTFLOW" not in codes(findings)


def test_sol_moved_by_program_is_flagged():
    other = "Receiver111111111111111111111111111111111111"
    t = make_tx([{"programId": "Dra1nerProgram1111111111111111111111111111", "accounts": [V, other], "data": ""}],
                keys=[V, other], pre=[5_000_000_000, 0], post=[1_000_000_000, 3_999_995_000])
    findings, _ = classify(t, V)
    assert "PROGRAM_OUTFLOW" in codes(findings)
