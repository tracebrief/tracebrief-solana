"""Explain *how* value left the victim's wallet in one transaction.

A plain transfer tracer only sees coins moving. On Solana a large share of
thefts do not look like the victim sending coins at all:

* the victim once signed an ``approve`` and a delegate moves the tokens later;
* the victim signed a ``setAuthority`` that hands the token account itself to
  the attacker - nothing moves in that transaction, yet the tokens are gone;
* the wallet account is ``assign``-ed to a malicious program;
* a durable-nonce transaction was pre-signed long before it was executed;
* token accounts are closed with the rent sent to someone else.

Each rule below produces a :class:`~tbsol.model.Finding` with the signature
that proves it. Wording is factual and neutral: the same instruction can be
legitimate (a limit-order program also asks for a delegate), so findings say
what the permission allows, not who is guilty.
"""

from __future__ import annotations

from .model import U64_MAX, Finding, Transfer, fmt_amount
from .parse import (
    SYSTEM_PROGRAM,
    account_keys,
    iter_instructions,
    outflows_from,
    parsed,
    signers,
    sol_delta,
    token_accounts,
    token_deltas_by_owner,
    extract_transfers,
    fee_payer,
    burns_by_owner,
    sol_spent_explicitly,
)


def _short(a: str | None) -> str:
    return f"{a[:4]}…{a[-4:]}" if a and len(a) > 12 else str(a)


def classify(tx: dict, victim: str) -> tuple[list[Finding], list[Transfer]]:
    """Return ``(findings, outflows_from_victim)`` for one transaction."""
    sig = tx["transaction"]["signatures"][0]
    findings: list[Finding] = []
    tas = token_accounts(tx)
    victim_signed = victim in signers(tx)
    first = True

    for outer_i, inner_i, ix in iter_instructions(tx):
        program, typ, info = parsed(ix)
        is_first_outer = first and inner_i is None
        if inner_i is None:
            first = False

        # --- durable nonce: the transaction could have been signed long ago --------
        if is_first_outer and program == "system" and typ == "advanceNonce":
            findings.append(Finding(
                code="DURABLE_NONCE", severity="medium",
                title="Pre-signed transaction (durable nonce)",
                detail=(
                    "This transaction uses a durable nonce, so it does not expire. It could have been "
                    "signed days or weeks before it was executed - which explains a theft that happened "
                    "while the owner was not signing anything."
                ),
                signature=sig, accounts={"nonce_account": info.get("nonceAccount"), "nonce_authority": info.get("nonceAuthority")},
            ))

        if program == "spl-token" and typ == "setAuthority":
            acc = info.get("account")
            owner = tas.get(acc, {}).get("owner") or info.get("authority")
            new = info.get("newAuthority")
            kind = info.get("authorityType")
            if owner == victim and new and new != victim:
                if kind == "accountOwner":
                    findings.append(Finding(
                        code="OWNER_REASSIGNED", severity="critical",
                        title="Token account ownership handed to another address",
                        detail=(
                            f"The owner of token account {_short(acc)} was changed from the victim to {_short(new)}. "
                            "No tokens move in this step, so simple transfer tracing shows nothing - but from now on "
                            "only the new owner can move the balance."
                        ),
                        signature=sig, accounts={"token_account": acc, "old_owner": victim, "new_owner": new},
                    ))
                elif kind == "closeAccount":
                    findings.append(Finding(
                        code="CLOSE_AUTHORITY_REASSIGNED", severity="high",
                        title="Another address may now close this token account",
                        detail=(
                            f"Close authority of token account {_short(acc)} was given to {_short(new)}. "
                            "That address can close the account and collect its lamports."
                        ),
                        signature=sig, accounts={"token_account": acc, "new_close_authority": new},
                    ))

        if program == "spl-token" and typ in ("approve", "approveChecked"):
            owner = info.get("owner") or tas.get(info.get("source"), {}).get("owner")
            delegate = info.get("delegate")
            if owner == victim and delegate and delegate != victim:
                amt = int((info.get("tokenAmount") or {}).get("amount") or info.get("amount") or 0)
                unlimited = amt >= U64_MAX
                findings.append(Finding(
                    code="DELEGATE_APPROVED", severity="critical" if unlimited else "high",
                    title="Unlimited spending permission granted" if unlimited else "Spending permission granted",
                    detail=(
                        f"{_short(delegate)} was allowed to move "
                        + ("an unlimited amount" if unlimited else f"up to {amt} raw units")
                        + f" from token account {_short(info.get('source'))} without asking the owner again. "
                        "If this was not intended, it is how tokens can leave later without a new signature."
                    ),
                    signature=sig, accounts={"token_account": info.get("source"), "delegate": delegate, "mint": info.get("mint")},
                ))

        if program == "system" and typ == "assign" and info.get("account") == victim and info.get("owner") != SYSTEM_PROGRAM:
            findings.append(Finding(
                code="WALLET_ASSIGNED", severity="critical",
                title="Wallet account reassigned to a program",
                detail=(
                    f"The wallet itself was assigned to program {_short(info.get('owner'))}. "
                    "After this, the program - not the private key - decides what happens to the SOL in it."
                ),
                signature=sig, accounts={"wallet": victim, "program": info.get("owner")},
            ))

        if program == "spl-token" and typ == "closeAccount":
            acc, dst = info.get("account"), info.get("destination")
            owner = info.get("owner") or tas.get(acc, {}).get("owner")
            if owner == victim and dst and dst != victim:
                findings.append(Finding(
                    code="ACCOUNT_CLOSED_TO_OTHER", severity="high",
                    title="Token account closed, lamports sent to another address",
                    detail=f"Token account {_short(acc)} was closed and its lamports went to {_short(dst)}.",
                    signature=sig, accounts={"token_account": acc, "destination": dst},
                ))

    outflows = outflows_from(tx, victim, sig)
    for t in outflows:
        if t.via_delegate:
            findings.append(Finding(
                code="DELEGATE_SPEND", severity="critical",
                title="Tokens moved by a delegate, not by the owner",
                detail=(
                    f"{fmt_amount(t.amount)} of {_short(t.asset)} left the victim's account {_short(t.from_account)}. "
                    f"The move was authorised by {_short(t.authority)}, not by the owner - a permission granted "
                    "earlier was used."
                ),
                signature=sig, accounts={"authority": t.authority, "to_owner": t.to_owner, "asset": t.asset},
            ))

    direct = [t for t in outflows if not t.via_delegate and t.kind == "transfer"]
    if direct and victim_signed:
        findings.append(Finding(
            code="SIGNED_TRANSFER_OUT", severity="info",
            title="Transfer signed by the wallet owner",
            detail=(
                f"The owner's key signed {len(direct)} outgoing transfer(s) in this transaction. "
                "If the owner did not intend this, the signature was obtained by deception (a fake site or "
                "a malicious approval prompt) or the private key / seed phrase is known to someone else."
            ),
            signature=sig, accounts={"recipients": sorted({t.to_owner for t in direct if t.to_owner})},
        ))

    # Value that left without an explicit transfer instruction (moved by a program).
    # Everything the wallet itself sent with system instructions is explained,
    # including SOL moved into its own wSOL account and rent for new accounts.
    explicit_sol = sol_spent_explicitly(tx, victim)
    fee = (tx.get("meta") or {}).get("fee", 0) if victim == fee_payer(tx) else 0
    unexplained_sol = -sol_delta(tx, victim) - explicit_sol - fee
    if unexplained_sol > 1_000_000:  # > 0.001 SOL, ignore rent noise
        # Balance changes are on-chain facts. If the accounts that gained SOL in this transaction
        # together account for what the wallet lost, name them and make them traceable edges
        # (drainers often split the take, e.g. 75/25 between two addresses).
        gainers = sorted(
            ((a, sol_delta(tx, a)) for a in account_keys(tx) if a != victim and sol_delta(tx, a) > 0),
            key=lambda x: -x[1],
        )
        gained = sum(d for _, d in gainers)
        receivers = [g for g in gainers if g[1] >= 0.01 * unexplained_sol] if 0.95 * unexplained_sol <= gained <= 1.05 * unexplained_sol else []
        detail = (
            f"{fmt_amount(unexplained_sol / 1e9)} SOL left the wallet without a plain transfer instruction - "
            "a program moved it."
        )
        if receivers:
            parts = ", ".join(f"{_short(a)} received {fmt_amount(d / 1e9)} SOL" for a, d in receivers)
            detail += f" Balance changes in the same transaction show: {parts}."
            for a, d in receivers:
                outflows.append(Transfer(
                    signature=sig, asset="SOL", amount_raw=d, decimals=9,
                    from_owner=victim, to_owner=a, from_account=victim, to_account=a,
                    kind="balance_delta", slot=tx.get("slot"), block_time=tx.get("blockTime"),
                ))
        else:
            detail += " Check which program this transaction called."
        receiver = receivers[0] if receivers else None
        findings.append(Finding(
            code="PROGRAM_OUTFLOW", severity="high",
            title="SOL left the wallet through a program",
            detail=detail,
            signature=sig, accounts={"wallet": victim, "receiver": receiver[0] if receiver else None,
                                     "receivers": [a for a, _ in receivers]},
        ))
    explicit_tok: dict[str, int] = {}
    for t in outflows:
        if t.asset != "SOL":
            explicit_tok[t.asset] = explicit_tok.get(t.asset, 0) + t.amount_raw
    burned = burns_by_owner(tx, victim)
    for mint, delta in token_deltas_by_owner(tx, victim).items():
        missing = -delta - explicit_tok.get(mint, 0) - burned.get(mint, 0)
        if delta < 0 and missing > 0 and not any(f.code == "OWNER_REASSIGNED" for f in findings):
            findings.append(Finding(
                code="PROGRAM_OUTFLOW", severity="high",
                title="Tokens left the wallet through a program",
                detail=f"{missing} raw units of {_short(mint)} left the victim's token accounts without a matching transfer instruction.",
                signature=sig, accounts={"mint": mint},
            ))

    if not victim_signed and (outflows or any(f.severity == "critical" for f in findings)):
        findings.append(Finding(
            code="NOT_SIGNED_BY_VICTIM", severity="info",
            title="The victim did not sign this transaction",
            detail=(
                "The loss happened without the owner's signature in this transaction. That points to a permission "
                "granted earlier (delegate, ownership change) rather than a stolen key."
            ),
            signature=sig, accounts={"signers": sorted(signers(tx))},
        ))
    return findings, outflows


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))


__all__ = ["classify", "sort_findings", "extract_transfers"]
