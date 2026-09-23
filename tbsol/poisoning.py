"""Address-poisoning check.

Attackers send dust from an address whose first and last characters match an
address the victim uses, hoping the victim copies the fake one from history.
Wallets usually show only ``ABCD…WXYZ``, so a look-alike is enough.

Given the recipients of the incident and the victim's earlier counterparties,
this flags recipients that *look like* a previous counterparty but are not.
"""

from __future__ import annotations

from typing import Iterable, Optional

from .model import Finding


def lookalike(a: str, b: str, head: int = 4, tail: int = 4) -> bool:
    return a != b and a[:head] == b[:head] and a[-tail:] == b[-tail:]


def find_poisoning(
    incident_signature: str,
    recipients: Iterable[str],
    previous_counterparties: Iterable[str],
    dust_senders: Optional[Iterable[str]] = None,
) -> list[Finding]:
    prev = set(previous_counterparties)
    dust = set(dust_senders or [])
    out: list[Finding] = []
    for r in set(recipients):
        if r in prev:
            continue
        for c in prev:
            if lookalike(r, c):
                sent_dust = r in dust
                out.append(Finding(
                    code="POISONED_ADDRESS", severity="critical" if sent_dust else "high",
                    title="Funds went to a look-alike of an address used before",
                    detail=(
                        f"The recipient {r[:4]}…{r[-4:]} matches the first and last characters of {c[:4]}…{c[-4:]}, "
                        "an address this wallet had sent to before, but it is a different address."
                        + (" It had also sent a tiny 'dust' transfer to this wallet earlier - the classic address-poisoning setup." if sent_dust else "")
                    ),
                    signature=incident_signature,
                    accounts={"recipient": r, "genuine_counterparty": c, "sent_dust": sent_dust},
                ))
                break
    return out
