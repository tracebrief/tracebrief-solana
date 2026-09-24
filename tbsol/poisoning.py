"""Address-poisoning check.

Attackers send dust from an address whose first and/or last characters match an
address the victim uses, hoping the victim copies the fake one from history.
Wallets usually show only ``ABCD…WXYZ``, and many people check only the start,
so matching the first four OR the last four characters is enough to fool them
(a real case: 7,000,000 PYTH sent to ``4yfu…izcY`` instead of ``4yfu…gnhY``).
A random address matches four given base58 characters with probability 1/58^4
(about 1 in 11 million), so the check stays specific.

Given the recipients of the incident and the victim's earlier counterparties,
this flags recipients that *look like* a previous counterparty but are not.
"""

from __future__ import annotations

from typing import Iterable, Optional

from .model import Finding


def lookalike(a: str, b: str, head: int = 4, tail: int = 4) -> bool:
    """Different address that shares the first ``head`` OR the last ``tail`` characters."""
    return a != b and (a[:head] == b[:head] or a[-tail:] == b[-tail:])


def _match_desc(a: str, b: str) -> str:
    head, tail = a[:4] == b[:4], a[-4:] == b[-4:]
    if head and tail:
        return "the first and last characters"
    return "the first four characters" if head else "the last four characters"


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
                        f"The recipient {r[:4]}…{r[-4:]} matches {_match_desc(r, c)} of {c[:4]}…{c[-4:]}, "
                        "an address this wallet had sent to before, but it is a different address."
                        + (" It had also sent a tiny 'dust' transfer to this wallet earlier - the classic address-poisoning setup." if sent_dust else "")
                    ),
                    signature=incident_signature,
                    accounts={"recipient": r, "genuine_counterparty": c, "sent_dust": sent_dust},
                ))
                break
    return out
