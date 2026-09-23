import copy
import json
import pathlib

import pytest

FIX = pathlib.Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIX / f"{name}.json").read_text())


@pytest.fixture
def tx():
    """Return a fresh deep copy of a real mainnet fixture by name."""
    return lambda name: copy.deepcopy(load(name))


def make_tx(instructions, signers=("VictimWa11et1111111111111111111111111111111",), pre=None, post=None,
            pre_tokens=None, post_tokens=None, keys=None, fee=5000, sig="SyntheticSig111"):
    """Build a minimal jsonParsed transaction for synthetic scenarios."""
    keys = list(keys or signers)
    return {
        "slot": 100, "blockTime": 1_790_000_000, "version": 0,
        "transaction": {
            "signatures": [sig],
            "message": {
                "accountKeys": [{"pubkey": k, "signer": k in signers, "writable": True, "source": "transaction"} for k in keys],
                "instructions": instructions,
            },
        },
        "meta": {
            "err": None, "fee": fee,
            "preBalances": pre or [0] * len(keys), "postBalances": post or [0] * len(keys),
            "preTokenBalances": pre_tokens or [], "postTokenBalances": post_tokens or [],
            "innerInstructions": [],
        },
    }


def ix(program, typ, **info):
    return {"program": program, "parsed": {"type": typ, "info": info}, "programId": "x", "stackHeight": 1}


def tb(index, mint, owner, amount, decimals=6):
    return {"accountIndex": index, "mint": mint, "owner": owner, "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "uiTokenAmount": {"amount": str(amount), "decimals": decimals}}
