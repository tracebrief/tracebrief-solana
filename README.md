# tracebrief-solana

**Explain how funds left a Solana wallet - and where they went - in words a victim, an exchange and a police officer can read.**

`tbsol` is the open-source Solana module of [TraceBrief](https://tracebrief.io), a fund-tracing report service for people who lost crypto to a scam. It was built during the [Colosseum Crypto World's Fair](https://colosseum.com/worldsfair) hackathon (September-October 2026).

## Why this exists

Transfer tracers answer *"where did the coins go?"*. On Solana that is often the wrong first question, because many thefts do not look like the victim sending coins at all:

| What the victim experiences | What actually happened on-chain | Code |
|---|---|---|
| "My USDC is gone, but I never sent it" | An earlier `approve` gave a delegate spending rights; the delegate moved the tokens | `DELEGATE_APPROVED`, `DELEGATE_SPEND` |
| "Nothing moved, but I can't use my tokens" | `setAuthority` (accountOwner) handed the **token account itself** to the attacker - zero transfers in that transaction | `OWNER_REASSIGNED` |
| "I didn't sign anything today" | A **durable-nonce** transaction was pre-signed earlier and executed later | `DURABLE_NONCE` |
| "My SOL disappeared without a transfer" | The wallet was `assign`-ed to a program, or a program moved lamports directly | `WALLET_ASSIGNED`, `PROGRAM_OUTFLOW` |
| "I sent it to my usual address" | The recipient only *looks* like a previous counterparty (same first/last characters) - address poisoning | `POISONED_ADDRESS` |

`tbsol` detects these patterns, states each one in plain language, and attaches the transaction signature that proves it. Then it follows the funds forward hop by hop and says exactly why the trail stops.

## Quick start

Python 3.10+, no dependencies (stdlib only).

```bash
git clone https://github.com/tracebrief/tracebrief-solana && cd tracebrief-solana

# explain an incident and trace funds forward (public RPC by default)
python -m tbsol explain <SIGNATURE> --victim <WALLET> --hops 4

# classify a saved getTransaction JSON offline
python -m tbsol offline tests/fixtures/spl-token_approveChecked.json \
    --victim D353humRbsSRGXoYpGJE9SFCNLWV5Xs433YcrfiEXrws

# machine-readable output for the TraceBrief PDF renderer
python -m tbsol explain <SIGNATURE> --victim <WALLET> --json
```

Options: `--rpc URL` (use your own RPC for speed), `--labels labels.csv`, `--no-poisoning`, `--no-trace`, `--fanout N`.

Sample outputs: [`examples/owner-change-drain.md`](examples/owner-change-drain.md) (synthetic ownership-change drain) and [`examples/unlimited-approval-mainnet.md`](examples/unlimited-approval-mainnet.md) (real mainnet transaction).

## How it works

```
signature ──► getTransaction (jsonParsed, maxSupportedTransactionVersion=1)
                │
                ├─ parse.py     outer + inner (CPI) instructions, SOL/SPL transfers,
                │               pre/post token-account owners, burns, rent
                ├─ classify.py  how value left: delegate, owner change, nonce, assign,
                │               closed accounts, program-moved value, signer check
                ├─ poisoning.py look-alike recipient vs. earlier counterparties + dust
                └─ trace.py     follow wallets forward until an endpoint:
                                  labelled exchange/bridge/DEX (primary source only)
                                  program-controlled account (pool, vault, escrow)
                                  high-activity address (service-like, unlabelled)
                                  dormant address (funds still there)
                                  hop limit
                        ▼
                report.py  Markdown / JSON, every claim linked to its signature
```

Design rules inherited from TraceBrief:

- **Read-only.** Public chain data only. No keys, no custody, no signing.
- **Every claim is verifiable.** Each finding and hop carries the transaction signature.
- **Labels need a primary source.** Exchange lists come from exchanges' own proof-of-reserves publications, sanctions from OFAC, program IDs from protocol docs. The CSV loader refuses a label without a source. Labels name companies and protocols, **never private individuals**.
- **No guessing.** When the trail cannot be followed with evidence, the report says where and why it stops.
- **Neutral wording.** An unlimited approval can be legitimate (limit-order programs ask for one). Findings describe what a permission allows, not who is guilty.

## Labels

Built-in: program IDs verified on mainnet (System, SPL Token, Token-2022, Associated Token Account, Jupiter v6, Raydium AMM v4, Wormhole core and token bridge). Exchange wallets are supplied at runtime:

```csv
address,label,type,source
<base58 address>,Example Exchange hot wallet,EXCHANGE,https://example.com/proof-of-reserves
```

TraceBrief's production label set (exchange proof-of-reserves wallets, OFAC list) is maintained separately and is not part of this repository.

## Tests

```bash
pip install pytest && python -m pytest -q
```

The suite combines **real mainnet transactions** captured with `getTransaction` (unlimited `approveChecked`, `approve` + `burn`, durable nonce, `closeAccount`, `assign`, SOL and USDC transfers, Token-2022 `transferCheckedWithFee`) with **synthetic attack scenarios** (ownership change without any transfer, delegate spend without the victim's signature, wallet reassignment, SOL moved by a program, address poisoning) and an offline fake RPC for the tracer.

## Limits

- The public RPC is rate-limited; use `--rpc` with your own endpoint for real cases.
- Swaps are followed as outflows of any asset from the wallet; the report does not yet price assets in USD.
- Bridges end the Solana trail; TraceBrief continues on the destination chain only when the bridge confirms the destination transaction.
- A finding explains a mechanism. It is not legal advice and it does not recover funds.

## License

MIT - see [LICENSE](LICENSE). © 2026 MB Kriptika (Lithuania).
