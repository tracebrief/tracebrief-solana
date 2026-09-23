# Build log - Colosseum Crypto World's Fair

Prior work (before 2026-09-14): TraceBrief engine, report templates and website ([tracebrief.io](https://tracebrief.io)) - closed source, not in this repository. Everything in this repository was written inside the hackathon window.

## 2026-09-23

- Captured real mainnet transactions for every instruction pattern the classifier must understand (scanned recent blocks with `getBlock`, saved `getTransaction` jsonParsed results as fixtures). Found that current blocks contain **version 1** transactions, so the client requests `maxSupportedTransactionVersion: 1`.
- `parse.py`: outer + inner instruction walk, SOL/SPL/Token-2022 transfers, pre/post token-account owners (needed to see ownership changes), burns, account-creation rent, SOL wrapped into the owner's own wSOL account (not an outflow).
- `classify.py`: `DELEGATE_APPROVED` (unlimited = u64::MAX), `DELEGATE_SPEND`, `OWNER_REASSIGNED`, `CLOSE_AUTHORITY_REASSIGNED`, `DURABLE_NONCE`, `WALLET_ASSIGNED`, `ACCOUNT_CLOSED_TO_OTHER`, `PROGRAM_OUTFLOW`, `SIGNED_TRANSFER_OUT`, `NOT_SIGNED_BY_VICTIM`.
- `poisoning.py`: look-alike recipient check against earlier counterparties and dust senders.
- `trace.py`: forward trace over wallets with endpoints (labelled, program-controlled, high-activity, dormant, hop limit); ownership changes become traceable edges.
- `labels.py`: primary-source-only label store; built-in program IDs verified as executable on mainnet.
- `report.py` + CLI: Markdown and JSON; every claim links to its signature.
- 21 tests (real fixtures + synthetic attacks + offline fake RPC), all passing. Live end-to-end runs against mainnet for SOL and USDC incidents.

## Next

- USD value at time of transfer for each hop.
- Hand-off to TraceBrief's PDF renderer (JSON already matches the report sections).
- Solana-side bridge confirmation (Wormhole, deBridge, Mayan) to continue on the destination chain.
- First real users through the free pre-check on tracebrief.io.
