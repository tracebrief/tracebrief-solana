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

## 2026-09-24 - validation on real incidents

- Ran `tbsol` on 15 transactions from 10 wallets in 4 publicly investigated campaigns: SlowMist's Nov 2025 owner-change drain, a Nov 2024 address-poisoning loss of 7,000,000 PYTH, the Apr 2026 Drift durable-nonce takeover, and the Dec 2024 `@solana/web3.js` key theft. Results, including what the engine got wrong, are in [VALIDATION.md](VALIDATION.md).
- Baseline: 14/15 mechanisms right, but only 2/9 fund trails complete and one false "funds sit here". After the fixes below: 15/15 and 9/9. The trail agrees with SlowMist's published laundering addresses.
- Found that the drainer program from SlowMist's case still owns 1,019 wallets. All four program drains checked were signed by the same operator address.
- Fixes, each with a regression test built on the real case:
  - look-alike = first **or** last 4 characters (the real case matched only the first 4);
  - follow a delegate approval or wallet reassignment into the later transactions that used it;
  - name the receivers of program-moved SOL from balance changes (split drains);
  - read further at collector addresses;
  - never follow a top-up back into the victim;
  - no scientific notation in amounts;
  - "funds still here" only when the live balance confirms it, otherwise `UNRESOLVED`;
  - an address is called "service-like" only if its latest 1,000 transactions fall within a week.
- Final re-run of all 15 transactions with the final engine: 15/15 mechanisms, 9/9 trails, no unverified "funds sit here". 31 tests.

## Next

- USD value at time of transfer for each hop.
- Hand-off to TraceBrief's PDF renderer (JSON already matches the report sections).
- Solana-side bridge confirmation (Wormhole, deBridge, Mayan) to continue on the destination chain.
- Labels for DEX pool programs (Orca, Raydium CLMM, Meteora, PumpSwap) from the protocols' own docs.
- First real users through the free pre-check on tracebrief.io.
