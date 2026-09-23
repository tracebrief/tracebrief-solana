> **Synthetic scenario** (built with `tests/conftest.py` helpers, no real wallet): a durable-nonce transaction that hands a USDC token account to an attacker with `setAuthority`. Plain transfer tracing sees nothing here.

# TraceBrief - Solana incident explanation

- **Transaction:** [ExampleOwner…](https://solscan.io/tx/ExampleOwnerChangeSig)
- **Time:** 2026-09-21 14:13:20 UTC (slot 100)
- **Wallet examined:** `VictimWa11et1111111111111111111111111111111`
- **Signed by this wallet:** yes

## What happened

**[CRITICAL] Token account ownership handed to another address**  
The owner of token account Vict…1111 was changed from the victim to Atta…1111. No tokens move in this step, so simple transfer tracing shows nothing - but from now on only the new owner can move the balance.  
Evidence: [ExampleOwner…](https://solscan.io/tx/ExampleOwnerChangeSig)

**[MEDIUM] Pre-signed transaction (durable nonce)**  
This transaction uses a durable nonce, so it does not expire. It could have been signed days or weeks before it was executed - which explains a theft that happened while the owner was not signing anything.  
Evidence: [ExampleOwner…](https://solscan.io/tx/ExampleOwnerChangeSig)

## Where the funds went

| Hop | From | To | Amount | Transaction | Stops here because |
|---|---|---|---|---|---|
| 1 | `Vict…1111` | `Atta…1111` | 12,500 USDC (ownership change) | [ExampleO…](https://solscan.io/tx/ExampleOwnerChangeSig) | No outgoing movement since - funds appear to sit here |

## Method and limits

Read-only analysis of public Solana data (getTransaction, jsonParsed). Every statement links to the transaction that proves it. Labels come only from primary sources and name companies or protocols, never private individuals. A trail stops at a labelled endpoint, a program-controlled account, a high-activity address, a dormant address or the hop limit - the report says which. This is not legal advice and does not recover funds.
