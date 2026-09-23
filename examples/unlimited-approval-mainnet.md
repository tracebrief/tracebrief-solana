> **Real mainnet transaction** (public data). The findings describe what the permissions allow; this may well be a legitimate trading program. The point: a victim sees in plain words what they signed.

# TraceBrief - Solana incident explanation

- **Transaction:** [5CHrAx421RJX…](https://solscan.io/tx/5CHrAx421RJXFg4ZX4XpSMXBrwoi9jPdcitHAUK6eF3WFtuM59ihjLeW397iPt3yzpdf847pWmcMxYe7jEqRtcBT)
- **Time:** 2026-09-23 14:10:26 UTC (slot 449726519)
- **Wallet examined:** `D353humRbsSRGXoYpGJE9SFCNLWV5Xs433YcrfiEXrws`
- **Signed by this wallet:** yes

## What happened

**[CRITICAL] Unlimited spending permission granted**  
Cntx…aCrg was allowed to move an unlimited amount from token account 3K52…ZPFR without asking the owner again. If this was not intended, it is how tokens can leave later without a new signature.  
Evidence: [5CHrAx421RJX…](https://solscan.io/tx/5CHrAx421RJXFg4ZX4XpSMXBrwoi9jPdcitHAUK6eF3WFtuM59ihjLeW397iPt3yzpdf847pWmcMxYe7jEqRtcBT)

**[HIGH] Another address may now close this token account**  
Close authority of token account 3K52…ZPFR was given to Cntx…aCrg. That address can close the account and collect its lamports.  
Evidence: [5CHrAx421RJX…](https://solscan.io/tx/5CHrAx421RJXFg4ZX4XpSMXBrwoi9jPdcitHAUK6eF3WFtuM59ihjLeW397iPt3yzpdf847pWmcMxYe7jEqRtcBT)

## Where the funds went

No outgoing value from this wallet in this transaction.

## Method and limits

Read-only analysis of public Solana data (getTransaction, jsonParsed). Every statement links to the transaction that proves it. Labels come only from primary sources and name companies or protocols, never private individuals. A trail stops at a labelled endpoint, a program-controlled account, a high-activity address, a dormant address or the hop limit - the report says which. This is not legal advice and does not recover funds.

