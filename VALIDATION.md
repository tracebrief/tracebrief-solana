# Validation on real mainnet incidents

**Date:** 2026-09-24. **Engine:** `tbsol` as released on 2026-09-23 (baseline), then the same engine with the fixes listed below.

The unit tests prove each detector works on hand-built and captured transactions. This document asks a harder question: **what does `tbsol` say about real Solana thefts that security firms have already investigated in public?** Where a firm published its findings, we compare against them. Where it did not, we compare against the chain itself (balance changes, instructions, signers).

## How the cases were chosen

- Only incidents with a public write-up that gives at least one full address or signature. The transactions were then located on-chain from those identifiers.
- Four incident types: wallet-owner reassignment plus delegate drain, address poisoning, durable-nonce pre-signing, and stolen private keys.
- One of these campaigns turned out to be large. The drainer program in SlowMist's November 2025 case (`GKJBELftW5Rjg24wP88NRaKGsEBtrPLgMiv3DhbJwbzQ`) still **owns 1,019 wallets today** (`getProgramAccounts`). Five of them were picked at random with a fixed seed.
- Total: **15 transactions from 10 wallets in 4 campaigns**.
- **Privacy:** addresses and signatures of victims that no security firm published are not listed here. They are kept for reproduction and available to reviewers on request. Labels name companies and protocols, never people.

## Results

"Mechanism" means whether `tbsol` explains *how* value left. "Trail" means whether it finds *where* the value went.

| # | Incident | What the public source / chain shows | Baseline: mechanism | Baseline: trail | After fixes |
|---|---|---|---|---|---|
| 1 | SlowMist, Nov 2025, ~$3M ([write-up](https://slowmist.medium.com/beware-of-solana-phishing-attacks-wallet-owner-permissions-may-be-altered-708bbb30518e)). The phishing transaction [`524t8LW1…`](https://solscan.io/tx/524t8LW1PFWd4DLYDgvtKxCX6HmxLFy2Ho9YSGzuo9mX4iiGDhtBTejx7z7bK4C9RocL8hfeuKF1QaYMnK3itMVJ) | The wallet is assigned to a program, and delegates are approved | ✅ `WALLET_ASSIGNED` + 2× `DELEGATE_APPROVED` | ❌ nothing moves in this transaction; the drains are later transactions that do not list the wallet | ✅ finds the 3 later drains and traces them to `BaBc…NSmd` and `7pSj…9bM8`, **the two laundering addresses SlowMist named** |
| 2 | Same victim, token drain [`2vuHKrN6…`](https://solscan.io/tx/2vuHKrN6ytyRsWx5UL9V1SaZXPbx5A7ksSgidUd4E25rAcVPHwG9QN6ikK83pFRQHoVdMwsAbq63t9HcM6QTLhn5) | The delegate moves tokens; the victim did not sign | ✅ `DELEGATE_SPEND`, `NOT_SIGNED_BY_VICTIM` | ✅ hop 1 = `BaBc…NSmd` / `7pSj…9bM8` (SlowMist: ~$2.38M / ~$790K) | - |
| 3 | Same victim, SOL drain [`LgkZNLik…`](https://solscan.io/tx/LgkZNLikbKmMyoSMYkfLxgtAM1CqAjoe5MvkWydDP2XTQyocqd7EMxMaEtGqvpRkqTFZrjMfU6mHiARxDX78rwk) | The program moves 1.7727 SOL; balance changes show a 75/25 split to the same two addresses | ⚠️ `PROGRAM_OUTFLOW`, recipient unknown | ❌ | ✅ names both receivers from balance changes and traces them |
| 4 | Address poisoning, Nov 2024, 7,000,000 PYTH, ~$2.9M ([Pine Analytics](https://pineanalytics.substack.com/p/solana-account-dusting-and-address)), [`T3vqZjME…`](https://solscan.io/tx/T3vqZjMEi8MrJ34pwgnPG1ZjrFwygw6KYzij4Rt8dcFp2gZMqurHxC2Ta9gK7gELq2XXr4xpyotUYZryvQ2h5RP) | Sent to `4yfu…izcY`, not to `4yfu…gnhY`, which the wallet had paid 13 times; the fake had sent 0.000001 SOL two days earlier | ❌ only "signed by the owner"; the look-alike rule demanded first **and** last 4 characters | ✅ follows the poisoner onward | ✅ `POISONED_ADDRESS` (critical): first 4 characters match, plus the dust |
| 5-9 | Same drainer program as #1: 5 random wallets of the 1,019 it owns (Nov 2025) | Each wallet was reassigned to the drainer program by an `assign` it signed | ✅ 5/5 `WALLET_ASSIGNED`; durable nonce in 4/5, delegate approvals in 2/5 | - | - |
| 5-9 | Drains of those wallets (3 found in the following 25 transactions) | The program moves SOL out, split between two addresses | ⚠️ 3/3 `PROGRAM_OUTFLOW`, recipient unknown | ❌ | ✅ receivers named and traced. **All four program drains (#3 and these three) are signed by the same address `AzFiF4NE…Vj31`**, which links separate victims to one operator |
| 10 | Drift Protocol, Apr 2026, $285M governance takeover ([BlockSec](https://blocksec.com/blog/drift-protocol-incident-multisig-governance-compromise-via-durable-nonce-exploitation), [Utila](https://utila.io/blog/drift-protocol-hack-using-solana-durable-nonces)). Execution transaction [`4BKBmAJn…RsN1`](https://solscan.io/tx/4BKBmAJn6TdsENij7CsVbyMVLJU1tX27nfrMM1zgKv1bs2KJy6Am2NqdA3nJm4g9C6eC64UAf5sNs974ygB9RsN1), located from the nonce account Utila published | Multisig approvals pre-signed with durable nonces, executed weeks later | ✅ `DURABLE_NONCE` (matches the ID BlockSec cites) | n/a (a protocol-level theft, not a wallet drain) | - |
| 11-12 | `@solana/web3.js` backdoor, Dec 2024 ([Cyfrin](https://www.cyfrin.io/blog/critical-security-alert-solana-web3-js-library-compromise)): two victims paying the attacker address `FnvL…Kbfx` | Stolen private keys: the victims' own keys signed | ✅ "signed by the owner - the key is known to someone else" | ⚠️ #11 reaches `FnvL…Kbfx`, then follows a fee top-up back into the victim's wallet. ❌ #12 says the funds **sit** at `FnvL…Kbfx`, which is wrong: the attacker moved them on later | ✅ both: stops at the victim's wallet, reads 67-76 transactions of the collector and finds the 74,387.56 USDC consolidation and its split |

### Score

| | Baseline | After fixes |
|---|---|---|
| Mechanism explained correctly | **14 / 15** (missed: poisoning) | **15 / 15** |
| Trail found where value left the victim (9 transactions) | **2 / 9** fully, 1 partly, **1 wrong** (said the funds sat still), 5 missing | **9 / 9** |
| Trail agrees with a published investigation (#1-3) | 1 / 3 | 3 / 3 |

## What the cases changed in the engine

Each fix has a regression test built on the real case, and the suite has 31 tests.

1. **Look-alike rule** (`poisoning.py`): now 4 matching characters at the start **or** the end, instead of both. The real case matched only the start. A random address shares four given base58 characters with probability 1/58⁴, about 1 in 11 million.
2. **Later use of a permission** (`trace.py`, `_follow_up`): when a transaction grants a delegate or reassigns the wallet but moves nothing, `tbsol` reads the affected accounts afterwards and pulls in the transactions that used the permission. Without this, a victim who brings the transaction they signed gets "no outgoing value". That is the most common thing a victim remembers.
3. **SOL moved by a program** (`classify.py`): the receivers are taken from the transaction's own balance changes, when these add up to what the wallet lost. Drainers split the take, 75/25 here.
4. **Collectors** (`trace.py`): an address that first receives from many wallets is read further (up to 100 transactions) until something leaves. The report says that funds are pooled from that point on.
5. **Victim's own wallet**: a top-up back to the victim ends that branch instead of being followed as the attacker's trail.
6. **Amounts** are never printed in scientific notation (`7e+06` became `7,000,000`).
7. **"Funds appear to still be here" is checked against the balance now.** The released engine inferred it from the transactions it happened to read, and in case #12 that was false. The claim is now made only when the current balance still covers the amount. Otherwise the hop says "moved on, but not within the transactions read" (`UNRESOLVED`).
8. **"Service-like" is judged by pace.** An address is called exchange- or service-like only if its latest 1,000 transactions fall within 7 days. Slower addresses are reported as `ACTIVE` and left out of "Who to contact".

**Final re-run (2026-09-24, all 15 transactions, final engine, 31 tests):** every mechanism is still found (15/15), and every fund trail is found (9/9). No hop claims that funds are sitting still unless the live balance confirms it. The follow-up of later permission use also found the drains for three of the five sampled hijacked wallets starting from their setup transaction alone.

## What is still missing

- **Who to contact.** Most trails end at addresses that behave like services but carry no label. One of them, `3Cgv…sRoD`, appears at the end of two unrelated incidents (#4 and #11) and handles roughly 700 transactions an hour. Naming it requires an exchange's own proof-of-reserves publication. That label set lives in TraceBrief's production data, not in this repository. It is the gap that matters most to a victim.
- **Not tested:** the Slope wallet incident (Aug 2022). The attacker address received thousands of zero-value spam transactions within minutes, and the public RPC cannot page back through them. A dedicated RPC endpoint would solve this.
- **Selection bias:** every case comes from a public investigation, and well-documented thefts may be easier than a typical victim's case. Real victims' cases are the next test.
- **DEX pools** are reported as "account controlled by program …". Naming Orca, Raydium CLMM, Meteora and PumpSwap needs their program IDs from the protocols' own docs.

## Reproduce

```bash
python -m tbsol explain 2vuHKrN6ytyRsWx5UL9V1SaZXPbx5A7ksSgidUd4E25rAcVPHwG9QN6ikK83pFRQHoVdMwsAbq63t9HcM6QTLhn5 \
  --victim 9w2e3kpt5XUQXLdGb51nRWZoh4JFs6FL7TdEYsvKq6Wb --hops 2
python -m tbsol explain T3vqZjMEi8MrJ34pwgnPG1ZjrFwygw6KYzij4Rt8dcFp2gZMqurHxC2Ta9gK7gELq2XXr4xpyotUYZryvQ2h5RP \
  --victim 5LbwC1ewY3Sca7T8CwzX9wsjvwMAHbdRo6SCQL8j7EWc --hops 1
```

The public RPC is rate-limited, so a full run of all 15 transactions takes about 25 minutes. Use `--rpc` with your own endpoint.
