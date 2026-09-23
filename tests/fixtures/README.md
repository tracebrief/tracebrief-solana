# Fixtures

Real mainnet transactions returned by `getTransaction` (`encoding: jsonParsed`, `maxSupportedTransactionVersion: 1`), captured on 2026-09-23 by scanning recent blocks for each instruction pattern the classifier handles. Fields the parser does not use (log messages, rewards, compute units) were stripped to keep the files small; everything else is exactly as returned by the RPC.

| File | Pattern |
|---|---|
| `spl-token_approveChecked.json` | unlimited delegate approval (u64::MAX) + close-authority change |
| `spl-token_approve.json` | limited approval + burn |
| `system_advanceNonce.json` | durable-nonce transaction |
| `spl-token_closeAccount.json` | token account closed, rent to another address |
| `system_assign.json` | `assign` of a newly created token account (must not be flagged) |
| `system_transfer.json` | plain SOL transfer |
| `spl-token_transfer.json` | SPL transfers inside a program call |
| `spl-token_transferChecked.json` | USDC `transferChecked` |
| `spl-token_transferCheckedWithFee.json` | Token-2022 transfer with fee |
