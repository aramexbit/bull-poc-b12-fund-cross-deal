# bull-poc-b12-fund-cross-deal

Proof-of-concept for Bull (bull.family) bug bounty report **B-12**:
the Bull SDK's `fund()` executes a funding step for a **different deal**
than the one passed in — the buyer pays 0.5 ETH and receives 0 tokens.

## Summary

The victim agrees to buy 100 tokens for 0.5 ETH (deal A, legitimate
seller). A compromised/malicious API server (1) slips the attacker's
deal B into the victim's first `open()` — the new `open()` catches the
tamper and throws, but the transaction is already mined, so deal B
exists on-chain with buyer=victim (deal B passes the v3 consent gate
legitimately, because the attacker signs the Consent for B's own
terms) — and (2) returns `fundPayment(B)` when the victim calls
`fund(A)`. `fund()` caps the value at `payAmount(A)` but never checks
that the step belongs to the `dealId` passed in; `payAmount(B) ==
payAmount(A) == 0.5 ETH`, so the step passes and deal B settles to the
attacker. Result: victim −0.5 ETH, 0 tokens; deal A never funded.

- SDK: the real new Bull SDK (`bull-sdk.mjs`, verbatim copy of the live
  file, sha256
  `03bd949872c5bf4b0362af164aa959cab0bd6bd6d26d791afae92e01107a9a27`)
- Chain: local Anvil; `MockEscrowV3` (v2 source verbatim + v3 EIP-712
  seller-consent gate) etched at the production escrow address
  `0xd961ca37e339e14e0d3478383a252e218fe7aa4a`
- API: mock Bull API (local). No real funds, no mainnet, no Bull
  infrastructure.
- Result: `poc-result.json` — `exploited: true` (reproduced 3x).

## How to run

Prerequisites: [Foundry](https://book.getfoundry.sh/) (`anvil`) and
Node.js 20+.

```bash
# 1. Start a fresh local Anvil chain
anvil --port 8560 --chain-id 31337

# 2. In this directory (dependencies are vendored in node_modules)
node run-poc.mjs
```

Expected output: `EXPLOITED: true` — deal B settles, deal A stays
unfunded, victim token balance stays 0.

## Files

- `bull-sdk.mjs` — real new Bull SDK, verbatim
- `run-poc.mjs` — PoC driver
- `mock-api.mjs` — mock Bull API server
- `chain/` — Foundry project (`src/MockEscrowV3.sol`, `src/Mocks.sol`,
  compiled artifacts in `out/`)
- `poc-result.json` — recorded result of the verified run
- `package.json` — only dependency is `viem`

## Notes

- PoC for bug bounty report B-12 submitted to
  https://www.bull.family/bounty (severity: Major, argued Critical).
- No user wallet addresses, no private keys, no seed phrases in this
  repo — only Anvil throwaway keys generated at runtime.
