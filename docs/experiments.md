# Gas experiments (full transaction gas from receipts)

Run: 2026-11-03T13:56:13.588Z · 5 oracles registered · local Anvil

## Baseline (original single-oracle contract)

- Screening (one oracle callback): 39,413 gas
- Audited access (accessKYC): 39,979 gas

## Screening cost vs quorum k

| k | non-final vote | final vote | total initial screening | total periodic re-screen |
|---|---|---|---|---|
| 1 | – | 68,982 | 68,982 | 130,199 |
| 2 | 59,984 | 68,982 | 128,966 | 187,383 |
| 3 | 59,984 | 68,982 | 188,950 | 247,319 |
| 4 | 59,984 | 68,982 | 248,934 | 310,139 |
| 5 | 59,984 | 68,982 | 308,918 | 370,063 |

## Disagreement path (k = 3: clear, clear, hit)

- Votes: 59,552, 59,552, 67,755 gas; status after votes = 4 (4 = Review)
- resolveReview by regulator: 34,307 gas; status after = 2 (2 = Clear)

## Freshness policy

- setFreshnessPolicy (one-time per institution): 47,808 gas
- accessKYC without policy: 42,551 gas
- accessKYC with 24 h policy: 42,921 gas
- accessKYC with policy, screening 2 days old: 42,921 gas (valid for this bank: false)
