# JurySourceGuard for GenLayer

JurySourceGuard is a reusable GenLayer Intelligent Contract for admitting or challenging web evidence before an AI jury uses it to support a claim.

## Decision primitive

The caller submits a canonical claim (`claim_type`, `subject`, `assertion`), 2-5 allowed authority domains, and 2-5 HTTPS evidence URLs. The contract creates one append-only `jsg_*` receipt:

- `admit` only when direct, authority-bound evidence cleanly supports the exact claim;
- `challenge` when evidence contains a concrete manipulation or conflict signal;
- `inconclusive` for inaccessible, incomplete, mismatched, injected, or insufficient material.

## Integrity model

- validators independently render each complete source, never a search snippet or truncated prefix;
- `www` and sibling subdomains collapse to one registrable-domain identity, preventing fake independence;
- two authority-bound, independent sources are required before adjudication;
- canonical structured claim fields and full SHA-256 snapshot commitments are persisted in every receipt;
- validators compare every consequential decision, source count, signal list, and commitment in `gl.vm.run_nondet_unsafe`;
- opaque caller-provided claim hashes are not accepted.

## API

```python
admit_evidence(claim_type, subject, assertion, authority_domains, evidence_urls) -> str
get_receipt(receipt_id) -> str
get_latest_receipt_id() -> str
get_receipt_count() -> u64
list_receipt_ids() -> str
```

## Verification

```powershell
python -m unittest discover -s tests -v
```
