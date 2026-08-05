# Worked examples (canonical, used as tests)

Each is a full authoritative trace used to lock behaviour. Traces are verified
against the pinned data (CWE 4.20, CAPEC 3.9, ATT&CK 19.1).

## Hard-coded credentials (canonical — completes the chain)
- Finding: Semgrep hardcoded-credentials rule, cwe_ids=["CWE-798"]
- Chain: CWE-798 → CAPEC-191 → T1552.001 (Unsecured Credentials: Credentials In Files)
  and CWE-798 → CAPEC-70 → T1078.001 (Valid Accounts: Default Accounts)
- method=authoritative, confidence=high
- NOTE on tools: Bandit's hard-coded-password checks (B105-B107) report the
  *related but distinct* CWE-259 (Hard-coded Password), which is itself an
  authoritative gap (no CAPEC→ATT&CK mapping). Only CWE-798 completes the chain —
  a concrete example of how the emitting tool's CWE choice decides coverage.

## SQL Injection (documented GAP — authoritative path can't map it)
- Finding: Bandit B608 / Semgrep sql-injection, cwe_ids=["CWE-89"]
- CWE-89 relates to CAPEC-66, but CAPEC-66 carries no ATT&CK taxonomy mapping in
  the pinned data (nor do CWE-89's other CAPECs), and no CAPEC maps to T1190.
- Authoritative path yields no mapping → the finding falls through to the NLP
  fallback (O5, RQ2). This gap is the reason RQ2 exists. See
  `data-catalogue-chain-gap` (memory) for the coverage numbers (~15% of CWEs).
