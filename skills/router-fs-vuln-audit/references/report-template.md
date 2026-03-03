# Vulnerability Report Template (Router Firmware)

## 1. Summary

- Title:
- Severity:
- Affected firmware/model:
- Attack surface: pre-auth / auth-bypass / post-auth

## 2. Environment

- Firmware image/hash:
- Extraction method:
- Test environment (lab topology):
- Tooling (IDA version, MCP, commands):

## 3. Technical Root Cause

### 3.1 Entry Point
- Protocol/endpoint:
- Binary/function:
- Reachability conditions:

### 3.2 Validation and Trust Boundary
- Expected check:
- Actual behavior:
- Bypass condition:

### 3.3 Sink
- Execution/config sink:
- Controlled fields:
- Why this is exploitable:

## 4. Reproduction

1. Preconditions
2. Step-by-step request sequence
3. Observable proof

## 5. Impact

- Confidentiality:
- Integrity:
- Availability:
- Worst-case scenario:

## 6. Suggested Fix

1. Code-level fix.
2. Input handling rules.
3. Auth/session hardening.
4. Regression test cases.

## 7. Evidence Appendix

- Decompiled snippet references (function/address):
- File paths used for correlation:
- PoC transcript/log excerpts:
