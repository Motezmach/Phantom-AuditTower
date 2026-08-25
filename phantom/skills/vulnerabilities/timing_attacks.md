---
name: timing_attacks
description: Timing side-channel testing for authentication, account enumeration, cryptographic oracles, and state-dependent processing
---

# Timing Attacks

Use statistical, low-volume testing to distinguish meaningful state-dependent timing from network noise. Timing is evidence only when the difference is reproducible, tied to a security boundary, and not explained by caching or workload.

## Attack Surface

- Login, password reset, signup, invite, and account recovery flows
- Token, signature, MAC, password, and cryptographic comparison paths
- Permission checks, object existence, and user/tenant enumeration
- Search, filtering, rate limits, and database-backed conditional branches
- WebSocket or asynchronous workflows with observable completion timing

## Methodology

1. Select matched valid/invalid, existing/non-existing, and authorized/unauthorized controls.
2. Warm the connection and keep method, headers, body size, and session state constant.
3. Collect a small balanced sample in randomized order; record server timing headers, total time, status, size, and cache state.
4. Use median and spread, not a single slow request; repeat after idle and under normal load.
5. Check whether the difference persists across regions, connections, and equivalent endpoints before escalating.

## Safe Tests

- Username/email existence with synthetic accounts only.
- Password-reset and invite token behavior without sending mail to real users.
- Signature/MAC comparisons using controlled invalid values of equal length.
- Object existence using records owned by the test principals.
- Rate-limit and lockout boundaries with conservative request counts.

Do not use timing probes to brute-force secrets, degrade the service, or create large computational loads.

## Validation

- Demonstrate a statistically stable difference across repeated matched trials.
- Show the difference reveals a security-relevant property, not merely database/cache behavior.
- Confirm a control implementation or alternate path does not exhibit the same difference.
- Document sample size, median/spread, network conditions, and confounders.

## False Positives

- CDN, proxy, browser, or connection reuse effects.
- Cold starts, garbage collection, database cache misses, or asynchronous jobs.
- Rate limits, retries, WAF inspection, or logging overhead.
- A timing difference with no useful information gain or security impact.

## Handoffs

- `authentication_jwt` for token and authentication paths.
- `idor` for existence or authorization oracles.
- `oauth` for authorization-code/token timing differences.
- `race_conditions` when concurrency changes the observed state.

## Summary

Timing findings require disciplined controls and statistical repetition. Report the information revealed and its practical impact, not just a millisecond difference.
