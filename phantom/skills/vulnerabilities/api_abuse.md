---
name: api_abuse
description: API abuse and authorization testing covering rate limits, batch operations, version drift, mass assignment, and parser differentials
---

# API Abuse and Authorization

Use this skill for REST, JSON-RPC, GraphQL-adjacent, and versioned APIs where normal functionality can be abused through missing limits, inconsistent authorization, or alternate request representations. Pair it with `idor`, `broken_function_level_authorization`, `mass_assignment`, or `oauth` for deeper cases.

## Reconnaissance

- Inventory methods, versions, content types, pagination, batch endpoints, imports/exports, and asynchronous jobs.
- Identify principals, roles, tenant identifiers, API keys, OAuth scopes, and service-to-service tokens.
- Compare public, browser, mobile, admin, and legacy API routes for shared resources and inconsistent controls.
- Record rate-limit headers, retry behavior, idempotency keys, request correlation IDs, and error shapes.
- Look for undocumented fields in OpenAPI, GraphQL schemas, JavaScript bundles, forms, and proxy history.

## High-Value Test Areas

### Authorization and Scope

- Verify object and function authorization on every version and method.
- Remove, downgrade, or replace scopes and permissions only with test principals.
- Compare browser and API enforcement for the same action.
- Test tenant, account, role, and ownership fields independently; never assume a client-supplied field is authoritative.

### Mass Assignment and Field Exposure

- Add one non-sensitive unknown field at a time to create/update requests.
- Test protected fields such as role, owner, tenant, status, price, limit, and verification flags.
- Compare accepted fields with response serialization to identify write-only or read-only boundary gaps.
- Confirm any change persists and affects an authorized security-relevant behavior before reporting.

### Batch and Pagination Abuse

- Check whether batch requests apply authorization, limits, and validation per item rather than only once per request.
- Compare single-item and multi-item behavior with a small bounded batch.
- Test cursor, page-size, filter, sort, and export parameters for cross-tenant or hidden-record access.
- Verify rate limits account for work performed, not only HTTP request count.

### Version and Method Drift

- Compare `/v1`, `/v2`, preview, mobile, admin, and legacy routes for the same operation.
- Test method alternatives and documented method override behavior only where supported.
- Compare JSON, form, multipart, and documented alternate content types for authorization parity.
- Check whether deprecated routes still accept weaker tokens or fields.

### Rate Limits and Resource Controls

- Test anonymous, authenticated, per-account, per-token, and per-IP limits with a small measured sequence.
- Check whether failed and successful operations consume the same budget.
- Verify limits apply across aliases, batch items, pagination, GraphQL operations, and alternate hostnames.
- Do not perform credential stuffing, mass enumeration, denial-of-service testing, or distributed evasion.

### Parser and Gateway Differentials

- Compare duplicate parameters, arrays vs scalars, null vs omitted fields, and normalization only when the stack supports them.
- Inspect differences between gateway, application, worker, and cache interpretations.
- Preserve the original request and change one representation at a time.

## Testing Methodology

1. Establish a clean baseline for every principal and operation.
2. Build a subject × action × object × transport matrix.
3. Select one hypothesis and one minimal mutation per request.
4. Observe status, body, headers, timing, side effects, audit events, and quota counters.
5. Repeat from a clean session to rule out cache, retries, and stale state.
6. Hand candidates to an independent validator with paired baseline evidence.

## Validation

- Prove unauthorized data access, durable state change, quota bypass, or a meaningful integrity failure.
- Demonstrate the expected denial using the same principal and corrected request.
- Repeat across the affected API version or transport if the issue is a parity failure.
- Record exact request/response pairs, principal, object IDs, and timestamps.

## False Positives

- A field is accepted but ignored and no protected state changes.
- A batch returns mixed results but each item is correctly authorized.
- A rate-limit header is absent while server-side limits still enforce correctly.
- A legacy route is intentionally public and returns only public data.
- Different errors reveal resource existence without exposing restricted content or enabling a protected action.

## Handoffs

- `idor` for cross-object access.
- `broken_function_level_authorization` for role/function boundaries.
- `business_logic` and `race_conditions` for workflow invariants.
- `web_payload_crafting` for context-specific request mutations.
- `oauth` or `authentication_jwt` for token, scope, and audience validation.

## Summary

API abuse is not simply “send more requests.” Model the authority boundary, vary one representation at a time, measure actual work and side effects, and report only demonstrated impact.
