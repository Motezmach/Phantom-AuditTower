---
name: cache_poisoning
description: Web cache poisoning and deception testing covering cache-key confusion, unkeyed inputs, host handling, and authorization leakage
---

# Cache Poisoning and Deception

Separate cache poisoning from cache deception and from SSRF/DNS rebinding. The goal is to prove that a cache stores or serves the wrong representation to another request context, not merely that a header is accepted.

## Reconnaissance

- Identify CDN, reverse proxy, application, and browser-cache layers.
- Record cache indicators: `Age`, `X-Cache`, `CF-Cache-Status`, `ETag`, `Vary`, cache-control, and surrogate keys.
- Compare cache behavior for authenticated/anonymous requests, hostnames, query parameters, headers, methods, and content types.
- Find personalized, state-changing, redirect, error, and static-looking paths.

## Cache-Key Tests

- Change one candidate input at a time: query order, selected headers, host-related fields, language, encoding, and path normalization.
- Determine whether the response varies on `Authorization`, cookies, tenant, origin, and content negotiation as required.
- Test cacheable redirects, error responses, compressed variants, and partial responses only with bounded requests.
- Check whether a poisoned representation is served to a clean control request from a separate session.

## Web Cache Deception

- Test whether a dynamic or authenticated path can be made to look like a static asset through path suffixes, delimiters, or normalization.
- Verify the origin still returns private content and whether an intermediary stores it.
- Use synthetic secrets or a dedicated test record; never collect another user’s private data.

## Validation

1. Capture a clean control response.
2. Send the candidate request with a unique canary.
3. Request the same cache key from a separate clean context.
4. Prove the canary or protected representation is served to the wrong context.
5. Repeat after cache expiry/purge and record cache headers and timing.

## False Positives

- The response is not stored and the second request reaches the origin.
- `Vary` or authorization controls correctly separate the contexts.
- A browser-local cache artifact is mistaken for shared-cache behavior.
- A different response is caused by a session, feature flag, or backend race and cannot be reproduced.

## Handoffs

- `idor` for protected-object exposure.
- `ssrf` for server-side URL fetching; DNS rebinding is not a cache finding by itself.
- `semantic_confusion` for proxy/origin parser differentials.
- `web_payload_crafting` for controlled header/path/query mutations.

## Summary

Cache impact requires a cross-context proof: one request influences a representation and a clean, unauthorized request receives it. Headers and unusual cache behavior alone are not enough.
