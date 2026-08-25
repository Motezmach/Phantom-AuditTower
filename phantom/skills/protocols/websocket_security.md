---
name: websocket_security
description: WebSocket and realtime API security testing covering handshake, origin, per-message authorization, replay, and schema abuse
---

# WebSocket Security

Test WebSocket and realtime channels as a separate authorization and parser boundary. A secure HTTP login or handshake does not prove that every subscription, message, room, or state-changing event is protected.

## Attack Surface

- Upgrade handshake: `Upgrade`, `Connection`, `Origin`, cookies, bearer tokens, subprotocols
- Protocols: native WebSocket, `graphql-ws`, `graphql-transport-ws`, Socket.IO, SSE fallbacks
- Message types: subscribe, publish, request/response, presence, file, admin, and billing events
- Identity boundaries: user, organization, project, room, tenant, and service role
- Encodings: JSON, text, binary, compressed frames, batched messages, and nested payloads

## Reconnaissance

1. Discover WebSocket URLs in HTML, JavaScript bundles, source maps, proxy history, and API documentation.
2. Record the handshake request, response, negotiated subprotocol, cookies, and authentication mechanism.
3. Capture the first application messages and build a message/schema inventory.
4. Identify channel identifiers, object references, event names, and state-changing operations.
5. Map which HTTP endpoints, jobs, or database-backed objects each message can affect.

## Key Tests

### Handshake and Origin

- Verify the server validates the expected `Origin` and does not rely only on a browser-controlled header.
- Test missing, unexpected, and cross-site origins only within the engagement scope.
- Check whether cookie-authenticated handshakes can be initiated cross-site and whether CSWSH would expose data.
- Confirm subprotocol and authentication negotiation cannot downgrade to an unauthenticated mode.

### Per-Message Authorization

- Authenticate as each available principal and compare access to owned and foreign channels.
- Re-check authorization on subscribe, publish, read, update, delete, and admin events.
- Change room, tenant, project, user, and object identifiers after a valid handshake.
- Verify authorization continues after reconnect, token refresh, role change, and idle timeout.

### Message and Schema Abuse

- Change scalar/object/array types, omit required fields, add unknown fields, and vary duplicate keys where the parser permits them.
- Test event-name confusion, client-supplied roles, tenant fields, and server-trusted metadata.
- Check whether a message intended for one protocol is accepted by another transport or fallback endpoint.
- Test replay of captured messages and reuse of message IDs, nonces, or idempotency keys.

### Rate Limits and State

- Use a small bounded request set to test per-connection, per-user, per-channel, and per-IP limits.
- Check whether one connection can subscribe to excessive rooms or bypass HTTP rate limits.
- Verify state-changing messages are idempotent and protected against duplicate delivery.
- Avoid flooding, oversized frames, fragmentation abuse, or resource-exhaustion testing unless explicitly authorized.

## Validation

1. Reproduce the issue from a clean handshake.
2. Compare owner, non-owner, unauthenticated, and lower-privilege sessions where available.
3. Capture the exact handshake and message sequence, including direction and timestamps.
4. Demonstrate unauthorized data exposure or durable state change, not merely an accepted message.
5. Repeat after reconnect or token rotation when session-bound behavior is relevant.

## False Positives

- A message is accepted but produces no unauthorized read, write, or state change.
- The channel is intentionally public and the data is confirmed public.
- A cross-origin handshake fails before an authenticated session is established.
- A malformed message is rejected by the application but logged by the proxy.
- A disconnect or timeout is mistaken for a security impact.

## Evidence

Record the endpoint, negotiated protocol, principal, origin, handshake headers, message sequence, responses, close codes, and affected object/channel. Redact tokens and personal data in notes and reports.

## Handoffs

- Use `idor` or `broken_function_level_authorization` for object/role boundary failures.
- Use `business_logic` or `race_conditions` for state invariants and concurrent events.
- Use `web_payload_crafting` for context-specific message mutations.
- Send confirmed candidates to an independent validator before reporting.

## Summary

WebSocket security is primarily a per-message authorization, origin, replay, and state-integrity problem. Validate the complete message lifecycle, not just the initial upgrade.
