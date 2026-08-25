---
name: webhook_security
description: Webhook and callback security testing covering signature validation, replay, tenant binding, event confusion, and delivery abuse
---

# Webhook Security

Webhooks cross trust boundaries asynchronously. Test both inbound webhook receivers and outbound callback configuration, with special attention to authenticity, replay, tenant binding, and state transitions.

## Reconnaissance

- Discover webhook registration, test-delivery, retry, replay, and event-log endpoints.
- Identify providers, signing algorithms, secret rotation, timestamp tolerance, event IDs, and delivery headers.
- Map which events create, update, refund, provision, disable, or otherwise change application state.
- Trace tenant/account ownership from registration through delivery and asynchronous processing.
- Identify queues, workers, dead-letter handling, status pages, and delivery logs.

## Inbound Receiver Tests

### Authenticity and Integrity

- Remove, alter, reorder, or duplicate signature and timestamp headers using a controlled test event.
- Verify the receiver signs the exact raw body, not a parsed/re-serialized representation.
- Test algorithm negotiation and key selection only with documented provider formats.
- Confirm secrets are not accepted from the event body, query string, or client-controlled metadata.

### Replay and Ordering

- Replay a captured event within and outside the documented timestamp window.
- Reuse an event ID with changed content and send valid events out of order.
- Verify idempotency is scoped to provider, tenant, event type, and event ID.
- Check whether retries can repeat a refund, role change, provisioning action, or fulfillment step.

### Event and Tenant Confusion

- Change event type, object ID, account, tenant, environment, and API version fields one at a time.
- Ensure the receiver obtains authority from the verified provider relationship rather than trusting those fields.
- Confirm a valid signature for one tenant/provider cannot authorize another tenant or environment.
- Test whether test-mode events can affect live records or live events can affect test records.

## Outbound Callback Tests

- Validate allowlists for callback destinations, schemes, ports, redirects, and DNS resolution.
- Check whether registration or event data can cause requests to unintended internal or third-party destinations.
- Use only an engagement-controlled callback or canary endpoint; do not probe arbitrary infrastructure.
- Verify callback authentication, certificate validation, retry limits, and sensitive-data minimization.

## Validation

1. Reproduce from a clean event and receiver state.
2. Show the exact signature, timestamp, event ID, principal/tenant, and body used.
3. Demonstrate unauthorized processing or a durable state change.
4. Compare with a correctly rejected event and inspect audit/queue evidence.
5. Confirm replay, cross-tenant, or environment confusion is repeatable without flooding the service.

## False Positives

- An invalid event is accepted at the HTTP layer but rejected before processing.
- A duplicate is logged but idempotently ignored.
- A callback DNS lookup occurs but the application does not send or process the response.
- A provider intentionally exposes public delivery metadata without sensitive state impact.
- A test event is isolated from live records by a verified environment boundary.

## Handoffs

- `ssrf` for confirmed server-side destination fetching.
- `idor` or `api_abuse` for tenant/object authorization failures.
- `race_conditions` for duplicate delivery or ordering bugs.
- `web_payload_crafting` for event/parser mutations.
- `payment_systems` when the webhook controls settlement, refunds, or credits.

## Summary

Treat a webhook as an authenticated API request that arrives later and may be retried. Verify authenticity, freshness, tenant binding, and idempotent state transitions independently.
