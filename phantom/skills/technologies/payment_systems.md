---
name: payment_systems
description: Payment and billing workflow testing covering authorization, amount integrity, idempotency, refunds, webhooks, and environment separation
---

# Payment Systems

Test payment integrations as business workflows, not only as API endpoints. Keep all activity in the authorized sandbox/test account and use provider-supported test instruments or synthetic values.

## Workflow Map

Map the full lifecycle:

```text
cart/quote → checkout → authorization → capture/settlement
          → fulfillment → refund/void/dispute → webhook reconciliation
```

Record the application, provider, merchant account, currency, tenant, user role, and environment for every step.

## High-Value Tests

### Amount and Product Integrity

- Compare client-submitted price, quantity, tax, discount, shipping, currency, and product identifiers with server-side calculation.
- Change one value at a time and verify the server recomputes totals from trusted catalog/order data.
- Test negative, zero, fractional, high-precision, overflow, and currency-conversion boundaries in the provider sandbox.
- Verify discounts, coupons, credits, and gift cards are bound to the correct account and order.

### Authorization and State

- Confirm only the correct principal can create, capture, refund, void, dispute, or view an order.
- Verify payment status cannot be advanced by editing client fields, replaying a callback, or calling an alternate API version.
- Check that fulfillment requires verified provider state rather than a browser-controlled success flag.
- Test tenant and merchant-account isolation with separate sandbox principals.

### Idempotency and Replay

- Reuse documented idempotency keys across retries and confirm exactly one durable operation occurs.
- Check key binding to principal, route, amount, currency, and order; keys must not be transferable across operations.
- Replay provider events and verify duplicate deliveries do not double-capture, double-refund, or duplicate fulfillment.
- Use small controlled concurrency for race testing; do not create real charges.

### Webhooks and Reconciliation

- Pair with `webhook_security` for signature, freshness, event ordering, and environment checks.
- Confirm webhook amounts, currency, merchant account, order ID, and event type match the locally pending transaction.
- Test out-of-order events, missing events, retries, and manual reconciliation paths.

### Sensitive Data and Environment Separation

- Ensure raw card data, secrets, provider tokens, and full payment details do not reach logs, URLs, analytics, or client bundles.
- Verify test credentials and test events cannot alter live orders, and live credentials are not usable in the test environment.
- Check return URLs, hosted checkout origins, and post-payment redirects for open redirect or account-binding issues.

## Validation

1. Establish the expected order/payment state before testing.
2. Perform one bounded mutation or replay.
3. Prove durable financial or authorization impact using sandbox records, audit logs, and provider state.
4. Show the correctly rejected control request.
5. Report monetary impact only when demonstrated; do not infer it from a client-side display.

## False Positives

- A client value changes visually but the provider/server recalculates the trusted amount.
- A webhook is accepted at the transport layer but ignored after signature or state validation.
- A repeated request returns the same result because the operation is correctly idempotent.
- Test-mode behavior is intentionally different from production and is documented by the provider.

## Handoffs

- `business_logic` for workflow invariants and authorization.
- `race_conditions` for duplicate operations.
- `webhook_security` for callbacks and reconciliation.
- `api_abuse` for batch, version, and rate-limit differences.
- `oauth` for payment-provider login or delegated authorization flows.

## Summary

Payment testing should prove trusted amount calculation, authorization, idempotency, provider-state reconciliation, and environment separation without creating real charges or causing irreversible transactions.
