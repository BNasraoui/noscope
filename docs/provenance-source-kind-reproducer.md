# `SourceBuilder` cannot declare a non-document source kind

Recorded against Provenance `49ed0162e9e3fea46332d5f769bac17f863ff348`
(the merge of PR 152, `core, sdk: add exact declaration adoption`).

This is a NoScope note about an upstream limit we work around locally. It is
not a request that lands in this repository, and NoScope does not patch
Provenance to remove it.

## What happens

`provenance_core::authoring::SourceBuilder` exposes `id`, `adopt_unowned`,
`document`, and `name`. It has no method that selects a source type, and
`collect_source` hardcodes the kind it emits:

```rust
// crates/provenance-core/src/authoring/document.rs
let declaration = TypedSourceInput {
    name: source.name.unwrap_or_else(|| source.key.clone()),
    key: source.key,
    id: source.explicit_id,
    kind: "document".to_string(),
    url: None,
    reference: source.reference,
};
```

`SourceType` itself accepts ten values, `external_integration` among them
(`crates/provenance-core/src/model/artifacts.rs`). So the store models a kind
the fluent authoring API cannot declare.

## Minimal reproducer

NoScope's `source_workflowd_integration_brief` is an `external_integration`.
Declaring it through the fluent API only, then planning against the existing
graph, reports a conflict instead of adopting the record:

```console
$ provenance sdk plan --repo . < document.json
{
  "created": 0, "updated": 0, "retired": 0, "conflicts": 1, "unchanged": 0,
  "resources": [
    {
      "kind": "source",
      "id": "source_workflowd_integration_brief",
      "state": "conflict",
      "changes": [
        { "field": "declared_by", "before": null, "after": "spec://rust/noscope" },
        { "field": "address", "before": null, "after": ["noscope", "source", "workflowd-integration-brief"] },
        { "field": "kind", "before": "external_integration", "after": "document" }
      ]
    }
  ]
}
```

Reconciliation is behaving correctly here: it refuses to rewrite a source type
that the declaration did not intend to change. The gap is that the fluent API
gives no way to state the kind the record already holds.

## Why this blocks the port

`req_env_key_at_invocation`, `req_no_group_survivors`,
`req_provider_owns_lease_identity`, and `req_scheduled_restart_before_expiry`
each cite this brief. Adoption refuses a Requirement whose relationships the
document would drop, so those four Requirements cannot be adopted unless the
brief is declared too. Declaring the brief through the fluent API alone
conflicts on `kind`. The two constraints leave no fluent-only document that
adopts all seventy Requirements.

## What NoScope does instead

`provenance_spec::desired_state` builds the document with the fluent API and
then restores the brief's kind on the materialized
`provenance_sdk::TypedSpecInput`, which the SDK re-exports as public API:

```rust
let mut input = document()?.materialize(DECLARED_BY);
for source in &mut input.sources {
    if source.id.as_deref() == Some(WORKFLOWD_BRIEF_ID) {
        source.kind = WORKFLOWD_BRIEF_KIND.to_owned();
    }
}
```

With that one field restored the same plan reports zero conflicts and moves all
seventy-five records into declaration ownership without touching a statement, a
name, a kind, or a relationship.

## What would remove the workaround

A source-type selector on `SourceBuilder`, so a declaration can name the kind
it adopts. When that lands, `desired_state` collapses back into `document`.
