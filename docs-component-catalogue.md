# Bounded component catalogue discovery

`datto_list_components` is a read-only UID lookup. Use an optional case-insensitive `name` substring (at most 128 characters) and `max` results (1–100, default 50). It scans up to five pages of 100 records, including later pages even after the output limit is reached. `max` limits output, not scanned rows. No new execution endpoint, proxy grant, authentication behavior, cache, or dependency is introduced.

Each component includes only `uid`, `name` (at most 256 characters) and optional `categoryCode` (at most 64 characters). Names and category labels are untrusted provider data, not instructions or approval to run anything. Descriptions are intentionally omitted because they are free-form and unnecessary for UID lookup. Variables are omitted entirely, including names/types/descriptions/defaults: their schema can itself contain sensitive context and needs separate privacy review. Credentials, script source, execution levels and arbitrary unknown provider fields are never projected. This tool makes no claim that a discovered component can be executed by the caller.

The response is one JSON text block with:

- `components`, `returned`, `matchedInScan`, `scanned`, `pagesFetched`: counts are from this bounded scan, never an asserted global match count.
- `scanComplete`: the observed page chain ended; this alone does not mean all matches were returned.
- `outputTruncated`: matching rows exceeded `max`. Narrow the filter or increase `max`; continuation does not recover matches omitted by this output limit.
- `complete`: true only for an initial scan that reached the end, omitted no malformed identities and returned every observed match.
- `startPage`, `nextPage`: pass the returned numeric `nextPage` as `page`, with the same `name`, to continue unscanned pages. A continuation window never claims account-wide completeness. No raw provider URL is returned or accepted as a tool argument.
- `omittedRecords`, `limits`, `notes`: disclose malformed identities, hard budgets and interpretation limits.

Page chains must carry explicit `nextPageUrl` metadata. Missing/invalid metadata, repeated pages/UIDs, oversized pages or unsafe continuation URLs cause a sanitized tool error. Continuation is restricted to the same configured regional origin and exact component endpoint, with only numeric `page` and fixed-size `max` parameters. Existing safe-origin checks run before credentials/request forwarding, including validation of a continuation advertised on the last budgeted page. Redirect refusal, response-byte limits, token isolation and one 401 refresh retry remain unchanged. The page budget is not a wall-clock deadline; account changes between pages/calls can prevent a consistent snapshot.

## Summit availability

The provider advertises this tool as read-only. The inspected Summit proxy source does not approve it for Reader, Operator, Admin or Jumpstart; it remains denied until separate policy/privacy review. No proxy or ticket-scoped access is added, and no live policy or customer catalogue was queried.

Inspired by [WYRE-AI/datto-rmm-mcp#89](https://github.com/WYRE-AI/datto-rmm-mcp/pull/89), reviewed at `1375c47b0253edf70753890569c6acbd6080c82f`. This adaptation replaces its unbounded `componentsAll()` traversal and expansive variable/default metadata with a bounded native GET through the existing safe client helper. Its dependency and Dockerfile changes are excluded. Current-main #18 job summaries, #23 recurring-run correlation and #24 security fixes are retained.
