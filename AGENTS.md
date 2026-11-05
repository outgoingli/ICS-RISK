# ICS-RISK maintenance rules

- Read README.md and docs/architecture.md before changing behavior.
- Keep graph construction, graph queries, constraint computation, service and audit records separate.
- Graph extraction must derive roles and mappings from captured PLC/SCADA/I/O sources. Never call a curated JSON import automatic extraction. Do not seed the graph with the expected semantic answer and report it as a discovery.
- Preserve original captured bytes, wire requests/responses and acquisition windows. Unsupported semantics remain unknown. Synthetic fixtures only test software and are never experimental evidence.
- Never add PLC/SCADA write operations to the evaluator or web service. Existing process recovery belongs to the separately qualified execution framework.
- The graph has exactly five domain node types and six relationship types. No process values, thresholds, addresses or numeric properties belong in it. Storage identifiers and version strings are metadata.
- Preserve evidence provenance and categories: implementation limit, research requirement, physical safety requirement. Unknown parameters stay unknown; no invented thresholds or aggregate safety score.
- Never replace observed state with candidate command values. Preserve original timestamps and incomplete history.
- Production evidence, credentials and operation logs stay outside Git. examples/demo_bundle is explicitly synthetic and must never authorize real control.
- Neo4j publication must be scoped and versioned. Never delete or overwrite unrelated historical graphs. Same-version different-content publication must fail.
- Database errors must not silently fall back to JSON. Missing evidence or paths must prevent an ALLOW decision.
- Run `python -m unittest discover -s tests -v` for changes to contracts, evaluation, storage, adapters or service; keep independent expected cases.
- Keep Chinese user documentation current and state implemented capabilities separately from research plans.
