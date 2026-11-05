"""Validate a curated graph and the evidence that supports its assertions."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from lvsp_eval.graph import Graph


class GraphBuildError(ValueError):
    """The candidate cannot be published as a supported graph version."""


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise GraphBuildError("duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"),
                          object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(GraphBuildError("nonfinite_json")))
    except (OSError, ValueError) as exc:
        raise GraphBuildError("unreadable_graph_or_evidence_manifest") from exc


def validate_graph(data):
    """Return an independent validated copy, keeping all numerical data outside."""
    if not isinstance(data, dict) or set(data) != {"schema_version", "graph_version", "nodes", "edges"}:
        raise GraphBuildError("invalid_graph_envelope")
    if not all(isinstance(data.get(key), str) and data[key] for key in ("schema_version", "graph_version")):
        raise GraphBuildError("missing_graph_version")
    if data["schema_version"] != "1":
        raise GraphBuildError("unsupported_graph_schema")
    if not isinstance(data["nodes"], list) or not data["nodes"] or not isinstance(data["edges"], list):
        raise GraphBuildError("empty_or_invalid_graph_collections")
    try:
        graph = Graph(data)
    except (TypeError, KeyError, ValueError) as exc:
        raise GraphBuildError("malformed_graph") from exc
    if graph.issues:
        raise GraphBuildError("invalid_graph: " + ",".join(sorted({x["code"] for x in graph.issues})))
    for item in data["nodes"] + data["edges"]:
        for key, value in item.items():
            if key == "evidence_refs":
                if not value or any(not isinstance(v, str) or not v for v in value):
                    raise GraphBuildError("invalid_evidence_refs")
            elif not isinstance(value, str) or not value:
                raise GraphBuildError("graph_properties_must_be_nonempty_strings")
    if not any(n["type"] == "Component" for n in data["nodes"]):
        raise GraphBuildError("component_required_for_version_identity")
    return copy.deepcopy(data)


def graph_digest(data):
    """Stable content digest; node/edge list order has no graph meaning."""
    canonical = copy.deepcopy(data)
    canonical["nodes"] = sorted(canonical["nodes"], key=lambda item: item["id"])
    canonical["edges"] = sorted(canonical["edges"], key=lambda item: item["id"])
    return hashlib.sha256(json.dumps(canonical, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def build_graph(bundle_dir):
    """Build from curated config, verifying evidence bytes, not source truth.

    This deliberately does not infer relationships from numerical observations,
    execute PLC code, invent thresholds, or regard a matching hash as authenticity.
    """
    root = Path(bundle_dir).resolve()
    graph = validate_graph(read_json(root / "config" / "graph.json"))
    manifest = read_json(root / "config" / "provenance.json")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("sources"), list):
        raise GraphBuildError("invalid_evidence_manifest")
    sources = {}
    for source in manifest["sources"]:
        if not isinstance(source, dict) or not isinstance(source.get("id"), str) or source["id"] in sources:
            raise GraphBuildError("invalid_or_duplicate_evidence_source")
        try:
            path = (root / source["path"]).resolve()
            if not path.is_relative_to(root):
                raise GraphBuildError("evidence_path_outside_bundle")
            if not source.get("locator") or not source.get("kind"):
                raise GraphBuildError("evidence_source_missing_provenance")
            if hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]:
                raise GraphBuildError("evidence_digest_mismatch: " + source["id"])
        except (OSError, KeyError, TypeError) as exc:
            raise GraphBuildError("unreadable_evidence_source") from exc
        sources[source["id"]] = source
    for item in graph["nodes"] + graph["edges"]:
        if any(ref not in sources for ref in item["evidence_refs"]):
            raise GraphBuildError("unresolved_graph_evidence: " + item["id"])
    return graph
