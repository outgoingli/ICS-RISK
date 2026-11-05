"""Neo4j 4.4/5.x HTTP adapter with immutable, isolated graph versions.

HTTP transactions are supported by the lab's Neo4j 5.20. This endpoint was
deprecated in 5.26; newer deployments should implement the repository protocol
using Bolt or the Query API. No PLC or SCADA IO is performed here.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from lvsp_eval.graph import NODE_TYPES, RELATIONS
from ics_risk.graph_build.builder import GraphBuildError, graph_digest, validate_graph
from .repository import GraphNotFound, GraphRepositoryError, semantic_context


class VersionConflict(GraphRepositoryError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward credentials to a location chosen by the remote server.
        return None


def _identity(*parts):
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode("utf-8")).hexdigest()


def _statement(query, parameters=None):
    return {"statement": query, "parameters": parameters or {}, "resultDataContents": ["row"]}


def _rows(result):
    try:
        return [dict(zip(result["columns"], entry["row"])) for entry in result["data"]]
    except (TypeError, KeyError) as exc:
        raise GraphRepositoryError("malformed_database_result") from exc


_SNAPSHOT = """
MATCH (n) WHERE n._ics_scope = $scope AND n._ics_version = $version
WITH collect({properties: properties(n), labels: labels(n)}) AS nodes
OPTIONAL MATCH (a)-[r]->(b)
WHERE r._ics_scope = $scope AND r._ics_version = $version
RETURN nodes, collect(CASE WHEN r IS NULL THEN null ELSE
 {properties: properties(r), type: type(r), source: a.id, target: b.id,
  source_scope: a._ics_scope, source_version: a._ics_version,
  target_scope: b._ics_scope, target_version: b._ics_version} END) AS edges
"""


class Neo4jRepository:
    def __init__(self, uri, user, password, database="neo4j", scope="ics-risk", timeout=15):
        parsed = urlsplit(uri)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
            raise ValueError("neo4j_http_origin_required_without_embedded_credentials")
        if not all(isinstance(x, str) and x for x in (user, password, database, scope)):
            raise ValueError("neo4j_connection_fields_required")
        self.uri = uri.rstrip("/")
        self.database = database
        self.scope = scope
        self.timeout = timeout
        self._auth = "Basic " + base64.b64encode((user + ":" + password).encode("utf-8")).decode("ascii")
        self._endpoint = self.uri + "/db/" + quote(database, safe="") + "/tx"
        self._opener = build_opener(_NoRedirect())

    @classmethod
    def from_env(cls):
        return cls(os.environ.get("ICS_RISK_NEO4J_URI", "http://127.0.0.1:7474"),
                   os.environ.get("ICS_RISK_NEO4J_USER", "neo4j"),
                   os.environ.get("ICS_RISK_NEO4J_PASSWORD", ""),
                   os.environ.get("ICS_RISK_NEO4J_DATABASE", "neo4j"),
                   os.environ.get("ICS_RISK_NEO4J_SCOPE", "ics-risk"))

    def _request(self, endpoint, statements=None, method="POST"):
        payload = None if method == "DELETE" else json.dumps(
            {"statements": statements or []}, ensure_ascii=False, allow_nan=False).encode("utf-8")
        request = Request(endpoint, data=payload, method=method,
                          headers={"Authorization": self._auth, "Content-Type": "application/json",
                                   "Accept": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            # Error bodies/URLs may expose credentials, data or query parameters.
            raise GraphRepositoryError("neo4j_http_status_" + str(exc.code)) from None
        except (URLError, OSError, ValueError) as exc:
            raise GraphRepositoryError("neo4j_transport_or_response_error") from None
        if (not isinstance(result, dict) or not isinstance(result.get("results"), list)
                or not isinstance(result.get("errors", []), list)):
            raise GraphRepositoryError("malformed_database_response")
        if result.get("errors"):
            error = result["errors"][0]
            code = error.get("code", "unspecified") if isinstance(error, dict) else "unspecified"
            if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z0-9_.]+", code):
                code = "unspecified"
            raise GraphRepositoryError("neo4j_error: " + code)
        return result

    def _begin(self, statements):
        result = self._request(self._endpoint, statements)
        commit = result.get("commit", "")
        # Rebuild against the configured origin; never trust the returned host.
        match = re.search(r"/tx/([0-9]+)/commit$", urlsplit(commit).path)
        if not match:
            raise GraphRepositoryError("missing_transaction_identity")
        return self._endpoint + "/" + match.group(1), result

    def _rollback(self, tx):
        try:
            self._request(tx, method="DELETE")
        except GraphRepositoryError:
            pass  # A broken connection may have already rolled the transaction back.

    def ensure_schema(self):
        """Explicit publication-only schema setup. Query/evaluation never calls it."""
        statements = [_statement(
            "CREATE CONSTRAINT icsrisk_version_component IF NOT EXISTS "
            "FOR (n:Component) REQUIRE n._ics_version_key IS UNIQUE")]
        for label in sorted(NODE_TYPES):
            statements.append(_statement(
                f"CREATE CONSTRAINT icsrisk_key_{label.lower()} IF NOT EXISTS "
                f"FOR (n:{label}) REQUIRE n._ics_key IS UNIQUE"))
        self._request(self._endpoint + "/commit", statements)

    def _metadata(self, graph, item_id):
        return {"_ics_scope": self.scope, "_ics_version": graph["graph_version"],
                "_ics_schema_version": graph["schema_version"], "_ics_graph_sha256": graph_digest(graph),
                "_ics_key": _identity(self.scope, graph["graph_version"], item_id)}

    def _decode(self, result, version):
        rows = _rows(result)
        if len(rows) != 1:
            raise GraphRepositoryError("invalid_graph_snapshot_result")
        node_rows, edge_rows = rows[0].get("nodes"), rows[0].get("edges")
        if not isinstance(node_rows, list) or not isinstance(edge_rows, list):
            raise GraphRepositoryError("malformed_graph_snapshot")
        if not node_rows:
            raise GraphNotFound("graph_version_not_found")
        nodes, edges, digests, schemas, anchors = [], [], set(), set(), []
        allowed_meta = {"_ics_scope", "_ics_version", "_ics_schema_version", "_ics_graph_sha256",
                        "_ics_key", "_ics_version_key"}
        for records, output, is_node in ((node_rows, nodes, True), (edge_rows, edges, False)):
            for record in records:
                if not isinstance(record, dict):
                    raise GraphRepositoryError("malformed_stored_graph_record")
                props = record.get("properties", {})
                if not isinstance(props, dict):
                    raise GraphRepositoryError("malformed_stored_graph_properties")
                meta = {key: value for key, value in props.items() if key.startswith("_ics_")}
                if (set(meta) - allowed_meta or not all(isinstance(v, str) for v in meta.values())
                        or meta.get("_ics_scope") != self.scope or meta.get("_ics_version") != version
                        or meta.get("_ics_key") != _identity(self.scope, version, props.get("id"))):
                    raise GraphRepositoryError("stored_graph_metadata_mismatch")
                digests.add(meta.get("_ics_graph_sha256"))
                schemas.add(meta.get("_ics_schema_version"))
                if "_ics_version_key" in meta:
                    if not is_node or props.get("type") != "Component":
                        raise GraphRepositoryError("invalid_version_anchor")
                    anchors.append((props.get("id"), meta["_ics_version_key"]))
                if is_node:
                    if (not isinstance(props.get("type"), str) or record.get("labels") != [props.get("type")]
                            or props.get("type") not in NODE_TYPES):
                        raise GraphRepositoryError("stored_graph_node_labels_mismatch")
                elif (record.get("type") != props.get("type")
                      or record.get("source") != props.get("source")
                      or record.get("target") != props.get("target")
                      or record.get("source_scope") != self.scope or record.get("target_scope") != self.scope
                      or record.get("source_version") != version or record.get("target_version") != version):
                    raise GraphRepositoryError("stored_graph_edge_endpoint_mismatch")
                output.append({key: value for key, value in props.items() if not key.startswith("_ics_")})
        expected_anchor = min(n["id"] for n in nodes if n["type"] == "Component") if any(
            n["type"] == "Component" for n in nodes) else None
        if anchors != [(expected_anchor, _identity(self.scope, version))] or len(schemas) != 1 or None in schemas:
            raise GraphRepositoryError("incomplete_graph_version_identity")
        data = {"schema_version": schemas.pop(), "graph_version": version,
                "nodes": sorted(nodes, key=lambda n: n["id"]), "edges": sorted(edges, key=lambda e: e["id"])}
        try:
            data = validate_graph(data)
        except GraphBuildError as exc:
            raise GraphRepositoryError(str(exc)) from exc
        if digests != {graph_digest(data)}:
            raise GraphRepositoryError("stored_graph_digest_mismatch")
        return data

    def _read_in_transaction(self, tx, version):
        result = self._request(tx, [_statement(_SNAPSHOT, {"scope": self.scope, "version": version})])
        if len(result["results"]) != 1:
            raise GraphRepositoryError("invalid_graph_snapshot_result")
        return self._decode(result["results"][0], version)

    def get_graph(self, version):
        """One read query returns the whole version; no silent JSON fallback."""
        result = self._request(self._endpoint + "/commit", [
            _statement(_SNAPSHOT, {"scope": self.scope, "version": version})])
        if len(result["results"]) != 1:
            raise GraphRepositoryError("invalid_graph_snapshot_result")
        return self._decode(result["results"][0], version)

    def semantic_context(self, point_id, version):
        return semantic_context(self.get_graph(version), point_id)

    def publish(self, graph):
        """Publish a validated graph atomically; same version is immutable.

        Call build_graph(bundle) first to verify evidence. Only this explicit
        construction operation writes the database; evaluation calls get_graph.
        """
        data = validate_graph(graph)
        version = data["graph_version"]
        fingerprint = graph_digest(data)
        anchor = min((n for n in data["nodes"] if n["type"] == "Component"), key=lambda n: n["id"])
        version_key = _identity(self.scope, version)
        token = uuid.uuid4().hex
        anchor_props = dict(anchor, **self._metadata(data, anchor["id"]))
        anchor_props["_ics_version_key"] = version_key
        self.ensure_schema()
        tx = None
        try:
            # A uniqueness-backed actual Component anchors the version. Updating
            # its own string key obtains a write lock before inspecting the hash.
            tx, response = self._begin([_statement(
                "MERGE (a:Component {_ics_version_key: $version_key}) "
                "ON CREATE SET a += $props, a._ics_import_token = $token "
                "SET a._ics_version_key = a._ics_version_key + '' "
                "RETURN a._ics_graph_sha256 AS fingerprint, a._ics_import_token AS token, a.id AS id",
                {"version_key": version_key, "props": anchor_props, "token": token})])
            rows = _rows(response["results"][0])
            if len(rows) != 1 or rows[0].get("fingerprint") != fingerprint or rows[0].get("id") != anchor["id"]:
                raise VersionConflict("graph_version_already_has_different_content")
            created = rows[0].get("token") == token
            if created:
                existing = self._request(tx, [_statement(
                    "MATCH (n) WHERE n._ics_scope=$scope AND n._ics_version=$version "
                    "RETURN count(n) AS count", {"scope": self.scope, "version": version})])
                if _rows(existing["results"][0])[0]["count"] != 1:
                    raise VersionConflict("orphaned_graph_version_requires_manual_review")
                statements = []
                for label in sorted(NODE_TYPES):
                    items = [dict(n, **self._metadata(data, n["id"])) for n in data["nodes"] if n["type"] == label]
                    if items:
                        statements.append(_statement(
                            f"UNWIND $items AS item MERGE (n:{label} {{_ics_key: item._ics_key}}) "
                            "ON CREATE SET n += item", {"items": items}))
                for relation in sorted(RELATIONS):
                    items = [{"properties": dict(e, **self._metadata(data, e["id"])),
                              "source_key": _identity(self.scope, version, e["source"]),
                              "target_key": _identity(self.scope, version, e["target"])}
                             for e in data["edges"] if e["type"] == relation]
                    if items:
                        statements.append(_statement(
                            "UNWIND $items AS item MATCH (a {_ics_key:item.source_key}), "
                            "(b {_ics_key:item.target_key}) "
                            f"CREATE (a)-[r:{relation}]->(b) SET r += item.properties", {"items": items}))
                statements.append(_statement(
                    "MATCH (a:Component {_ics_version_key:$version_key}) REMOVE a._ics_import_token",
                    {"version_key": version_key}))
                self._request(tx, statements)
            readback = self._read_in_transaction(tx, version)
            if graph_digest(readback) != fingerprint:
                raise GraphRepositoryError("publication_readback_mismatch")
            self._request(tx + "/commit")
            return {"status": "created" if created else "unchanged", "scope": self.scope,
                    "graph_version": version, "graph_sha256": fingerprint,
                    "node_count": len(data["nodes"]), "edge_count": len(data["edges"])}
        except Exception:
            if tx:
                self._rollback(tx)
            raise
