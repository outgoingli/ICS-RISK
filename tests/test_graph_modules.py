"""Independent module tests; the fixture below asserts no plant facts."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ics_risk.graph_build import GraphBuildError, build_graph, graph_digest, validate_graph
from ics_risk.graph_query import GraphNotFound, GraphRepositoryError, JsonRepository, Neo4jRepository, VersionConflict
from ics_risk.graph_query.neo4j import _identity


def fixture():
    nodes = [{"id": identifier, "type": kind, "label": identifier, "evidence_refs": ["src:synthetic"]}
             for identifier, kind in (("component:plc", "Component"), ("point:sp", "Point"),
                                      ("var:sp", "Variable"), ("loop:level", "ControlLoop"),
                                      ("constraint:step", "Constraint"))]
    edges = [{"id": "edge:" + kind, "type": kind, "source": source, "target": target,
              "evidence_refs": ["src:synthetic"]}
             for source, kind, target in (("component:plc", "EXPOSES", "point:sp"),
                                          ("point:sp", "MAPS_TO", "var:sp"),
                                          ("var:sp", "HOSTED_BY", "component:plc"),
                                          ("var:sp", "IN_LOOP", "loop:level"),
                                          ("constraint:step", "APPLIES_TO", "var:sp"),
                                          ("constraint:step", "REQUIRES", "var:sp"))]
    return {"schema_version": "1", "graph_version": "SYNTHETIC-test-v1", "nodes": nodes, "edges": edges}


def db_result(repository, graph):
    nodes = []
    for node in graph["nodes"]:
        props = dict(node, **repository._metadata(graph, node["id"]))
        if node["id"] == "component:plc":
            props["_ics_version_key"] = _identity(repository.scope, graph["graph_version"])
        nodes.append({"properties": props, "labels": [node["type"]]})
    edges = [{"properties": dict(edge, **repository._metadata(graph, edge["id"])),
              "type": edge["type"], "source": edge["source"], "target": edge["target"],
              "source_scope": repository.scope, "target_scope": repository.scope,
              "source_version": graph["graph_version"], "target_version": graph["graph_version"]}
             for edge in graph["edges"]]
    return {"columns": ["nodes", "edges"], "data": [{"row": [nodes, edges]}]}


class GraphBuildTests(unittest.TestCase):
    def setUp(self):
        self.graph = fixture()

    def test_same_semantics_have_order_independent_digest(self):
        changed = copy.deepcopy(self.graph)
        changed["nodes"].reverse()
        changed["edges"].reverse()
        self.assertEqual(graph_digest(self.graph), graph_digest(changed))

    def test_numeric_graph_property_rejected(self):
        self.graph["nodes"][0]["upper"] = 100
        with self.assertRaises(GraphBuildError):
            validate_graph(self.graph)

    def test_numeric_limit_hidden_as_string_rejected(self):
        self.graph["nodes"][0]["upper"] = "100"
        with self.assertRaises(GraphBuildError):
            validate_graph(self.graph)

    def test_wrong_relation_direction_rejected(self):
        self.graph["edges"][0]["source"] = "point:sp"
        self.graph["edges"][0]["target"] = "component:plc"
        with self.assertRaises(GraphBuildError):
            validate_graph(self.graph)

    def test_unapproved_node_type_rejected(self):
        self.graph["nodes"][0]["type"] = "Risk"
        with self.assertRaises(GraphBuildError):
            validate_graph(self.graph)

    def test_malformed_nested_type_rejected(self):
        self.graph["nodes"][0]["type"] = []
        with self.assertRaises(GraphBuildError):
            validate_graph(self.graph)

    def make_bundle(self, root):
        (root / "config").mkdir()
        (root / "evidence").mkdir()
        payload = b"SYNTHETIC TEST ONLY; no real plant assertions.\n"
        (root / "evidence" / "source.txt").write_bytes(payload)
        (root / "config" / "graph.json").write_text(json.dumps(self.graph), encoding="utf-8")
        manifest = {"sources": [{"id": "src:synthetic", "path": "evidence/source.txt",
                                 "sha256": hashlib.sha256(payload).hexdigest(),
                                 "locator": "entire file", "kind": "synthetic_test_only"}]}
        (root / "config" / "provenance.json").write_text(json.dumps(manifest), encoding="utf-8")
        return manifest

    def test_curated_evidence_bundle_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_bundle(root)
            self.assertEqual(build_graph(root), self.graph)

    def test_tampered_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_bundle(root)
            (root / "evidence" / "source.txt").write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(GraphBuildError, "digest_mismatch"):
                build_graph(root)

    def test_missing_evidence_reference_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.graph["nodes"][0]["evidence_refs"] = ["src:missing"]
            self.make_bundle(root)
            with self.assertRaisesRegex(GraphBuildError, "unresolved"):
                build_graph(root)

    def test_evidence_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self.make_bundle(root)
            manifest["sources"][0]["path"] = "../outside.txt"
            (root / "config" / "provenance.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(GraphBuildError, "outside_bundle"):
                build_graph(root)

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_bundle(root)
            (root / "config" / "graph.json").write_text('{"nodes":[],"nodes":[]}', encoding="utf-8")
            with self.assertRaises(GraphBuildError):
                build_graph(root)


class GraphQueryTests(unittest.TestCase):
    def test_paths_and_operands(self):
        repo = JsonRepository(fixture())
        result = repo.semantic_context("point:sp", "SYNTHETIC-test-v1")
        self.assertEqual(result["variable_id"], "var:sp")
        self.assertEqual(result["loop_id"], "loop:level")
        self.assertEqual(result["constraints"][0]["requires"],
                         [{"variable_id": "var:sp", "host": "component:plc"}])
        self.assertEqual(result["issues"], [])
        self.assertTrue(any(q["relation"] == "REQUIRES" for q in result["query_trace"]))

    def test_repository_returns_independent_copy(self):
        repo = JsonRepository(fixture())
        result = repo.get_graph("SYNTHETIC-test-v1")
        result["nodes"].clear()
        self.assertEqual(len(repo.get_graph("SYNTHETIC-test-v1")["nodes"]), 5)

    def test_wrong_version_does_not_fallback(self):
        with self.assertRaises(GraphNotFound):
            JsonRepository(fixture()).get_graph("wrong-version")

    def test_unknown_point_does_not_guess(self):
        with self.assertRaises(GraphNotFound):
            JsonRepository(fixture()).semantic_context("unknown", "SYNTHETIC-test-v1")

    def test_missing_semantic_path_reported(self):
        graph = fixture()
        graph["edges"] = [e for e in graph["edges"] if e["type"] != "MAPS_TO"]
        result = JsonRepository(graph).semantic_context("point:sp", graph["graph_version"])
        self.assertIsNone(result["variable_id"])
        self.assertEqual(result["issues"][0]["code"], "non_unique_query_result")


class Neo4jTests(unittest.TestCase):
    def setUp(self):
        self.repo = Neo4jRepository("http://127.0.0.1:17474", "neo4j", "synthetic-secret", scope="synthetic-tests")
        self.graph = fixture()
        self.version = self.graph["graph_version"]

    def test_decode_exact_graph_content(self):
        restored = self.repo._decode(db_result(self.repo, self.graph), self.version)
        self.assertEqual(graph_digest(restored), graph_digest(self.graph))

    def test_decode_missing_edge_detects_digest_mismatch(self):
        result = db_result(self.repo, self.graph)
        result["data"][0]["row"][1].pop()
        with self.assertRaisesRegex(GraphRepositoryError, "digest_mismatch"):
            self.repo._decode(result, self.version)

    def test_decode_cross_scope_edge_rejected(self):
        result = db_result(self.repo, self.graph)
        result["data"][0]["row"][1][0]["source_scope"] = "other-project"
        with self.assertRaisesRegex(GraphRepositoryError, "endpoint_mismatch"):
            self.repo._decode(result, self.version)

    def test_decode_extra_domain_label_rejected(self):
        result = db_result(self.repo, self.graph)
        result["data"][0]["row"][0][0]["labels"].append("Unapproved")
        with self.assertRaisesRegex(GraphRepositoryError, "labels_mismatch"):
            self.repo._decode(result, self.version)

    def test_empty_version_raises_not_found(self):
        with self.assertRaises(GraphNotFound):
            self.repo._decode({"columns": ["nodes", "edges"], "data": [{"row": [[], []]}]}, self.version)

    def test_query_is_read_only_parameterized_and_scoped(self):
        self.repo._request = Mock(return_value={"results": [db_result(self.repo, self.graph)]})
        self.repo.get_graph(self.version)
        url, statements = self.repo._request.call_args.args
        self.assertTrue(url.endswith("/tx/commit"))
        self.assertEqual(statements[0]["parameters"], {"scope": "synthetic-tests", "version": self.version})
        self.assertNotIn("CREATE", statements[0]["statement"])
        self.assertNotIn("synthetic-secret", statements[0]["statement"])

    def test_connection_failure_is_not_json_fallback(self):
        self.repo._request = Mock(side_effect=GraphRepositoryError("neo4j_transport_or_response_error"))
        with self.assertRaises(GraphRepositoryError):
            self.repo.get_graph(self.version)

    def test_credentials_embedded_in_url_rejected(self):
        with self.assertRaises(ValueError):
            Neo4jRepository("http://user:secret@localhost:7474", "user", "secret")

    def test_error_body_does_not_leak_secrets(self):
        response = Mock()
        response.read.return_value = json.dumps({"results": [], "errors": [
            {"code": "Neo.ClientError.Security.Unauthorized", "message": "synthetic-secret"}]}).encode()
        self.repo._opener.open = Mock()
        self.repo._opener.open.return_value.__enter__ = Mock(return_value=response)
        self.repo._opener.open.return_value.__exit__ = Mock(return_value=False)
        with self.assertRaises(GraphRepositoryError) as context:
            self.repo._request(self.repo._endpoint)
        self.assertNotIn("synthetic-secret", str(context.exception))

    def setup_publish(self, fingerprint=None, created=True):
        self.repo.ensure_schema = Mock()
        def begin(statements):
            params = statements[0]["parameters"]
            return "http://127.0.0.1:17474/db/neo4j/tx/42", {"results": [
                {"columns": ["fingerprint", "token", "id"], "data": [{"row": [
                    fingerprint or graph_digest(self.graph), params["token"] if created else None, "component:plc"]}]}]}
        self.repo._begin = Mock(side_effect=begin)
        self.repo._request = Mock(return_value={"results": [{"columns": ["count"], "data": [{"row": [1]}]}]})
        self.repo._read_in_transaction = Mock(return_value=self.graph)
        self.repo._rollback = Mock()

    def test_publication_is_verified_before_commit(self):
        self.setup_publish()
        result = self.repo.publish(self.graph)
        self.assertEqual(result["status"], "created")
        self.assertEqual(result["node_count"], 5)
        self.repo._read_in_transaction.assert_called_once()
        self.assertTrue(self.repo._request.call_args.args[0].endswith("/42/commit"))
        self.repo._rollback.assert_not_called()

    def test_same_content_is_idempotent(self):
        self.setup_publish(created=False)
        result = self.repo.publish(self.graph)
        self.assertEqual(result["status"], "unchanged")
        # No node or relationship publication statement is issued.
        self.assertEqual(self.repo._request.call_count, 1)

    def test_existing_version_conflict_rolls_back(self):
        self.setup_publish(fingerprint="different")
        with self.assertRaises(VersionConflict):
            self.repo.publish(self.graph)
        self.repo._rollback.assert_called_once()
        self.repo._request.assert_not_called()

    def test_readback_failure_rolls_back(self):
        self.setup_publish()
        self.repo._read_in_transaction.side_effect = GraphRepositoryError("stored_graph_digest_mismatch")
        with self.assertRaises(GraphRepositoryError):
            self.repo.publish(self.graph)
        self.repo._rollback.assert_called_once()
        self.assertFalse(any(call.args[0].endswith("/commit") for call in self.repo._request.call_args_list))


if __name__ == "__main__":
    unittest.main()
