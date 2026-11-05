"""Service integration checks with no connection to a PLC or real Neo4j server."""
import copy
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from ics_risk.records import RecordStore
from ics_risk.service import RiskApplication, create_server


GRAPH = {"graph_version": "test-v1", "nodes": [], "edges": []}
REQUEST = {"command": {"raw": 20}, "snapshot": {"raw": 10},
           "history": {"events": []}, "graph_version": "test-v1"}


class Repository:
    def __init__(self):
        self.calls = []
        self.fail = False

    def get_graph(self, version):
        self.calls.append(version)
        if self.fail:
            raise RuntimeError("password=secret-must-not-leak")
        return copy.deepcopy(GRAPH)


class EvaluatorFixture:
    def __init__(self, bundle_dir, graph_data=None):
        assert graph_data == GRAPH

    def evaluate(self, command, snapshot, history, graph_version):
        return {"decision": "INDETERMINATE", "graph_version": graph_version,
                "constraints": [{"constraint_id": "constraint:interval", "status": "DISABLED"}],
                "query_trace": [{"node": "point:setpoint", "relation": "MAPS_TO"}],
                "evidence": [], "input_issues": [],
                "completeness": {"complete": False, "physical_safety_assessed": False}}


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        (self.root / "config/graph.json").write_text(json.dumps(GRAPH), encoding="utf-8")
        self.example = self.root / "request.json"
        self.example.write_text(json.dumps(REQUEST), encoding="utf-8")
        self.repo = Repository()
        self.app = RiskApplication(self.root, self.repo, self.root / "records", self.example,
                                   backend="test", evaluator_factory=EvaluatorFixture)
        self.server = create_server(self.app, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read()
        result = (response.status, dict(response.getheaders()), data)
        connection.close()
        return result

    def test_health_and_graph_version(self):
        status, _, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["control_writes"])
        self.assertEqual(json.loads(body)["bundle_profile"], "unclassified")
        status, _, body = self.request("GET", "/api/graph?version=test-v1")
        self.assertEqual(json.loads(body), GRAPH)

    def test_evaluation_records_original_inputs_and_result(self):
        original = copy.deepcopy(REQUEST)
        status, _, body = self.request("POST", "/api/evaluate", json.dumps(REQUEST), {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        record = json.loads(body)
        self.assertEqual(record["request"], original)
        self.assertEqual(record["result"]["decision"], "INDETERMINATE")
        status, _, body = self.request("GET", "/api/records/" + record["record_id"])
        self.assertEqual(json.loads(body), record)
        self.assertEqual(REQUEST, original)

    def test_backend_failure_is_recorded_without_fallback_or_secret(self):
        self.repo.fail = True
        status, _, body = self.request("POST", "/api/evaluate", json.dumps(REQUEST), {"Content-Type": "application/json"})
        self.assertEqual(status, 503)
        record = json.loads(body)
        self.assertEqual(record["result"]["decision"], "INDETERMINATE")
        self.assertEqual(record["result"]["constraints"], [])
        self.assertNotIn(b"secret-must-not-leak", body)
        self.assertEqual(len(self.app.records.list()), 1)

    def test_record_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            self.app.records.get("../config/graph")
        status, _, _ = self.request("GET", "/api/records/../../config/graph")
        self.assertEqual(status, 400)

    def test_json_duplicate_and_nonfinite_rejected(self):
        for body in ['{"command": {}, "command": {}}', '{"command": NaN}']:
            status, _, _ = self.request("POST", "/api/evaluate", body, {"Content-Type": "application/json"})
            self.assertEqual(status, 400)
        self.assertEqual(self.app.records.list(), [])

    def test_cross_origin_and_dns_rebinding_rejected(self):
        status, _, _ = self.request("POST", "/api/evaluate", json.dumps(REQUEST),
                                    {"Content-Type": "application/json", "Origin": "https://attacker.invalid"})
        self.assertEqual(status, 403)
        status, _, _ = self.request("GET", "/api/records", headers={"Host": "attacker.invalid:" + str(self.server.server_port)})
        self.assertEqual(status, 403)

    def test_token_required_for_api_when_configured(self):
        self.app.token = "test-only-token"
        status, _, _ = self.request("GET", "/api/records")
        self.assertEqual(status, 401)
        status, _, _ = self.request("GET", "/api/records", headers={"Authorization": "Bearer test-only-token"})
        self.assertEqual(status, 200)

    def test_external_bind_without_token_rejected(self):
        with self.assertRaises(ValueError):
            create_server(self.app, host="0.0.0.0", port=0)

    def test_static_page_has_csp_and_no_execution_controls(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn("不下发 PLC 指令".encode(), body)
        self.assertNotIn(b"http://cdn", body)

    def test_invalid_media_type_and_size_rejected(self):
        status, _, _ = self.request("POST", "/api/evaluate", "{}", {"Content-Type": "text/plain"})
        self.assertEqual(status, 415)
        status, _, _ = self.request("POST", "/api/evaluate", "{}", {"Content-Type": "application/json", "Content-Length": "1048577"})
        self.assertEqual(status, 413)

    def test_example_is_labelled_and_not_retimed(self):
        status, _, body = self.request("GET", "/api/example")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["request"], REQUEST)
        self.assertIn("不代表当前现场", data["notice"])

    def test_synthetic_profile_is_explicit(self):
        (self.root / "config/bindings.json").write_text('{"bundle_profile":"synthetic_demo"}', encoding="utf-8")
        app = RiskApplication(self.root, self.repo, self.root / "records", self.example,
                              backend="test", evaluator_factory=EvaluatorFixture)
        self.assertEqual(app.health()["bundle_profile"], "synthetic_demo")

    def test_archived_profile_requires_explicit_declaration(self):
        (self.root / "config/bindings.json").write_text('{"bundle_profile":"archived_lab_evidence"}', encoding="utf-8")
        app = RiskApplication(self.root, self.repo, self.root / "records", self.example,
                              backend="test", evaluator_factory=EvaluatorFixture)
        self.assertEqual(app.health()["bundle_profile"], "archived_lab_evidence")

    def test_missing_bindings_does_not_claim_archived_or_live(self):
        self.assertFalse((self.root / "config/bindings.json").exists())
        self.assertEqual(self.app.health()["bundle_profile"], "unclassified")
        _, record = self.app.evaluate(copy.deepcopy(REQUEST))
        self.assertEqual(record["bundle_profile"], "unclassified")

    def test_unknown_or_missing_profile_is_unclassified(self):
        for bindings in ({}, {"bundle_profile": "live"}, {"bundle_profile": "unknown"},
                         {"bundle_profile": None}, {"bundle_profile": []}):
            with self.subTest(bindings=bindings):
                (self.root / "config/bindings.json").write_text(json.dumps(bindings), encoding="utf-8")
                app = RiskApplication(self.root, self.repo, self.root / "records", self.example,
                                      backend="test", evaluator_factory=EvaluatorFixture)
                self.assertEqual(app.health()["bundle_profile"], "unclassified")
                _, record = app.evaluate(copy.deepcopy(REQUEST))
                self.assertEqual(record["bundle_profile"], "unclassified")

    def test_append_uses_distinct_ids_and_does_not_overwrite(self):
        first = self.app.records.append(REQUEST, {"decision": "BLOCK"}, backend="test")
        second = self.app.records.append(REQUEST, {"decision": "BLOCK"}, backend="test")
        self.assertNotEqual(first["record_id"], second["record_id"])
        self.assertEqual(len(self.app.records.list()), 2)


if __name__ == "__main__":
    unittest.main()
