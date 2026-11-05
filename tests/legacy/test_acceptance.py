"""Independent black-box acceptance checks for CONTRACT.txt.

Run from the prototype root: python -B -m unittest discover -s tests -p test_acceptance.py -v
Only temporary fixture copies are mutated. No remote access or process control occurs.
The 10 s interval and physical-category examples are SYNTHETIC TEST DATA, not plant facts.
Expected decisions/statuses come from cases.json, not from the evaluator under test.
"""
from __future__ import annotations

import copy
from decimal import Decimal, localcontext
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "examples/demo_bundle"
sys.path.insert(0, str(REPO))
from lvsp_eval import Evaluator  # noqa: E402
from lvsp_eval.templates import evaluate_rule  # noqa: E402

SPEC = json.loads((Path(__file__).with_name("cases.json")).read_text(encoding="utf-8"))
INTERVAL_ID = "constraint:min_interval"
SYNTHETIC_SOURCE = "src:SYNTHETIC_ACCEPTANCE_ONLY_interval"
ALLOWED_NODES = {"Component", "Point", "Variable", "ControlLoop", "Constraint"}
ALLOWED_EDGES = {"EXPOSES", "MAPS_TO", "HOSTED_BY", "IN_LOOP", "APPLIES_TO", "REQUIRES"}


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def parameter_sha(parameters):
    payload = json.dumps(parameters, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def exact_percent(raw):
    with localcontext() as context:
        context.prec = 50
        return str(Decimal(raw) * Decimal(100) / Decimal(65535))


def file_fingerprints(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for directory in (root / "config", root / "evidence")
            for path in directory.rglob("*") if path.is_file()}


def copied_bundle(destination, synthetic=False):
    destination = Path(destination)
    for name in ("config", "evidence"):
        shutil.copytree(ROOT / name, destination / name)
    if synthetic:
        # This source intentionally asserts only a test parameter, never a real operating limit.
        relative = "evidence/SYNTHETIC_ACCEPTANCE_ONLY_interval.txt"
        path = destination / relative
        path.write_text("SYNTHETIC ACCEPTANCE FIXTURE ONLY\n"
                        "The minimum interval is 10 seconds solely to exercise evaluator arithmetic.\n"
                        "This is not evidence of any GRFICS physical or safety requirement.\n", encoding="utf-8")
        provenance = read(destination / "config/provenance.json")
        provenance["sources"].append({"id": SYNTHETIC_SOURCE, "path": relative,
                                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                      "locator": "SYNTHETIC_ACCEPTANCE_ONLY_interval.txt, entire file",
                                      "kind": "synthetic_test_only"})
        write(destination / "config/provenance.json", provenance)
        constraints = read(destination / "config/constraints.json")
        rule = next(r for r in constraints["rules"] if r["id"] == INTERVAL_ID)
        rule.update(enabled=True, verification="verified", evidence_refs=[SYNTHETIC_SOURCE])
        rule["parameters"]["seconds"] = 10
        rule["verified_parameters_sha256"] = parameter_sha(rule["parameters"])
        write(destination / "config/constraints.json", constraints)
        graph = read(destination / "config/graph.json")
        for node in graph["nodes"]:
            if node["id"] == INTERVAL_ID:
                node["evidence_refs"] = [SYNTHETIC_SOURCE]
        for edge in graph["edges"]:
            if INTERVAL_ID in (edge["source"], edge["target"]):
                edge["evidence_refs"] = [SYNTHETIC_SOURCE]
        write(destination / "config/graph.json", graph)
    return destination


def inputs(case, bundle):
    base = SPEC["base"]
    bindings = read(bundle / "config/bindings.json")
    candidate = case.get("candidate_raw", base["candidate_raw"])
    reference = case.get("reference_raw", base["reference_raw"])
    last = case.get("last_operation_at", base["last_operation_at"])
    command = {"id": "command:SYNTHETIC_ACCEPTANCE_ONLY", "action": "write",
               "point_id": "point:level_sp", "value": exact_percent(candidate), "raw": candidate,
               "unit": "percent", "evaluation_at": base["evaluation_at"]}
    signals = {}
    for name, value, unit in (("var:level_sp", reference, "raw_count"),
                              ("var:run", True, "boolean"), ("var:e_stop", False, "boolean")):
        signals[name] = {"value": value, "unit": unit, "observed_at": base["observed_at"],
                         "available_at": base["available_at"], "quality": "good",
                         "span_seconds": base["span_seconds"]}
    snapshot = {"graph_version": bindings["graph_version"], "runtime_sha256": bindings["runtime_sha256"],
                "captured_at": base["captured_at"], "signals": signals}
    history = {"complete": True, "coverage_start": base["history_coverage_start"],
               "coverage_end": base["history_coverage_end"], "events": [
                   {"id": "event:SYNTHETIC_ACCEPTANCE_ONLY_previous", "point_id": "point:level_sp",
                    "action": "write", "outcome": "confirmed", "occurred_at": last,
                    "available_at": last + 0.1, "raw": reference}]}
    objects = {"command": command, "snapshot": snapshot, "history": history}
    for change in case.get("mutations", []):
        owner = objects[change["target"]]
        for key in change["path"][:-1]:
            owner = owner[key]
        key = change["path"][-1]
        if change.get("op") == "remove":
            del owner[key]
        else:
            owner[key] = copy.deepcopy(change["value"])
    version = case.get("graph_version", bindings["graph_version"])
    return command, snapshot, history, version


def change_bundle(bundle, operation):
    if not operation:
        return
    graph_path = bundle / "config/graph.json"
    graph = read(graph_path)
    if operation == "remove_required_run_host":
        graph["edges"] = [edge for edge in graph["edges"]
                          if not (edge["source"] == "var:run" and edge["type"] == "HOSTED_BY")]
    elif operation == "graph_hidden_quantity":
        next(node for node in graph["nodes"] if node["id"] == "constraint:encoding_range")["lower"] = "100"
    elif operation.startswith("remove_"):
        edge_type = operation.removeprefix("remove_")
        if edge_type == "EXPOSES":
            selector = lambda e: e["type"] == edge_type and e["target"] == "point:level_sp"
        elif edge_type in ("MAPS_TO",):
            selector = lambda e: e["type"] == edge_type and e["source"] == "point:level_sp"
        elif edge_type in ("HOSTED_BY", "IN_LOOP"):
            selector = lambda e: e["type"] == edge_type and e["source"] == "var:level_sp"
        else:
            selector = lambda e: e["type"] == edge_type and e["source"] == "constraint:step_limit"
        removed = [edge for edge in graph["edges"] if selector(edge)]
        if not removed:
            raise AssertionError(f"Fixture has no targeted edge for {operation}")
        graph["edges"] = [edge for edge in graph["edges"] if not selector(edge)]
    elif operation in ("wrong_binding", "multiple_bindings"):
        edge = next(e for e in graph["edges"] if e["type"] == "MAPS_TO" and e["source"] == "point:level_sp")
        if operation == "multiple_bindings":
            edge = copy.deepcopy(edge)
            edge["id"] = "edge:SYNTHETIC_ACCEPTANCE_ONLY_extra_binding"
            graph["edges"].append(edge)
        edge["target"] = "var:run"
    elif operation == "illegal_node_type":
        next(n for n in graph["nodes"] if n["id"] == "var:level_sp")["type"] = "UnapprovedType"
    elif operation == "illegal_relation_type":
        graph["edges"][0]["type"] = "UNAPPROVED_RELATION"
    elif operation == "tamper_synthetic_evidence":
        with (bundle / "evidence/SYNTHETIC_ACCEPTANCE_ONLY_interval.txt").open("a", encoding="utf-8") as stream:
            stream.write("Modified without updating source SHA.\n")
        return
    elif operation in ("unverify_interval", "tamper_interval_parameter", "malformed_step_parameters",
                       "wrong_delta_operand", "wrong_interval_point"):
        path = bundle / "config/constraints.json"
        constraints = read(path)
        rule_id = "constraint:step_limit" if operation in ("malformed_step_parameters", "wrong_delta_operand") else INTERVAL_ID
        rule = next(r for r in constraints["rules"] if r["id"] == rule_id)
        if operation == "unverify_interval":
            rule["verification"] = "unverified"
        elif operation == "tamper_interval_parameter":
            rule["parameters"]["seconds"] = 9
        elif operation == "malformed_step_parameters":
            rule["parameters"] = []
        elif operation == "wrong_interval_point":
            rule["parameters"]["point_ref"] = "point:SYNTHETIC_wrong_point"
            rule["verified_parameters_sha256"] = parameter_sha(rule["parameters"])
        elif operation == "wrong_delta_operand":
            rule["parameters"]["reference_signal"] = "var:run"
            rule["verified_parameters_sha256"] = parameter_sha(rule["parameters"])
            for edge in graph["edges"]:
                if edge["source"] == rule_id and edge["type"] == "REQUIRES":
                    edge["target"] = "var:run"
            write(graph_path, graph)
        write(path, constraints)
        return
    else:
        raise AssertionError(f"Unknown fixture operation: {operation}")
    write(graph_path, graph)


def constraints_by_id(result):
    return {item["constraint_id"]: item for item in result["constraints"]}


def semantic_result(result):
    return {"decision": result["decision"],
            "constraints": {key: {field: item[field] for field in ("template", "category", "status", "metrics")}
                            for key, item in constraints_by_id(result).items()}}


def reverse_mapping_order(value):
    if isinstance(value, dict):
        return {key: reverse_mapping_order(item) for key, item in reversed(list(value.items()))}
    if isinstance(value, list):
        return [reverse_mapping_order(item) for item in value]
    return value


class AcceptanceTests(unittest.TestCase):
    def assert_number(self, observed, expected, label):
        self.assertNotIsInstance(observed, bool, label)
        self.assertEqual(Decimal(str(observed)), Decimal(str(expected)), label)

    def check_case(self, case):
        with tempfile.TemporaryDirectory(prefix="lvsp_acceptance_") as directory:
            bundle = copied_bundle(Path(directory), case["fixture"] == "synthetic_interval")
            arguments = inputs(case, bundle)
            change_bundle(bundle, case.get("bundle_mutation"))
            before_inputs = copy.deepcopy(arguments)
            before_files = file_fingerprints(bundle)
            with patch("socket.create_connection", side_effect=AssertionError("Network forbidden in evaluation")), \
                 patch("socket.socket", side_effect=AssertionError("Network forbidden in evaluation")):
                result = Evaluator(bundle).evaluate(*arguments)
            self.assertEqual(arguments, before_inputs, "evaluate mutated its caller-owned input")
            self.assertEqual(file_fingerprints(bundle), before_files, "evaluate modified bundle evidence/config")
            diagnostic = {"decision": result.get("decision"), "input_issues": result.get("input_issues"),
                          "checks": [{key: item.get(key) for key in ("constraint_id", "status", "metrics")}
                                     for item in result.get("constraints", [])]}
            self.assertEqual(result["decision"], case["decision"], json.dumps(diagnostic, ensure_ascii=False))
            actual = constraints_by_id(result)
            for constraint_id, status in case.get("statuses", {}).items():
                self.assertIn(constraint_id, actual, "Configured constraint silently disappeared")
                self.assertEqual(actual[constraint_id]["status"], status, constraint_id)
            for constraint_id, metrics in case.get("metrics", {}).items():
                for name, expected in metrics.items():
                    self.assertIn(name, actual[constraint_id]["metrics"], constraint_id)
                    self.assert_number(actual[constraint_id]["metrics"][name], expected, f"{constraint_id}/{name}")
            self.assertEqual(result["command"], arguments[0])
            self.assertIsInstance(result["input_issues"], list)
            self.assertIsInstance(result["query_trace"], list)
            self.assertIsInstance(result["completeness"], dict)
            if case["decision"] == "ALLOW":
                self.assertTrue(actual, "Empty checks cannot establish ALLOW")
                self.assertTrue(all(item["status"] == "PASS" for item in actual.values()))

    def test_case_ids_are_unique_and_source_classifications_are_explicit(self):
        ids = [case["id"] for case in SPEC["engine_cases"] + SPEC["metamorphic_cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        rules = read(ROOT / "config/constraints.json")["rules"]
        categories = {r["id"]: r["category"] for r in rules}
        self.assertEqual(categories["constraint:encoding_range"], "implementation_limit")
        self.assertEqual(categories["constraint:step_limit"], "research_requirement")
        self.assertNotIn("physical_safety_requirement", categories.values(), "Do not invent a production physical-safety rule")

    def test_determinism_and_input_immutability(self):
        evaluator = Evaluator(ROOT)
        arguments = inputs({}, ROOT)
        original = copy.deepcopy(arguments)
        first = evaluator.evaluate(*arguments)
        self.assertEqual(first, evaluator.evaluate(*arguments))
        self.assertEqual(arguments, original)
        self.assertEqual(first, evaluator.evaluate(*(reverse_mapping_order(x) for x in arguments)))
        self.assertEqual(first["snapshot_ref"], evaluator.evaluate(*original)["snapshot_ref"])

    def test_candidate_and_previous_evaluation_cannot_replace_snapshot(self):
        evaluator = Evaluator(ROOT)
        original = inputs({}, ROOT)
        candidate_a = inputs({"candidate_raw": 29164}, ROOT)
        candidate_a[0]["snapshot"] = {"signals": {"var:level_sp": {"value": 29164}}}
        saved = copy.deepcopy(candidate_a)
        result_a = evaluator.evaluate(*candidate_a)
        self.assertNotEqual(result_a["decision"], "ALLOW")
        step = constraints_by_id(result_a).get("constraint:step_limit", {})
        if "reference_raw" in step.get("metrics", {}):
            self.assert_number(step["metrics"]["reference_raw"], 28835, "authoritative snapshot reference")
        self.assertEqual(candidate_a, saved)
        self.assertEqual(evaluator.evaluate(*original), Evaluator(ROOT).evaluate(*copy.deepcopy(original)))

    def test_graph_serialization_order_does_not_change_semantic_answer(self):
        arguments = inputs({}, ROOT)
        expected = semantic_result(Evaluator(ROOT).evaluate(*arguments))
        with tempfile.TemporaryDirectory(prefix="lvsp_acceptance_order_") as directory:
            bundle = copied_bundle(Path(directory))
            path = bundle / "config/graph.json"
            graph = read(path)
            graph["nodes"].reverse()
            graph["edges"].reverse()
            write(path, graph)
            self.assertEqual(semantic_result(Evaluator(bundle).evaluate(*arguments)), expected)

    def test_irrelevant_past_history_cannot_become_current_point_last_operation(self):
        with tempfile.TemporaryDirectory(prefix="lvsp_acceptance_history_") as directory:
            bundle = copied_bundle(Path(directory), synthetic=True)
            arguments = inputs({}, bundle)
            expected = Evaluator(bundle).evaluate(*arguments)
            arguments[2]["events"].append({"id": "event:SYNTHETIC_other_point", "point_id": "point:other",
                                           "action": "write", "outcome": "confirmed", "occurred_at": 999,
                                           "available_at": 999.1, "raw": 123})
            actual = Evaluator(bundle).evaluate(*arguments)
            self.assertEqual(actual["decision"], "ALLOW")
            self.assertEqual(semantic_result(actual), semantic_result(expected))

    def test_no_graph_quantities_and_exact_schema_types(self):
        graph = read(ROOT / "config/graph.json")
        self.assertEqual({n["type"] for n in graph["nodes"]}, ALLOWED_NODES)
        self.assertEqual({e["type"] for e in graph["edges"]}, ALLOWED_EDGES)
        def inspect(value):
            self.assertNotIsInstance(value, (int, float, bool), "Quantity embedded in graph")
            if isinstance(value, dict):
                for child in value.values():
                    inspect(child)
            elif isinstance(value, list):
                for child in value:
                    inspect(child)
        inspect(graph)

    def test_pure_templates_keep_classification_and_strict_boolean_equality(self):
        for category in ("implementation_limit", "research_requirement", "physical_safety_requirement"):
            with self.subTest(category=category):
                # Physical category propagation is tested synthetically, never added to production.
                rule = {"id": "constraint:SYNTHETIC_category", "template": "precondition", "enabled": True,
                        "category": category, "verification": "verified", "evidence_refs": ["src:SYNTHETIC_unit_only"],
                        "parameters": {"signal": "var:run", "operator": "eq", "expected": True}}
                context = {"signals": {"var:run": 1}}
                original = copy.deepcopy((rule, context))
                result = evaluate_rule(rule, context)
                self.assertEqual(result["status"], "FAIL", "Python True == 1 must not bypass strict boolean semantics")
                self.assertEqual(result["category"], category)
                self.assertEqual((rule, context), original)
                context["signals"]["var:run"] = True
                self.assertEqual(evaluate_rule(rule, context)["status"], "PASS")

    def test_disabled_templates_do_not_compute_or_auto_verify(self):
        for template in ("range", "max_delta", "min_interval", "precondition"):
            with self.subTest(template=template):
                rule = {"id": "constraint:SYNTHETIC_disabled", "template": template, "enabled": False,
                        "category": "research_requirement", "verification": "unverified",
                        "evidence_refs": [], "parameters": {}}
                self.assertEqual(evaluate_rule(rule, {})["status"], "DISABLED")
                rule["enabled"] = True
                self.assertEqual(evaluate_rule(rule, {})["status"], "UNKNOWN")

    def test_quality_age_boundaries_and_separate_simulator_age(self):
        bindings = read(ROOT / "config/bindings.json")
        with tempfile.TemporaryDirectory(prefix="lvsp_acceptance_age_") as directory:
            bundle = copied_bundle(Path(directory), synthetic=True)
            for signal, bound in (("var:level_sp", bindings["quality"]["max_age_seconds"]),
                                   ("var:e_stop", bindings["signals"]["var:e_stop"]["max_age_seconds"])):
                for delta, expected in ((Decimal("0"), "ALLOW"), (Decimal("0.000001"), "INDETERMINATE")):
                    with self.subTest(signal=signal, delta=str(delta)):
                        arguments = inputs({}, bundle)
                        observed = Decimal("1000") - Decimal(str(bound)) - delta
                        # PLC values belong to one sequential row, so change their common window together.
                        affected = ("var:level_sp", "var:run") if signal == "var:level_sp" else (signal,)
                        for target in affected:
                            arguments[1]["signals"][target]["observed_at"] = str(observed)
                            arguments[1]["signals"][target]["available_at"] = str(observed + Decimal("0.1"))
                        self.assertEqual(Evaluator(bundle).evaluate(*arguments)["decision"], expected)


def make_engine_test(case):
    def test(self):
        self.check_case(case)
    test.__doc__ = case.get("note", case["id"])
    return test


for _case in SPEC["engine_cases"]:
    setattr(AcceptanceTests, "test_case_" + _case["id"], make_engine_test(_case))


if __name__ == "__main__":
    unittest.main(verbosity=2)
