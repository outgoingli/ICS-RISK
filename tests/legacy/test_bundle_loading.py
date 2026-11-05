"""Regression checks for explicit deployment bundles and supplied graph snapshots."""
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from lvsp_eval import Evaluator

REPO = Path(__file__).resolve().parents[2]
BUNDLE = REPO / 'examples/demo_bundle'


class BundleLoadingTests(unittest.TestCase):
    def setUp(self):
        self.request = json.loads((REPO / 'examples/request.json').read_text(encoding='utf-8'))

    def test_default_is_explicitly_synthetic(self):
        with patch.dict(os.environ, {}, clear=True):
            evaluator = Evaluator()
        self.assertEqual(evaluator.root, BUNDLE.resolve())
        self.assertEqual(evaluator.config['bindings']['bundle_profile'], 'synthetic_demo')
        self.assertTrue(all(source['kind'] == 'synthetic_demo_only'
                            for source in evaluator.sources.values()))
        self.assertEqual(evaluator.evaluate(**self.request)['decision'], 'INDETERMINATE')

    def test_environment_selects_bundle(self):
        with patch.dict(os.environ, {'ICS_RISK_BUNDLE': str(BUNDLE)}):
            self.assertEqual(Evaluator().root, BUNDLE.resolve())

    def test_explicit_bundle_wins_over_environment(self):
        with patch.dict(os.environ, {'ICS_RISK_BUNDLE': str(REPO / 'nonexistent-private-bundle')}):
            self.assertEqual(Evaluator(BUNDLE).load_issues, [])

    def test_supplied_graph_is_copied_and_changes_configuration_digest(self):
        original = Evaluator(BUNDLE)
        graph = copy.deepcopy(original.config['graph'])
        graph['edges'] = [edge for edge in graph['edges']
                          if edge['id'] != 'edge:requires_step_limit']
        external = Evaluator(BUNDLE, graph_data=graph)
        self.assertNotEqual(external.config_digest, original.config_digest)
        graph['edges'].clear()
        result = external.evaluate(**self.request)
        delta = next(item for item in result['constraints']
                     if item['constraint_id'] == 'constraint:step_limit')
        self.assertEqual(delta['status'], 'UNKNOWN')
        self.assertEqual(delta['reason'], 'required_variable_path_missing')
        self.assertEqual(result['decision'], 'INDETERMINATE')

    def test_external_graph_version_is_not_silently_substituted(self):
        graph = copy.deepcopy(Evaluator(BUNDLE).config['graph'])
        graph['graph_version'] = 'different-graph-version'
        result = Evaluator(BUNDLE, graph_data=graph).evaluate(**self.request)
        self.assertEqual(result['decision'], 'INDETERMINATE')
        self.assertIn('graph_version_mismatch', [issue['code'] for issue in result['input_issues']])


if __name__ == '__main__':
    unittest.main()
