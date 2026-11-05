"""Integration contract tests using synthetic request fixtures, without a live PLC."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "examples/demo_bundle"
sys.path.insert(0, str(REPO))
from lvsp_eval import Evaluator
from lvsp_eval.adapter import assess_qualified_request, qualified_inputs


class AdapterTests(unittest.TestCase):
    def setUp(self):
        record = json.loads((Path(__file__).parent / 'fixtures/qualification_request.json').read_text(encoding='utf-8'))
        self.inputs = record['inputs']
        self.excerpt = record['source_excerpt']
        self.cfg = {'target_raw': 29163, 'point_id': 21, 'plc_host': 'plc.example.invalid', 'unit': 1,
                    'expected_st_sha256': self.inputs['snapshot']['runtime_sha256']}
        self.args = (self.cfg, self.excerpt['selected_row'], self.excerpt['selected_simulator'],
                     self.inputs['history'], self.inputs['command']['evaluation_at'], 'lvsp-demo-v1')

    def test_measured_reference_never_uses_candidate_or_config_original(self):
        self.cfg['original_raw'] = 50000
        payload = qualified_inputs(*self.args)
        self.assertEqual(payload['command']['raw'], 29163)
        self.assertEqual(payload['snapshot']['signals']['var:level_sp']['value'], 28835)
        self.assertNotEqual(payload['command']['raw'], payload['snapshot']['signals']['var:level_sp']['value'])

    def test_read_only_shadow_has_no_dispatch_and_preserves_arguments(self):
        before = copy.deepcopy(self.args)
        with patch('socket.socket', side_effect=AssertionError('No network in assessment')):
            answer = assess_qualified_request(*self.args, evaluator=Evaluator(ROOT))
        self.assertEqual(self.args, before)
        self.assertFalse(answer['dispatch_performed'])
        self.assertFalse(answer['existing_protection_modified'])
        self.assertEqual(answer['assessment']['decision'], 'INDETERMINATE')
        by_id = {r['constraint_id']: r for r in answer['assessment']['constraints']}
        self.assertEqual(by_id['constraint:step_limit']['status'], 'PASS')
        self.assertEqual(by_id['constraint:step_limit']['metrics']['abs_delta_raw'], 328)
        self.assertEqual(by_id['constraint:min_interval']['status'], 'DISABLED')

    def test_failed_collection_cannot_fall_back_to_config_original(self):
        self.excerpt['selected_row']['error'] = {'type': 'TimeoutError'}
        answer = assess_qualified_request(*self.args, evaluator=Evaluator(ROOT))['assessment']
        self.assertEqual(answer['decision'], 'INDETERMINATE')
        by_id = {r['constraint_id']: r for r in answer['constraints']}
        self.assertEqual(by_id['constraint:step_limit']['status'], 'UNKNOWN')

    def test_unverified_execution_binding_is_not_relabelled_level_sp(self):
        self.cfg['point_id'] = 999
        answer = assess_qualified_request(*self.args, evaluator=Evaluator(ROOT))['assessment']
        self.assertEqual(answer['decision'], 'INDETERMINATE')


if __name__ == '__main__':
    unittest.main()
