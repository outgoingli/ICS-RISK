"""Synthetic assembly tests, NOT field evidence or an extraction experiment.

All capture bytes and parser outputs below are independent test fixtures. The
temporary manifest uses the live_capture input contract only to exercise its
validation branch; directories are deleted after each test and never published
as research results. No PLC, SCADA, simulator or database is contacted.
"""
from contextlib import ExitStack
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from ics_risk.semantic import pipeline as p
from lvsp_eval.graph import graph_numbers

ROOT = Path(__file__).resolve().parents[1]


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


class PipelineAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.capture = self.root / 'SYNTHETIC-capture'
        self.capture.mkdir()
        self.policy = self.root / 'SYNTHETIC-policy'
        shutil.copytree(ROOT / 'examples/demo_bundle', self.policy)
        bindings = json.loads((self.policy / 'config/bindings.json').read_text())
        bindings['bundle_profile'] = 'fixture_only'
        (self.policy / 'config/bindings.json').write_bytes(encoded(bindings))
        provenance = json.loads((self.policy / 'config/provenance.json').read_text())
        for source in provenance['sources']:
            source['kind'] = 'synthetic_test_only'
        (self.policy / 'config/provenance.json').write_bytes(encoded(provenance))
        self.output = self.root / 'SYNTHETIC-generated'
        self.manifest = {'schema_version': '1', 'source_kind': 'live_capture', 'complete': True,
            'fixture_notice': 'SYNTHETIC SOFTWARE TEST ONLY; not a real collection',
            'finished_at': {'epoch': 100, 'utc': 'SYNTHETIC'}, 'sources': []}
        source_ids = ('active_st', 'modbus_driver', 'modbus_master', 'remote_io_config',
                      'glue', 'tank_bridge', 'bridge_common', 'bridge_context')
        for sid in source_ids:
            self.source(sid, ('SYNTHETIC TEST SOURCE: ' + sid + '\n').encode())
        self.source('glue',b'''// SYNTHETIC SOFTWARE TEST ONLY
void glueVars() {
 int_input[307] = (IEC_UINT *)__IW307;
 int_memory[17] = (IEC_UINT *)__MW17;
 int_output[42] = (IEC_UINT *)__QW42;
 int_input[308] = (IEC_UINT *)__IW308;
 bool_output[9][3] = (IEC_BOOL *)__QX9_3;
}
''')
        bindings['runtime_sha256']=next(x['sha256'] for x in self.manifest['sources'] if x['id']=='active_st')
        (self.policy/'config/bindings.json').write_bytes(encoded(bindings))
        self.point = {'id': 88, 'dataSourceId': 7, 'enabled': True, 'name': 'unlabelled setting',
            'pointLocator': {'range': 3, 'offset': 2017, 'slaveId': 1, 'settable': True,
                             'modbusDataType': 2, 'multiplier': 100 / 65535, 'additive': 0}}
        self.datasource = {'id': 7, 'enabled': True, 'host': '192.0.2.41', 'port': 502,
                           'transportType': 'TCP'}
        self.source('inventory', encoded({'plc': {'id': 'SYNTHETIC-plc', 'networks': {'fixture': '192.0.2.41'}},
            'simulation': {'id': 'SYNTHETIC-sim'}, 'HMI': {'id': 'SYNTHETIC-hmi'}}))
        self.sync_point()
        self.source('scada_datasource', encoded({'data': self.datasource, 'redacted_fields': []}))
        self.st = {'declarations': [
            {'symbol': 'measured_x', 'address': '%IW307', 'data_type': 'UINT', 'line': 11},
            {'symbol': 'goal_x', 'address': '%MW17', 'data_type': 'UINT', 'line': 12},
            {'symbol': 'drive_cmd', 'address': '%QW42', 'data_type': 'UINT', 'line': 13},
            {'symbol': 'drive_feedback', 'address': '%IW308', 'data_type': 'UINT', 'line': 14},
            {'symbol': 'permitted', 'address': '%QX9.3', 'data_type': 'BOOL', 'line': 15}],
            'control_calls': [{'function': 'feedback_function', 'program': 'main_fixture',
                'line': 30, 'end_line': 37, 'output': 'drive_cmd', 'pv': 'measured_x', 'sp': 'goal_x',
                'actuator_feedback': 'drive_feedback', 'gain': -2, 'range_min': 0, 'range_max': 100,
                'pv_scale': {'numerator': 100, 'denominator': 65535, 'offset': 0},
                'function_span': {'line': 2, 'end_line': 9}, 'adoption': 'conditional',
                'program_binding': 'configured'}],
            'output_gates': [{'condition': {'symbol': 'permitted', 'operator': 'not'},
                'line': 41, 'end_line': 43, 'overrides': [{'output': 'drive_cmd', 'value': 65535,
                    'line': 42, 'branch': 'then', 'final_override': True}]}],
            'configured_programs': ['main_fixture'], 'issues': []}
        self.io = {'address_model': {'fixture': 'independent protocol model'},
            'physical_signals': [{'source_field': 'outputs.liquid_level',
                'status': 'static_configured_mapping', 'plc_location': '%IW307',
                'origin_json_path': '$.outputs.liquid_level',
                'evidence': [{'source': 'tank_bridge', 'line_start': 6, 'line_end': 8},
                             {'source': 'modbus_master', 'line_start': 10, 'line_end': 12}]}],
            'issues': []}

    def tearDown(self):
        self.temp.cleanup()

    def source(self, sid, data):
        path = sid + '.txt'
        (self.capture / path).write_bytes(data)
        item = {'id': sid, 'path': path, 'sha256': hashlib.sha256(data).hexdigest(),
                'locator': 'SYNTHETIC fixture ' + sid, 'kind': 'synthetic_test_only',
                'acquired_start': {'epoch': 90}, 'acquired_end': {'epoch': 99}}
        self.manifest['sources'] = [x for x in self.manifest['sources'] if x['id'] != sid] + [item]
        (self.capture / 'manifest.json').write_bytes(encoded(self.manifest))

    def sync_point(self, rows=None):
        self.source('point_88', encoded(self.point))
        self.source('scada_points', encoded({'points': rows or [
            {'point': self.point, 'source_id': 'point_88'}]}))

    def resolve(self, location, _model):
        addresses = {'%IW307': (4, 307, 'input'), '%MW17': (3, 2017, 'holding'),
                     '%QW42': (3, 42, 'holding'), '%IW308': (4, 308, 'input'),
                     '%QX9.3': (1, 75, 'coil')}
        if location not in addresses:
            return None
        fc, address, kind = addresses[location]
        return {'fc': fc, 'address': address, 'register_kind': kind,
                'evidence': [{'source': 'modbus_driver', 'line_start': 3, 'line_end': 5}]}

    def context(self):
        stack = ExitStack()
        stack.enter_context(patch.object(p, 'analyze_st', return_value=copy.deepcopy(self.st)))
        stack.enter_context(patch.object(p, 'analyze_io', return_value=copy.deepcopy(self.io)))
        stack.enter_context(patch.object(p, 'resolve_plc_address', side_effect=self.resolve))
        return stack

    def extract(self):
        with self.context():
            return p.extract_capture(self.capture)

    def build(self):
        with self.context():
            return p.build_extracted_bundle(self.capture, self.policy, self.output)

    def test_roles_follow_parsed_dataflow_and_physical_mapping(self):
        report = self.extract()
        roles = {x['role']: x for x in report['variables']}
        self.assertEqual('measured_x', roles['process_value']['symbol'])
        self.assertEqual('goal_x', roles['setpoint']['symbol'])
        self.assertEqual('$.outputs.liquid_level', roles['process_value']['origin_json_path'])
        self.assertEqual([88], roles['setpoint']['point_ids'])
        self.assertTrue(report['gate']['automatic_expected'])

    def test_extra_unknown_gate_prevents_claim_of_complete_semantics(self):
        self.st['issues'].append({'code':'gate_condition_not_simple_boolean','line':50})
        with self.assertRaisesRegex(p.ExtractionError,'unsupported_program_semantics'):
            self.extract()

    def test_mismatched_compiled_memory_binding_is_not_silently_accepted(self):
        glue=(self.capture/'glue.txt').read_bytes().replace(b'__MW17',b'__MW18')
        self.source('glue',glue)
        with self.assertRaisesRegex(p.ExtractionError,'compiled_binding_unresolved'):
            self.extract()

    def test_level_policy_is_not_attached_to_another_physical_loop(self):
        with self.assertRaisesRegex(p.ExtractionError,'scoped_to_liquid_level'):
            p.extract_capture(self.capture,physical_field='outputs.pressure')

    def test_policy_from_a_different_runtime_requires_requalification(self):
        path=self.policy/'config/bindings.json'
        data=json.loads(path.read_text());data['runtime_sha256']='different-runtime'
        path.write_bytes(encoded(data))
        with self.assertRaisesRegex(p.ExtractionError,'runtime_scope_mismatch'):
            self.build()

    def test_invalid_seed_graph_is_never_read_and_topology_is_generated(self):
        (self.policy / 'config/graph.json').write_text('THIS IS NOT JSON AND MUST NOT BE READ', encoding='utf-8')
        result = self.build()
        self.assertEqual('point:scada:88', result['target_point'])
        graph = json.loads((self.output / 'config/graph.json').read_text())
        self.assertEqual([], list(graph_numbers(graph)))
        triples = {(x['source'], x['type'], x['target']) for x in graph['edges']}
        self.assertIn(('component:scada', 'EXPOSES', 'point:scada:88'), triples)
        self.assertIn(('point:scada:88', 'MAPS_TO', 'var:plc:goal_x'), triples)
        self.assertIn(('var:plc:goal_x', 'HOSTED_BY', 'component:plc'), triples)
        self.assertNotIn(('component:plc', 'EXPOSES', 'point:scada:88'), triples)
        for symbol in ('measured_x', 'goal_x', 'drive_cmd', 'drive_feedback', 'permitted'):
            self.assertIn(('var:plc:' + symbol, 'IN_LOOP', 'loop:plc:drive_cmd'), triples)
        self.assertIn(('constraint:run_required', 'REQUIRES', 'var:plc:permitted'), triples)
        self.assertIn(('constraint:step_limit', 'REQUIRES', 'var:plc:goal_x'), triples)
        self.assertNotIn('var:level_sp', {n['id'] for n in graph['nodes']})
        bindings = json.loads((self.output / 'config/bindings.json').read_text())
        point = bindings['points']['point:scada:88']
        self.assertEqual('component:scada', point['exposing_component_ref'])
        self.assertEqual('component:plc', point['component_ref'])
        self.assertEqual(2017, point['offset'])

    def test_absent_policy_seed_graph_is_accepted(self):
        (self.policy / 'config/graph.json').unlink()
        self.assertEqual('point:scada:88', self.build()['target_point'])

    def test_source_digest_mismatch_is_rejected(self):
        (self.capture / 'active_st.txt').write_bytes(b'CHANGED SYNTHETIC SOURCE')
        with self.assertRaisesRegex(p.ExtractionError, 'digest_mismatch'):
            self.extract()

    def test_missing_physical_link_is_not_guessed_from_names(self):
        self.io['physical_signals'] = []
        self.point['name'] = 'Definitely real liquid level setpoint'
        self.sync_point()
        with self.assertRaisesRegex(p.ExtractionError, 'physical_feedback_mapping'):
            self.extract()

    def test_scada_host_must_match_captured_plc(self):
        self.datasource['host'] = '192.0.2.42'
        self.source('scada_datasource', encoded({'data': self.datasource}))
        with self.assertRaisesRegex(p.ExtractionError, 'scada_target'):
            self.extract()

    def test_setpoint_locator_must_be_writable(self):
        self.point['pointLocator']['settable'] = False
        self.sync_point()
        with self.assertRaisesRegex(p.ExtractionError, 'writable'):
            self.extract()

    def test_disabled_setpoint_is_rejected(self):
        self.point['enabled'] = False
        self.sync_point()
        with self.assertRaises(p.ExtractionError):
            self.extract()

    def test_disabled_datasource_is_rejected(self):
        self.datasource['enabled'] = False
        self.source('scada_datasource', encoded({'data': self.datasource}))
        with self.assertRaises(p.ExtractionError):
            self.extract()

    def test_inconsistent_setpoint_scale_is_rejected(self):
        self.point['pointLocator']['multiplier'] *= 2
        self.sync_point()
        with self.assertRaisesRegex(p.ExtractionError, 'scales_disagree'):
            self.extract()

    def test_nonfinite_serialized_scale_is_rejected(self):
        self.point['pointLocator']['multiplier'] = 'nan'
        self.sync_point()
        with self.assertRaises(p.ExtractionError):
            self.extract()

    def test_unconfigured_program_is_not_an_adopted_loop(self):
        self.st['control_calls'][0]['program_binding'] = 'unconfigured'
        with self.assertRaisesRegex(p.ExtractionError, 'feedback_loop_not_uniquely_adopted'):
            self.extract()

    def test_overwritten_output_is_not_an_adopted_loop(self):
        self.st['control_calls'][0]['adoption'] = 'overwritten'
        with self.assertRaisesRegex(p.ExtractionError, 'feedback_loop_not_uniquely_adopted'):
            self.extract()

    def test_duplicate_scada_points_are_rejected(self):
        row = {'point': self.point, 'source_id': 'point_88'}
        self.sync_point([row, copy.deepcopy(row)])
        with self.assertRaises(p.ExtractionError):
            self.extract()

    def test_duplicate_id_with_different_addresses_is_rejected(self):
        other = copy.deepcopy(self.point)
        other['pointLocator'].update(range=4, offset=307, settable=False)
        self.source('point_conflicting', encoded(other))
        self.sync_point([{'point': self.point, 'source_id': 'point_88'},
                         {'point': other, 'source_id': 'point_conflicting'}])
        with self.assertRaises(p.ExtractionError):
            self.extract()

    def test_index_must_equal_individual_raw_api_response(self):
        rows = [{'point': dict(self.point, name='INDEX WAS ALTERED'), 'source_id': 'point_88'}]
        self.source('scada_points', encoded({'points': rows}))
        with self.assertRaisesRegex(p.ExtractionError, 'point_index_raw_response_mismatch'):
            self.extract()

    def test_unresolved_protocol_binding_is_rejected(self):
        self.st['declarations'][1]['address'] = '%UNSUPPORTED17'
        with self.assertRaisesRegex(p.ExtractionError, 'unsupported_protocol_binding'):
            self.extract()

    def test_demo_policy_profile_is_rejected(self):
        bindings = json.loads((self.policy / 'config/bindings.json').read_text())
        bindings['bundle_profile'] = 'synthetic_demo'
        (self.policy / 'config/bindings.json').write_bytes(encoded(bindings))
        with self.assertRaisesRegex(p.ExtractionError, 'synthetic_policy_bundle'):
            self.build()

    def test_policy_parameter_change_without_digest_is_rejected(self):
        path = self.policy / 'config/constraints.json'
        policies = json.loads(path.read_text())
        next(x for x in policies['rules'] if x['id'] == 'constraint:step_limit')['parameters']['limit_raw'] = 999
        path.write_bytes(encoded(policies))
        with self.assertRaisesRegex(p.ExtractionError, 'policy_parameter_integrity_mismatch'):
            self.build()

    def test_policy_evidence_bytes_are_checked(self):
        provenance = json.loads((self.policy / 'config/provenance.json').read_text())
        (self.policy / provenance['sources'][0]['path']).write_bytes(b'CHANGED SYNTHETIC POLICY SOURCE')
        with self.assertRaisesRegex(p.ExtractionError, 'policy_evidence_digest_mismatch'):
            self.build()

    def test_generation_does_not_overwrite_previous_bundle(self):
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            self.build()


if __name__ == '__main__':
    unittest.main()
