"""Synthetic observation contracts only; no live reads or scientific results.

Every packet, clock, identity, and simulator response is a controlled independent
fixture. Real collection is patched out. Temporary bundles are never published.
"""
import copy
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

from ics_risk.semantic import observations as o
from lvsp_eval import Evaluator

ROOT = Path(__file__).resolve().parents[1]


def write(path, value):
    Path(path).write_bytes((json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode())


def stamp(epoch):
    return {'epoch': epoch, 'monotonic': epoch - 500, 'utc': 'SYNTHETIC TEST CLOCK'}


def read_fixture(fc, address, value, start, end, tid):
    request = struct.pack('>HHHBBHH', tid, 0, 6, 1, fc, address, 1)
    pdu = bytes([fc, 1, value]) if fc == 1 else bytes([fc, 2]) + struct.pack('>H', value)
    response = struct.pack('>HHHB', tid, 0, len(pdu) + 1, 1) + pdu
    return {'fc': fc, 'address': address, 'count': 1, 'unit': 1,
            'request_hex': request.hex(), 'response_hex': response.hex(),
            'values': [value], 'quality': 'good', 'start': stamp(start), 'end': stamp(end),
            'span_seconds': end - start, 'monotonic_span_seconds': end - start}


class SourceObservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bundle = self.root / 'SYNTHETIC-bundle'
        shutil.copytree(ROOT / 'examples/demo_bundle', self.bundle)
        self.bindings = json.loads((self.bundle / 'config/bindings.json').read_text())
        self.bindings['graph_construction'] = 'deterministic_source_extraction'
        self.bindings['signals']['var:fixture_pv'] = {
            'source': 'plc', 'function_code': 4, 'offset': 307, 'count': 1, 'unit_id': 1,
            'unit': 'raw_count', 'evidence_refs': ['src:active_st'], 'component_ref': 'component:plc'}
        write(self.bundle / 'config/bindings.json', self.bindings)
        self.inventory = {'plc': {'id': 'SYNTHETIC-CONTAINER', 'networks': {'fixture': '192.0.2.23'}}}
        path = self.bundle / 'evidence/capture_inventory.json'
        write(path, self.inventory)
        sources = json.loads((self.bundle / 'config/provenance.json').read_text())
        sources['sources'].append({'id': 'src:capture:inventory', 'path': 'evidence/capture_inventory.json',
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'locator': 'SYNTHETIC fixture only', 'kind': 'synthetic_test_only'})
        write(self.bundle / 'config/provenance.json', sources)
        self.source_bytes = (self.bundle / 'evidence/SYNTHETIC_active_st.txt').read_bytes()
        self.plan = {'endpoint': {'host': '192.0.2.23', 'port': 502, 'unit': 1}, 'requests': [
            {'fc': 3, 'address': 1028, 'count': 1}, {'fc': 1, 'address': 40, 'count': 1},
            {'fc': 4, 'address': 307, 'count': 1}]}
        write(self.bundle / 'read_plan.json', self.plan)
        identity = {'verified': True, 'container_id': 'SYNTHETIC-CONTAINER',
            'active_program': 'fixture.st', 'source_sha256': self.bindings['runtime_sha256'],
            'network_addresses': ['192.0.2.23']}
        sim_data = {'outputs': {'liquid_level': 41.5}, 'state': {'e_stop': False}}
        self.report = {'source_kind': 'source_bound_live_observation', 'identity_verified': True,
            'graph_version': self.bindings['graph_version'], 'runtime_sha256': self.bindings['runtime_sha256'],
            'endpoint': self.plan['endpoint'], 'read_plan': self.plan['requests'],
            'identity_checks': {'before': copy.deepcopy(identity), 'after': copy.deepcopy(identity)},
            'samples': [{'start': stamp(999.0), 'end': stamp(1000.0),
                'reads': [read_fixture(3, 1028, 28835, 999.1, 999.2, 1),
                          read_fixture(1, 40, 1, 999.3, 999.4, 2),
                          read_fixture(4, 307, 28000, 999.5, 999.6, 3)],
                'simulator': {'start': stamp(999.7), 'end': stamp(999.8), 'quality': 'good',
                    'request_text': '{"request":"read"}\n', 'response_text': json.dumps(sim_data), 'data': sim_data}}]}

    def tearDown(self):
        self.tmp.cleanup()

    def prepare(self, **kwargs):
        return o.prepare_request(self.bundle, self.report, 29163, **kwargs)

    def docker_fixture(self, args):
        if args == ['docker', 'inspect', 'plc']:
            return json.dumps([{'Id': 'SYNTHETIC-CONTAINER', 'State': {'Running': True},
                'NetworkSettings': {'Networks': {'fixture': {'IPAddress': '192.0.2.23'}}}}]).encode()
        if args[-1] == '/docker_persistent/active_program':
            return b'fixture.st\n'
        if args[-1] == '/workdir/webserver/st_files/fixture.st':
            return self.source_bytes
        self.fail('Unexpected source identity command')

    def test_candidate_keeps_observed_sp_and_pv_unchanged(self):
        before = copy.deepcopy(self.report)
        request = self.prepare()
        self.assertEqual(before, self.report)
        self.assertEqual(29163, request['command']['raw'])
        self.assertEqual(28835, request['snapshot']['signals']['var:level_sp']['value'])
        self.assertEqual(28000, request['snapshot']['signals']['var:fixture_pv']['value'])
        self.assertEqual('unexecuted_candidate', request['command']['origin'])
        self.assertEqual('replay_at_observation_end', request['command']['evaluation_mode'])
        self.assertEqual(1000.0, request['command']['evaluation_at'])
        self.assertLess(abs(Decimal(request['command']['value']) - Decimal(29163) * 100 / 65535), Decimal('1e-24'))

    def test_plc_row_window_is_shared_and_individual_windows_preserved(self):
        request = self.prepare()
        windows = set()
        for sid in ('var:level_sp', 'var:run', 'var:fixture_pv'):
            signal = request['snapshot']['signals'][sid]
            windows.add((signal['observed_at'], signal['available_at'], signal['span_seconds']))
            self.assertEqual('0.5', signal['span_seconds'])
            self.assertIn('not simultaneous', signal['acquisition_semantics'])
        self.assertEqual({('999.1', '999.6', '0.5')}, windows)
        self.assertEqual(999.3, request['snapshot']['signals']['var:run']['individual_observation']['start']['epoch'])
        self.assertEqual('999.7', request['snapshot']['signals']['var:e_stop']['observed_at'])

    def test_current_mode_preserves_old_observation_times_and_is_stale(self):
        with patch.object(o.time, 'time', return_value=2000.0):
            request = self.prepare(mode='current')
        self.assertEqual(2000.0, request['command']['evaluation_at'])
        self.assertEqual(1000.0, request['snapshot']['captured_at'])
        self.assertEqual('999.1', request['snapshot']['signals']['var:level_sp']['observed_at'])
        result = Evaluator(self.bundle).evaluate(**request)
        self.assertEqual('INDETERMINATE', result['decision'])
        self.assertIn('snapshot_time_invalid_or_stale', {x['code'] for x in result['input_issues']})

    def test_history_is_explicitly_incomplete(self):
        history = self.prepare()['history']
        self.assertFalse(history['complete'])
        self.assertEqual([], history['events'])
        self.assertEqual('999.0', history['coverage_start'])
        self.assertEqual('1000.0', history['coverage_end'])

    def test_tampered_decoded_values_are_not_used(self):
        self.report['samples'][0]['reads'][0]['values'] = [29163]
        request = self.prepare()
        self.assertNotIn('var:level_sp', request['snapshot']['signals'])
        result = Evaluator(self.bundle).evaluate(**request)
        delta = next(x for x in result['constraints'] if x['constraint_id'] == 'constraint:step_limit')
        self.assertEqual('UNKNOWN', delta['status'])

    def test_wrong_unit_or_address_metadata_is_omitted(self):
        for field, value in [('unit', 2), ('address', 1029), ('fc', 4), ('count', 2)]:
            with self.subTest(field=field):
                report = copy.deepcopy(self.report)
                report['samples'][0]['reads'][0][field] = value
                request = o.prepare_request(self.bundle, report, 29163)
                self.assertNotIn('var:level_sp', request['snapshot']['signals'])

    def test_reversed_or_future_read_time_is_omitted(self):
        for end in (998.0, 1001.0):
            with self.subTest(end=end):
                report = copy.deepcopy(self.report)
                report['samples'][0]['reads'][0]['end']['epoch'] = end
                request = o.prepare_request(self.bundle, report, 29163)
                self.assertNotIn('var:level_sp', request['snapshot']['signals'])

    def test_invalid_frame_and_modbus_exception_are_omitted(self):
        for response in ('00', '000100000003018302'):
            with self.subTest(response=response):
                report = copy.deepcopy(self.report)
                report['samples'][0]['reads'][0]['response_hex'] = response
                request = o.prepare_request(self.bundle, report, 29163)
                self.assertNotIn('var:level_sp', request['snapshot']['signals'])

    def test_missing_or_bad_simulator_boolean_is_not_defaulted(self):
        for value in (None, 0, 'false'):
            with self.subTest(value=value):
                report = copy.deepcopy(self.report)
                sim = report['samples'][0]['simulator']
                sim['data']['state']['e_stop'] = value
                sim['response_text'] = json.dumps(sim['data'])
                request = o.prepare_request(self.bundle, report, 29163)
                self.assertNotIn('var:e_stop', request['snapshot']['signals'])

    def test_simulator_raw_response_mismatch_is_omitted(self):
        self.report['samples'][0]['simulator']['data']['state']['e_stop'] = True
        self.assertNotIn('var:e_stop', self.prepare()['snapshot']['signals'])

    def test_duplicate_matching_reads_are_ambiguous_even_if_one_is_bad(self):
        duplicate = copy.deepcopy(self.report['samples'][0]['reads'][0])
        duplicate['quality'] = 'bad'
        self.report['samples'][0]['reads'].append(duplicate)
        self.assertNotIn('var:level_sp', self.prepare()['snapshot']['signals'])

    def test_missing_reads_are_not_replaced_with_source_initializers(self):
        self.report['samples'][0]['reads'] = None
        request = self.prepare()
        self.assertEqual({'var:e_stop'}, set(request['snapshot']['signals']))

    def test_identity_flag_cannot_override_failed_after_check(self):
        self.report['identity_checks']['after']['verified'] = False
        with self.assertRaisesRegex(o.ObservationError, 'before_after_identity'):
            self.prepare()

    def test_wrong_graph_source_or_endpoint_is_rejected(self):
        for field, value in [('graph_version', 'different'), ('runtime_sha256', 'wrong'),
                             ('identity_verified', False), ('source_kind', 'synthetic_not_bound')]:
            with self.subTest(field=field):
                report = copy.deepcopy(self.report)
                report[field] = value
                with self.assertRaises(o.ObservationError):
                    o.prepare_request(self.bundle, report, 29163)
        self.report['endpoint'] = dict(self.report['endpoint'], host='192.0.2.99')
        with self.assertRaisesRegex(o.ObservationError, 'endpoint_mismatch'):
            self.prepare()

    def test_capture_performs_before_after_identity_checks_and_saves_wire(self):
        output = self.root / 'SYNTHETIC-observations.json'
        with patch.object(o, '_run', side_effect=self.docker_fixture), \
                patch.object(o, 'collect_observations', return_value=copy.deepcopy(self.report)) as collect:
            result = o.capture_for_bundle(self.bundle, output, count=1)
        self.assertTrue(result['identity_verified'])
        self.assertEqual(self.plan['requests'], collect.call_args.args[2])
        saved = json.loads(output.read_text())
        self.assertEqual(result, saved)
        self.assertEqual(self.report['samples'][0]['reads'][0]['response_hex'], saved['samples'][0]['reads'][0]['response_hex'])
        self.assertEqual(29163, o.prepare_request(self.bundle, output, 29163)['command']['raw'])

    def test_capture_identity_failure_preserves_report_without_collecting(self):
        output = self.root / 'SYNTHETIC-failed.json'
        with patch.object(o, '_run', return_value=b'[{"Id":"OTHER","State":{"Running":true}}]'), \
                patch.object(o, 'collect_observations') as collect:
            result = o.capture_for_bundle(self.bundle, output)
        collect.assert_not_called()
        self.assertFalse(result['identity_verified'])
        with self.assertRaises(o.ObservationError):
            o.prepare_request(self.bundle, output, 29163)

    def test_capture_after_identity_change_rejects_preparation_but_keeps_samples(self):
        good = copy.deepcopy(self.report['identity_checks']['before'])
        bad = dict(good, verified=False, container_id='CHANGED')
        output = self.root / 'SYNTHETIC-changed.json'
        with patch.object(o, '_identity', side_effect=[good, bad]), \
                patch.object(o, 'collect_observations', return_value=copy.deepcopy(self.report)):
            result = o.capture_for_bundle(self.bundle, output)
        self.assertFalse(result['identity_verified'])
        self.assertEqual(1, len(result['samples']))
        with self.assertRaises(o.ObservationError):
            o.prepare_request(self.bundle, result, 29163)

    def test_existing_observation_file_is_not_overwritten(self):
        output = self.root / 'existing.json'
        output.write_text('ORIGINAL SYNTHETIC BYTES')
        with patch.object(o, '_run') as run, self.assertRaises(FileExistsError):
            o.capture_for_bundle(self.bundle, output)
        run.assert_not_called()
        self.assertEqual('ORIGINAL SYNTHETIC BYTES', output.read_text())

    def test_changed_read_plan_is_rejected_before_any_io(self):
        self.plan['requests'][0]['fc'] = 6
        write(self.bundle / 'read_plan.json', self.plan)
        with patch.object(o, '_run') as run, self.assertRaises(o.ObservationError):
            o.capture_for_bundle(self.bundle, self.root / 'not-captured.json')
        run.assert_not_called()

    def test_candidate_type_and_range_are_checked(self):
        for value in (True, -1, 65536, 1.5):
            with self.subTest(value=value), self.assertRaises(o.ObservationError):
                o.prepare_request(self.bundle, self.report, value)


if __name__ == '__main__':
    unittest.main()
