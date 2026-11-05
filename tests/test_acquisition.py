"""Independent synthetic transport fixtures; never connect to a real lab."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.request import Request

from ics_risk.acquisition import grfics as g


class FakeReader:
    point = {'id': 21, 'dataSourceId': 1, 'name': 'arbitrary',
             'pointLocator': {'offset': 2500, 'range': 3}}
    datasource = {'id': 1, 'host': 'plc.example.invalid', 'port': 502,
                  'name': 'SYNTHETIC', 'password': 'SECRET_MUST_NOT_BE_CAPTURED'}

    def __init__(self, base, username, password):
        pass

    def get(self, path):
        data = self.point if '/datapoint?' in path else self.datasource
        raw = json.dumps(data).encode('utf-8')
        return {'value': copy.deepcopy(data), 'response_bytes': raw,
                'acquired_start': {'epoch': 100}, 'acquired_end': {'epoch': 101}}


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'new-capture'
        self.commands = []
        self.pointer_reads = 0
        self.changed_pointer = False
        self.pointer = b'generated.st\n'

    def tearDown(self):
        self.tmp.cleanup()

    def run_fixture(self, args, *, input=None, timeout=20):
        self.commands.append(args)
        if args[:2] == ['docker', 'inspect']:
            return json.dumps([{'Id': 'SYNTHETIC-container', 'Image': 'SYNTHETIC-image',
                'Config': {'Image': 'SYNTHETIC-runtime', 'Env': ['SECRET=NOT_CAPTURED']},
                'State': {'Running': True},
                'NetworkSettings': {'Networks': {'SYNTHETIC-network': {'IPAddress': '192.0.2.1'}}}}]).encode()
        if 'cat' in args:
            if args[-1] == '/docker_persistent/active_program':
                self.pointer_reads += 1
                if self.changed_pointer and self.pointer_reads > 1:
                    return b'changed.st\n'
                return self.pointer
            return b'SYNTHETIC SOURCE FIXTURE\n'
        if 'mysql' in args:
            self.assertIn('SELECT id FROM dataPoints', args[-1])
            self.assertNotIn('users', args[-1])
            return b'21\n'
        if 'python3' in args:
            return b'class ModbusSlaveContext: pass # SYNTHETIC\n'
        self.fail('Unexpected read command')

    def capture(self, **kwargs):
        with patch.object(g, '_run', side_effect=self.run_fixture), patch.object(g, '_ScadaReader', FakeReader):
            return g.capture_sources(self.root, scada_base='http://scada.example.invalid',
                scada_username='SYNTHETIC_USER', scada_password='SYNTHETIC_PASSWORD', **kwargs)

    def test_exact_source_hashes_and_raw_point_response(self):
        manifest = self.capture()
        self.assertTrue(manifest['complete'])
        for source in manifest['sources']:
            self.assertEqual(source['sha256'], hashlib.sha256((self.root / source['path']).read_bytes()).hexdigest())
            self.assertIn('acquired_start', source)
        self.assertEqual((self.root / 'point_21.json').read_bytes(), json.dumps(FakeReader.point).encode())
        points = json.loads((self.root / 'scada_points.json').read_text())
        self.assertEqual(points['points'][0]['source_id'], 'point_21')
        self.assertEqual(points['points'][0]['point']['pointLocator']['offset'], 2500)

    def test_credentials_and_full_environment_are_not_archived(self):
        self.capture()
        content = b'\n'.join(p.read_bytes() for p in self.root.iterdir())
        for secret in (b'SYNTHETIC_PASSWORD', b'SECRET_MUST_NOT_BE_CAPTURED', b'NOT_CAPTURED'):
            self.assertNotIn(secret, content)
        ds = json.loads((self.root / 'scada_datasource.json').read_text())
        self.assertEqual(['password'], ds['redacted_fields'])
        self.assertEqual('plc.example.invalid', ds['data']['host'])
        inventory = json.loads((self.root / 'inventory.json').read_text())
        self.assertEqual('192.0.2.1', inventory['plc']['networks']['SYNTHETIC-network'])

    def test_existing_capture_is_not_overwritten(self):
        self.root.mkdir()
        with self.assertRaises(FileExistsError):
            self.capture()

    def test_unsafe_program_pointer_does_not_read_target(self):
        self.pointer = b'../../secrets.st\n'
        manifest = self.capture()
        self.assertFalse(manifest['complete'])
        self.assertFalse((self.root / 'active_st.txt').exists())
        self.assertFalse(any('/secrets.st' in a for cmd in self.commands for a in cmd))

    def test_source_change_is_reported(self):
        self.changed_pointer = True
        manifest = self.capture()
        self.assertFalse(manifest['complete'])
        self.assertEqual('source_capture_incomplete', manifest['issues'][0]['code'])

    def test_source_failure_keeps_partial_manifest_without_secret_error(self):
        with patch.object(g, '_run', side_effect=RuntimeError('password=VERY_SECRET')):
            manifest = g.capture_sources(self.root, scada_base='http://example.invalid',
                scada_username='SYNTHETIC', scada_password='secret')
        self.assertFalse(manifest['complete'])
        self.assertNotIn('VERY_SECRET', (self.root / 'manifest.json').read_text())

    def test_explicit_point_inventory_does_not_query_database(self):
        self.capture(point_ids=[21])
        self.assertFalse(any('mysql' in cmd for cmd in self.commands))

    def test_sensitive_point_response_is_not_saved(self):
        with patch.object(FakeReader, 'point', dict(FakeReader.point, token='DO_NOT_SAVE')):
            manifest = self.capture()
        self.assertFalse(manifest['complete'])
        self.assertFalse((self.root / 'point_21.json').exists())

    def test_auth_redirect_cannot_leave_origin(self):
        redirect = g._SameOrigin('https://scada.example.invalid/base')
        with self.assertRaises(g.AcquisitionError):
            redirect.redirect_request(Request('https://scada.example.invalid/base/login.htm'),
                                      None, 302, 'redirect', {}, 'https://different.example.invalid/')

    def test_authentication_uses_no_environment_proxy(self):
        with patch.object(g, 'build_opener') as build, patch.object(g._ScadaReader, '_request'):
            g._ScadaReader('http://scada.example.invalid/base', 'SYNTHETIC', 'SYNTHETIC_SECRET')
        handlers = build.call_args.args
        self.assertEqual({}, next(h.proxies for h in handlers if isinstance(h, g.ProxyHandler)))


class FakeSocket:
    def __init__(self, data):
        self.data = bytearray.fromhex(data)
        self.sent = b''

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def sendall(self, value):
        self.sent += value

    def settimeout(self, value):
        pass

    def recv(self, size):
        size = min(size, 3)
        part = self.data[:size]
        del self.data[:size]
        return bytes(part)


class WireTests(unittest.TestCase):
    def test_read_holding_decodes_independent_bytes_and_retains_wire(self):
        sock = FakeSocket('00010000000701030400010002')
        with patch.object(g.socket, 'create_connection', return_value=sock):
            read = g.modbus_read('plc.example.invalid', fc=3, address=100, count=2)
        self.assertEqual('000100000006010300640002', sock.sent.hex())
        self.assertEqual([1, 2], read['values'])
        self.assertEqual('00010000000701030400010002', read['response_hex'])
        self.assertEqual('good', read['quality'])
        self.assertGreaterEqual(read['monotonic_span_seconds'], 0)

    def test_coil_bit_order(self):
        sock = FakeSocket('0001000000050101020501')
        with patch.object(g.socket, 'create_connection', return_value=sock):
            read = g.modbus_read('plc.example.invalid', fc=1, address=10, count=9)
        self.assertEqual([1, 0, 1, 0, 0, 0, 0, 0, 1], read['values'])

    def test_write_functions_never_open_socket(self):
        with patch.object(g.socket, 'create_connection') as connect:
            for fc in (5, 6, 15, 16, 23, True):
                with self.subTest(fc=fc), self.assertRaises(ValueError):
                    g.modbus_read('plc.example.invalid', fc=fc, address=100, count=1)
            connect.assert_not_called()

    def test_out_of_bound_request_never_opens_socket(self):
        with patch.object(g.socket, 'create_connection') as connect:
            for address, count in [(0, 33), (65535, 2), (-1, 1), (0, True)]:
                with self.subTest(address=address, count=count), self.assertRaises(ValueError):
                    g.modbus_read('plc.example.invalid', fc=4, address=address, count=count)
            connect.assert_not_called()

    def test_invalid_and_truncated_replies_preserve_failure(self):
        for wire in ('000100000003018302', '00020000000701030400010002', '00010000'):
            with self.subTest(wire=wire), patch.object(g.socket, 'create_connection', return_value=FakeSocket(wire)):
                read = g.modbus_read('plc.example.invalid', fc=3, address=100, count=2)
                self.assertEqual('bad', read['quality'])
                self.assertNotIn('values', read)
                self.assertTrue(read['response_hex'])

    def test_observation_plan_is_validated_before_any_container_call(self):
        with patch.object(g, '_run') as run:
            with self.assertRaises(ValueError):
                g.collect_observations('plc.example.invalid', 1, [{'fc': 6, 'address': 1, 'count': 1}])
            run.assert_not_called()

    def test_sequential_observations_keep_source_values_without_role_labels(self):
        responses = [json.dumps([{'fc': 4, 'address': 777, 'values': [123],
                                 'start': {'epoch': 1}, 'end': {'epoch': 2}}]).encode(),
                     b'{"outputs":{"arbitrary_sensor":4.5},"state":{"e_stop":false}}\n']
        with patch.object(g, '_run', side_effect=responses) as run:
            result = g.collect_observations('plc.example.invalid', 1,
                [{'fc': 4, 'address': 777, 'count': 1}], count=1)
        sample = result['samples'][0]
        self.assertTrue(result['sequential_acquisition'])
        self.assertEqual([123], sample['reads'][0]['values'])
        self.assertEqual(4.5, sample['simulator']['data']['outputs']['arbitrary_sensor'])
        self.assertNotIn('level_sp', json.dumps(result))
        payload = json.loads(run.call_args_list[0].kwargs['input'])
        self.assertEqual(777, payload['plan'][0]['address'])
        self.assertEqual('{"request":"read"}\n', sample['simulator']['request_text'])


if __name__ == '__main__':
    unittest.main()
