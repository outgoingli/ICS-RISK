"""Read actual source/configuration and wire observations, without actuation.

This module runs on the authorized Linux Docker host. It never changes a point,
PLC register, simulator state, service, or password. Authentication credentials
are parameters held in memory and excluded from evidence and diagnostics.
"""
from __future__ import annotations

import datetime
import hashlib
import http.cookiejar
import inspect
import json
import re
import socket
import struct
import subprocess
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, ProxyHandler, Request, build_opener


class AcquisitionError(RuntimeError):
    pass


def _stamp():
    return {'epoch': time.time(), 'monotonic': time.monotonic(),
            'utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}


def _name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value):
        raise ValueError('Invalid container name')
    return value


def _run(args, *, input=None, timeout=20):
    try:
        result = subprocess.run(args, input=input, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcquisitionError('Source read unavailable: ' + type(exc).__name__) from None
    if result.returncode:
        # Do not propagate subprocess output: it may contain local secrets.
        raise AcquisitionError('Source read returned a nonzero status')
    return result.stdout


def _json(data):
    def invalid(_):
        raise ValueError('Non-finite JSON')
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('Duplicate JSON key')
            out[key] = value
        return out
    return json.loads(data, parse_constant=invalid, object_pairs_hook=pairs)


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8')


class _SameOrigin(HTTPRedirectHandler):
    def __init__(self, base):
        self.origin = urlsplit(base)[:2]

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl)[:2] != self.origin:
            raise AcquisitionError('Cross-origin authentication redirect rejected')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _ScadaReader:
    def __init__(self, base, username, password):
        parsed = urlsplit(base)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise ValueError('SCADA base must be an origin/path without credentials')
        if not all(isinstance(x, str) and x for x in (username, password)):
            raise ValueError('SCADA credentials are required in memory')
        self.base = base.rstrip('/')
        self.opener = build_opener(ProxyHandler({}), _SameOrigin(base),
                                  HTTPCookieProcessor(http.cookiejar.CookieJar()))
        payload = urlencode({'username': username, 'password': password, 'submit': 'Login'}).encode('utf-8')
        try:
            self._request('/login.htm', payload)
        finally:
            del payload, username, password

    def _request(self, path, data=None):
        if not path.startswith('/') or path.startswith('//'):
            raise ValueError('SCADA relative path required')
        headers = {'Accept': 'application/json'}
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        try:
            with self.opener.open(Request(self.base + path, data=data, headers=headers), timeout=8) as r:
                body = r.read(2_000_001)
            if len(body) > 2_000_000:
                raise AcquisitionError('SCADA response exceeds capture bound')
            return body
        except AcquisitionError:
            raise
        except Exception:
            raise AcquisitionError('SCADA read or authentication unavailable') from None

    def get(self, path):
        start = _stamp()
        body = self._request(path)
        end = _stamp()
        try:
            value = _json(body)
        except (ValueError, UnicodeError):
            raise AcquisitionError('SCADA did not return valid JSON') from None
        return {'value': value, 'response_bytes': body, 'acquired_start': start, 'acquired_end': end}


def _credential_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if re.search(r'password|passwd|credential|secret|token|authorization|cookie', key, re.I):
                return True
            if _credential_keys(item):
                return True
    elif isinstance(value, list):
        return any(_credential_keys(item) for item in value)
    return False


_DATASOURCE_FIELDS = {
    'id', 'xid', 'name', 'type', 'enabled', 'connectionDescription', 'updatePeriodType',
    'updatePeriods', 'quantize', 'timeout', 'retries', 'contiguousBatches',
    'createSlaveMonitorPoints', 'maxReadBitCount', 'maxReadRegisterCount',
    'maxWriteRegisterCount', 'transportType', 'host', 'port', 'encapsulated',
    'createSocketMonitorPort',
}


def capture_sources(destination, *, plc_container='plc', simulator_container='simulation',
                    hmi_container='HMI', scada_base, scada_username, scada_password,
                    point_ids=None, data_source_id=1):
    """Create a new evidence directory; never overwrite any prior capture.

    Returns a manifest even if a source read fails, with complete=False and
    non-sensitive diagnostics. The datasource file is an explicitly labelled
    field projection; point responses and source files preserve captured bytes.
    No graph, role label, threshold or process assertion is supplied as input.
    """
    for name in (plc_container, simulator_container, hmi_container):
        _name(name)
    if type(data_source_id) is not int or data_source_id < 0:
        raise ValueError('Invalid datasource ID')
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    manifest = {'schema_version': '1', 'source_kind': 'live_capture',
                'started_at': _stamp(), 'sequential_acquisition': True,
                'complete': False, 'sources': [], 'issues': []}

    def save(sid, content, locator, start, end, *, kind='live_capture', suffix='.txt'):
        name = sid + suffix
        with (root / name).open('xb') as f:
            f.write(content)
        manifest['sources'].append({'id': sid, 'path': name,
            'sha256': hashlib.sha256(content).hexdigest(), 'locator': locator,
            'acquired_start': start, 'acquired_end': end, 'kind': kind})

    def docker_source(sid, container, path):
        start = _stamp()
        data = _run(['docker', 'exec', container, 'cat', path])
        save(sid, data, container + ':' + path, start, _stamp())
        return data

    try:
        start = _stamp()
        inventory = {}
        for container in (plc_container, simulator_container, hmi_container):
            obj = _json(_run(['docker', 'inspect', container]))[0]
            inventory[container] = {'id': obj['Id'], 'image': obj['Image'],
                'image_name': obj['Config']['Image'], 'running': obj['State']['Running'],
                'networks': {key: row.get('IPAddress')
                             for key, row in obj['NetworkSettings']['Networks'].items()}}
        save('inventory', _json_bytes(inventory), 'selected Docker inspect fields; no environment',
             start, _stamp(), kind='live_capture_projection', suffix='.json')
        pointer = docker_source('active_program', plc_container, '/docker_persistent/active_program')
        active = pointer.decode('utf-8').strip()
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,160}\.st', active) or active.startswith('.'):
            raise AcquisitionError('Unsafe or unsupported active program pointer')
        active_path = '/workdir/webserver/st_files/' + active
        active_bytes = docker_source('active_st', plc_container, active_path)
        for sid, path in [('modbus_driver', '/workdir/webserver/core/modbus.cpp'),
                          ('modbus_master', '/workdir/webserver/core/modbus_master.cpp'),
                          ('glue', '/workdir/webserver/core/glueVars.cpp'),
                          ('remote_io_config', '/docker_persistent/mbconfig.cfg')]:
            docker_source(sid, plc_container, path)
        for sid, path in [('tank_bridge', '/app/modbus/tank.py'),
                          ('bridge_common', '/app/modbus/modbusdevice.py'),
                          ('product_bridge', '/app/modbus/product.py')]:
            docker_source(sid, simulator_container, path)
        start = _stamp()
        library = _run(['docker', 'exec', simulator_container, 'python3', '-c',
            'import inspect; from pymodbus.datastore.context import ModbusSlaveContext; '
            'print(inspect.getsource(ModbusSlaveContext))'])
        save('bridge_context', library, simulator_container + ':installed pymodbus ModbusSlaveContext source',
             start, _stamp(), kind='live_runtime_source_extract')

        reader = _ScadaReader(scada_base, scada_username, scada_password)
        if point_ids is None:
            sql = 'SELECT id FROM dataPoints WHERE dataSourceId=' + str(data_source_id) + ' ORDER BY id'
            raw_ids = _run(['docker', 'exec', hmi_container, 'mysql', '-uroot', '-N', '-B', 'scadalts', '-e', sql])
            point_ids = [int(line) for line in raw_ids.decode('ascii').splitlines() if line.strip()]
        if (not isinstance(point_ids, (list, tuple)) or not 1 <= len(point_ids) <= 256
                or any(type(x) is not int or x < 0 for x in point_ids) or len(set(point_ids)) != len(point_ids)):
            raise AcquisitionError('Invalid or empty point inventory')
        start = _stamp()
        points = []
        for pid in point_ids:
            path = '/api/datapoint?id=' + str(pid)
            reply = reader.get(path)
            point = reply['value']
            if (not isinstance(point, dict) or point.get('id') != pid
                    or point.get('dataSourceId') != data_source_id or not isinstance(point.get('pointLocator'), dict)):
                raise AcquisitionError('Unexpected SCADA point response')
            if _credential_keys(point):
                raise AcquisitionError('Credential-like field in point response; capture refused')
            source_id = 'point_' + str(pid)
            save(source_id, reply['response_bytes'], 'authenticated SCADA GET ' + path,
                 reply['acquired_start'], reply['acquired_end'], suffix='.json')
            points.append({'point': point, 'request_path': path,
                           'source_id': source_id,
                           'response_text': reply['response_bytes'].decode('utf-8'),
                           'acquired_start': reply['acquired_start'], 'acquired_end': reply['acquired_end']})
        save('scada_points', _json_bytes({'points': points}), 'index of authenticated SCADA GET /api/datapoint captures; individual original files retained', start, _stamp(), kind='live_capture_index', suffix='.json')
        reply = reader.get('/api/datasource?id=' + str(data_source_id))
        ds = reply['value']
        if not isinstance(ds, dict) or ds.get('id') != data_source_id:
            raise AcquisitionError('Unexpected SCADA datasource response')
        projected = {k: v for k, v in ds.items() if k in _DATASOURCE_FIELDS}
        if _credential_keys(projected):
            raise AcquisitionError('Credential-like nested datasource data; capture refused')
        payload = {'data': projected, 'projection': 'explicit safe field whitelist',
                   'acquired_start': reply['acquired_start'], 'acquired_end': reply['acquired_end'],
                   'redacted_fields': sorted(set(ds) - _DATASOURCE_FIELDS),
                   'response_sha256': hashlib.sha256(reply['response_bytes']).hexdigest()}
        save('scada_datasource', _json_bytes(payload), 'authenticated SCADA GET /api/datasource; safe field projection',
             reply['acquired_start'], reply['acquired_end'], kind='live_capture_projection', suffix='.json')
        final_pointer = _run(['docker', 'exec', plc_container, 'cat', '/docker_persistent/active_program'])
        final_st = _run(['docker', 'exec', plc_container, 'cat', active_path])
        if final_pointer != pointer or final_st != active_bytes:
            raise AcquisitionError('PLC source changed during capture')
        manifest['identity_checks'] = {'active_program_unchanged': True, 'active_st_unchanged': True}
        manifest['complete'] = True
    except Exception as exc:
        manifest['issues'].append({'code': 'source_capture_incomplete', 'error_type': type(exc).__name__})
    finally:
        manifest['finished_at'] = _stamp()
        with (root / 'manifest.json').open('xb') as f:
            f.write(_json_bytes(manifest))
    return manifest


def _validate_read(fc, address, count, unit, transaction_id):
    if fc not in (1, 3, 4) or type(fc) is not int:
        raise ValueError('Only FC01, FC03 and FC04 reads are permitted')
    if not all(type(x) is int for x in (address, count, unit, transaction_id)):
        raise ValueError('Modbus fields must be integers')
    if not (0 <= address <= 65535 and 1 <= count <= 32 and address + count <= 65536
            and 0 <= unit <= 255 and 0 <= transaction_id <= 65535):
        raise ValueError('Modbus request is outside acquisition bounds')


def modbus_read(host, *, fc, address, count, unit=1, transaction_id=1, timeout=1.5):
    """A single bounded protocol read with raw bytes and request-local timing."""
    _validate_read(fc, address, count, unit, transaction_id)
    if not isinstance(host, str) or not host or not 0 < timeout <= 5:
        raise ValueError('Invalid host or read timeout')
    request = struct.pack('>HHHBBHH', transaction_id, 0, 6, unit, fc, address, count)
    record = {'fc': fc, 'address': address, 'count': count, 'unit': unit,
              'request_hex': request.hex(), 'start': _stamp()}
    response = bytearray()
    try:
        deadline = time.monotonic() + timeout
        with socket.create_connection((host, 502), timeout=timeout) as sock:
            sock.sendall(request)
            def exact(n):
                data = bytearray()
                while len(data) < n:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('Read deadline exceeded')
                    sock.settimeout(remaining)
                    part = sock.recv(n - len(data))
                    if not part:
                        raise ConnectionError('Truncated response')
                    data.extend(part)
                    response.extend(part)
                return bytes(data)
            header = exact(7)
            tid, protocol, length, reply_unit = struct.unpack('>HHHB', header)
            if (tid, protocol, reply_unit) != (transaction_id, 0, unit) or not 2 <= length <= 254:
                raise ValueError('Response identity or length mismatch')
            pdu = exact(length - 1)
            size = (count + 7) // 8 if fc == 1 else count * 2
            if len(pdu) != size + 2 or pdu[0] != fc or pdu[1] != size:
                raise ValueError('Response function or byte count mismatch')
            record['values'] = ([(pdu[2 + i // 8] >> (i % 8)) & 1 for i in range(count)] if fc == 1
                                else list(struct.unpack('>' + 'H' * count, pdu[2:])))
            record['quality'] = 'good'
    except Exception as exc:
        record.update(quality='bad', error_type=type(exc).__name__)
    record['response_hex'] = response.hex()
    record['end'] = _stamp()
    record['span_seconds'] = record['end']['epoch'] - record['start']['epoch']
    record['monotonic_span_seconds'] = record['end']['monotonic'] - record['start']['monotonic']
    return record


def collect_observations(plc_host, unit, read_plan, simulator_container='simulation',
                         transport_container='kali', count=3, interval_seconds=0.2):
    """Read a source-derived plan; preserve sequential timings without relabelling.

    Returns raw observations, not an evaluator snapshot or a semantic assertion.
    Caller must bind source identity, graph version and request-local times.
    """
    _name(simulator_container)
    _name(transport_container)
    if (type(count) is not int or not 1 <= count <= 10 or not isinstance(read_plan, list)
            or not 1 <= len(read_plan) <= 16 or type(interval_seconds) not in (int, float)
            or not 0 <= interval_seconds <= 2):
        raise ValueError('Observation plan exceeds acquisition bounds')
    for item in read_plan:
        if not isinstance(item, dict) or set(item) != {'fc', 'address', 'count'}:
            raise ValueError('Read plan entries require fc/address/count only')
        _validate_read(item['fc'], item['address'], item['count'], unit, 1)
    worker = ('import datetime,time,socket,struct,json,sys\n' + inspect.getsource(_stamp) + '\n'
              + inspect.getsource(_validate_read) + '\n' + inspect.getsource(modbus_read) + '\n'
              + 'q=json.load(sys.stdin)\n'
              + 'print(json.dumps([modbus_read(q["host"],unit=q["unit"],transaction_id=i+1,**p) '
              + 'for i,p in enumerate(q["plan"])],allow_nan=False))\n')
    sim_code = ('import socket,json\n'
                'with socket.create_connection(("127.0.0.1",55555),timeout=1.5) as s:\n'
                ' s.settimeout(1.5); s.sendall(b\'{"request":"read"}\\n\'); b=b""\n'
                ' while not b.endswith(b"\\n"):\n'
                '  p=s.recv(8192)\n'
                '  if not p: raise RuntimeError("truncated simulator response")\n'
                '  b+=p\n'
                '  if len(b)>100000: raise RuntimeError("oversize simulator response")\n'
                ' print(b.decode(),end="")\n')
    report = {'schema_version': '1', 'source_kind': 'live_observation', 'started_at': _stamp(),
              'endpoint': {'host': plc_host, 'port': 502, 'unit': unit,
                           'transport_container': transport_container,
                           'simulator_container': simulator_container},
              'read_plan': [dict(item) for item in read_plan],
              'sequential_acquisition': True, 'samples': []}
    for index in range(count):
        sample = {'index': index, 'start': _stamp()}
        payload = _json_bytes({'host': plc_host, 'unit': unit, 'plan': read_plan})
        try:
            raw = _run(['docker', 'exec', '-i', transport_container, 'python3', '-c', worker],
                       input=payload, timeout=min(40, len(read_plan) * 2 + 3))
            sample['reads'] = _json(raw)
        except Exception as exc:
            sample['reads'] = []
            sample['read_error_type'] = type(exc).__name__
        sim = {'start': _stamp(), 'request_text': '{"request":"read"}\n'}
        try:
            raw = _run(['docker', 'exec', simulator_container, 'python3', '-c', sim_code], timeout=3)
            sim.update(response_text=raw.decode('utf-8'), data=_json(raw), quality='good')
        except Exception as exc:
            sim.update(quality='bad', error_type=type(exc).__name__)
        sim['end'] = _stamp()
        sample.update(simulator=sim, end=_stamp())
        report['samples'].append(sample)
        if index + 1 < count:
            time.sleep(interval_seconds)
    report['finished_at'] = _stamp()
    return report
