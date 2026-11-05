"""Bind real read observations to extracted roles without inventing current state.

Identity checks concern the captured PLC container and active source bytes, not
attestation of a running binary. Replay time and current decision time are kept
distinct. Preparing a candidate never sends a control request.
"""
from __future__ import annotations

import copy
from decimal import Decimal, InvalidOperation, localcontext
import hashlib
import json
from pathlib import Path
import re
import struct
import time
import uuid

from ics_risk.acquisition.grfics import _json, _run, collect_observations
from ics_risk.graph_build.builder import read_json


class ObservationError(ValueError):
    pass


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise ObservationError('non_numeric_observation_time')
    try:
        value = Decimal(str(value))
    except InvalidOperation:
        raise ObservationError('invalid_observation_number') from None
    if not value.is_finite():
        raise ObservationError('nonfinite_observation_number')
    return value


def _inside(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ObservationError('evidence_path_outside_bundle')
    return path


def _bundle(root):
    root = Path(root).resolve()
    bindings = read_json(root / 'config/bindings.json')
    plan = read_json(root / 'read_plan.json')
    if bindings.get('graph_construction') != 'deterministic_source_extraction':
        raise ObservationError('source_extracted_bundle_required')
    endpoint = plan['endpoint']
    if endpoint.get('port') != 502:
        raise ObservationError('unsupported_modbus_port')
    expected = []
    for definition in bindings['signals'].values():
        if definition.get('source') != 'plc':
            continue
        if definition.get('unit_id') != endpoint.get('unit') or definition.get('count') != 1:
            raise ObservationError('signal_read_plan_identity_mismatch')
        expected.append({'fc': definition['function_code'], 'address': definition['offset'], 'count': 1})
    canonical = lambda items: sorted(json.dumps(x, sort_keys=True) for x in items)
    if not expected or canonical(expected) != canonical(plan['requests']):
        raise ObservationError('read_plan_does_not_match_signal_bindings')
    for request in plan['requests']:
        if (request['fc'] not in (1, 3, 4) or type(request['fc']) is not int
                or type(request['address']) is not int or not 0 <= request['address'] <= 65535):
            raise ObservationError('unsupported_read_plan_operation')
    return root, bindings, plan


def _expected_inventory(root):
    provenance = read_json(root / 'config/provenance.json')
    matching = [s for s in provenance['sources'] if s['id'] == 'src:capture:inventory']
    if len(matching) != 1:
        raise ObservationError('captured_inventory_reference_required')
    source = matching[0]
    path = _inside(root, source['path'])
    if hashlib.sha256(path.read_bytes()).hexdigest() != source['sha256']:
        raise ObservationError('captured_inventory_digest_mismatch')
    return read_json(path)['plc']


def _identity(root, bindings, endpoint):
    """Return non-sensitive observations even when identity fails."""
    result = {'verified': False, 'checked_at': time.time(), 'container': 'plc'}
    try:
        expected = _expected_inventory(root)
        current = json.loads(_run(['docker', 'inspect', 'plc']))[0]
        result['container_id'] = current['Id']
        if current['Id'] != expected['id'] or current['State']['Running'] is not True:
            raise ObservationError('plc_container_identity_mismatch')
        addresses = [v.get('IPAddress') for v in current['NetworkSettings']['Networks'].values()]
        result['network_addresses'] = addresses
        if endpoint['host'] not in addresses:
            raise ObservationError('plc_endpoint_not_current_container_address')
        pointer = _run(['docker', 'exec', 'plc', 'cat', '/docker_persistent/active_program']).decode('utf-8').strip()
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,160}\.st', pointer) or pointer.startswith('.'):
            raise ObservationError('unsafe_active_program_pointer')
        result['active_program'] = pointer
        source = _run(['docker', 'exec', 'plc', 'cat', '/workdir/webserver/st_files/' + pointer])
        result['source_sha256'] = hashlib.sha256(source).hexdigest()
        if result['source_sha256'] != bindings['runtime_sha256']:
            raise ObservationError('active_source_digest_mismatch')
        result['verified'] = True
    except Exception as exc:
        result['error_type'] = type(exc).__name__
        if isinstance(exc, ObservationError):
            result['reason'] = str(exc)
        else:
            result['reason'] = 'identity_read_unavailable'
    return result


def capture_for_bundle(bundle_dir, destination, count=3):
    """Preserve one source-bound observation report in a new file.

    A failed before/after identity is recorded and prevents prepare_request from
    treating the observations as eligible input. No unknown value is filled in.
    """
    root, bindings, plan = _bundle(bundle_dir)
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Reserve the destination before any remote read; an existing archive stays intact.
    with output.open('x', encoding='utf-8') as stream:
        before = _identity(root, bindings, plan['endpoint'])
        report = {'schema_version': '1', 'source_kind': 'source_bound_live_observation',
                  'graph_version': bindings['graph_version'], 'runtime_sha256': bindings['runtime_sha256'],
                  'endpoint': copy.deepcopy(plan['endpoint']), 'samples': [], 'identity_verified': False,
                  'identity_checks': {'before': before},
                  'identity_scope': 'Container identity and active source bytes; not running-binary attestation'}
        try:
            if before['verified']:
                observed = collect_observations(plan['endpoint']['host'], plan['endpoint']['unit'],
                                                plan['requests'], count=count)
                report.update(observed)
                report['source_kind'] = 'source_bound_live_observation'
                after = _identity(root, bindings, plan['endpoint'])
                report['identity_checks']['after'] = after
                report['identity_verified'] = bool(after['verified']
                    and before.get('container_id') == after.get('container_id')
                    and before.get('active_program') == after.get('active_program')
                    and before.get('source_sha256') == after.get('source_sha256'))
            else:
                report['identity_checks']['after'] = {'verified': False, 'reason': 'not_collected_after_failed_identity'}
        except Exception as exc:
            report['collection_error_type'] = type(exc).__name__
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')
        stream.flush()
    return report


def _window(start, end, outer_start, outer_end):
    lo, hi = _number(start['epoch']), _number(end['epoch'])
    mono_lo, mono_hi = _number(start['monotonic']), _number(end['monotonic'])
    if not outer_start <= lo <= hi <= outer_end or mono_hi < mono_lo:
        raise ObservationError('invalid_observation_window')
    return lo, hi, mono_lo, mono_hi


def _decode_read(read):
    if read.get('quality') != 'good':
        raise ObservationError('bad_read_quality')
    req, resp = bytes.fromhex(read['request_hex']), bytes.fromhex(read['response_hex'])
    if len(req) != 12 or len(resp) < 9:
        raise ObservationError('malformed_wire_frame')
    tid, protocol, length, unit, fc, address, count = struct.unpack('>HHHBBHH', req)
    if protocol != 0 or length != 6 or fc not in (1, 3, 4) or not 1 <= count <= 32:
        raise ObservationError('unsupported_wire_request')
    if any(type(read.get(k)) is not int for k in ('fc', 'address', 'count', 'unit')):
        raise ObservationError('non_integer_wire_metadata')
    if (fc, address, count, unit) != (read['fc'], read['address'], read['count'], read['unit']):
        raise ObservationError('wire_request_metadata_mismatch')
    rt, rp, rl, ru = struct.unpack('>HHHB', resp[:7])
    size = (count + 7) // 8 if fc == 1 else count * 2
    if ((rt, rp, ru) != (tid, 0, unit) or rl != len(resp) - 6 or len(resp) != 9 + size
            or resp[7] != fc or resp[8] != size):
        raise ObservationError('wire_response_identity_or_size_mismatch')
    decoded = ([(resp[9+i//8] >> (i % 8)) & 1 for i in range(count)] if fc == 1
               else list(struct.unpack('>' + 'H' * count, resp[9:])))
    values = read.get('values')
    if not isinstance(values, list) or any(type(x) is not int for x in values) or values != decoded:
        raise ObservationError('decoded_values_differ_from_wire')
    return (fc, address, count, unit), decoded


def _path(value, dotted):
    if not isinstance(dotted, str) or not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', dotted):
        raise ObservationError('unsupported_simulator_field_path')
    for key in dotted.split('.'):
        if not isinstance(value, dict) or key not in value:
            raise ObservationError('simulator_field_missing')
        value = value[key]
    return value


def prepare_request(bundle_dir, observations_or_path, candidate_raw, sample_index=-1, mode='replay'):
    """Prepare an unexecuted candidate using measured state from one sample.

    replay uses the captured sample end; current uses current time and leaves
    stale data to the evaluator. Missing/bad observations are omitted, never
    replaced with PLC initializers or candidate values.
    """
    root, bindings, plan = _bundle(bundle_dir)
    if type(candidate_raw) is not int or not 0 <= candidate_raw <= 65535:
        raise ObservationError('candidate_raw_must_be_uint16')
    if mode not in ('replay', 'current'):
        raise ObservationError('unsupported_evaluation_mode')
    report = (read_json(Path(observations_or_path)) if isinstance(observations_or_path, (str, Path))
              else copy.deepcopy(observations_or_path))
    if (not isinstance(report, dict) or report.get('source_kind') != 'source_bound_live_observation'
            or report.get('identity_verified') is not True
            or report.get('graph_version') != bindings['graph_version']
            or report.get('runtime_sha256') != bindings['runtime_sha256']):
        raise ObservationError('observation_source_identity_not_verified')
    expected_inventory = _expected_inventory(root)
    checks = report.get('identity_checks', {})
    before, after = checks.get('before', {}), checks.get('after', {})
    for identity in (before, after):
        if (identity.get('verified') is not True or identity.get('container_id') != expected_inventory['id']
                or identity.get('source_sha256') != bindings['runtime_sha256']
                or plan['endpoint']['host'] not in identity.get('network_addresses', [])):
            raise ObservationError('observation_before_after_identity_mismatch')
    if (not isinstance(before.get('active_program'), str)
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,160}\.st', before['active_program'])
            or before['active_program'].startswith('.')
            or before['active_program'] != after.get('active_program')):
        raise ObservationError('observation_active_program_changed')
    endpoint = report.get('endpoint', {})
    if any(endpoint.get(k) != plan['endpoint'].get(k) for k in ('host', 'port', 'unit')):
        raise ObservationError('observation_endpoint_mismatch')
    if type(sample_index) is not int:
        raise ObservationError('sample_index_must_be_integer')
    try:
        sample = report['samples'][sample_index]
        sample_start, sample_end = _number(sample['start']['epoch']), _number(sample['end']['epoch'])
        if sample_end < sample_start:
            raise ObservationError('invalid_sample_interval')
    except (KeyError, IndexError, TypeError):
        raise ObservationError('observation_sample_unavailable') from None
    now = sample['end']['epoch'] if mode == 'replay' else time.time()
    _number(now)
    if len(bindings['points']) != 1:
        raise ObservationError('single_extracted_command_point_required')
    point_id, point = next(iter(bindings['points'].items()))
    scale = point['scale']
    with localcontext() as ctx:
        ctx.prec = 50
        denominator = _number(scale['denominator'])
        if denominator <= 0:
            raise ObservationError('invalid_encoding_denominator')
        candidate = (Decimal(candidate_raw) * _number(scale['numerator']) / denominator
                     + _number(scale['additive']))
    valid, windows, occurrences = {}, [], {}
    reads = sample.get('reads', [])
    if not isinstance(reads, list):
        reads = []
    for read in reads:
        try:
            metadata_key = (read['fc'], read['address'], read['count'], read['unit'])
            if all(type(x) is int for x in metadata_key):
                occurrences[metadata_key] = occurrences.get(metadata_key, 0) + 1
            window = _window(read['start'], read['end'], sample_start, sample_end)
            windows.append(window)
            key, values = _decode_read(read)
            valid.setdefault(key, []).append((read, values))
        except (ObservationError, KeyError, TypeError, ValueError, struct.error):
            continue
    signals, omitted = {}, []
    common = None
    if windows:
        common = (min(w[0] for w in windows), max(w[1] for w in windows),
                  min(w[2] for w in windows), max(w[3] for w in windows))
    for sid, definition in bindings['signals'].items():
        try:
            if definition.get('source') == 'plc':
                key = (definition['function_code'], definition['offset'], definition['count'], definition['unit_id'])
                matched = valid.get(key, [])
                if len(matched) != 1 or occurrences.get(key) != 1 or key[2] != 1 or common is None:
                    raise ObservationError('unique_matching_wire_observation_required')
                read, values = matched[0]
                value = values[0]
                if definition['unit'] == 'boolean':
                    if key[0] != 1 or value not in (0, 1):
                        raise ObservationError('coil_bit_required_for_boolean')
                    value = bool(value)
                elif definition['unit'] != 'raw_count' or not 0 <= value <= 65535:
                    raise ObservationError('unsupported_plc_observation_unit')
                signals[sid] = {'value': value, 'unit': definition['unit'], 'quality': 'good',
                    'observed_at': str(common[0]), 'available_at': str(common[1]),
                    'span_seconds': str(common[1]-common[0]),
                    'monotonic_span_seconds': str(common[3]-common[2]),
                    'acquisition_semantics': 'same sequential row window; not simultaneous measurements',
                    'individual_observation': {'start': copy.deepcopy(read['start']), 'end': copy.deepcopy(read['end']),
                                               'request_hex': read['request_hex'], 'response_hex': read['response_hex']}}
            elif definition.get('source') == 'simulator':
                sim = sample['simulator']
                if sim.get('quality') != 'good':
                    raise ObservationError('simulator_observation_unavailable')
                window = _window(sim['start'], sim['end'], sample_start, sample_end)
                # Preserve and cross-check the original JSON response, not only the decoded copy.
                data = _json(sim['response_text'])
                if (json.dumps(data, sort_keys=True, allow_nan=False) != json.dumps(sim['data'], sort_keys=True, allow_nan=False)
                        or sim.get('request_text') != '{"request":"read"}\n'):
                    raise ObservationError('simulator_raw_response_mismatch')
                value = _path({'data': data}, definition['json_path'])
                if definition['unit'] != 'boolean' or type(value) is not bool:
                    raise ObservationError('simulator_boolean_observation_required')
                signals[sid] = {'value': value, 'unit': definition['unit'], 'quality': 'good',
                    'observed_at': str(window[0]), 'available_at': str(window[1]),
                    'span_seconds': str(window[1]-window[0]),
                    'monotonic_span_seconds': str(window[3]-window[2])}
            else:
                raise ObservationError('unsupported_observation_source')
        except (ObservationError, KeyError, TypeError, ValueError):
            omitted.append(sid)
    return {'command': {'id': 'unexecuted-candidate-' + uuid.uuid4().hex,
                'origin': 'unexecuted_candidate',
                'evaluation_mode': 'replay_at_observation_end' if mode == 'replay' else 'current_time_with_captured_observations',
                'action': 'write', 'point_id': point_id, 'raw': candidate_raw, 'value': str(candidate),
                'unit': scale['unit'], 'evaluation_at': now},
            'snapshot': {'graph_version': bindings['graph_version'], 'runtime_sha256': bindings['runtime_sha256'],
                'captured_at': sample['end']['epoch'], 'signals': signals,
                'observation_sample_index': sample_index, 'omitted_signals': omitted,
                'acquisition_semantics': 'sequential PLC row plus separately timed simulator read'},
            'history': {'complete': False, 'coverage_start': str(sample_start),
                        'coverage_end': str(sample_end), 'events': []},
            'graph_version': bindings['graph_version']}
