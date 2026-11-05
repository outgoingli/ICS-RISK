"""Pure assessment after read-only configuration loading. Never performs process IO."""
from __future__ import annotations
import copy
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
from .graph import Graph
from .templates import evaluate_rule


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise ValueError('Not a numeric quantity')
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError('Invalid numeric quantity') from exc
    if not result.is_finite():
        raise ValueError('Nonfinite numeric quantity')
    return result


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))


def default_bundle_dir():
    """Resolve an explicit deployment bundle, otherwise the synthetic demo."""
    configured = os.environ.get('ICS_RISK_BUNDLE')
    return Path(configured) if configured else Path(__file__).resolve().parents[1] / 'examples' / 'demo_bundle'


class Evaluator:
    def __init__(self, bundle_dir=None, *, graph_data=None):
        self.root = Path(bundle_dir if bundle_dir is not None else default_bundle_dir()).resolve()
        self.config = {}
        self.load_issues = []
        self.sources = {}
        for name in ['graph', 'bindings', 'constraints', 'provenance']:
            try:
                self.config[name] = read_json(self.root / 'config' / (name + '.json'))
            except (OSError, ValueError) as exc:
                self.config[name] = {}
                self.load_issues.append({'code': 'config_unreadable', 'config': name,
                                          'detail': str(exc)})
            if not isinstance(self.config[name], dict):
                self.config[name] = {}
                self.load_issues.append({'code': 'config_object_required', 'config': name})
        # A backend may provide a versioned graph snapshot. It is still checked
        # against bindings and evidence by the same evaluator; never silently
        # fall back to the local graph after a backend error.
        if graph_data is not None:
            self.config['graph'] = copy.deepcopy(graph_data)
        self.config_digest = digest(self.config)
        source_list = self.config['provenance'].get('sources', [])
        if not isinstance(source_list, list):
            self.load_issues.append({'code': 'invalid_source_inventory'})
            source_list = []
        for source in source_list:
            if not isinstance(source, dict) or not isinstance(source.get('id'), str):
                self.load_issues.append({'code': 'invalid_source_record'})
                continue
            sid = source.get('id')
            item = copy.deepcopy(source)
            item['integrity'] = 'unverified'
            try:
                if not isinstance(sid, str) or sid in self.sources:
                    raise ValueError('Duplicate/invalid source ID')
                path = (self.root / source['path']).resolve()
                if not path.is_relative_to(self.root):
                    raise ValueError('Evidence path leaves bundle')
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                item['actual_sha256'] = actual
                if actual != source['sha256']:
                    raise ValueError('Evidence digest mismatch')
                if not source.get('locator') or not source.get('kind'):
                    raise ValueError('Missing evidence locator or category')
                item['integrity'] = 'verified'
            except (OSError, KeyError, ValueError, TypeError) as exc:
                item['integrity_error'] = str(exc)
                self.load_issues.append({'code': 'evidence_integrity_failure', 'source_id': sid})
            self.sources[sid] = item

    def _refs_valid(self, refs):
        return isinstance(refs, list) and bool(refs) and all(
            ref in self.sources and self.sources[ref]['integrity'] == 'verified' for ref in refs)

    @staticmethod
    def _unknown(rule, reason):
        return {'constraint_id': rule['id'], 'template': rule.get('template'),
                'category': rule.get('category'), 'status': 'UNKNOWN', 'metrics': {},
                'reason': reason, 'evidence_refs': copy.deepcopy(rule.get('evidence_refs', []))}

    def evaluate(self, command, snapshot, history, graph_version):
        try:
            return self._evaluate(command, snapshot, history, graph_version)
        except (TypeError, AttributeError, KeyError, IndexError, ValueError, ArithmeticError) as exc:
            # Malformed public data cannot turn into permission to execute or crash
            # the caller's established protection/recovery path.
            def safe_digest(value):
                try:
                    return digest(value)
                except (TypeError, ValueError):
                    return None
            return {'schema_version': '1', 'decision': 'INDETERMINATE', 'constraints': [],
                    'evaluation_id': safe_digest([command, snapshot, history, graph_version]),
                    'graph_version': graph_version if isinstance(graph_version, str) else None,
                    'config_sha256': self.config_digest, 'command': copy.deepcopy(command),
                    'snapshot_ref': safe_digest(snapshot), 'history_ref': safe_digest(history),
                    'evidence': [], 'query_trace': [],
                    'input_issues': [{'code': 'malformed_contract', 'error_type': type(exc).__name__,
                                      'detail': str(exc)}],
                    'completeness': {'complete': False, 'gaps': ['malformed_contract'],
                                     'physical_safety_assessed': False}}

    def _evaluate(self, command, snapshot, history, graph_version):
        # No mutable query or evaluation state survives a call.
        command, snapshot, history = copy.deepcopy(command), copy.deepcopy(snapshot), copy.deepcopy(history)
        try:
            input_hash = digest([command, snapshot, history, graph_version])
        except (TypeError, ValueError):
            return {'schema_version': '1', 'decision': 'INDETERMINATE', 'constraints': [],
                    'evidence': [], 'query_trace': [], 'input_issues': [{'code': 'not_finite_json_input'}],
                    'completeness': {'complete': False, 'gaps': ['not_finite_json_input'],
                                     'physical_safety_assessed': False}}
        graph = Graph(self.config['graph'])
        issues = copy.deepcopy(self.load_issues)
        bindings = self.config['bindings']
        rules = self.config['constraints'].get('rules', [])
        results, context, bad_signals = [], {}, set()
        global_invalid = False
        def issue(code, **details):
            issues.append({'code': code, **details})
        def fatal(code, **details):
            nonlocal global_invalid
            global_invalid = True
            issue(code, **details)

        if not all(isinstance(x, dict) for x in [command, snapshot, history]):
            command = command if isinstance(command, dict) else {}
            snapshot = snapshot if isinstance(snapshot, dict) else {}
            history = history if isinstance(history, dict) else {}
            fatal('input_object_required')
        if graph_version != graph.data.get('graph_version') or graph_version != bindings.get('graph_version'):
            fatal('graph_version_mismatch')
        if snapshot.get('graph_version') != graph_version:
            fatal('snapshot_graph_version_mismatch')
        if snapshot.get('runtime_sha256') != bindings.get('runtime_sha256') or not bindings.get('runtime_sha256'):
            fatal('runtime_version_mismatch')
        if command.get('action') != 'write' or command.get('unit') != 'percent' or not command.get('id'):
            fatal('unsupported_command_contract')
        point = command.get('point_id')
        binding = bindings.get('points', {}).get(point)
        if not isinstance(binding, dict):
            binding = {}
            fatal('unknown_point_binding')
        if graph.nodes.get(point, {}).get('type') != 'Point':
            fatal('missing_or_wrong_point_node')
        owner = graph.unique(point, 'EXPOSES', 'in')
        variable = graph.unique(point, 'MAPS_TO')
        host = graph.unique(variable, 'HOSTED_BY') if variable else None
        loop = graph.unique(variable, 'IN_LOOP') if variable else None
        if owner != binding.get('exposing_component_ref', binding.get('component_ref')) or host != binding.get('component_ref'):
            fatal('component_binding_mismatch')
        if variable != binding.get('variable_ref') or loop != binding.get('loop_ref'):
            fatal('semantic_binding_mismatch')
        applicable = set()
        for target in [variable, loop]:
            if target:
                applicable.update(graph.adjacent(target, 'APPLIES_TO', 'in'))
        configured_ids = [r.get('id') for r in rules if isinstance(r, dict)]
        if len(configured_ids) != len(rules) or len(set(configured_ids)) != len(configured_ids):
            fatal('invalid_rule_inventory')
        required_ids = binding.get('required_constraint_refs', configured_ids)
        for cid in set(required_ids) | applicable:
            if cid not in configured_ids or cid not in applicable or graph.nodes.get(cid, {}).get('type') != 'Constraint':
                fatal('constraint_coverage_path_missing', constraint_id=cid)
        for item in list(graph.nodes.values()) + graph.edges:
            if not self._refs_valid(item.get('evidence_refs')):
                fatal('graph_evidence_unresolved', item_id=item.get('id'))
        if not self._refs_valid(binding.get('evidence_refs')):
            fatal('binding_evidence_unresolved')
        if not self._refs_valid(bindings.get('quality', {}).get('evidence_refs')):
            fatal('freshness_policy_unverified')
        if graph.issues:
            global_invalid = True
            issues.extend(graph.issues)

        now = None
        try:
            now = number(command.get('evaluation_at'))
            context['evaluation_at'] = str(now)
            captured = number(snapshot.get('captured_at'))
            max_age = number(bindings['quality']['max_age_seconds'])
            max_span = number(bindings['quality']['max_span_seconds'])
            if max_age < 0 or max_span < 0 or not 0 <= now - captured <= max_age:
                fatal('snapshot_time_invalid_or_stale')
        except (ValueError, KeyError, TypeError):
            max_age = max_span = Decimal(0)
            fatal('missing_or_invalid_decision_time')
        try:
            candidate = number(command.get('value'))
            context['candidate_value'] = str(candidate)
        except ValueError:
            candidate = None
            issue('invalid_candidate_value')
        raw = command.get('raw')
        if raw is None:
            issue('canonical_raw_unavailable_quantization_unverified')
        elif type(raw) is not int or not 0 <= raw <= 65535:
            issue('invalid_candidate_raw')
        elif candidate is not None:
            try:
                scale = binding['scale']
                decoded = Decimal(raw) * number(scale['numerator']) / number(scale['denominator']) + number(scale['additive'])
                tolerance = number(bindings['representation']['engineering_raw_tolerance'])
                if tolerance < 0 or abs(candidate - decoded) > tolerance:
                    issue('candidate_engineering_raw_mismatch')
                else:
                    context['candidate_raw'] = raw
            except (KeyError, ValueError, TypeError, ArithmeticError):
                issue('unverified_encoding_conversion')

        context['signals'] = {}
        signals = snapshot.get('signals', {})
        if not isinstance(signals, dict):
            signals = {}
        plc_windows = {}
        for sid, definition in bindings.get('signals', {}).items():
            signal = signals.get(sid)
            try:
                if not isinstance(signal, dict) or signal.get('quality') != 'good':
                    raise ValueError('missing_or_bad_quality')
                if not self._refs_valid(definition.get('evidence_refs')):
                    raise ValueError('unverified_signal_binding')
                if signal.get('unit') != definition['unit']:
                    raise ValueError('unit_mismatch')
                observed = number(signal['observed_at'])
                available = number(signal['available_at'])
                span = number(signal['span_seconds'])
                if now is None or not observed <= available <= captured <= now:
                    raise ValueError('future_or_reversed_time')
                if observed + span > available:
                    raise ValueError('observation_window_not_available')
                signal_max_age = number(definition.get('max_age_seconds', max_age))
                if not 0 <= now - observed <= signal_max_age or span < 0 or (definition.get('source') == 'plc' and span > max_span):
                    raise ValueError('stale_or_excessive_span')
                if definition.get('source') == 'plc' and 'monotonic_span_seconds' in signal:
                    if not 0 <= number(signal['monotonic_span_seconds']) <= max_span:
                        raise ValueError('monotonic_span_outside_bound')
                value = signal['value']
                if definition['unit'] == 'boolean' and type(value) is not bool:
                    raise ValueError('boolean_type_required')
                if definition['unit'] == 'raw_count' and (type(value) is not int or not 0 <= value <= 65535):
                    raise ValueError('uint16_required')
                context['signals'][sid] = value
                if definition.get('source') == 'plc':
                    plc_windows[sid] = (observed, available, span)
                if sid == binding.get('variable_ref'):
                    context['reference_raw'] = value
            except (ValueError, KeyError, TypeError) as exc:
                bad_signals.add(sid)
                issue('signal_unavailable', signal_id=sid, detail=str(exc))

        if len(set(plc_windows.values())) > 1:
            for sid in plc_windows:
                bad_signals.add(sid)
                context['signals'].pop(sid, None)
            context.pop('reference_raw', None)
            issue('plc_signals_not_same_sequential_row')

        history_valid = True
        try:
            start = number(history['coverage_start'])
            end = number(history['coverage_end'])
            if now is None or not start <= end <= now or type(history.get('complete')) is not bool:
                raise ValueError('invalid_coverage')
            events = history['events']
            if not isinstance(events, list):
                raise ValueError('invalid_events')
            previous = []
            ids = set()
            for event in events:
                if not isinstance(event, dict) or not isinstance(event.get('id'), str) or event['id'] in ids:
                    raise ValueError('invalid_or_duplicate_event')
                if not isinstance(event.get('point_id'), str) or not event['point_id'] or event.get('action') != 'write':
                    raise ValueError('incomplete_operation_identity')
                if event.get('outcome') not in ['confirmed', 'failed', 'uncertain']:
                    raise ValueError('missing_or_unknown_operation_outcome')
                if type(event.get('raw')) is not int or not 0 <= event['raw'] <= 65535:
                    raise ValueError('invalid_operation_value')
                ids.add(event['id'])
                occurred, available = number(event['occurred_at']), number(event['available_at'])
                if not start <= occurred <= available <= end:
                    raise ValueError('future_or_outside_coverage_event')
                if event.get('point_id') == point and event.get('action') == 'write':
                    if event.get('outcome') != 'confirmed':
                        raise ValueError('target_write_outcome_unknown')
                    previous.append(occurred)
            context.update(history_complete=history['complete'], history_coverage_start=str(start),
                           history_coverage_end=str(end),
                           last_operation_at=str(max(previous)) if previous else None)
        except (ValueError, KeyError, TypeError) as exc:
            history_valid = False
            issue('history_unavailable', detail=str(exc))

        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get('id'), str):
                continue
            cid = rule['id']
            if cid not in applicable and cid not in required_ids:
                continue
            dependencies = graph.adjacent(cid, 'REQUIRES')
            dependency_hosts_valid = True
            for sid in dependencies:
                hosts = graph.adjacent(sid, 'HOSTED_BY')
                definition = bindings.get('signals', {}).get(sid, {})
                if len(hosts) != 1 or hosts[0] != definition.get('component_ref'):
                    dependency_hosts_valid = False
            params = rule.get('parameters', {})
            operand = params.get('reference_signal') if rule.get('template') == 'max_delta' else params.get('signal') if rule.get('template') == 'precondition' else None
            reason = None
            if rule.get('enabled') is False:
                result = evaluate_rule(rule, context)
            else:
                if global_invalid or self.load_issues:
                    reason = 'evaluation_context_unverified'
                elif rule.get('verification') != 'verified' or not self._refs_valid(rule.get('evidence_refs')):
                    reason = 'constraint_source_unverified'
                elif rule.get('verified_parameters_sha256') != digest(params):
                    reason = 'verified_parameters_changed'
                elif operand and dependencies != [operand]:
                    reason = 'required_variable_path_missing'
                elif not dependency_hosts_valid:
                    reason = 'required_variable_host_unverified'
                elif rule.get('template') == 'max_delta' and (operand != variable or bindings.get('signals', {}).get(operand, {}).get('unit') != 'raw_count'):
                    reason = 'delta_reference_not_commanded_variable'
                elif rule.get('template') == 'min_interval' and params.get('point_ref') != point:
                    reason = 'interval_point_mismatch'
                elif any(sid in bad_signals for sid in dependencies):
                    reason = 'required_current_observation_unavailable'
                elif rule.get('template') == 'min_interval' and not history_valid:
                    reason = 'history_unavailable'
                result = self._unknown(rule, reason) if reason else evaluate_rule(rule, context)
            result['required_variables'] = dependencies
            results.append(result)

        failed = [r['constraint_id'] for r in results if r['status'] == 'FAIL']
        unresolved = [r['constraint_id'] for r in results if r['status'] in ['UNKNOWN', 'DISABLED']]
        if not results:
            issue('no_applicable_constraints')
        complete = bool(results) and not unresolved and not issues
        decision = 'BLOCK' if failed else 'ALLOW' if complete else 'INDETERMINATE'
        output = {'schema_version': '1', 'evaluation_id': 'eval-' + input_hash[:20],
                  'graph_version': graph_version, 'config_sha256': self.config_digest,
                  'decision': decision, 'constraints': results, 'query_trace': graph.trace,
                  'evidence': [copy.deepcopy(self.sources[k]) for k in sorted(self.sources) if isinstance(k, str)],
                  'input_issues': issues, 'command': command,
                  'snapshot_ref': digest(snapshot), 'history_ref': digest(history),
                  'completeness': {'complete': complete, 'failed_constraints': failed,
                                   'unresolved_constraints': unresolved,
                                   'gaps': sorted(set(i['code'] for i in issues)),
                                   'configured_required_count': len(required_ids),
                                   'evaluated_count': len(results),
                                   'physical_safety_assessed': False,
                                   'scope': 'Configured pre-execution constraints; no trajectory prediction or safety certification'}}
        return output


def evaluate(command, snapshot, history, graph_version):
    return Evaluator().evaluate(command, snapshot, history, graph_version)
