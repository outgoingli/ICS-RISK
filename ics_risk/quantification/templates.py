"""Pure, evidence-gated scalar constraint templates; no process predictions.

The engine resolves graph operands and evidence before calling this module.
This module neither reads configuration/evidence files nor mutates inputs.
Decimal-valued metrics are returned as decimal strings; raw counts stay ints.
"""
from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from copy import deepcopy
from decimal import Decimal, DecimalException, InvalidOperation, localcontext
import math


_TEMPLATES = {'range', 'max_delta', 'min_interval', 'precondition'}
_CATEGORIES = {'implementation_limit', 'research_requirement', 'physical_safety_requirement'}


class _Unknown(Exception):
    def __init__(self, reason: str, **metrics):
        super().__init__(reason)
        self.reason = reason
        self.metrics = metrics


def _required(source: Mapping, name: str, *, parameter: bool = False):
    if name not in source:
        label = 'missing_parameter' if parameter else 'missing_context_field'
        raise _Unknown(label, field=name)
    return source[name]


def _decimal(value, field: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (Decimal, int, float, str)):
        raise _Unknown('invalid_numeric_value', field=field)
    if isinstance(value, float) and not math.isfinite(value):
        raise _Unknown('nonfinite_numeric_value', field=field)
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise _Unknown('invalid_numeric_value', field=field) from None
    if not result.is_finite():
        raise _Unknown('nonfinite_numeric_value', field=field)
    return result


def _integer(value, field: str, *, raw: bool = False) -> int:
    if type(value) is not int:
        raise _Unknown('invalid_integer_value', field=field)
    if value < 0 or (raw and value > 65535):
        raise _Unknown('integer_out_of_domain', field=field)
    return value


def _identifier(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _Unknown('invalid_operand_reference', field=field)
    return value


@contextmanager
def _exact_arithmetic(*values: Decimal):
    """Reserve enough precision for exact additions/subtractions of input values.

    The work bound is an implementation limit, not a process constraint. Inputs
    requiring more than 10,000 significant places yield UNKNOWN, never a score.
    """
    exponent = min(int(x.as_tuple().exponent) for x in values)
    adjusted = max(x.adjusted() for x in values)
    precision = max(28, adjusted - exponent + 4)
    if precision > 10000 or abs(exponent) > 999999 or abs(adjusted) > 999999:
        raise _Unknown('numeric_precision_exceeds_implementation')
    with localcontext() as ctx:
        ctx.prec = precision
        yield


def _json_metrics(value):
    if isinstance(value, Decimal):
        return '0' if value.is_zero() else str(value)
    if isinstance(value, dict):
        return {key: _json_metrics(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_metrics(item) for item in value]
    return deepcopy(value)


def _range(parameters: Mapping, context: Mapping) -> tuple[str, str, dict]:
    unit = _required(parameters, 'unit', parameter=True)
    if unit != 'percent':
        raise _Unknown('unsupported_unit', field='unit')
    lower = _decimal(_required(parameters, 'lower', parameter=True), 'lower')
    upper = _decimal(_required(parameters, 'upper', parameter=True), 'upper')
    value = _decimal(_required(context, 'candidate_value'), 'candidate_value')
    if lower > upper:
        raise _Unknown('invalid_range_bounds')
    with _exact_arithmetic(value, lower, upper):
        lower_margin = value - lower
        upper_margin = upper - value
        exceedance = max(lower - value, value - upper, Decimal(0))
    passed = lower <= value <= upper
    return ('PASS' if passed else 'FAIL', 'within_range' if passed else 'outside_range',
            {'value': value, 'lower': lower, 'upper': upper, 'lower_margin': lower_margin,
             'upper_margin': upper_margin, 'exceedance': exceedance, 'unit': unit})


def _max_delta(parameters: Mapping, context: Mapping) -> tuple[str, str, dict]:
    _identifier(_required(parameters, 'reference_signal', parameter=True), 'reference_signal')
    limit = _integer(_required(parameters, 'limit_raw', parameter=True), 'limit_raw')
    candidate = _integer(_required(context, 'candidate_raw'), 'candidate_raw', raw=True)
    reference = _integer(_required(context, 'reference_raw'), 'reference_raw', raw=True)
    delta = candidate - reference
    margin = limit - abs(delta)
    passed = abs(delta) <= limit
    return ('PASS' if passed else 'FAIL', 'within_max_delta' if passed else 'max_delta_exceeded',
            {'candidate_raw': candidate, 'reference_raw': reference, 'delta_raw': delta,
             'abs_delta_raw': abs(delta), 'limit_raw': limit, 'margin_raw': margin,
             'exceedance_raw': max(-margin, 0)})


def _history_coverage(context: Mapping, evaluation_at: Decimal,
                      minimum: Decimal) -> tuple[bool, str, dict]:
    complete = _required(context, 'history_complete')
    if type(complete) is not bool:
        raise _Unknown('invalid_history_completeness')
    start = _decimal(_required(context, 'history_coverage_start'), 'history_coverage_start')
    end = _decimal(_required(context, 'history_coverage_end'), 'history_coverage_end')
    if start > end:
        raise _Unknown('invalid_history_coverage_order')
    if start > evaluation_at or end > evaluation_at:
        raise _Unknown('future_history_coverage')
    with _exact_arithmetic(evaluation_at, start, end, minimum):
        required_start = evaluation_at - minimum
        covered_seconds = evaluation_at - start
        gap = evaluation_at - end
    metrics = {'history_complete': complete, 'history_coverage_start': start,
               'history_coverage_end': end, 'required_coverage_start': required_start,
               'known_coverage_seconds': covered_seconds, 'coverage_end_gap_seconds': gap}
    if not complete:
        return False, 'history_incomplete', metrics
    if end < evaluation_at or start > required_start:
        return False, 'insufficient_history_coverage', metrics
    return True, 'history_coverage_complete', metrics


def _min_interval(parameters: Mapping, context: Mapping) -> tuple[str, str, dict]:
    _identifier(_required(parameters, 'point_ref', parameter=True), 'point_ref')
    minimum = _decimal(_required(parameters, 'seconds', parameter=True), 'seconds')
    if minimum < 0:
        raise _Unknown('negative_minimum_interval')
    evaluation_at = _decimal(_required(context, 'evaluation_at'), 'evaluation_at')
    previous = _required(context, 'last_operation_at')
    metrics = {'minimum_seconds': minimum}
    if previous is not None:
        last = _decimal(previous, 'last_operation_at')
        if last > evaluation_at:
            raise _Unknown('future_operation_time')
        with _exact_arithmetic(evaluation_at, last, minimum):
            elapsed = evaluation_at - last
            remaining = max(minimum - elapsed, Decimal(0))
        metrics.update(elapsed_seconds=elapsed, remaining_seconds=remaining,
                       last_operation_at=last)
        if elapsed < minimum:
            # A known recent operation proves a violation even if older history
            # is incomplete. The engine separately preserves coverage gaps.
            return 'FAIL', 'minimum_interval_not_elapsed', metrics
    try:
        covered, reason, coverage_metrics = _history_coverage(context, evaluation_at, minimum)
    except _Unknown as exc:
        raise _Unknown(exc.reason, **metrics, **exc.metrics) from None
    metrics.update(coverage_metrics)
    if not covered:
        return 'UNKNOWN', reason, metrics
    if previous is None:
        metrics.update(no_prior_operation_in_complete_window=True, remaining_seconds=Decimal(0))
        return 'PASS', 'no_prior_operation_in_complete_window', metrics
    return 'PASS', 'minimum_interval_elapsed', metrics


def _precondition_value(value, field: str) -> tuple[str, object]:
    if type(value) is bool:
        return 'boolean', value
    if isinstance(value, str):
        return 'string', value
    if isinstance(value, (Decimal, int, float)) and not isinstance(value, bool):
        return 'number', _decimal(value, field)
    raise _Unknown('invalid_precondition_value', field=field)


def _precondition(parameters: Mapping, context: Mapping) -> tuple[str, str, dict]:
    signal = _identifier(_required(parameters, 'signal', parameter=True), 'signal')
    operator = _required(parameters, 'operator', parameter=True)
    if operator != 'eq':
        raise _Unknown('unsupported_precondition_operator')
    expected_kind, expected = _precondition_value(
        _required(parameters, 'expected', parameter=True), 'expected')
    signals = _required(context, 'signals')
    if not isinstance(signals, Mapping):
        raise _Unknown('invalid_signals_context')
    if signal not in signals:
        raise _Unknown('missing_signal', signal=signal)
    observed_kind, observed = _precondition_value(signals[signal], signal)
    matches = observed_kind == expected_kind and observed == expected
    return ('PASS' if matches else 'FAIL', 'precondition_met' if matches else 'precondition_not_met',
            {'observed': observed, 'expected': expected, 'matches': bool(matches),
             'observed_type': observed_kind, 'expected_type': expected_kind})


def evaluate_rule(rule, context) -> dict:
    """Evaluate one configured template using only normalized caller inputs.

    Evidence resolution belongs to the engine. This function still requires
    explicit enabled/verified metadata and nonempty evidence-reference IDs.
    Missing inputs or invalid parameters yield UNKNOWN rather than invented
    defaults; disabled rules are not numerically evaluated.
    """
    if not isinstance(rule, Mapping):
        return {'constraint_id': None, 'template': None, 'category': None, 'status': 'UNKNOWN',
                'metrics': {}, 'reason': 'invalid_rule', 'evidence_refs': []}
    refs = rule.get('evidence_refs', [])
    result = {'constraint_id': deepcopy(rule.get('id')), 'template': deepcopy(rule.get('template')),
              'category': deepcopy(rule.get('category')), 'status': 'UNKNOWN', 'metrics': {},
              'reason': 'not_evaluated', 'evidence_refs': deepcopy(refs) if isinstance(refs, list) else []}
    if rule.get('enabled') is False:
        return {**result, 'status': 'DISABLED', 'reason': 'rule_disabled'}
    if rule.get('enabled') is not True:
        return {**result, 'reason': 'enabled_not_explicit_true'}
    if rule.get('verification') != 'verified':
        return {**result, 'reason': 'rule_unverified'}
    if not isinstance(refs, list) or not refs or any(not isinstance(x, str) or not x for x in refs):
        return {**result, 'reason': 'missing_or_invalid_evidence_refs'}
    template = rule.get('template')
    if not isinstance(template, str) or template not in _TEMPLATES:
        return {**result, 'reason': 'unsupported_template'}
    if not isinstance(rule.get('category'), str) or rule['category'] not in _CATEGORIES:
        return {**result, 'reason': 'invalid_category'}
    parameters = rule.get('parameters')
    if not isinstance(parameters, Mapping):
        return {**result, 'reason': 'missing_or_invalid_parameters'}
    if not isinstance(context, Mapping):
        return {**result, 'reason': 'invalid_context'}
    functions = {'range': _range, 'max_delta': _max_delta,
                 'min_interval': _min_interval, 'precondition': _precondition}
    try:
        status, reason, metrics = functions[template](parameters, context)
    except _Unknown as exc:
        status, reason, metrics = 'UNKNOWN', exc.reason, exc.metrics
    except DecimalException:
        status, reason, metrics = 'UNKNOWN', 'decimal_arithmetic_unavailable', {}
    result.update(status=status, reason=reason, metrics=_json_metrics(metrics))
    return result
