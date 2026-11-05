"""Pure synthetic-rule tests. These values are not deployed plant constraints."""
from copy import deepcopy
from decimal import Decimal
import json
import unittest

from lvsp_eval.templates import evaluate_rule


def rule(template, parameters, **overrides):
    return {'id': 'constraint:SYNTHETIC:' + template, 'template': template, 'enabled': True,
            'category': 'research_requirement', 'verification': 'verified',
            'evidence_refs': ['evidence:SYNTHETIC:test_fixture'], 'parameters': parameters,
            **overrides}


def interval_context(**overrides):
    return {'evaluation_at': '1000', 'history_complete': True,
            'history_coverage_start': '900', 'history_coverage_end': '1000',
            'last_operation_at': '940', **overrides}


class TemplateTests(unittest.TestCase):
    def test_range_endpoints_are_inclusive(self):
        r = rule('range', {'lower': '40', 'upper': '50', 'unit': 'percent'})
        for candidate in ['40', '50', 45, 45.0, Decimal('45')]:
            with self.subTest(candidate=candidate):
                result = evaluate_rule(r, {'candidate_value': candidate})
                self.assertEqual(result['status'], 'PASS')
                self.assertEqual(Decimal(result['metrics']['exceedance']), 0)

    def test_range_decimal_precision_preserves_tiny_violation(self):
        r = rule('range', {'lower': '40', 'upper': '50', 'unit': 'percent'})
        value = '50.000000000000000000000000000001'
        result = evaluate_rule(r, {'candidate_value': value})
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(Decimal(result['metrics']['exceedance']), Decimal('1e-30'))
        self.assertEqual(Decimal(result['metrics']['upper_margin']), Decimal('-1e-30'))

    def test_range_lower_violation_has_directional_margins(self):
        r = rule('range', {'lower': '40', 'upper': '50', 'unit': 'percent'})
        result = evaluate_rule(r, {'candidate_value': '39.9'})
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['metrics']['lower_margin'], '-0.1')
        self.assertEqual(result['metrics']['upper_margin'], '10.1')
        self.assertEqual(result['metrics']['exceedance'], '0.1')

    def test_degenerate_range_only_passes_exact_bound(self):
        r = rule('range', {'lower': '44', 'upper': '44', 'unit': 'percent'})
        self.assertEqual(evaluate_rule(r, {'candidate_value': 44})['status'], 'PASS')
        self.assertEqual(evaluate_rule(r, {'candidate_value': '44.01'})['status'], 'FAIL')

    def test_reversed_or_missing_range_bounds_are_unknown(self):
        for p in [{'lower': 50, 'upper': 40, 'unit': 'percent'},
                  {'lower': 40, 'unit': 'percent'}, {'upper': 50, 'unit': 'percent'}]:
            self.assertEqual(evaluate_rule(rule('range', p), {'candidate_value': 44})['status'], 'UNKNOWN')

    def test_numeric_templates_reject_boolean_and_nonfinite(self):
        bad_values = [True, False, float('nan'), float('inf'), float('-inf'),
                      Decimal('NaN'), Decimal('Infinity'), 'NaN', '-Infinity']
        r = rule('range', {'lower': 40, 'upper': 50, 'unit': 'percent'})
        for bad in bad_values:
            with self.subTest(value=bad):
                self.assertEqual(evaluate_rule(r, {'candidate_value': bad})['status'], 'UNKNOWN')
                ri = rule('min_interval', {'seconds': bad, 'point_ref': 'point:level_sp'})
                self.assertEqual(evaluate_rule(ri, interval_context())['status'], 'UNKNOWN')

    def test_delta_has_signed_difference_and_absolute_limit(self):
        r = rule('max_delta', {'limit_raw': 328, 'reference_signal': 'var:level_sp'})
        for target, status, delta in [(29163, 'PASS', 328), (28507, 'PASS', -328),
                                      (29164, 'FAIL', 329), (28506, 'FAIL', -329)]:
            result = evaluate_rule(r, {'candidate_raw': target, 'reference_raw': 28835})
            self.assertEqual(result['status'], status)
            self.assertEqual(result['metrics']['delta_raw'], delta)
            self.assertEqual(result['metrics']['exceedance_raw'], max(abs(delta) - 328, 0))

    def test_delta_does_not_infer_raw_or_reference(self):
        r = rule('max_delta', {'limit_raw': 328, 'reference_signal': 'var:level_sp'})
        for context in [{'candidate_value': '44.5', 'reference_raw': 28835},
                        {'candidate_raw': 29163}, {'candidate_raw': True, 'reference_raw': 28835},
                        {'candidate_raw': 29163.0, 'reference_raw': 28835},
                        {'candidate_raw': 65536, 'reference_raw': 28835}]:
            self.assertEqual(evaluate_rule(r, context)['status'], 'UNKNOWN')

    def test_delta_limit_is_explicit_nonnegative_integer(self):
        for limit in [None, -1, True, 328.0, '328', Decimal(328)]:
            r = rule('max_delta', {'limit_raw': limit, 'reference_signal': 'var:level_sp'})
            self.assertEqual(evaluate_rule(r, {'candidate_raw': 29163, 'reference_raw': 28835})['status'], 'UNKNOWN')

    def test_interval_exact_boundary_and_fractional_remaining(self):
        r = rule('min_interval', {'seconds': '60', 'point_ref': 'point:level_sp'})
        result = evaluate_rule(r, interval_context())
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['metrics']['elapsed_seconds'], '60')
        result = evaluate_rule(r, interval_context(last_operation_at='940.1'))
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['metrics']['remaining_seconds'], '0.1')

    def test_interval_known_violation_can_coexist_with_incomplete_history(self):
        r = rule('min_interval', {'seconds': 60, 'point_ref': 'point:level_sp'})
        self.assertEqual(evaluate_rule(r, interval_context(last_operation_at=970,
                                                         history_complete=False))['status'], 'FAIL')

    def test_interval_old_event_cannot_pass_incomplete_history(self):
        r = rule('min_interval', {'seconds': 60, 'point_ref': 'point:level_sp'})
        result = evaluate_rule(r, interval_context(history_complete=False, last_operation_at=900))
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(result['reason'], 'history_incomplete')

    def test_no_prior_event_needs_complete_sufficient_coverage(self):
        r = rule('min_interval', {'seconds': 60, 'point_ref': 'point:level_sp'})
        self.assertEqual(evaluate_rule(r, interval_context(last_operation_at=None))['status'], 'PASS')
        for fields in [{'history_complete': False}, {'history_coverage_start': 941},
                       {'history_coverage_end': 999}, {'history_complete': 1}]:
            result = evaluate_rule(r, interval_context(last_operation_at=None, **fields))
            self.assertEqual(result['status'], 'UNKNOWN')

    def test_empty_context_or_missing_history_does_not_mean_first_operation(self):
        r = rule('min_interval', {'seconds': 60, 'point_ref': 'point:level_sp'})
        for context in [{}, {'evaluation_at': 1000}, {'evaluation_at': 1000, 'last_operation_at': None}]:
            self.assertEqual(evaluate_rule(r, context)['status'], 'UNKNOWN')

    def test_future_operation_and_future_coverage_are_unknown(self):
        r = rule('min_interval', {'seconds': 60, 'point_ref': 'point:level_sp'})
        for context in [interval_context(last_operation_at=1001),
                        interval_context(last_operation_at=None, history_coverage_end=1001),
                        interval_context(last_operation_at=None, history_coverage_start=1001,
                                         history_coverage_end=1002)]:
            self.assertEqual(evaluate_rule(r, context)['status'], 'UNKNOWN')

    def test_negative_interval_is_unknown_and_zero_interval_is_explicit(self):
        bad = rule('min_interval', {'seconds': -1, 'point_ref': 'point:level_sp'})
        self.assertEqual(evaluate_rule(bad, interval_context())['status'], 'UNKNOWN')
        zero = rule('min_interval', {'seconds': 0, 'point_ref': 'point:level_sp'})
        self.assertEqual(evaluate_rule(zero, interval_context(last_operation_at=1000))['status'], 'PASS')

    def test_precondition_boolean_is_strict_and_missing_is_unknown(self):
        r = rule('precondition', {'signal': 'var:run', 'operator': 'eq', 'expected': True})
        self.assertEqual(evaluate_rule(r, {'signals': {'var:run': True}})['status'], 'PASS')
        for observed in [False, 1, 'true', Decimal(1)]:
            result = evaluate_rule(r, {'signals': {'var:run': observed}})
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse(result['metrics']['matches'])
        self.assertEqual(evaluate_rule(r, {'signals': {}})['status'], 'UNKNOWN')

    def test_precondition_numeric_types_compare_mathematically(self):
        r = rule('precondition', {'signal': 'var:test', 'operator': 'eq', 'expected': Decimal('1.00')})
        for observed in [1, 1.0, Decimal('1')]:
            result = evaluate_rule(r, {'signals': {'var:test': observed}})
            self.assertEqual(result['status'], 'PASS')
        for observed in [True, '1', 2]:
            self.assertEqual(evaluate_rule(r, {'signals': {'var:test': observed}})['status'], 'FAIL')

    def test_precondition_strings_are_enums_and_nonfinite_numeric_is_unknown(self):
        r = rule('precondition', {'signal': 'var:mode', 'operator': 'eq', 'expected': 'AUTO'})
        self.assertEqual(evaluate_rule(r, {'signals': {'var:mode': 'AUTO'}})['status'], 'PASS')
        self.assertEqual(evaluate_rule(r, {'signals': {'var:mode': 'MANUAL'}})['status'], 'FAIL')
        for observed in [None, [], float('nan'), Decimal('Infinity')]:
            self.assertEqual(evaluate_rule(r, {'signals': {'var:mode': observed}})['status'], 'UNKNOWN')

    def test_disabled_rule_does_not_compute_invalid_parameters(self):
        r = rule('min_interval', {'seconds': 'NaN'}, enabled=False, verification='unverified')
        result = evaluate_rule(r, None)
        self.assertEqual(result['status'], 'DISABLED')
        self.assertEqual(result['metrics'], {})

    def test_unverified_missing_evidence_or_nonboolean_enabled_never_execute(self):
        r = rule('range', {'lower': 40, 'upper': 50, 'unit': 'percent'})
        for fields in [{'verification': 'unverified'}, {'evidence_refs': []}, {'enabled': 1}]:
            self.assertEqual(evaluate_rule({**r, **fields}, {'candidate_value': 45})['status'], 'UNKNOWN')

    def test_inputs_remain_unchanged_and_results_are_detached(self):
        r = rule('range', {'lower': '40', 'upper': '50', 'unit': 'percent'})
        context = {'candidate_value': Decimal('44.1'), 'signals': {'var:run': True}}
        before = deepcopy((r, context))
        result = evaluate_rule(r, context)
        result['evidence_refs'].append('unrelated')
        self.assertEqual((r, context), before)

    def test_results_are_json_serializable_without_nonfinite_numbers(self):
        r = rule('range', {'lower': Decimal('40'), 'upper': Decimal('50'), 'unit': 'percent'})
        result = evaluate_rule(r, {'candidate_value': Decimal('44.1')})
        self.assertIn('44.1', json.dumps(result, allow_nan=False))
        self.assertFalse(any('risk' in key or 'probability' in key for key in result['metrics']))


if __name__ == '__main__':
    unittest.main()
