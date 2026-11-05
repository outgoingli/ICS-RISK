"""Synthetic programs test structural recognition, never serve as lab evidence."""
from copy import deepcopy
import re
import unittest

from ics_risk.semantic.st import analyze_st


SOURCE = '''
FUNCTION blend : UINT
VAR_INPUT
 aa : UINT;
 bb : UINT;
 cc : UINT;
 gg : REAL;
END_VAR
VAR
 x : REAL;
 y : REAL;
 z : REAL;
 limited : REAL;
END_VAR
x := UINT_TO_REAL(aa) * 100.0 / 65535.0;
y := UINT_TO_REAL(bb) * 100.0 / 65535.0;
z := UINT_TO_REAL(cc) * 100.0 / 65535.0;
limited := LIMIT(0.0, z + (y - x) * gg, 100.0);
blend := REAL_TO_UINT(limited * 65535.0 / 100.0);
END_FUNCTION

PROGRAM trial
VAR
 sensor AT %IW7 : UINT;
 target AT %MW9 : UINT := 100;
 position AT %IW8 : UINT;
 output AT %QW6 : UINT;
 enabled AT %QX2.3 : BOOL := TRUE;
END_VAR
output := blend(aa := sensor, bb := target, cc := position, gg := -2.0);
END_PROGRAM
'''


def appended(statement, source=SOURCE):
    return source.replace('END_PROGRAM', statement + '\nEND_PROGRAM')


class StSemanticsTests(unittest.TestCase):
    def test_dataflow_roles_without_role_names(self):
        result = analyze_st(SOURCE)
        self.assertEqual([], result['issues'])
        self.assertEqual(1, len(result['control_calls']))
        call = result['control_calls'][0]
        self.assertEqual(('sensor', 'target', 'position', 'output'),
                         (call['pv'], call['sp'], call['actuator_feedback'], call['output']))
        self.assertEqual(-2, call['gain'])
        self.assertEqual('sp_minus_pv', call['error_orientation'])
        self.assertEqual('active', call['adoption'])
        self.assertTrue(call['effective'])
        self.assertEqual((0, 100), (call['range_min'], call['range_max']))

    def test_alpha_renaming_preserves_roles(self):
        names = ['blend', 'aa', 'bb', 'cc', 'gg', 'x', 'y', 'z', 'limited',
                 'trial', 'sensor', 'target', 'position', 'output', 'enabled']
        mapping = {name: 'opaque_' + str(i) for i, name in enumerate(names)}
        renamed = re.sub(r'\b(' + '|'.join(names) + r')\b', lambda m: mapping[m[0]], SOURCE)
        call = analyze_st(renamed)['control_calls'][0]
        for role, symbol in [('pv', 'sensor'), ('sp', 'target'), ('actuator_feedback', 'position'), ('output', 'output')]:
            self.assertEqual(mapping[symbol], call[role])
        self.assertEqual(-2, call['gain'])

    def test_helper_function_is_inlined_and_included_in_evidence(self):
        helper = '''FUNCTION arbitrary : REAL
VAR_INPUT
 count : UINT;
 span : REAL;
END_VAR
arbitrary := UINT_TO_REAL(count) * span / 65535.0;
END_FUNCTION
'''
        source = helper + SOURCE
        for name in ('aa', 'bb', 'cc'):
            source = source.replace('UINT_TO_REAL(' + name + ') * 100.0 / 65535.0',
                                    'arbitrary(count := ' + name + ', span := 100.0)')
        call = analyze_st(source)['control_calls'][0]
        self.assertEqual('sensor', call['pv'])
        self.assertEqual({'blend', 'arbitrary'}, {x['function'] for x in call['function_spans']})
        changed = re.sub(r'\b(arbitrary|count|span)\b', lambda m: 'renamed_' + m[0], source)
        renamed = analyze_st(changed)['control_calls'][0]
        self.assertEqual(call['pv_scale'], renamed['pv_scale'])
        self.assertEqual(call['error_orientation'], renamed['error_orientation'])

    def test_unknown_output_function_is_explicitly_unrecognized(self):
        source = SOURCE.replace('output := blend(', 'output := not_defined(')
        result = analyze_st(source)
        self.assertEqual([], result['control_calls'])
        self.assertIn('output_control_pattern_not_recognized', {i['code'] for i in result['issues']})

    def test_swapped_actual_parameters_reverse_error_orientation(self):
        changed = SOURCE.replace('aa := sensor, bb := target', 'aa := target, bb := sensor')
        call = analyze_st(changed)['control_calls'][0]
        self.assertEqual('sensor', call['pv'])
        self.assertEqual('target', call['sp'])
        self.assertEqual('pv_minus_sp', call['error_orientation'])

    def test_changed_difference_does_not_match(self):
        self.assertEqual([], analyze_st(SOURCE.replace('(y - x)', '(y + x)'))['control_calls'])

    def test_removed_feedback_does_not_match(self):
        self.assertEqual([], analyze_st(SOURCE.replace('(y - x)', '(y - 0.0)'))['control_calls'])

    def test_zero_gain_does_not_produce_feedback_fact(self):
        self.assertEqual([], analyze_st(SOURCE.replace('gg := -2.0', 'gg := 0.0'))['control_calls'])

    def test_different_operand_scaling_does_not_match(self):
        changed = SOURCE.replace('UINT_TO_REAL(bb) * 100.0', 'UINT_TO_REAL(bb) * 200.0')
        self.assertEqual([], analyze_st(changed)['control_calls'])

    def test_noninverse_encoding_does_not_match(self):
        changed = SOURCE.replace('limited * 65535.0 / 100.0', 'limited * 32767.0 / 100.0')
        self.assertEqual([], analyze_st(changed)['control_calls'])

    def test_unconditional_final_overwrite_is_not_effective(self):
        result = analyze_st(appended('output := 0;'))
        self.assertFalse(result['control_calls'][0]['effective'])
        self.assertEqual('overwritten', result['control_calls'][0]['adoption'])
        self.assertIn('controller_output_overwritten', {i['code'] for i in result['issues']})

    def test_zero_times_previous_output_removes_adoption(self):
        call = analyze_st(appended('output := 0 * output;'))['control_calls'][0]
        self.assertFalse(call['effective'])

    def test_final_boolean_override_and_branch_polarity(self):
        result = analyze_st(appended('IF NOT enabled THEN output := 65535; END_IF;'))
        self.assertEqual('conditional', result['control_calls'][0]['adoption'])
        gate = result['output_gates'][0]
        self.assertEqual({'symbol': 'enabled', 'operator': 'not'}, gate['condition'])
        self.assertTrue(gate['final_override'])
        self.assertEqual({'output': 'output', 'value': 65535, 'branch': 'then', 'final_override': True},
                         {k: v for k, v in gate['overrides'][0].items() if k != 'line'})

    def test_later_assignment_supersedes_a_boolean_override(self):
        result = analyze_st(appended('IF NOT enabled THEN output := 65535; END_IF;\noutput := 123;'))
        self.assertFalse(result['control_calls'][0]['effective'])
        self.assertFalse(result['output_gates'][0]['final_override'])

    def test_configured_program_instance_is_not_parsed_as_definition(self):
        text = SOURCE + '''
CONFIGURATION config
 RESOURCE hardware ON PLC
  TASK cycle(INTERVAL := T#20ms, PRIORITY := 0);
  PROGRAM instance WITH cycle : trial;
 END_RESOURCE
END_CONFIGURATION
'''
        result = analyze_st(text)
        self.assertEqual(['trial'], result['configured_programs'])
        self.assertEqual([], result['issues'])
        self.assertEqual(1, len(result['control_calls']))
        self.assertEqual('configured', result['control_calls'][0]['program_binding'])

    def test_unconfigured_definition_is_not_a_running_program_fact(self):
        result = analyze_st(SOURCE)
        self.assertEqual('unbound_program_definitions_only', result['execution_scope'])
        self.assertEqual('unbound_definition', result['control_calls'][0]['program_binding'])

    def test_only_configured_program_is_selected(self):
        text = SOURCE + SOURCE[SOURCE.index('PROGRAM trial'):].replace('PROGRAM trial', 'PROGRAM unused')
        text += '\nCONFIGURATION c RESOURCE r ON PLC PROGRAM i WITH t : trial; END_RESOURCE END_CONFIGURATION'
        result = analyze_st(text)
        self.assertEqual(['trial'], result['configured_programs'])
        self.assertEqual(['trial'], [c['program'] for c in result['control_calls']])

    def test_program_initializer_is_not_current_boolean_state(self):
        source = SOURCE.replace('enabled AT %QX2.3', 'enabled')
        result = analyze_st(appended('IF NOT enabled THEN output := 65535; END_IF;', source))
        self.assertEqual('conditional', result['control_calls'][0]['adoption'])
        self.assertEqual('enabled', result['output_gates'][0]['condition']['symbol'])

    def test_malformed_source_returns_an_explicit_issue(self):
        for source in ('FUNCTION END_FUNCTION', 'PROGRAM', None):
            with self.subTest(source=source):
                result = analyze_st(source)
                self.assertEqual([], result['control_calls'])
                self.assertTrue(result['issues'])

    def test_names_alone_do_not_establish_a_controller(self):
        text = '''PROGRAM fake
VAR
 level AT %IW7 : UINT;
 level_sp AT %MW9 : UINT;
 valve AT %QW6 : UINT;
 run_bit AT %QX2.3 : BOOL;
END_VAR
valve := level_sp;
END_PROGRAM'''
        self.assertEqual([], analyze_st(text)['control_calls'])

    def test_unsupported_syntax_is_reported_without_guessing(self):
        result = analyze_st(appended('CASE target OF 1: output := 3; END_CASE;'))
        self.assertEqual([], result['control_calls'])
        self.assertIn('unsupported_statement', {i['code'] for i in result['issues']})

    def test_comments_do_not_supply_fake_calls_or_change_line_numbers(self):
        text = '(* false PROGRAM fake (* nested *) END_PROGRAM *)\n' + SOURCE
        result = analyze_st(text)
        baseline = analyze_st(SOURCE)
        self.assertEqual(1, len(result['control_calls']))
        self.assertEqual(baseline['control_calls'][0]['line'] + 1, result['control_calls'][0]['line'])

    def test_ambiguous_located_alias_is_rejected(self):
        result = analyze_st(SOURCE.replace('position AT %IW8', 'position AT %IW7'))
        self.assertEqual([], result['control_calls'])
        self.assertIn('duplicate_located_address', {i['code'] for i in result['issues']})

    def test_source_is_not_mutated(self):
        original = deepcopy(SOURCE)
        analyze_st(SOURCE)
        self.assertEqual(original, SOURCE)
