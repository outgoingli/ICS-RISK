"""Self-written synthetic C++ snippets; never evidence of the real deployment."""
import unittest

from ics_risk.semantic.compiled_bindings import verify_compiled_binding


GLUE = '''
#define BUFFER_SIZE 32
IEC_UINT *int_memory[BUFFER_SIZE];
IEC_UINT *int_input[BUFFER_SIZE];
IEC_UINT *int_output[BUFFER_SIZE];
IEC_BOOL *bool_output[BUFFER_SIZE][8];
void glueVars()
{
 int_memory[7] = (IEC_UINT *)__MW7;
 int_input[9] = (IEC_UINT *)__IW9;
 int_output[3] = (IEC_UINT *)__QW3;
 bool_output[2][4] = (IEC_BOOL *)__QX2_4;
}
'''


class CompiledBindingsTests(unittest.TestCase):
    def test_all_four_supported_locations(self):
        for location, line in (('%MW7', 9), ('%IW9', 10), ('%QW3', 11), ('%QX2.4', 12)):
            with self.subTest(location=location):
                result = verify_compiled_binding(location, GLUE)
                self.assertTrue(result['supported'])
                self.assertEqual([{'source': 'glue', 'line_start': line, 'line_end': line}], result['evidence'])

    def test_mismatched_generated_symbol_rejected(self):
        result = verify_compiled_binding('%MW7', GLUE.replace('__MW7', '__MW8'))
        self.assertFalse(result['supported'])
        self.assertEqual('compiled_index_symbol_or_cast_mismatch', result['reason'])

    def test_symbol_at_wrong_index_rejected(self):
        result = verify_compiled_binding('%MW7', GLUE.replace('int_memory[7]', 'int_memory[8]'))
        self.assertFalse(result['supported'])
        self.assertEqual('located_symbol_bound_to_different_index', result['reason'])

    def test_duplicate_even_if_identical_is_rejected(self):
        source = GLUE.replace(' int_memory[7]', ' int_memory[7] = (IEC_UINT *)__MW7;\n int_memory[7]')
        result = verify_compiled_binding('%MW7', source)
        self.assertEqual('duplicate_or_overwritten_compiled_binding', result['reason'])

    def test_dynamic_index_could_overwrite_target(self):
        source = GLUE.replace('\n}', '\n int_memory[i] = (IEC_UINT *)__MW7;\n}')
        self.assertEqual('computed_or_dynamic_binding_index', verify_compiled_binding('%MW7', source)['reason'])

    def test_computed_literal_index_is_explicitly_unsupported(self):
        self.assertFalse(verify_compiled_binding('%MW7', GLUE.replace('int_memory[7]', 'int_memory[3+4]'))['supported'])

    def test_comment_cannot_supply_a_binding(self):
        source = GLUE.replace('int_memory[7] = (IEC_UINT *)__MW7;', '/* int_memory[7] = (IEC_UINT *)__MW7; */')
        self.assertFalse(verify_compiled_binding('%MW7', source)['supported'])

    def test_comment_cannot_supply_a_fake_overwrite(self):
        source = GLUE.replace('\n}', '\n // int_memory[i] = evil;\n}')
        self.assertTrue(verify_compiled_binding('%MW7', source)['supported'])

    def test_macro_definition_is_not_an_executed_binding(self):
        source = '#define BIND int_memory[7] = (IEC_UINT *)__MW7;\nvoid glueVars() {}'
        self.assertFalse(verify_compiled_binding('%MW7', source)['supported'])

    def test_unexpanded_macro_call_is_unsupported(self):
        source = '#define BIND int_memory[7] = (IEC_UINT *)__MW7;\nvoid glueVars() {BIND;}'
        self.assertEqual('unsupported_glue_statement', verify_compiled_binding('%MW7', source)['reason'])

    def test_preprocessor_conditional_is_not_flattened(self):
        source = GLUE.replace(' int_memory[7] = (IEC_UINT *)__MW7;', '#if MODE\n int_memory[7] = (IEC_UINT *)__MW7;\n#endif')
        self.assertEqual('preprocessor_inside_glue_function_unsupported', verify_compiled_binding('%MW7', source)['reason'])

    def test_control_flow_is_unsupported(self):
        source = GLUE.replace(' int_memory[7] = (IEC_UINT *)__MW7;', ' if (mode) { int_memory[7] = (IEC_UINT *)__MW7; }')
        self.assertEqual('unsupported_glue_statement', verify_compiled_binding('%MW7', source)['reason'])

    def test_helper_call_could_mutate_bindings(self):
        self.assertFalse(verify_compiled_binding('%MW7', GLUE.replace('\n}', '\n resetBindings();\n}'))['supported'])

    def test_outside_function_overwrite_is_rejected(self):
        source = GLUE + 'void other() { int_memory[7] = (IEC_UINT *)__MW8; }'
        self.assertEqual('unclassified_array_reference_outside_glue_function', verify_compiled_binding('%MW7', source)['reason'])

    def test_pointer_arithmetic_alias_is_unsupported(self):
        source = GLUE.replace('int_memory[7] = (IEC_UINT *)__MW7;', '*(int_memory + 7) = (IEC_UINT *)__MW7;')
        self.assertFalse(verify_compiled_binding('%MW7', source)['supported'])

    def test_nested_write_in_another_binding_is_not_ignored(self):
        source = GLUE.replace('(IEC_UINT *)__QW3;', '(int_memory[7] = (IEC_UINT *)__MW8);')
        self.assertEqual('nonliteral_pointer_binding_unsupported', verify_compiled_binding('%MW7', source)['reason'])

    def test_unknown_array_could_be_an_alias(self):
        source = GLUE.replace('\n}', '\n alias[7] = (IEC_UINT *)__MW8;\n}')
        self.assertEqual('unknown_array_or_alias_in_glue_function', verify_compiled_binding('%MW7', source)['reason'])

    def test_boolean_index_and_symbol_must_both_match(self):
        self.assertFalse(verify_compiled_binding('%QX2.4', GLUE.replace('__QX2_4', '__QX2_5'))['supported'])
        self.assertFalse(verify_compiled_binding('%QX2.4', GLUE.replace('[2][4]', '[2][5]'))['supported'])

    def test_pointer_type_is_checked(self):
        source = GLUE.replace('(IEC_BOOL *)__QX2_4', '(IEC_UINT *)__QX2_4')
        self.assertFalse(verify_compiled_binding('%QX2.4', source)['supported'])

    def test_address_validation(self):
        for address in ('%QX2.8', '%QX2', '%MW2.3', '%MX2.3', 'MW7', None):
            with self.subTest(address=address):
                self.assertFalse(verify_compiled_binding(address, GLUE)['supported'])

    def test_literal_cannot_supply_fake_function_or_binding(self):
        source = 'char *s = "void glueVars() {int_memory[7] = (IEC_UINT *)__MW7;}";'
        self.assertFalse(verify_compiled_binding('%MW7', source)['supported'])

    def test_declared_symbol_does_not_establish_pointer_binding(self):
        source = 'IEC_UINT *__MW7; void glueVars() {}'
        self.assertFalse(verify_compiled_binding('%MW7', source)['supported'])
