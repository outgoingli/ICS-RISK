"""Independent synthetic source fragments; no historical plant code or values."""
import copy
import unittest

from ics_risk.semantic.io_mapping import analyze_io, resolve_plc_address


DRIVER = '''
#define MB_FC_READ_COILS 1
#define MB_FC_READ_HOLDING_REGISTERS 3
#define MB_FC_READ_INPUT_REGISTERS 4
#define MEMORY_BASE 4096
#define MEMORY_END 8191
#define INPUT_BOUND 1024
#define COIL_BOUND 512
void ReadHoldingRegisters(unsigned char *buffer, int size) {
 int position = Start + i;
 if (position < MEMORY_BASE) { b = lowByte(*int_output[position]); }
 else if (position >= MEMORY_BASE && position <= MEMORY_END) {
 b = lowByte(*int_memory[position - MEMORY_BASE]); }
}
void ReadInputRegisters(unsigned char *buffer, int size) {
 int position = Start + i;
 if (position < INPUT_BOUND) { b = lowByte(*int_input[position]); }
}
void ReadCoils(unsigned char *buffer, int size) {
 int position = Start + i * 8 + j;
 if (position < COIL_BOUND) { bitWrite(b, j, *bool_output[position/8][position%8]); }
}
int writeToRegisterWithoutLocking(int position, uint16_t value) {
 if(position >= MEMORY_BASE && position <= MEMORY_END) {
 *int_memory[position - MEMORY_BASE] = value; }
}
'''

MASTER = '''
void poll() {
 int int_input_index = 0;
 for (int i = 0; i < num_devices; i++) {
 modbus_read_input_registers(mb_devices[i].mb_ctx, mb_devices[i].input_registers.start_address,
 mb_devices[i].input_registers.num_regs, tempBuff);
 int_input_buf[int_input_index] = tempBuff[j]; int_input_index++;
 int_input_index += (mb_devices[i].input_registers.num_regs);
 modbus_read_registers(mb_devices[i].mb_ctx, mb_devices[i].holding_read_registers.start_address,
 mb_devices[i].holding_read_registers.num_regs, tempBuff);
 int_input_index += (mb_devices[i].holding_read_registers.num_regs);
 }
}
void update() { *int_input[20+i] = int_input_buf[i]; }
'''

CONFIG = '''
Num_Devices = "2"
device0.address = "unit-a.example.invalid"
device0.protocol = "TCP"
device0.Input_Registers_Start = "2"
device0.Input_Registers_Size = "2"
device0.Holding_Registers_Read_Size = "3"
device1.address = "unit-b.example.invalid"
device1.protocol = "TCP"
device1.Input_Registers_Start = "7"
device1.Input_Registers_Size = "2"
device1.Holding_Registers_Read_Size = "0"
'''

GLUE = '''
int_input[25] = (IEC_UINT *)__IW25;
int_input[26] = (IEC_UINT *)__IW26;
'''

COMMON = '''
import json
async def read_stream(reader, writer, interval):
    packet = json.loads(line.decode())
    return packet
def bounded(value):
    return max(0, min(65535, value))
'''

BRIDGE = '''
async def handle(context, reader, writer, interval):
    while True:
        packet = await io.read_stream(reader, writer, interval)
        try:
            alpha = int(packet["outputs"]["temperature"] / 200 * 65535)
            beta = int(packet["outputs"]["inventory"] / 80 * 65535)
            alpha = io.bounded(alpha)
            beta = io.bounded(beta)
            context[1].setValues(4, 7, [alpha, beta])
        except Exception:
            pass
io.run_device("Synthetic unit", "unit-b.example.invalid", handle)
'''

CONTEXT = '''
class ModbusSlaveContext:
    def getValues(self, fc, address, count):
        if not self.zero_mode:
            address += 1
        return self.store[self.decode(fc)].getValues(address, count)
    def setValues(self, fc, address, values):
        if not self.zero_mode:
            address += 1
        self.store[self.decode(fc)].setValues(address, values)
'''


def sources():
    return dict(modbus_driver=DRIVER, modbus_master=MASTER, remote_io_config=CONFIG,
                glue=GLUE, bridge_common=COMMON, tank_bridge=BRIDGE, bridge_context=CONTEXT)


class IoMappingTests(unittest.TestCase):
    def test_physical_chain_computes_offsets_and_preserves_source_field(self):
        result = analyze_io(sources())
        self.assertEqual([], result['issues'])
        signals = result['physical_signals']
        self.assertEqual(['%IW25', '%IW26'], [s['plc_location'] for s in signals])
        self.assertEqual(['outputs', 'inventory'], signals[1]['origin_json_path'])
        self.assertEqual('static_configured_mapping', signals[1]['status'])
        self.assertEqual('unverified', signals[1]['source_unit'])
        self.assertEqual(13107, signals[1]['encoding']['multiplier_numerator'])
        self.assertEqual(16, signals[1]['encoding']['multiplier_denominator'])
        self.assertGreater(len(signals[1]['evidence']), 8)

    def test_protocol_mapping_is_read_from_driver(self):
        model = analyze_io(sources())['address_model']
        self.assertEqual(4103, resolve_plc_address('%MW7', model)['address'])
        self.assertEqual(4, resolve_plc_address('%IW26', model)['fc'])
        self.assertEqual(26, resolve_plc_address('%IW26', model)['address'])
        self.assertEqual(19, resolve_plc_address('%QX2.3', model)['address'])
        self.assertEqual(31, resolve_plc_address('%QW31', model)['address'])
        self.assertIsNone(resolve_plc_address('%QX2.8', model))
        self.assertIsNone(resolve_plc_address('%IW1024', model))
        self.assertIsNone(resolve_plc_address('%QW4096', model))
        self.assertIsNone(resolve_plc_address('%MW4096', model))

    def test_changed_memory_base_changes_mapping(self):
        data = sources(); data['modbus_driver'] = DRIVER.replace('MEMORY_BASE 4096', 'MEMORY_BASE 2048')
        self.assertEqual(2055, resolve_plc_address('%MW7', analyze_io(data)['address_model'])['address'])

    def test_changed_remote_input_base_requires_new_glue(self):
        data = sources(); data['modbus_master'] = MASTER.replace('[20+i]', '[30+i]')
        self.assertEqual([], analyze_io(data)['physical_signals'])
        data['glue'] = GLUE.replace('25', '35').replace('26', '36')
        self.assertEqual(['%IW35', '%IW36'], [s['plc_location'] for s in analyze_io(data)['physical_signals']])

    def test_holding_read_sizes_contribute_to_next_device_offset(self):
        data = sources(); data['remote_io_config'] = CONFIG.replace('Read_Size = "3"', 'Read_Size = "0"')
        data['glue'] = GLUE.replace('25', '22').replace('26', '23')
        self.assertEqual(['%IW22', '%IW23'], [s['plc_location'] for s in analyze_io(data)['physical_signals']])

    def test_bridge_order_changes_mapping_not_name_guess(self):
        data = sources(); data['tank_bridge'] = BRIDGE.replace('[alpha, beta]', '[beta, alpha]')
        self.assertEqual(['outputs', 'inventory'], analyze_io(data)['physical_signals'][0]['origin_json_path'])

    def test_bridge_variable_renaming_preserves_meaning(self):
        data = sources()
        for old, new in [('packet', 'q'), ('alpha', 'level_sp'), ('beta', 'pressure'), ('handle', 'x')]:
            data['tank_bridge'] = data['tank_bridge'].replace(old, new)
        result = analyze_io(data)
        self.assertEqual(['outputs', 'inventory'], result['physical_signals'][1]['origin_json_path'])
        self.assertEqual('%IW26', result['physical_signals'][1]['plc_location'])

    def test_missing_driver_cannot_use_conventional_memory_offset(self):
        data = sources(); data['modbus_driver'] = ''
        result = analyze_io(data)
        self.assertIsNone(resolve_plc_address('%MW4', result['address_model']))
        self.assertEqual([], result['physical_signals'])

    def test_missing_polling_evidence_omits_physical_mapping(self):
        data = sources(); data['modbus_master'] = ''
        self.assertEqual([], analyze_io(data)['physical_signals'])

    def test_missing_common_reader_does_not_trust_arbitrary_json_subscript(self):
        data = sources(); data['bridge_common'] = ''
        self.assertEqual([], analyze_io(data)['physical_signals'])

    def test_unverified_library_is_explicit_candidate(self):
        data = sources(); data.pop('bridge_context')
        result = analyze_io(data)
        self.assertEqual('static_candidate_library_unverified', result['physical_signals'][0]['status'])
        self.assertIn('bridge_context_address_symmetry_unverified', [i['code'] for i in result['issues']])

    def test_asymmetric_library_is_not_silently_assumed(self):
        data = sources(); data['bridge_context'] = CONTEXT.replace('address += 1', 'address += 2', 1)
        self.assertEqual('static_candidate_library_unverified', analyze_io(data)['physical_signals'][0]['status'])

    def test_library_different_condition_or_call_address_is_unverified(self):
        for changed in [CONTEXT.replace('not self.zero_mode', 'self.zero_mode', 1),
                        CONTEXT.replace('getValues(address, count)', 'getValues(address + 1, count)')]:
            data = sources(); data['bridge_context'] = changed
            self.assertEqual('static_candidate_library_unverified', analyze_io(data)['physical_signals'][0]['status'])

    def test_later_glue_overwrite_does_not_keep_first_mapping(self):
        for suffix in ['int_input[26] = nullptr;',
                       'int_input[26] = (IEC_UINT *)__IW25;',
                       'int_input[26] = (IEC_UINT *)__IW26;']:
            data = sources(); data['glue'] += suffix
            self.assertEqual(['%IW25'], [s['plc_location'] for s in analyze_io(data)['physical_signals']])

    def test_glue_symbol_mismatch_or_dynamic_assignment_is_unknown(self):
        data = sources(); data['glue'] = GLUE.replace('__IW26', '__IW27')
        self.assertEqual(['%IW25'], [s['plc_location'] for s in analyze_io(data)['physical_signals']])
        data['glue'] = GLUE + 'int_input[i] = 0;'
        self.assertEqual([], analyze_io(data)['physical_signals'])

    def test_ambiguous_producers_are_not_silently_selected(self):
        data = sources(); data['other_bridge'] = BRIDGE.replace('inventory', 'other_value')
        result = analyze_io(data)
        self.assertEqual([], result['physical_signals'])
        self.assertIn('ambiguous_physical_producer', [i['code'] for i in result['issues']])

    def test_duplicate_config_key_rejected(self):
        data = sources(); data['remote_io_config'] += '\ndevice0.Input_Registers_Size = "9"\n'
        self.assertEqual([], analyze_io(data)['physical_signals'])

    def test_unknown_transform_omitted(self):
        data = sources(); data['tank_bridge'] = BRIDGE.replace('beta = io.bounded(beta)', 'beta = io.secret_transform(beta)')
        result = analyze_io(data)
        self.assertEqual(1, len(result['physical_signals']))
        self.assertIn('unresolved_bridge_value', [i['code'] for i in result['issues']])

    def test_misleading_driver_comment_is_not_code(self):
        data = sources(); data['modbus_driver'] = '/* ' + DRIVER + ' */'
        self.assertIsNone(resolve_plc_address('%MW4', analyze_io(data)['address_model']))

    def test_source_inputs_unchanged(self):
        data = sources(); before = copy.deepcopy(data)
        analyze_io(data)
        self.assertEqual(before, data)


if __name__ == '__main__':
    unittest.main()
