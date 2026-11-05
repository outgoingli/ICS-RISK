"""Source-backed I/O extraction for the inspected OpenPLC/Python bridge dialect.

This is a bounded static adapter, not a C++ compiler or a general plant ontology.
It never executes source, reads a device, invents a physical unit, or accepts a
pre-labelled graph. Unsupported source shapes are reported and omitted.
"""
from __future__ import annotations

import ast
import copy
from fractions import Fraction
import re


def _span(key, source, start, end=None):
    return {'source': key, 'line_start': source.count('\n', 0, start) + 1,
            'line_end': source.count('\n', 0, end if end is not None else start) + 1}


def _node_span(key, node):
    return {'source': key, 'line_start': node.lineno,
            'line_end': getattr(node, 'end_lineno', node.lineno)}


def _c_code(source):
    return re.sub(r'/\*.*?\*/|//[^\n]*',
                  lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]),
                  source, flags=re.S)


def _function(source, name):
    match = re.search(r'\b' + re.escape(name) + r'\s*\([^;{}]*\)\s*\{', source)
    if not match:
        return None
    depth = 1
    at = match.end()
    while at < len(source) and depth:
        depth += (source[at] == '{') - (source[at] == '}')
        at += 1
    return (source[match.end():at-1], match.start(), at) if depth == 0 else None


def _address_model(source, issues):
    key = 'modbus_driver'
    code = _c_code(source)
    defines = {}
    for m in re.finditer(r'^\s*#define\s+(\w+)\s+(\d+)\s*$', code, re.M):
        defines[m[1]] = (int(m[2]), _span(key, source, m.start(), m.end()))
    model = {'status': 'unsupported', 'locations': {}, 'evidence': []}
    specs = [
        ('MW', 'ReadHoldingRegisters', 'MB_FC_READ_HOLDING_REGISTERS',
         r'lowByte\s*\(\s*\*int_memory\s*\[\s*position\s*-\s*(\w+)\s*\]\s*\)'),
        ('IW', 'ReadInputRegisters', 'MB_FC_READ_INPUT_REGISTERS',
         r'lowByte\s*\(\s*\*int_input\s*\[\s*position\s*\]\s*\)'),
        ('QW', 'ReadHoldingRegisters', 'MB_FC_READ_HOLDING_REGISTERS',
         r'lowByte\s*\(\s*\*int_output\s*\[\s*position\s*\]\s*\)'),
        ('QX', 'ReadCoils', 'MB_FC_READ_COILS',
         r'\*bool_output\s*\[\s*position\s*/\s*(\d+)\s*\]\s*\[\s*position\s*%\s*(\d+)\s*\]'),
    ]
    for kind, function_name, fc_name, pattern in specs:
        found = _function(code, function_name)
        if not found or fc_name not in defines:
            issues.append({'code': 'unsupported_driver_mapping', 'location_kind': kind})
            continue
        body, start, end = found
        match = re.search(pattern, body)
        if not match or not re.search(r'position\s*=\s*Start\s*\+\s*i', body):
            issues.append({'code': 'unsupported_driver_mapping', 'location_kind': kind})
            continue
        entry = {'fc': defines[fc_name][0], 'address_base': 0,
                 'register_kind': 'coil' if kind == 'QX' else ('input' if kind == 'IW' else 'holding'),
                 'evidence': [_span(key, source, start, end), defines[fc_name][1]]}
        if kind == 'MW':
            base_name = match[1]
            write = _function(code, 'writeToRegisterWithoutLocking')
            end_match = re.search(r'position\s*>=\s*' + re.escape(base_name) + r'\s*&&\s*position\s*<=\s*(\w+)', body)
            if (base_name not in defines or not write or not re.search(
                    r'\*int_memory\s*\[\s*position\s*-\s*' + re.escape(base_name) + r'\s*\]\s*=\s*value', write[0])
                    or not end_match or end_match[1] not in defines):
                issues.append({'code': 'memory_read_write_mapping_not_confirmed'})
                continue
            entry['address_base'] = defines[base_name][0]
            entry['address_end'] = defines[end_match[1]][0]
            entry['evidence'] += [defines[base_name][1], _span(key, source, write[1], write[2])]
        if kind == 'QX':
            if match[1] != match[2]:
                issues.append({'code': 'coil_index_width_mismatch'})
                continue
            entry['word_width'] = int(match[1])
        if kind != 'MW':
            bounds = re.search(r'if\s*\(\s*position\s*<\s*(\w+)\s*\)', body)
            if not bounds or bounds[1] not in defines:
                issues.append({'code': 'driver_address_bound_unresolved', 'location_kind': kind})
                continue
            entry['address_end'] = defines[bounds[1]][0] - 1
        model['locations'][kind] = entry
        model['evidence'].extend(entry['evidence'])
    if model['locations']:
        model['status'] = 'supported_subset'
    return model


def resolve_plc_address(location, model):
    """Resolve an IEC located variable using extracted driver facts only."""
    match = re.fullmatch(r'%?(MW|IW|QW|QX)(\d+)(?:\.(\d+))?', str(location))
    if not match or match[1] not in model.get('locations', {}):
        return None
    kind, index, bit = match[1], int(match[2]), match[3]
    rule = model['locations'][kind]
    if kind == 'QX':
        if bit is None or not 0 <= int(bit) < rule['word_width']:
            return None
        address = index * rule['word_width'] + int(bit)
    else:
        if bit is not None:
            return None
        address = rule['address_base'] + index
    if not 0 <= address <= min(65535, rule['address_end']):
        return None
    return {'fc': rule['fc'], 'address': address, 'register_kind': rule['register_kind'],
            'evidence': copy.deepcopy(rule['evidence'])}


def _master_layout(source, issues):
    code = _c_code(source)
    required = [
        r'int_input_index\s*=\s*0\s*;',
        r'for\s*\(\s*int\s+i\s*=\s*0\s*;\s*i\s*<\s*num_devices\s*;\s*i\+\+\s*\)',
        r'modbus_read_input_registers\s*\([^;]+input_registers.start_address\s*,\s*mb_devices\[i\].input_registers.num_regs\s*,\s*tempBuff\s*\)',
        r'int_input_buf\s*\[\s*int_input_index\s*\]\s*=\s*tempBuff\s*\[j\]\s*;\s*int_input_index\+\+\s*;',
        r'int_input_index\s*\+=\s*\(mb_devices\[i\].input_registers.num_regs\)\s*;',
        r'int_input_index\s*\+=\s*\(mb_devices\[i\].holding_read_registers.num_regs\)\s*;',
    ]
    matches = [re.search(pattern, code, re.S) for pattern in required]
    base = re.search(r'\*int_input\s*\[\s*(\d+)\s*\+\s*i\s*\]\s*=\s*int_input_buf\s*\[i\]\s*;', code)
    ordered = code.find('modbus_read_input_registers(') < code.find('modbus_read_registers(')
    if not all(matches) or not base or not ordered:
        issues.append({'code': 'unsupported_remote_io_driver_layout'})
        return None
    return {'input_base': int(base[1]),
            'evidence': [_span('modbus_master', source, m.start(), m.end()) for m in matches + [base]],
            'assumption': 'Normal successful polling preserves configured input-register then holding-read counts.'}


def _devices(source, issues):
    entries, seen = {}, set()
    for m in re.finditer(r'^\s*(device(\d+)\.(\w+)|Num_Devices)\s*=\s*"([^"\n]+)"\s*$', source, re.M):
        if m[1] in seen:
            issues.append({'code': 'duplicate_remote_io_setting', 'key': m[1]})
            return []
        seen.add(m[1])
        if m[2] is not None:
            entries.setdefault(int(m[2]), {'evidence': []})[m[3]] = m[4]
            entries[int(m[2])]['evidence'].append(_span('remote_io_config', source, m.start(), m.end()))
        else:
            total = int(m[4]) if m[4].isdigit() else -1
    if 'Num_Devices' not in seen or set(entries) != set(range(total)):
        issues.append({'code': 'incomplete_remote_io_device_inventory'})
        return []
    offset, result = 0, []
    for index in range(total):
        item = entries[index]
        try:
            size = int(item['Input_Registers_Size'])
            holding = int(item['Holding_Registers_Read_Size'])
            start = int(item['Input_Registers_Start'])
            if min(size, holding, start) < 0 or item['protocol'] != 'TCP' or not item['address']:
                raise ValueError()
        except (KeyError, ValueError):
            issues.append({'code': 'unsupported_remote_io_device', 'device_index': index})
            return []
        result.append(dict(item, device_index=index, input_offset=offset,
                           input_start=start, input_size=size))
        offset += size + holding
    return result


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _common_facts(source):
    tree = ast.parse(source)
    readers, clamps = set(), {}
    for fun in tree.body:
        if not isinstance(fun, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        json_variables = set()
        for node in ast.walk(fun):
            if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Attribute)
                    and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == 'json'
                    and node.value.func.attr == 'loads'):
                json_variables.update(t.id for t in node.targets if isinstance(t, ast.Name))
        if any(isinstance(n, ast.Return) and isinstance(n.value, ast.Name)
               and n.value.id in json_variables for n in ast.walk(fun)):
            readers.add(fun.name)
        if len(fun.body) == 1 and isinstance(fun.body[0], ast.Return) and len(fun.args.args) == 1:
            expr = fun.body[0].value
            if (isinstance(expr, ast.Call) and _call_name(expr.func) == 'max' and len(expr.args) == 2
                    and isinstance(expr.args[0], ast.Constant) and isinstance(expr.args[1], ast.Call)):
                inner = expr.args[1]
                if (_call_name(inner.func) == 'min' and len(inner.args) == 2
                        and isinstance(inner.args[0], ast.Constant) and isinstance(inner.args[1], ast.Name)
                        and inner.args[1].id == fun.args.args[0].arg):
                    low, high = expr.args[0].value, inner.args[0].value
                    if type(low) is int and type(high) is int and low <= high:
                        clamps[fun.name] = (low, high)
    return readers, clamps


def _value(node, env, readers, clamps):
    if isinstance(node, ast.Await):
        return _value(node.value, env, readers, clamps)
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return Fraction(str(node.value))
    if isinstance(node, ast.Name):
        return copy.deepcopy(env.get(node.id))
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
        parent = _value(node.value, env, readers, clamps)
        if isinstance(parent, dict) and 'path' in parent:
            parent['path'].append(node.slice.value)
            return parent
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        if name in readers:
            return {'path': [], 'scale': Fraction(1), 'offset': Fraction(0), 'integer_conversion': None}
        if len(node.args) == 1 and (name == 'int' or name in clamps):
            value = _value(node.args[0], env, readers, clamps)
            if isinstance(value, dict) and value.get('path'):
                if name == 'int':
                    value['integer_conversion'] = 'truncate_toward_zero'
                else:
                    value['clamp'] = list(clamps[name])
                return value
    if isinstance(node, ast.BinOp):
        left, right = _value(node.left, env, readers, clamps), _value(node.right, env, readers, clamps)
        if isinstance(left, Fraction) and isinstance(right, Fraction):
            if isinstance(node.op, ast.Mult): return left * right
            if isinstance(node.op, ast.Div) and right: return left / right
            if isinstance(node.op, ast.Add): return left + right
            if isinstance(node.op, ast.Sub): return left - right
        if isinstance(left, Fraction) and isinstance(node.op, ast.Mult):
            left, right = right, left
        if isinstance(left, dict) and isinstance(right, Fraction) and not left.get('integer_conversion'):
            if isinstance(node.op, ast.Mult):
                left['scale'] *= right; left['offset'] *= right
            elif isinstance(node.op, ast.Div) and right:
                left['scale'] /= right; left['offset'] /= right
            elif isinstance(node.op, ast.Add): left['offset'] += right
            elif isinstance(node.op, ast.Sub): left['offset'] -= right
            else: return None
            return left
    return None


def _context_symmetric(source):
    """Verify the captured library's read/write address adjustment is identical."""
    if not source:
        return False
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ModbusSlaveContext']
    if len(classes) != 1:
        return False
    methods = {n.name: n for n in classes[0].body if isinstance(n, ast.FunctionDef)}
    found = []
    for name in ('getValues', 'setValues'):
        method = methods.get(name)
        if not method:
            return False
        adjustments = []
        def walk(statements, guards):
            for node in statements:
                if isinstance(node, ast.If):
                    walk(node.body, guards + [('if', ast.dump(node.test, include_attributes=False))])
                    walk(node.orelse, guards + [('else', ast.dump(node.test, include_attributes=False))])
                elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == 'address':
                    adjustments.append((guards, ast.dump(node, include_attributes=False)))
                elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'address' for t in node.targets):
                    adjustments.append(('unsupported_assignment',))
        walk(method.body, [])
        calls = [n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr == name]
        if (not adjustments or ('unsupported_assignment',) in adjustments or len(calls) != 1
                or not calls[0].args or not isinstance(calls[0].args[0], ast.Name)
                or calls[0].args[0].id != 'address'):
            return False
        found.append((adjustments, ast.dump(calls[0].func.value, include_attributes=False)))
    return found[0] == found[1]


def _bridge(source, key, readers, clamps, issues):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        issues.append({'code': 'invalid_bridge_python', 'source': key})
        return []
    handlers = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _call_name(n.func) == 'run_device' and len(n.args) >= 3:
            if isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str) and isinstance(n.args[2], ast.Name):
                handlers[n.args[2].id] = (n.args[1].value, _node_span(key, n))
    result = []
    def walk(statements, env, host, handler_span):
        for node in statements:
            if isinstance(node, ast.Assign):
                value = _value(node.value, env, readers, clamps)
                if isinstance(value, dict):
                    value.setdefault('evidence', []).append(_node_span(key, node))
                for target in node.targets:
                    if isinstance(target, ast.Name): env[target.id] = copy.deepcopy(value)
            elif isinstance(node, ast.While) and isinstance(node.test, ast.Constant) and node.test.value is True:
                walk(node.body, env, host, handler_span)
            elif isinstance(node, ast.Try):
                walk(node.body, env, host, handler_span)
            elif isinstance(node, ast.If):
                issues.append({'code': 'conditional_bridge_mapping_unsupported', 'source': key, 'line': node.lineno})
                # Do not select one branch as the physical mapping.
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name): env[target.id] = None
            elif isinstance(node, ast.Expr):
                call = node.value
                if isinstance(call, ast.Call) and _call_name(call.func) == 'setValues' and len(call.args) == 3:
                    fc, address = _value(call.args[0], env, readers, clamps), _value(call.args[1], env, readers, clamps)
                    values = call.args[2]
                    if fc != 4 or not isinstance(address, Fraction) or address.denominator != 1 or not isinstance(values, (ast.List, ast.Tuple)):
                        issues.append({'code': 'unsupported_bridge_register_write', 'source': key, 'line': node.lineno})
                        continue
                    for index, expr in enumerate(values.elts):
                        value = _value(expr, env, readers, clamps)
                        if not isinstance(value, dict) or not value.get('path') or value.get('integer_conversion') != 'truncate_toward_zero':
                            issues.append({'code': 'unresolved_bridge_value', 'source': key, 'line': node.lineno, 'index': index})
                            continue
                        result.append(dict(value, device_address=host, bridge_address=int(address)+index,
                                           evidence=value.get('evidence', []) + [_node_span(key, node), handler_span]))
    for fun in tree.body:
        if isinstance(fun, (ast.FunctionDef, ast.AsyncFunctionDef)) and fun.name in handlers:
            host, handler_span = handlers[fun.name]
            walk(fun.body, {}, host, handler_span)
    return result


def analyze_io(sources):
    """Extract configured I/O chains, preserving evidence and unresolved facts.

    Required keys: modbus_driver, modbus_master, remote_io_config, glue,
    bridge_common, plus one or more keys ending '_bridge'. Optional captured
    bridge_context supplies the actual ModbusSlaveContext implementation.
    Returned numerical addresses and encoding data are graph-external facts.
    """
    issues = []
    model = _address_model(sources.get('modbus_driver', ''), issues)
    layout = _master_layout(sources.get('modbus_master', ''), issues)
    devices = _devices(sources.get('remote_io_config', ''), issues)
    try:
        readers, clamps = _common_facts(sources.get('bridge_common', ''))
    except SyntaxError:
        readers, clamps = set(), {}
    if not readers:
        issues.append({'code': 'json_reader_source_unresolved'})
    support_evidence = []
    for key in ('bridge_common', 'bridge_context'):
        try:
            for node in ast.walk(ast.parse(sources.get(key, ''))):
                if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and node.name in (readers | set(clamps) | {'getValues', 'setValues'})):
                    support_evidence.append(_node_span(key, node))
        except SyntaxError:
            pass
    context_verified = _context_symmetric(sources.get('bridge_context', ''))
    if not context_verified:
        issues.append({'code': 'bridge_context_address_symmetry_unverified'})
    glue_text = sources.get('glue', '')
    glue, assignments, dynamic_glue = {}, {}, False
    for m in re.finditer(r'int_input\s*\[\s*([^\]]+)\s*\]\s*=(?!=)\s*([^;]+);', _c_code(glue_text)):
        index = m[1].strip()
        if not index.isdigit():
            dynamic_glue = True
            continue
        assignments.setdefault(int(index), []).append(m)
    if dynamic_glue:
        issues.append({'code': 'dynamic_compiled_input_binding_unsupported'})
    else:
        for index, matches in assignments.items():
            m = matches[0]
            target = re.fullmatch(r'\(IEC_UINT\s*\*\)\s*__IW(\d+)\s*', m[2])
            if len(matches) == 1 and target and int(target[1]) == index:
                glue[index] = _span('glue', glue_text, m.start(), m.end())
            else:
                issues.append({'code': 'ambiguous_or_mismatched_compiled_input_binding', 'input_index': index})
    physical = []
    for key, source in sources.items():
        if not key.endswith('_bridge'):
            continue
        for signal in _bridge(source, key, readers, clamps, issues):
            matching = [d for d in devices if d['address'] == signal['device_address']
                        and d['input_start'] <= signal['bridge_address'] < d['input_start'] + d['input_size']]
            if not layout or len(matching) != 1:
                issues.append({'code': 'bridge_to_plc_mapping_unresolved', 'source': key,
                               'origin_json_path': signal['path']})
                continue
            device = matching[0]
            plc_index = layout['input_base'] + device['input_offset'] + signal['bridge_address'] - device['input_start']
            location = '%IW' + str(plc_index)
            protocol = resolve_plc_address(location, model)
            if plc_index not in glue or protocol is None:
                issues.append({'code': 'compiled_input_binding_unresolved', 'plc_location': location})
                continue
            multiplier, offset = signal['scale'], signal['offset']
            evidence = signal['evidence'] + support_evidence + device['evidence'] + layout['evidence'] + [glue[plc_index]] + protocol['evidence']
            physical.append({'plc_location': location, 'protocol': protocol,
                'origin_json_path': signal['path'], 'source_field': '.'.join(signal['path']),
                'source_unit': 'unverified', 'device_address': signal['device_address'],
                'remote_address': signal['bridge_address'],
                'status': 'static_configured_mapping' if context_verified else 'static_candidate_library_unverified',
                'encoding': {'multiplier_numerator': multiplier.numerator,
                             'multiplier_denominator': multiplier.denominator,
                             'additive_numerator': offset.numerator, 'additive_denominator': offset.denominator,
                             'integer_conversion': signal['integer_conversion'], 'clamp': signal.get('clamp')},
                'evidence': evidence,
                'limitations': ['Static configured chain; successful poll and actual process origin require runtime observations.',
                                'No physical unit or safety limit inferred from a source-field name.']})
    by_location = {}
    for item in physical:
        by_location.setdefault(item['plc_location'], []).append(item)
    for location, candidates in by_location.items():
        if len(candidates) > 1:
            issues.append({'code': 'ambiguous_physical_producer', 'plc_location': location})
    physical = [items[0] for items in by_location.values() if len(items) == 1]
    return {'extractor': 'openplc_bridge_static_v1', 'address_model': model,
            'physical_signals': physical, 'issues': issues}
