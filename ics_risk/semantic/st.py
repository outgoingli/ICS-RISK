"""Bounded structural analysis of the scalar ST subset used by this lab.

This is not an IEC 61131-3 compiler. It recognizes a feedback controller only
after inlining its source: equally scaled operands, their difference times a
gain, addition to actuator feedback, LIMIT and inverse UINT encoding. Names do
not establish PV/SP roles; located input and memory declarations do. Physical
meaning (for example liquid level) must be joined from independent producer and
protocol evidence. Unsupported syntax is reported, never silently interpreted.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import re


@dataclass(frozen=True)
class _Token:
    value: str
    line: int


@dataclass(frozen=True)
class _Expr:
    kind: str
    value: object = None
    args: tuple = ()


class _Unsupported(ValueError):
    def __init__(self, code, line=0):
        super().__init__(code)
        self.code, self.line = code, line


def _tokens(source):
    # Preserve source line locations, including nested IEC comments.
    chars, index, depth = list(source), 0, 0
    while index < len(source):
        if source[index:index + 2] == '(*':
            depth += 1
            chars[index:index + 2] = [' ', ' ']
            index += 2
        elif depth and source[index:index + 2] == '*)':
            depth -= 1
            chars[index:index + 2] = [' ', ' ']
            index += 2
        elif depth:
            if chars[index] != '\n':
                chars[index] = ' '
            index += 1
        else:
            index += 1
    if depth:
        raise _Unsupported('unterminated_comment')
    clean = re.sub(r'//[^\n]*', lambda m: ' ' * len(m[0]), ''.join(chars))
    pattern = re.compile(r'\s+|%[IQM][XWDLB]\d+(?:\.\d+)?|'
                         r'(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?|'
                         r'[A-Za-z_]\w*|:=|<=|>=|<>|.', re.I)
    result, line = [], 1
    for match in pattern.finditer(clean):
        value = match[0]
        if not value.isspace():
            result.append(_Token(value.lower(), line))
        line += value.count('\n')
    return result


def _constant(value):
    return _Expr('const', Fraction(value))


def _operation(kind, *args):
    if kind == 'neg' and args[0].kind == 'const':
        return _constant(-args[0].value)
    if kind in {'add', 'sub', 'mul', 'div'}:
        a, b = args
        if a.kind == b.kind == 'const':
            if kind == 'add': return _constant(a.value + b.value)
            if kind == 'sub': return _constant(a.value - b.value)
            if kind == 'mul': return _constant(a.value * b.value)
            if b.value: return _constant(a.value / b.value)
        if kind == 'mul' and any(x.kind == 'const' and not x.value for x in args):
            return _constant(0)
        if kind in {'add', 'sub'} and b == _constant(0): return a
        if kind == 'add' and a == _constant(0): return b
        if kind in {'mul', 'div'} and b == _constant(1): return a
        if kind == 'mul' and a == _constant(1): return b
    return _Expr(kind, args=tuple(args))


class _Parser:
    precedence = {'or': 1, 'and': 2, '=': 3, '<>': 3, '<': 3, '>': 3,
                  '<=': 3, '>=': 3, '+': 4, '-': 4, '*': 5, '/': 5}
    operations = {'+': 'add', '-': 'sub', '*': 'mul', '/': 'div'}

    def __init__(self, tokens):
        self.tokens, self.index = tokens, 0

    def peek(self, offset=0):
        i = self.index + offset
        return self.tokens[i].value if i < len(self.tokens) else ''

    def take(self, expected=None):
        if self.index >= len(self.tokens):
            raise _Unsupported('unexpected_end_of_source')
        token = self.tokens[self.index]
        if expected is not None and token.value != expected:
            raise _Unsupported('expected_' + expected, token.line)
        self.index += 1
        return token

    def expression(self, minimum=0):
        token = self.take()
        value = token.value
        if value in {'-', '+', 'not'}:
            child = self.expression(6)
            left = child if value == '+' else _operation('neg' if value == '-' else 'not', child)
        elif value == '(':
            left = self.expression()
            self.take(')')
        elif re.fullmatch(r'(?:\d+\.\d*|\.\d+|\d+)(?:e[+-]?\d+)?', value):
            left = _constant(value)
        elif value in {'true', 'false'}:
            left = _Expr('bool', value == 'true')
        elif re.fullmatch(r'[a-z_]\w*', value):
            left = _Expr('var', value)
            if self.peek() == '(':
                self.take('(')
                arguments = []
                while self.peek() != ')':
                    name = None
                    if self.peek(1) == ':=':
                        name = self.take().value
                        self.take(':=')
                    arguments.append(_Expr('argument', name, (self.expression(),)))
                    if self.peek() != ',': break
                    self.take(',')
                self.take(')')
                left = _Expr('call', value, tuple(arguments))
        else:
            raise _Unsupported('unsupported_expression_token', token.line)
        while self.peek() in self.precedence and self.precedence[self.peek()] >= minimum:
            operator = self.take().value
            right = self.expression(self.precedence[operator] + 1)
            left = _operation(self.operations.get(operator, operator), left, right)
        return left

    def statements(self, stops=()):
        result = []
        while self.peek() and self.peek() not in stops:
            token = self.take()
            if token.value == ';':
                continue
            if token.value == 'if':
                condition = self.expression()
                self.take('then')
                yes = self.statements(('else', 'elsif', 'end_if'))
                if self.peek() == 'elsif':
                    raise _Unsupported('unsupported_elsif', self.tokens[self.index].line)
                no = []
                if self.peek() == 'else':
                    self.take('else')
                    no = self.statements(('end_if',))
                end = self.take('end_if')
                self.take(';')
                result.append({'kind': 'if', 'condition': condition, 'yes': yes, 'no': no,
                               'line': token.line, 'end_line': end.line})
            elif re.fullmatch(r'[a-z_]\w*', token.value) and self.peek() == ':=':
                self.take(':=')
                expression = self.expression()
                end = self.take(';')
                result.append({'kind': 'assign', 'target': token.value, 'expression': expression,
                               'line': token.line, 'end_line': end.line})
            else:
                raise _Unsupported('unsupported_statement', token.line)
        return result


def _unit(tokens, name, kind, return_type):
    parser = _Parser(tokens)
    declarations = []
    while parser.peek() in {'var', 'var_input', 'var_output'}:
        section = parser.take().value
        while parser.peek() != 'end_var':
            symbol = parser.take()
            if not re.fullmatch(r'[a-z_]\w*', symbol.value):
                raise _Unsupported('unsupported_declaration', symbol.line)
            address = None
            if parser.peek() == 'at':
                parser.take()
                address = parser.take().value.upper()
                if not re.fullmatch(r'%[IQM][XWDLB]\d+(?:\.\d+)?', address):
                    raise _Unsupported('unsupported_located_address', symbol.line)
            parser.take(':')
            dtype = parser.take().value.upper()
            initial = None
            if parser.peek() == ':=':
                parser.take()
                initial = parser.expression()
            parser.take(';')
            declarations.append({'symbol': symbol.value, 'address': address, 'data_type': dtype,
                                 'section': section, 'line': symbol.line, 'program': name,
                                 'initial': initial})
        parser.take('end_var')
    return {'name': name, 'kind': kind, 'return_type': return_type,
            'declarations': declarations, 'body': parser.statements()}


def _read_units(tokens):
    units, issues, scheduled, i = {}, [], [], 0
    while i < len(tokens):
        start = tokens[i]
        if start.value == 'configuration':
            end = next((j for j in range(i + 1, len(tokens)) if tokens[j].value == 'end_configuration'), None)
            if end is None:
                issues.append({'code': 'unterminated_configuration', 'line': start.line})
                break
            for j in range(i + 1, end):
                if tokens[j].value != 'program': continue
                terminator = next((k for k in range(j + 1, end) if tokens[k].value == ';'), end)
                colon = next((k for k in range(j + 1, terminator) if tokens[k].value == ':'), None)
                if colon is None or colon + 1 >= terminator:
                    issues.append({'code': 'unsupported_program_instance', 'line': tokens[j].line})
                else:
                    scheduled.append(tokens[colon + 1].value)
            i = end + 1
            continue
        if start.value not in {'function', 'program', 'function_block'}:
            i += 1
            continue
        kind = start.value
        end_word = 'end_' + kind
        end = next((j for j in range(i + 1, len(tokens)) if tokens[j].value == end_word), None)
        if end is None:
            issues.append({'code': 'unterminated_program_unit', 'line': start.line})
            break
        name = tokens[i + 1].value
        if kind == 'function_block':
            # Uninstantiated blocks are not analyzed as active PROGRAM bodies.
            issues.append({'code': 'function_block_not_analyzed', 'line': start.line, 'unit': name})
            i = end + 1
            continue
        body_start, return_type = i + 2, None
        if kind == 'function':
            if tokens[body_start].value != ':':
                issues.append({'code': 'missing_function_return_type', 'line': start.line})
                i = end + 1
                continue
            return_type = tokens[body_start + 1].value.upper()
            body_start += 2
        try:
            if name in units:
                raise _Unsupported('duplicate_program_unit', start.line)
            unit = _unit(tokens[body_start:end], name, kind, return_type)
            unit.update(line=start.line, end_line=tokens[end].line)
            units[name] = unit
        except _Unsupported as exc:
            issues.append({'code': exc.code, 'line': exc.line or start.line, 'unit': name})
        i = end + 1
    return units, issues, scheduled


def _evaluate(expression, env, units, stack=()):
    if expression.kind == 'var':
        return env.get(expression.value, _Expr('unknown', expression.value))
    if expression.kind in {'const', 'bool'}:
        return expression
    if expression.kind != 'call':
        return _operation(expression.kind, *(_evaluate(x, env, units, stack) for x in expression.args))
    arguments = [(a.value, _evaluate(a.args[0], env, units, stack)) for a in expression.args]
    name = expression.value
    conversion = re.fullmatch(r'(uint|int|real|lreal|dint|udint|word)_to_(uint|int|real|lreal|dint|udint|word)', name)
    if conversion and len(arguments) == 1:
        return _Expr('cast', conversion[2].upper(), (arguments[0][1],))
    if name == 'limit' and len(arguments) == 3 and all(k is None for k, _ in arguments):
        return _Expr('limit', args=tuple(v for _, v in arguments))
    if name not in units or units[name]['kind'] != 'function' or name in stack or len(stack) > 12:
        return _Expr('opaque', name, tuple(v for _, v in arguments))
    unit = units[name]
    parameters = [d for d in unit['declarations'] if d['section'] == 'var_input']
    if len(arguments) > len(parameters) or len({k for k, _ in arguments if k is not None}) != sum(k is not None for k, _ in arguments):
        return _Expr('unknown', 'invalid_function_arguments')
    values = {}
    for index, (key, value) in enumerate(arguments):
        key = key if key is not None else parameters[index]['symbol']
        if key not in {d['symbol'] for d in parameters} or key in values:
            return _Expr('unknown', 'invalid_function_arguments')
        values[key] = value
    local = {}
    for declaration in unit['declarations']:
        key = declaration['symbol']
        initial = declaration['initial']
        local[key] = values.get(key, _evaluate(initial, local, units, stack) if initial is not None
                                else _Expr('unknown', name + '::' + key))
    local = _execute(unit['body'], local, units, stack + (name,))
    return local.get(name, _Expr('unknown', 'missing_function_result'))


def _execute(statements, env, units, stack=(), assignment=None, gates=None):
    env = dict(env)
    for statement in statements:
        if statement['kind'] == 'assign':
            value = _evaluate(statement['expression'], env, units, stack)
            if assignment is not None:
                value = assignment(statement, value)
            env[statement['target']] = value
        else:
            condition = _evaluate(statement['condition'], env, units, stack)
            yes = _execute(statement['yes'], env, units, stack, assignment, gates)
            no = _execute(statement['no'], env, units, stack, assignment, gates)
            if gates is not None:
                gates.append((statement, condition))
            for key in set(env) | set(yes) | set(no):
                a, b = yes.get(key, env.get(key)), no.get(key, env.get(key))
                if a == b: env[key] = a
                elif condition.kind == 'bool': env[key] = a if condition.value else b
                else: env[key] = _Expr('phi', statement['line'], (condition, a, b))
    return env


def _walk(expression):
    if expression is not None:
        yield expression
        for child in expression.args:
            yield from _walk(child)


def _affine(expression):
    """Exact symbolic affine coefficients; integer-output casts are not affine."""
    if expression.kind == 'const': return {}, expression.value
    if expression.kind == 'var': return {expression.value: Fraction(1)}, Fraction(0)
    if expression.kind == 'cast' and expression.value in {'REAL', 'LREAL'}:
        return _affine(expression.args[0])
    if expression.kind == 'neg':
        terms, offset = _affine(expression.args[0])
        return {key: -value for key, value in terms.items()}, -offset
    if expression.kind not in {'add', 'sub', 'mul', 'div'}:
        raise ValueError('non_affine')
    (left, a), (right, b) = (_affine(x) for x in expression.args)
    if expression.kind in {'add', 'sub'}:
        sign = 1 if expression.kind == 'add' else -1
        terms = dict(left)
        for key, value in right.items(): terms[key] = terms.get(key, 0) + sign * value
        return {k: v for k, v in terms.items() if v}, a + sign * b
    if expression.kind == 'div':
        if right or not b: raise ValueError('non_affine_division')
        return {key: value / b for key, value in left.items()}, a / b
    if left and right: raise ValueError('non_affine_product')
    if left: return {key: value * b for key, value in left.items()}, a * b
    return {key: value * a for key, value in right.items()}, a * b


def _single_affine(expression):
    terms, offset = _affine(expression)
    if len(terms) != 1: raise ValueError('single_source_required')
    symbol, coefficient = next(iter(terms.items()))
    if not coefficient: raise ValueError('zero_coefficient')
    return symbol, coefficient, offset


def _replace(expression, target, replacement):
    if expression == target: return replacement
    return _Expr(expression.kind, expression.value, tuple(_replace(x, target, replacement) for x in expression.args))


def _number(value):
    return value.numerator if value.denominator == 1 else float(value)


def _detect(expression, declarations, output):
    if declarations.get(output, {}).get('data_type') != 'UINT': return None
    if not (declarations.get(output, {}).get('address') or '').startswith('%QW'): return None
    if expression.kind != 'cast' or expression.value != 'UINT': return None
    limits = [node for node in _walk(expression) if node.kind == 'limit']
    if len(limits) != 1: return None
    limit = limits[0]
    lower, update, upper = limit.args
    if lower.kind != 'const' or upper.kind != 'const' or update.kind != 'add': return None
    for position, difference in (update.args, update.args[::-1]):
        try:
            gain = Fraction(1)
            if difference.kind == 'mul':
                if difference.args[0].kind == 'const':
                    gain, difference = difference.args[0].value, difference.args[1]
                elif difference.args[1].kind == 'const':
                    difference, gain = difference.args[0], difference.args[1].value
                else: continue
            if difference.kind != 'sub' or not gain: continue
            a, b = (_single_affine(x) for x in difference.args)
            actuator = _single_affine(position)
            if a[1:] != b[1:] or a[0] == b[0]: continue
            roles = {}
            for symbol, coefficient, offset in (a, b):
                declaration = declarations.get(symbol, {})
                address = declaration.get('address') or ''
                if declaration.get('data_type') != 'UINT': raise ValueError('unsupported_operand_type')
                if address.startswith('%IW'): roles['pv'] = symbol
                elif address.startswith('%MW'): roles['sp'] = symbol
            if set(roles) != {'pv', 'sp'}: continue
            if not (declarations.get(actuator[0], {}).get('address') or '').startswith('%IW'): continue
            if actuator[0] in (roles['pv'], roles['sp']): continue
            encoded = _replace(expression.args[0], limit, _Expr('var', '__limited_output__'))
            name, encoding_coefficient, encoding_offset = _single_affine(encoded)
            if name != '__limited_output__' or encoding_coefficient * actuator[1] != 1: continue
            if encoding_offset + actuator[2] * encoding_coefficient != 0: continue
            return {**roles, 'actuator_feedback': actuator[0], 'gain': _number(gain),
                    'error_orientation': 'sp_minus_pv' if a[0] == roles['sp'] else 'pv_minus_sp',
                    'range_min': _number(a[2]), 'range_max': _number(a[2] + a[1] * 65535),
                    'range_basis': 'affine_transform_over_declared_uint_domain_not_safety_limit',
                    'pv_scale': {'numerator': a[1].numerator, 'denominator': a[1].denominator,
                                 'offset': _number(a[2])},
                    'output_limits': [_number(lower.value), _number(upper.value)]}
        except (ValueError, ZeroDivisionError, TypeError):
            continue
    return None


def _adoption(expression, origin, conditional=False, uncertain=False):
    if expression is None: return []
    if expression.kind == 'origin' and expression.value == origin:
        return ['unknown' if uncertain else ('conditional' if conditional else 'active')]
    states = []
    for index, child in enumerate(expression.args):
        states.extend(_adoption(child, origin, conditional or (expression.kind == 'phi' and index > 0),
                                uncertain or expression.kind == 'opaque'))
    return states


def _function_spans(name, units, seen=None):
    seen = set() if seen is None else seen
    if name in seen or name not in units or units[name]['kind'] != 'function': return []
    seen.add(name)
    unit = units[name]
    result = [{'function': name, 'line': unit['line'], 'end_line': unit['end_line']}]
    def expressions(statements):
        for statement in statements:
            if statement['kind'] == 'assign': yield statement['expression']
            else:
                yield statement['condition']
                yield from expressions(statement['yes'])
                yield from expressions(statement['no'])
    for expression in expressions(unit['body']):
        for node in _walk(expression):
            if node.kind == 'call': result.extend(_function_spans(node.value, units, seen))
    return result


def analyze_st(source: str) -> dict:
    """Extract structural roles from actual source, without role-name matching.

    Addresses/numbers remain in this extraction report, not graph properties.
    A recognized call describes static potential computation, not a measured
    process response or a guarantee that its branch is currently adopted.
    """
    result = {'parser_scope': 'bounded_scalar_st_feedback_subset_v1', 'declarations': [],
              'configured_programs': [],
              'execution_scope': 'unbound_program_definitions_only',
              'control_calls': [], 'output_gates': [], 'issues': []}
    if not isinstance(source, str):
        result['issues'].append({'code': 'source_text_required', 'line': 0})
        return result
    try:
        units, issues, scheduled = _read_units(_tokens(source))
    except _Unsupported as exc:
        result['issues'].append({'code': exc.code, 'line': exc.line})
        return result
    except (IndexError, TypeError):
        result['issues'].append({'code': 'malformed_program_structure', 'line': 0})
        return result
    result['issues'].extend(issues)
    result['configured_programs'] = sorted(set(scheduled))
    if scheduled: result['execution_scope'] = 'configured_program_instances'
    for name in scheduled:
        if name not in units or units[name]['kind'] != 'program':
            result['issues'].append({'code': 'configured_program_unavailable', 'program': name})
    for name, unit in units.items():
        if unit['kind'] != 'program': continue
        if scheduled and name not in scheduled: continue
        declarations = {d['symbol']: d for d in unit['declarations']}
        result['declarations'].extend({k: v for k, v in d.items() if k != 'initial'}
                                      for d in declarations.values())
        addresses = [d['address'] for d in declarations.values() if d['address']]
        if len(addresses) != len(set(addresses)):
            result['issues'].append({'code': 'duplicate_located_address', 'program': name})
            continue
        env = {}
        for symbol, declaration in declarations.items():
            # PROGRAM initializers are startup settings, not current measurements.
            # Program variables can retain values across scans.
            env[symbol] = _Expr('var', symbol)
        calls, gates = [], []

        def assignment(statement, value):
            expression = statement['expression']
            if expression.kind != 'call': return value
            detected = _detect(value, declarations, statement['target'])
            if detected is None:
                if (declarations.get(statement['target'], {}).get('address') or '').startswith('%QW'):
                    result['issues'].append({'code': 'output_control_pattern_not_recognized',
                                             'line': statement['line'], 'output': statement['target']})
                return value
            call_id = name + ':' + str(statement['line']) + ':' + statement['target']
            function = units.get(expression.value)
            calls.append({'id': call_id, 'function': expression.value, 'program': name,
                          'line': statement['line'], 'end_line': statement['end_line'],
                          'program_binding': 'configured' if scheduled else 'unbound_definition',
                          'output': statement['target'], **detected,
                          'evidence_lines': [statement['line'], statement['end_line']],
                          'function_span': {'line': function['line'], 'end_line': function['end_line']},
                          'function_spans': _function_spans(expression.value, units)})
            return _Expr('origin', call_id, (value,))

        final = _execute(unit['body'], env, units, assignment=assignment, gates=gates)
        for call in calls:
            adoption = _adoption(final.get(call['output']), call['id'])
            call['adoption'] = 'unknown' if 'unknown' in adoption else 'conditional' if 'conditional' in adoption else 'active' if adoption else 'overwritten'
            call['effective'] = bool(adoption) if call['adoption'] != 'unknown' else None
            if not adoption:
                result['issues'].append({'code': 'controller_output_overwritten', 'line': call['line'], 'output': call['output']})
            result['control_calls'].append(call)
        for statement, condition in gates:
            operator = 'identity'
            if condition.kind == 'not':
                operator, condition = 'not', condition.args[0]
            if condition.kind != 'var' or declarations.get(condition.value, {}).get('data_type') != 'BOOL':
                result['issues'].append({'code': 'gate_condition_not_simple_boolean', 'line': statement['line']})
                continue
            overrides = []
            for branch, items in (('then', statement['yes']), ('else', statement['no'])):
                for item in items:
                    if item['kind'] != 'assign' or item['target'] not in {c['output'] for c in calls}: continue
                    value = _evaluate(item['expression'], env, units)
                    if value.kind != 'const': continue
                    present = any(x.kind == 'phi' and x.value == statement['line'] for x in _walk(final.get(item['target'])))
                    overrides.append({'output': item['target'], 'value': _number(value.value),
                                      'line': item['line'], 'branch': branch, 'final_override': present})
            if overrides:
                result['output_gates'].append({'program': name, 'condition': {'symbol': condition.value, 'operator': operator},
                                              'line': statement['line'], 'end_line': statement['end_line'],
                                              'overrides': overrides, 'final_override': any(x['final_override'] for x in overrides)})
    return result
