"""Check explicit generated OpenPLC pointer bindings without executing C++.

Supported glueVars bodies contain only direct array-pointer assignments. This
bounded source check rejects macros, control flow, calls, computed indices and
unexplained references; it is not a C++ compiler or executable attestation.
"""
from __future__ import annotations

import re


_KINDS = {'MW': ('int_memory', 'IEC_UINT'), 'IW': ('int_input', 'IEC_UINT'),
          'QW': ('int_output', 'IEC_UINT'), 'QX': ('bool_output', 'IEC_BOOL')}
_GENERATED_ARRAYS = {'bool_input', 'bool_output', 'byte_input', 'byte_output',
                     'int_input', 'int_output', 'dint_input', 'dint_output',
                     'lint_input', 'lint_output', 'int_memory', 'dint_memory',
                     'lint_memory', 'special_functions'}


def _mask(source):
    chars = list(source)
    i = 0
    while i < len(source):
        start = i
        if source[i:i + 2] == '//':
            i = source.find('\n', i)
            if i < 0: i = len(source)
        elif source[i:i + 2] == '/*':
            end = source.find('*/', i + 2)
            if end < 0: raise ValueError('unterminated_comment')
            i = end + 2
        elif source[i] in {'"', "'"}:
            quote = source[i]
            i += 1
            while i < len(source):
                if source[i] == '\\':
                    i += 2
                elif source[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise ValueError('unterminated_literal')
            # Keep a non-C marker so a literal in a binding cannot disappear and
            # accidentally make an unsupported statement look valid.
            chars[start] = '@'
            start += 1
        else:
            i += 1
            continue
        for j in range(start, min(i, len(source))):
            if chars[j] != '\n': chars[j] = ' '
    masked = ''.join(chars)
    directives = []
    offset, continuation = 0, False
    chars = list(masked)
    for line in masked.splitlines(keepends=True):
        if continuation or line.lstrip().startswith('#'):
            directives.append((offset, offset + len(line)))
            continuation = line.rstrip('\r\n').rstrip().endswith('\\')
            for j in range(offset, offset + len(line)):
                if chars[j] != '\n': chars[j] = ' '
        offset += len(line)
    return ''.join(chars), directives


def _evidence(source, start, end):
    return {'source': 'glue', 'line_start': source.count('\n', 0, start) + 1,
            'line_end': source.count('\n', 0, max(start, end - 1)) + 1}


def verify_compiled_binding(location: str, glue_source: str) -> dict:
    """Verify one located symbol against its unique compiled pointer binding.

    Both locations and generated symbols must match exactly. A source snippet
    that only mentions an address in a macro, declaration or comment is not
    accepted as a runtime pointer assignment.
    """
    def reject(reason, evidence=None):
        return {'supported': False, 'evidence': evidence or [], 'reason': reason}

    if not isinstance(location, str) or not isinstance(glue_source, str):
        return reject('location_and_glue_text_required')
    parsed = re.fullmatch(r'%(MW|IW|QW|QX)(\d+)(?:\.(\d+))?', location)
    if not parsed:
        return reject('unsupported_location')
    kind, index, bit = parsed[1], int(parsed[2]), parsed[3]
    if (kind == 'QX') != (bit is not None) or (bit is not None and not 0 <= int(bit) < 8):
        return reject('invalid_location_dimensions')
    indices = (index, int(bit)) if bit is not None else (index,)
    array, dtype = _KINDS[kind]
    expected = '__' + kind + str(index) + ('_' + str(int(bit)) if bit is not None else '')
    try:
        code, directives = _mask(glue_source)
    except ValueError as exc:
        return reject(str(exc))
    definitions = list(re.finditer(r'\bvoid\s+glueVars\s*\(\s*(?:void\s*)?\)\s*\{', code))
    if len(definitions) != 1:
        return reject('unique_glue_function_required')
    definition = definitions[0]
    depth, end = 1, definition.end()
    while end < len(code) and depth:
        depth += (code[end] == '{') - (code[end] == '}')
        end += 1
    if depth:
        return reject('unterminated_glue_function')
    start, body_end = definition.end(), end - 1
    body_evidence = [_evidence(glue_source, definition.start(), end)]
    if any(start <= a < body_end or start < b <= body_end for a, b in directives):
        return reject('preprocessor_inside_glue_function_unsupported', body_evidence)
    # A later helper might overwrite bindings. Only the ordinary global pointer
    # declaration is allowed outside the checked function for the selected array.
    outside = code[:definition.start()] + ' ' * (end - definition.start()) + code[end:]
    declaration = (r'\b(?:extern\s+|static\s+)?' + re.escape(dtype) + r'\s*\*\s*'
                   + re.escape(array) + r'\s*(?:\[[^\]]+\]\s*){1,2};')
    outside = re.sub(declaration, lambda m: ' ' * len(m[0]), outside)
    if re.search(r'\b' + re.escape(array) + r'\b', outside):
        return reject('unclassified_array_reference_outside_glue_function')
    records = []
    cursor = start
    for match in re.finditer(r'[^;]*;', code[start:body_end], re.S):
        segment = match[0]
        statement_start, statement_end = start + match.start(), start + match.end()
        cursor = statement_end
        if segment.strip() == ';': continue
        assignment = re.fullmatch(r'\s*([A-Za-z_]\w*)\s*((?:\[[^\]]+\]\s*){1,2})'
                                  r'=\s*([^;{}]+);\s*', segment)
        if assignment is None:
            return reject('unsupported_glue_statement', [_evidence(glue_source, statement_start, statement_end)])
        lhs, bracket_text, rhs = assignment.groups()
        if lhs not in _GENERATED_ARRAYS:
            return reject('unknown_array_or_alias_in_glue_function', [_evidence(glue_source, statement_start, statement_end)])
        subscripts = re.findall(r'\[\s*([^\]]+)\s*\]', bracket_text)
        if any(not re.fullmatch(r'\d+', x.strip()) for x in subscripts):
            return reject('computed_or_dynamic_binding_index', [_evidence(glue_source, statement_start, statement_end)])
        literal_pointer = r'\(\s*IEC_(?:BOOL|BYTE|UINT|UDINT|ULINT)\s*\*\s*\)\s*__[IQM][XBWDL]\d+(?:_\d+)?'
        if re.fullmatch(literal_pointer, rhs.strip()) is None:
            return reject('nonliteral_pointer_binding_unsupported', [_evidence(glue_source, statement_start, statement_end)])
        if lhs != array: continue
        record_indices = tuple(int(x) for x in subscripts)
        if len(record_indices) != len(indices):
            return reject('binding_array_dimension_mismatch', [_evidence(glue_source, statement_start, statement_end)])
        leading = len(segment) - len(segment.lstrip())
        records.append({'indices': record_indices, 'rhs': rhs.strip(),
                        'evidence': _evidence(glue_source, statement_start + leading, statement_end)})
    if code[cursor:body_end].strip():
        return reject('unsupported_glue_trailing_statement', body_evidence)
    matches = [row for row in records if row['indices'] == indices]
    if not matches:
        misplaced = [row['evidence'] for row in records if re.search(r'\b' + re.escape(expected) + r'\b', row['rhs'])]
        return reject('located_symbol_bound_to_different_index' if misplaced else 'compiled_binding_missing', misplaced)
    if len(matches) != 1:
        return reject('duplicate_or_overwritten_compiled_binding', [x['evidence'] for x in matches])
    record = matches[0]
    pattern = r'\(\s*' + re.escape(dtype) + r'\s*\*\s*\)\s*' + re.escape(expected)
    if re.fullmatch(pattern, record['rhs']) is None:
        return reject('compiled_index_symbol_or_cast_mismatch', [record['evidence']])
    return {'supported': True, 'evidence': [record['evidence']],
            'reason': 'unique_literal_compiled_pointer_binding'}
