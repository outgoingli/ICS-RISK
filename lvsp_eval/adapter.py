"""Read-only bridge for existing qualification data; no import of execution code."""
from decimal import Decimal, localcontext
from .engine import Evaluator


def qualified_inputs(config, row, simulator_record, history, evaluation_at, graph_version,
                     command_id='qualification-candidate', *, expected_binding=None):
    """Separate intended raw/value from measured row; never substitute original_raw.

    Caller supplies already collected records. Missing/bad measurements remain
    absent/invalid and are evaluated as UNKNOWN. Conversion here is raw->decimal,
    not an assumption about arbitrary SCADA engineering->raw rounding.
    """
    target = config.get('target_raw')
    value = None
    if type(target) is int:
        with localcontext() as ctx:
            ctx.prec = 40
            value = str(Decimal(target) * 100 / Decimal(65535))
    command = {'id': command_id, 'action': 'write', 'point_id': 'point:level_sp',
               'value': value, 'raw': target, 'unit': 'percent', 'evaluation_at': evaluation_at}
    snapshot = {'graph_version': graph_version, 'runtime_sha256': config.get('expected_st_sha256'),
                'captured_at': row.get('end', {}).get('epoch'), 'signals': {}}
    if expected_binding is None:
        expected_binding = Evaluator().config['bindings'].get('execution_binding', {})
    fields = ('point_id', 'plc_host', 'unit')
    if (not isinstance(expected_binding, dict)
            or any(key not in expected_binding for key in fields)
            or any(type(config.get(key)) is not type(expected_binding[key])
                   or config.get(key) != expected_binding[key] for key in fields)):
        command['point_id'] = 'unverified-execution-binding'
    if 'error' not in row:
        try:
            common = {'observed_at': row['start']['epoch'], 'available_at': row['end']['epoch'],
                      'span_seconds': str(Decimal(str(row['end']['epoch'])) - Decimal(str(row['start']['epoch']))),
                      'monotonic_span_seconds': row['end']['mono'] - row['start']['mono'], 'quality': 'good'}
            snapshot['signals']['var:level_sp'] = {**common, 'value': row['setpoints'][4], 'unit': 'raw_count'}
            run = row['run']
            # A protocol integer bit is explicitly normalized, never Python truthiness.
            run_value = bool(run) if type(run) is int and run in (0, 1) else run
            snapshot['signals']['var:run'] = {**common, 'value': run_value, 'unit': 'boolean'}
        except (KeyError, IndexError, TypeError):
            pass
    if simulator_record:
        try:
            sim_end = simulator_record['end']['epoch']
            snapshot['signals']['var:e_stop'] = {
                'value': simulator_record['data']['state']['e_stop'], 'unit': 'boolean',
                'observed_at': simulator_record['start']['epoch'], 'available_at': sim_end,
                'span_seconds': str(Decimal(str(sim_end)) - Decimal(str(simulator_record['start']['epoch']))),
                'quality': 'good'}
            if snapshot['captured_at'] is not None:
                snapshot['captured_at'] = max(snapshot['captured_at'], sim_end)
        except (KeyError, TypeError):
            pass
    return {'command': command, 'snapshot': snapshot, 'history': history, 'graph_version': graph_version}


def assess_qualified_request(config, row, simulator_record, history, evaluation_at,
                             graph_version, evaluator=None, command_id='qualification-candidate'):
    evaluator = evaluator or Evaluator()
    inputs = qualified_inputs(config, row, simulator_record, history, evaluation_at,
                              graph_version, command_id,
                              expected_binding=evaluator.config['bindings'].get('execution_binding', {}))
    result = evaluator.evaluate(**inputs)
    return {'mode': 'read_only_shadow', 'dispatch_performed': False,
            'existing_protection_modified': False, 'assessment': result}
