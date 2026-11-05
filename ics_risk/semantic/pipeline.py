"""Build a focused graph from captured source/configuration, never a seed graph.

The supported domain is the deployed scalar feedback loop and its I/O adapters.
Physical identities come from producer JSON paths; role identities come from
program dataflow. Research policies remain explicitly configured requirements.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
from fractions import Fraction
from pathlib import Path
import shutil

from .st import analyze_st
from .io_mapping import analyze_io, resolve_plc_address
from .compiled_bindings import verify_compiled_binding
from ics_risk.graph_build.builder import read_json, validate_graph


class ExtractionError(ValueError):
    pass


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _write(path, value):
    Path(path).write_bytes(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False).encode()+b'\n')


def _inside(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ExtractionError('source_path_outside_capture')
    return path


def load_capture(directory):
    root = Path(directory).resolve()
    manifest = read_json(root / 'manifest.json')
    if manifest.get('source_kind') != 'live_capture' or manifest.get('complete') is not True:
        raise ExtractionError('complete_actual_capture_required')
    files, records = {}, {}
    for item in manifest['sources']:
        sid = item['id']
        if sid in records:
            raise ExtractionError('duplicate_capture_source')
        data = _inside(root, item['path']).read_bytes()
        if _sha(data) != item['sha256']:
            raise ExtractionError('capture_source_digest_mismatch:' + sid)
        files[sid] = data
        records[sid] = copy.deepcopy(item)
    return manifest, files, records


def extract_capture(directory, *, physical_field='outputs.liquid_level'):
    if physical_field!='outputs.liquid_level':
        raise ExtractionError('this_adapter_is_scoped_to_liquid_level')
    manifest, files, records = load_capture(directory)
    required = {'active_st','modbus_driver','modbus_master','remote_io_config','glue',
                'tank_bridge','bridge_common','bridge_context','scada_points','scada_datasource','inventory'}
    if not required.issubset(files):
        raise ExtractionError('missing_source_evidence:' + ','.join(sorted(required-set(files))))
    texts = {key: value.decode('utf-8-sig') for key,value in files.items()}
    st, io = analyze_st(texts['active_st']), analyze_io(texts)
    critical = [x for x in st['issues'] if x['code'] not in {'function_block_not_analyzed'}]
    if critical:
        raise ExtractionError('unsupported_program_semantics:' + ','.join(sorted({x['code'] for x in critical})))
    if len(st.get('configured_programs',[]))!=1:
        raise ExtractionError('single_configured_program_required_for_this_adapter')
    declarations = {d['symbol']:d for d in st['declarations']}
    physical = [p for p in io['physical_signals'] if p['source_field']==physical_field
                and p['status']=='static_configured_mapping']
    if len(physical) != 1:
        raise ExtractionError('physical_feedback_mapping_unresolved_or_ambiguous')
    feedback = physical[0]
    calls = [c for c in st['control_calls']
             if declarations[c['pv']]['address']==feedback['plc_location']]
    if (len(calls)!=1 or calls[0]['adoption'] not in ('active','conditional')
            or calls[0].get('program_binding')!='configured'):
        raise ExtractionError('feedback_loop_not_uniquely_adopted_in_supported_source')
    loop = calls[0]
    gates = [(g,o) for g in st['output_gates'] for o in g['overrides']
             if o['output']==loop['output'] and o['final_override']]
    if len(gates)!=1 or gates[0][0]['condition']['operator'] not in ('identity','not'):
        raise ExtractionError('final_output_gate_unresolved_or_ambiguous')
    gate, override = gates[0]
    expected = gate['condition']['operator']=='not'
    if override['branch']=='else': expected=not expected
    ds = json.loads(texts['scada_datasource'])['data']
    inventory = json.loads(texts['inventory'])
    # Deployment identities are checked, not inferred from similar IP prefixes.
    plc_inventory = inventory.get('plc', {})
    if (ds.get('host') not in plc_inventory.get('networks', {}).values() or ds.get('transportType')!='TCP'
            or ds.get('enabled') is not True or ds.get('port')!=502):
        raise ExtractionError('scada_target_does_not_match_captured_plc')
    point_rows = json.loads(texts['scada_points'])['points']
    points = []
    point_ids=set()
    for row in point_rows:
        point = row['point']
        if type(point.get('id')) is not int or point['id'] in point_ids:
            raise ExtractionError('invalid_or_duplicate_scada_point_identity')
        point_ids.add(point['id'])
        if point.get('dataSourceId') != ds.get('id'):
            raise ExtractionError('point_datasource_mismatch')
        # Check that the aggregate index agrees with the independently saved raw response.
        raw = json.loads(texts[row['source_id']])
        if raw != point:
            raise ExtractionError('point_index_raw_response_mismatch')
        points.append(point)
    roles = {'process_value':loop['pv'], 'setpoint':loop['sp'],
             'control_output':loop['output'], 'actuator_feedback':loop['actuator_feedback'],
             'automatic_output_gate':gate['condition']['symbol']}
    variables = []
    for role,symbol in roles.items():
        declaration = declarations[symbol]
        protocol = resolve_plc_address(declaration['address'], io['address_model'])
        if protocol is None:
            raise ExtractionError('unsupported_protocol_binding:' + symbol)
        compiled=verify_compiled_binding(declaration['address'],texts['glue'])
        if not compiled['supported']:
            raise ExtractionError('compiled_binding_unresolved:'+symbol+':'+compiled['reason'])
        matched = [p for p in points if p['pointLocator'].get('range')==protocol['fc']
                   and p['pointLocator'].get('offset')==protocol['address']]
        if len(matched)>1:
            raise ExtractionError('ambiguous_scada_point_binding:' + symbol)
        variables.append({'role':role, 'symbol':symbol, 'plc_location':declaration['address'],
            'data_type':declaration['data_type'], 'protocol':protocol,
            'point_ids':[p['id'] for p in matched], 'points':matched,
            'origin_json_path':feedback['origin_json_path'] if role=='process_value' else None,
            'evidence':[{'source':'active_st','line_start':declaration['line'],'line_end':declaration['line']},
                        {'source':'active_st','line_start':loop['line'],'line_end':loop['end_line']},
                        {'source':'active_st','line_start':loop['function_span']['line'],'line_end':loop['function_span']['end_line']}]
                       + (feedback['evidence'] if role=='process_value' else protocol.get('evidence',[]))
                       + compiled['evidence']})
    by_role = {v['role']:v for v in variables}
    sp = by_role['setpoint']
    if len(sp['points'])!=1 or sp['data_type']!='UINT':
        raise ExtractionError('unique_uint_setpoint_scada_binding_required')
    locator = sp['points'][0]['pointLocator']
    if sp['points'][0].get('enabled') is not True or locator.get('settable') is not True or locator.get('modbusDataType')!=2:
        raise ExtractionError('scada_setpoint_locator_not_supported_writable_uint16')
    if any(p['pointLocator'].get('slaveId')!=locator.get('slaveId') for v in variables for p in v['points']):
        raise ExtractionError('cross_unit_semantic_mapping_unverified')
    scale = loop['pv_scale']
    scale_value = Fraction(scale['numerator'],scale['denominator'])
    # The API decimal is a serialized floating number, so use an explicit small
    # representation comparison, not an inferred plant tolerance or a guessed scale.
    api_multiplier=float(locator.get('multiplier',0))
    if not math.isfinite(api_multiplier) or abs(float(scale_value)-api_multiplier)>1e-15 or locator.get('additive')!=scale['offset']:
        raise ExtractionError('scada_and_controller_setpoint_scales_disagree')
    return {'method':'deterministic_source_extraction', 'extractor_version':'scalar-loop-source-v1',
        'source_kind':'live_capture', 'capture_finished_at':manifest['finished_at'],
        'source_digests':{key:record['sha256'] for key,record in records.items()},
        'extractor_digests':{name:_sha(Path(__file__).with_name(name).read_bytes().replace(b'\r\n',b'\n'))
                             for name in ['pipeline.py','st.py','io_mapping.py','compiled_bindings.py']},
        'code_digest_normalization':'LF line endings only; original captured evidence bytes are not normalized',
        'selected_physical_field':physical_field, 'selected_loop':loop, 'variables':variables,
        'gate':{'symbol':gate['condition']['symbol'],'automatic_expected':expected,
                'line_start':gate['line'],'line_end':gate['end_line'],'override':override},
        'endpoint':{'host':ds['host'],'port':ds['port'],'unit':locator['slaveId']},
        'physical_mapping':feedback, 'configured_programs':st.get('configured_programs',[]),
        'issues':st['issues']+io['issues'],
        'limitations':['Supported scalar ST and inspected OpenPLC/Python bridge dialect only.',
            'Source dataflow is static evidence; it does not prove identity of the running binary.',
            'Physical identity follows the simulator producer field, not statistical correlation.',
            'Engineering units remain a reviewed command contract; encoding scale alone does not establish a unit.',
            'Research thresholds are separately declared policies, not discovered physical safety limits.',
            'A bounded observation capture is not a baseline or an intervention-effect experiment.']}


def build_extracted_bundle(capture_dir, policy_bundle, destination, *, physical_field='outputs.liquid_level'):
    """No graph.json from the policy bundle is read. All topology is generated.

    Existing policy parameters/evidence are carried explicitly as research
    requirements. Semantic operand IDs are rebound to the extracted roles.
    """
    report = extract_capture(capture_dir, physical_field=physical_field)
    manifest, raw, sources = load_capture(capture_dir)
    policy = Path(policy_bundle).resolve()
    policy_sources = read_json(policy/'config/provenance.json')['sources']
    policy_bindings = read_json(policy/'config/bindings.json')
    policies = read_json(policy/'config/constraints.json')
    if policy_bindings.get('bundle_profile')=='synthetic_demo':
        raise ExtractionError('synthetic_policy_bundle_not_eligible_for_lab_graph')
    if policy_bindings.get('runtime_sha256')!=sources['active_st']['sha256']:
        raise ExtractionError('research_policy_runtime_scope_mismatch')
    for rule in policies['rules']:
        if rule.get('verified_parameters_sha256') != _sha(_canonical(rule.get('parameters'))):
            raise ExtractionError('policy_parameter_integrity_mismatch')
    if len(policy_bindings.get('points',{}))!=1:
        raise ExtractionError('unique_existing_command_unit_contract_required')
    verified_sources = []
    for source in policy_sources:
        data = _inside(policy,source['path']).read_bytes()
        if _sha(data)!=source['sha256']:
            raise ExtractionError('policy_evidence_digest_mismatch')
        verified_sources.append((source,data))
    expected_rules={'constraint:encoding_range','constraint:step_limit','constraint:run_required',
                    'constraint:e_stop_clear','constraint:min_interval'}
    if {r['id'] for r in policies['rules']}!=expected_rules:
        raise ExtractionError('unsupported_research_policy_inventory')
    root=Path(destination).resolve()
    root.mkdir(parents=True,exist_ok=False)
    (root/'config').mkdir(); (root/'evidence').mkdir()
    provenance=[]
    for sid,data in raw.items():
        relative='evidence/capture_'+sid+Path(sources[sid]['path']).suffix
        (root/relative).write_bytes(data)
        provenance.append({'id':'src:capture:'+sid,'path':relative,'sha256':_sha(data),
            'locator':sources[sid]['locator'],'kind':sources[sid]['kind'],
            'acquired_start':sources[sid]['acquired_start'],'acquired_end':sources[sid]['acquired_end']})
    policy_ref={}
    for source,data in verified_sources:
        sid='src:policy:'+source['id'].removeprefix('src:')
        policy_ref[source['id']]=sid
        relative='evidence/policy_'+source['id'].replace(':','_')+Path(source['path']).suffix
        (root/relative).write_bytes(data)
        provenance.append({'id':sid,'path':relative,'sha256':_sha(data),
                           'locator':source['locator'],'kind':source['kind']})
    version='lvsp-extracted-'+_sha(_canonical([report['source_digests'],report['extractor_digests'],policies]))[:16]
    report['graph_version']=version
    report['declared_policy_dependencies']=[{'variable':'simulator emergency-stop flag',
        'origin':'declared_policy_dependency',
        'json_path':policy_bindings['signals']['var:e_stop']['json_path'],
        'note':'Research prerequisite carried from reviewed policy; not discovered as a PLC program gate. Actual JSON existence/type must be checked against observations.'}]
    report['policy_attachment']={'origin':'reviewed_existing_research_and_implementation_contract',
        'rule_ids':sorted(expected_rules),
        'note':'Policy parameters are not learned from the captured values. Graph operands are rebound to source-extracted roles; no seed graph is read.'}
    _write(root/'semantic_report.json',report)
    report_bytes=(root/'semantic_report.json').read_bytes()
    (root/'evidence/extraction_report.json').write_bytes(report_bytes)
    provenance.append({'id':'src:extraction','path':'evidence/extraction_report.json','sha256':_sha(report_bytes),
                       'locator':'variables[].evidence; selected_loop; physical_mapping; gate',
                       'kind':'deterministically_derived_source_analysis'})
    nodes,edges={},{}
    def node(key,kind,label,refs,description=None):
        nodes[key]={'id':key,'type':kind,'label':label,'evidence_refs':sorted(set(refs))}
        if description: nodes[key]['description']=description
        return key
    def edge(src,kind,dst,refs):
        eid='edge:'+_sha(_canonical([src,kind,dst]))[:20]
        edges[eid]={'id':eid,'type':kind,'source':src,'target':dst,'evidence_refs':sorted(set(refs))}
    inventory_ref=['src:capture:inventory']
    plc=node('component:plc','Component','Captured PLC',inventory_ref)
    scada=node('component:scada','Component','Captured SCADA',inventory_ref+['src:capture:scada_datasource'])
    sim=node('component:simulator','Component','Captured process simulator',inventory_ref)
    loop_id=node('loop:plc:'+report['selected_loop']['output'],'ControlLoop',physical_field+' feedback loop',
                 ['src:capture:active_st','src:extraction'])
    role_ids,signals,point_bindings={}, {}, {}
    for variable in report['variables']:
        role=variable['role']; vid='var:plc:'+variable['symbol'];role_ids[role]=vid
        refs=['src:capture:active_st','src:capture:modbus_driver','src:extraction']
        if role=='process_value': refs += ['src:capture:'+e['source'] for e in report['physical_mapping']['evidence']]
        node(vid,'Variable',role+': '+variable['symbol'],refs,'Role extracted from source dataflow; see external evidence spans.')
        edge(vid,'HOSTED_BY',plc,refs);edge(vid,'IN_LOOP',loop_id,refs)
        protocol=variable['protocol']
        signals[vid]={'unit':'boolean' if variable['data_type']=='BOOL' else 'raw_count','source':'plc',
            'protocol':'modbus_tcp','function_code':protocol['fc'],'unit_id':report['endpoint']['unit'],
            'offset':protocol['address'],'count':1,'plc_symbol':variable['plc_location'],
            'component_ref':plc,'evidence_refs':sorted(set(refs))}
        if variable['points']:
            point=variable['points'][0];pid='point:scada:'+str(point['id'])
            p_refs=refs+['src:capture:point_'+str(point['id']),'src:capture:scada_datasource']
            node(pid,'Point',point['name'],p_refs)
            edge(scada,'EXPOSES',pid,p_refs);edge(pid,'MAPS_TO',vid,p_refs)
        else:
            pid='point:plc:'+variable['symbol'];p_refs=refs
            node(pid,'Point','PLC communication point: '+variable['symbol'],refs)
            edge(plc,'EXPOSES',pid,refs);edge(pid,'MAPS_TO',vid,refs)
        if role=='setpoint':
            scale=report['selected_loop']['pv_scale']
            # Unit is explicitly inherited from the reviewed command contract;
            # no physical unit is guessed from a 0..100 encoding range.
            old_point=next(iter(policy_bindings['points'].values()))
            point_bindings[pid]={'component_ref':plc,'exposing_component_ref':scada,'variable_ref':vid,
                'loop_ref':loop_id,'scada_point_id':point['id'],'data_source_id':point['dataSourceId'],
                'protocol':'modbus_tcp','unit':point['pointLocator']['slaveId'],'offset':protocol['address'],
                'register_kind':protocol['register_kind'],'plc_symbol':variable['plc_location'],'data_type':'uint16',
                'scale':{'numerator':scale['numerator'],'denominator':scale['denominator'],
                         'additive':scale['offset'],'unit':old_point['scale']['unit']},
                'unit_assurance':'reviewed_existing_command_contract_not_inferred_from_scale',
                'required_constraint_refs':sorted(expected_rules),'evidence_refs':sorted(set(p_refs))}
    estop='var:simulator:e_stop'
    e_refs=[policy_ref[x] for x in policy_bindings['signals']['var:e_stop']['evidence_refs']]
    node(estop,'Variable','Simulator emergency-stop flag',e_refs,
         'Simulator JSON field required by the declared research admission policy; not a PLC gate.')
    edge(estop,'HOSTED_BY',sim,e_refs)
    signals[estop]=copy.deepcopy(policy_bindings['signals']['var:e_stop'])
    signals[estop]['evidence_refs']=e_refs;signals[estop]['component_ref']=sim
    target_point=next(iter(point_bindings))
    rules=copy.deepcopy(policies['rules'])
    for rule in rules:
        cid=rule['id'];refs=[policy_ref[x] for x in rule['evidence_refs']]
        dependency=None;target=role_ids['setpoint']
        if cid=='constraint:encoding_range':
            rule['parameters']['lower']=report['selected_loop']['range_min']
            rule['parameters']['upper']=report['selected_loop']['range_max']
            refs += ['src:capture:active_st','src:capture:point_'+str(point_bindings[target_point]['scada_point_id']),'src:extraction']
        elif cid=='constraint:step_limit':
            dependency=role_ids['setpoint'];rule['parameters']['reference_signal']=dependency
        elif cid=='constraint:run_required':
            dependency=role_ids['automatic_output_gate'];target=loop_id
            rule['parameters']['signal']=dependency;rule['parameters']['expected']=report['gate']['automatic_expected']
            refs+=['src:capture:active_st','src:extraction']
        elif cid=='constraint:e_stop_clear':
            dependency=estop;target=loop_id;rule['parameters']['signal']=dependency
        elif cid=='constraint:min_interval': rule['parameters']['point_ref']=target_point
        rule['evidence_refs']=sorted(set(refs))
        rule['verified_parameters_sha256']=_sha(_canonical(rule['parameters']))
        node(cid,'Constraint',cid.removeprefix('constraint:'),refs)
        edge(cid,'APPLIES_TO',target,refs)
        if dependency: edge(cid,'REQUIRES',dependency,refs)
    graph={'schema_version':'1','graph_version':version,'nodes':list(nodes.values()),'edges':list(edges.values())}
    validate_graph(graph)
    quality=copy.deepcopy(policy_bindings['quality'])
    quality['evidence_refs']=[policy_ref[x] for x in quality['evidence_refs']]
    representation=copy.deepcopy(policy_bindings['representation'])
    representation['evidence_refs']=[policy_ref[x] for x in representation['evidence_refs']]
    bindings={'schema_version':'1','graph_version':version,'runtime_sha256':sources['active_st']['sha256'],
        'runtime_artifact':'captured active ST source','runtime_assurance':'captured source, not executable attestation',
        'bundle_profile':'source_extracted_lab_evidence','graph_construction':'deterministic_source_extraction',
        'quality':quality,'representation':representation,'points':point_bindings,'signals':signals}
    for name,data in [('graph',graph),('bindings',bindings),('constraints',{'schema_version':'1','rules':rules}),
                      ('provenance',{'schema_version':'1','sources':provenance})]: _write(root/'config'/f'{name}.json',data)
    read_plan=[{'fc':x['function_code'],'address':x['offset'],'count':1}
               for x in signals.values() if x['source']=='plc']
    _write(root/'read_plan.json',{'endpoint':report['endpoint'],'requests':read_plan})
    return {'graph_version':version,'nodes':len(nodes),'edges':len(edges),'bundle':str(root),
            'target_point':target_point,'roles':role_ids,'read_plan':read_plan,'endpoint':report['endpoint']}
