"""Prepare as-of input records from preserved qualification logs, without actuation."""
from pathlib import Path
import hashlib
import json
from .adapter import qualified_inputs


def _lines(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def prepare_run(run_dir, graph_version, *, expected_binding=None):
    root = Path(run_dir)
    config = json.loads((root / 'config.json').read_text(encoding='utf-8'))
    events = _lines(root / 'runner_events.jsonl')
    intents = [e for e in events if e.get('event') == 'target_send_intent']
    if not intents:
        return {'status': 'NO_CANDIDATE', 'run_id': config.get('run_id'),
                'reason': 'No target-send intent recorded; not a low-risk negative sample'}
    intent = intents[0]
    now = intent['epoch']
    samples = _lines(root / 'data' / 'samples.jsonl')
    # Latest known row, not latest good row: a final failed acquisition stays a failure.
    before = [r for r in samples if r.get('end', {}).get('epoch', float('inf')) <= now]
    row = max(before, key=lambda r: r['end']['epoch']) if before else {}
    sim_before = [r for r in _lines(root / 'data' / 'simulator.jsonl')
                  if r.get('end', {}).get('epoch', float('inf')) <= now]
    sim = max(sim_before, key=lambda r: r['end']['epoch']) if sim_before else None
    earliest = min((r.get('start', {}).get('epoch', now) for r in before), default=now)
    # Capture is scoped and not an authoritative all-writers operation journal.
    # Never manufacture a complete empty history or use later restoration data.
    history = {'complete': False, 'coverage_start': earliest, 'coverage_end': now, 'events': []}
    proposed = dict(config)
    proposed['target_raw'] = intent['raw']
    inputs = qualified_inputs(proposed, row, sim, history, now, graph_version,
                              command_id=config['run_id'] + ':target',
                              expected_binding=expected_binding)
    paths = [root / 'config.json', root / 'runner_events.jsonl', root / 'data' / 'samples.jsonl',
             root / 'data' / 'simulator.jsonl']
    return {'status': 'READY', 'run_id': config['run_id'], 'inputs': inputs,
            'source_excerpt': {'intent': intent, 'selected_row': row, 'selected_simulator': sim},
            'provenance': [{'filename': p.name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                           for p in paths if p.exists()],
            'limitations': ['Read-response completion is the recorded availability boundary; '
                            'collector file-publication latency was not separately logged.',
                            'History coverage is incomplete; later outcomes are not decision inputs.',
                            'Offline replay is not a live interception test or proof of physical safety.']}
