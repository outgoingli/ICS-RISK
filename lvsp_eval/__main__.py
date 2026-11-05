"""Offline evaluate/replay CLI. Evaluation itself is read-only; this wrapper records results."""
import argparse
import json
from pathlib import Path
from .engine import Evaluator, digest
from .replay import prepare_run


def write_record(destination, payload):
    # Create exclusively: an existing assessment must never be silently replaced.
    with destination.open('x', encoding='utf-8') as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=None,
                        help='Bundle directory; defaults to ICS_RISK_BUNDLE or the synthetic demo')
    sub = parser.add_subparsers(dest='action', required=True)
    one = sub.add_parser('evaluate')
    one.add_argument('--input', type=Path, required=True)
    one.add_argument('--output', type=Path, required=True)
    replay = sub.add_parser('replay')
    replay.add_argument('--run', type=Path, action='append', required=True)
    replay.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    evaluator = Evaluator(args.bundle)
    if args.action == 'evaluate':
        inputs = json.loads(args.input.read_text(encoding='utf-8'))
        result = evaluator.evaluate(**inputs)
        write_record(args.output, {'inputs': inputs, 'result': result})
        print(json.dumps({'decision': result['decision'], 'output': str(args.output)}))
        return
    args.output_dir.mkdir(parents=True, exist_ok=False)
    version = evaluator.config['graph'].get('graph_version')
    summary = []
    for index, run in enumerate(args.run, 1):
        prepared = prepare_run(run, version,
                               expected_binding=evaluator.config['bindings'].get('execution_binding', {}))
        result = evaluator.evaluate(**prepared['inputs']) if prepared['status'] == 'READY' else None
        name = f'{index:03d}_{run.name}.json'
        record = {'replay': prepared, 'result': result}
        write_record(args.output_dir / name, record)
        summary.append({'run': run.name, 'file': name, 'sha256': digest(record),
                        'status': prepared['status'], 'decision': result['decision'] if result else None,
                        'complete': result['completeness']['complete'] if result else None})
    write_record(args.output_dir / 'summary.json', {'evaluations': summary})
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == '__main__':
    main()
