"""Explicit graph publication and read-only command assessment commands."""
import argparse
import json
import os
from pathlib import Path

from .graph_build import build_graph, graph_digest
from .graph_query import JsonRepository, Neo4jRepository
from .service import RiskApplication, serve, _strict_json

ROOT = Path(__file__).resolve().parents[1]


def parser():
    p = argparse.ArgumentParser(description='ICS-RISK 图谱驱动的执行前约束评估')
    p.add_argument('--bundle', type=Path, default=os.environ.get('ICS_RISK_BUNDLE', str(ROOT / 'examples/demo_bundle')))
    p.add_argument('--backend', choices=['json', 'neo4j'], default=os.environ.get('ICS_RISK_BACKEND', 'json'))
    p.add_argument('--records', type=Path, default=os.environ.get('ICS_RISK_RECORDS', str(ROOT / 'runtime/records')))
    commands = p.add_subparsers(dest='action', required=True)
    commands.add_parser('validate', help='校验人工审定图谱及证据包')
    commands.add_parser('publish-graph', help='明确发布图版本到 Neo4j；这是唯一写库命令')
    q = commands.add_parser('query', help='查询点位语义、约束与依赖')
    q.add_argument('--point', default='point:level_sp')
    q.add_argument('--version')
    e = commands.add_parser('evaluate', help='评估候选请求并保存独立记录；不执行控制')
    e.add_argument('--input', type=Path, required=True)
    s = commands.add_parser('serve', help='启动本地网页及 HTTP 评估接口')
    s.add_argument('--host', default=os.environ.get('ICS_RISK_HOST', '127.0.0.1'))
    s.add_argument('--port', type=int, default=int(os.environ.get('ICS_RISK_PORT', '18081')))
    s.add_argument('--example', type=Path, default=os.environ.get('ICS_RISK_EXAMPLE'))
    return p


def run(args):
    if args.action in {'validate', 'publish-graph'}:
        graph = build_graph(args.bundle)
        if args.action == 'publish-graph':
            return Neo4jRepository.from_env().publish(graph)
        return {'valid': True, 'graph_version': graph['graph_version'],
                'nodes': len(graph['nodes']), 'edges': len(graph['edges']),
                'graph_sha256': graph_digest(graph),
                'note': 'Evidence byte integrity checked; this is not a physical safety certificate.'}
    repo = (Neo4jRepository.from_env() if args.backend == 'neo4j'
            else JsonRepository(args.bundle / 'config/graph.json'))
    if args.action == 'query':
        version = args.version or _strict_json((args.bundle / 'config/graph.json').read_text(encoding='utf-8-sig'))['graph_version']
        return repo.semantic_context(args.point, version)
    example = getattr(args, 'example', None)
    if example is None and args.bundle.resolve() == (ROOT / 'examples/demo_bundle').resolve():
        example = ROOT / 'examples/request.json'
    app = RiskApplication(args.bundle, repo, args.records, example_path=example,
                          backend=args.backend, token=os.environ.get('ICS_RISK_API_TOKEN') or None)
    if args.action == 'evaluate':
        request = _strict_json(args.input.read_text(encoding='utf-8-sig'))
        status, record = app.evaluate(request)
        result = record['result']
        return {'http_status': status, 'record_id': record['record_id'],
                'decision': result['decision'], 'completeness': result['completeness'],
                'record_path': str(app.records.directory / (record['record_id'] + '.json'))}
    print(json.dumps({'listening': f'http://{args.host}:{args.port}', 'backend': args.backend,
                      'graph_version': app.graph_version, 'control_writes': False}), flush=True)
    serve(app, host=args.host, port=args.port)
    return None


def main():
    args = parser().parse_args()
    try:
        result = run(args)
    except KeyboardInterrupt:
        return
    except Exception as exc:
        # Exception details may contain paths or remote response bodies. Do not
        # disclose secrets through a generic public-facing CLI error.
        print(json.dumps({'error': type(exc).__name__,
                          'message': 'Operation failed; check reviewed configuration, evidence and backend availability.'}))
        raise SystemExit(1) from None
    if result is not None:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result.get('http_status', 200) >= 500:
            raise SystemExit(2)


if __name__ == '__main__':
    main()
