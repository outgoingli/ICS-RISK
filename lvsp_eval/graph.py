"""Explicit directed queries over JSON. No database, inference or numeric graph data."""
import copy

NODE_TYPES = {'Component', 'Point', 'Variable', 'ControlLoop', 'Constraint'}
RELATIONS = {
    'EXPOSES': ({'Component'}, {'Point'}),
    'MAPS_TO': ({'Point'}, {'Variable'}),
    'HOSTED_BY': ({'Variable'}, {'Component'}),
    'IN_LOOP': ({'Variable'}, {'ControlLoop'}),
    'APPLIES_TO': ({'Constraint'}, {'Variable', 'ControlLoop'}),
    'REQUIRES': ({'Constraint'}, {'Variable'}),
}


def graph_numbers(value, path='$'):
    if isinstance(value, (int, float, bool)):
        yield path
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from graph_numbers(item, path + '.' + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from graph_numbers(item, f'{path}[{index}]')


class Graph:
    def __init__(self, data):
        self.data = copy.deepcopy(data)
        self.nodes = {}
        self.edges = []
        self.issues = []
        self.trace = []
        if not isinstance(data, dict):
            self.issues.append({'code': 'invalid_graph_object'})
            return
        for path in graph_numbers(data):
            self.issues.append({'code': 'numeric_graph_property', 'path': path})
        nodes = data.get('nodes', [])
        edges = data.get('edges', [])
        if not isinstance(nodes, list) or not isinstance(edges, list):
            self.issues.append({'code': 'invalid_graph_collections'})
            return
        for node in nodes:
            if not isinstance(node, dict) or not isinstance(node.get('id'), str):
                self.issues.append({'code': 'invalid_node'})
                continue
            key = node['id']
            if key in self.nodes or node.get('type') not in NODE_TYPES:
                self.issues.append({'code': 'duplicate_or_unknown_node_type', 'id': key})
            self.nodes[key] = node
            unknown = set(node) - {'id', 'type', 'label', 'description', 'evidence_refs'}
            if unknown:
                self.issues.append({'code': 'unsupported_node_properties', 'id': key, 'properties': sorted(unknown)})
            self._evidence(node)
        edge_ids, triples = set(), set()
        for edge in edges:
            if not isinstance(edge, dict):
                self.issues.append({'code': 'invalid_edge'})
                continue
            key, kind = edge.get('id'), edge.get('type')
            unknown = set(edge) - {'id', 'type', 'source', 'target', 'label', 'description', 'evidence_refs'}
            if unknown:
                self.issues.append({'code': 'unsupported_edge_properties', 'id': key, 'properties': sorted(unknown)})
            source, target = edge.get('source'), edge.get('target')
            triple = (source, kind, target)
            if not isinstance(key, str) or key in edge_ids or triple in triples:
                self.issues.append({'code': 'duplicate_or_invalid_edge', 'id': key})
            edge_ids.add(key)
            triples.add(triple)
            if kind not in RELATIONS or source not in self.nodes or target not in self.nodes:
                self.issues.append({'code': 'invalid_relation_or_endpoint', 'id': key})
                continue
            src_types, dst_types = RELATIONS[kind]
            if self.nodes[source]['type'] not in src_types or self.nodes[target]['type'] not in dst_types:
                self.issues.append({'code': 'relation_type_mismatch', 'id': key})
            self.edges.append(edge)
            self._evidence(edge)

    def _evidence(self, item):
        refs = item.get('evidence_refs')
        if not isinstance(refs, list) or not refs or not all(isinstance(x, str) for x in refs):
            self.issues.append({'code': 'missing_graph_evidence', 'id': item.get('id')})

    def adjacent(self, node_id, relation, direction='out'):
        field, other = ('source', 'target') if direction == 'out' else ('target', 'source')
        found = [edge for edge in self.edges if edge['type'] == relation and edge[field] == node_id]
        result = sorted({edge[other] for edge in found})
        self.trace.append({'node': node_id, 'relation': relation, 'direction': direction,
                           'edge_ids': sorted(edge['id'] for edge in found), 'result': result})
        return result

    def unique(self, node_id, relation, direction='out'):
        found = self.adjacent(node_id, relation, direction)
        if len(found) != 1:
            self.issues.append({'code': 'non_unique_query_result', 'node': node_id,
                                'relation': relation, 'direction': direction, 'matches': found})
            return None
        return found[0]
