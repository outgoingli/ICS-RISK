"""Query the same schema through JSON or a database snapshot, without inference."""
from __future__ import annotations

import copy
from pathlib import Path

from lvsp_eval.graph import Graph
from ics_risk.graph_build.builder import GraphBuildError, read_json, validate_graph


class GraphRepositoryError(RuntimeError):
    pass


class GraphNotFound(GraphRepositoryError):
    pass


def semantic_context(graph_data, point_id):
    """Resolve concrete paths and return every traversal used, including gaps."""
    data = validate_graph(graph_data)
    graph = Graph(data)
    if graph.nodes.get(point_id, {}).get("type") != "Point":
        raise GraphNotFound("point_not_found")
    component = graph.unique(point_id, "EXPOSES", "in")
    variable = graph.unique(point_id, "MAPS_TO")
    host = graph.unique(variable, "HOSTED_BY") if variable else None
    loop = graph.unique(variable, "IN_LOOP") if variable else None
    applicable = set()
    for target in (variable, loop):
        if target:
            applicable.update(graph.adjacent(target, "APPLIES_TO", "in"))
    constraints = []
    for constraint_id in sorted(applicable):
        dependencies = graph.adjacent(constraint_id, "REQUIRES")
        constraints.append({"constraint_id": constraint_id,
                            "applies_to": graph.adjacent(constraint_id, "APPLIES_TO"),
                            "requires": [{"variable_id": dep, "host": graph.unique(dep, "HOSTED_BY")}
                                         for dep in dependencies]})
    return {"graph_version": data["graph_version"], "point_id": point_id,
            "exposing_component": component, "variable_id": variable,
            "hosting_component": host, "loop_id": loop,
            "constraints": constraints, "query_trace": graph.trace, "issues": graph.issues}


class JsonRepository:
    def __init__(self, graph):
        self._graph = copy.deepcopy(graph) if isinstance(graph, dict) else Path(graph)

    def get_graph(self, version):
        try:
            graph = validate_graph(self._graph if isinstance(self._graph, dict) else read_json(self._graph))
        except GraphBuildError as exc:
            raise GraphRepositoryError(str(exc)) from exc
        if graph["graph_version"] != version:
            raise GraphNotFound("graph_version_not_found")
        return graph

    def semantic_context(self, point_id, version):
        return semantic_context(self.get_graph(version), point_id)
