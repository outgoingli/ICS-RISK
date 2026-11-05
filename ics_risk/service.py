"""Local HTTP interface for graph-driven assessment; never sends control writes."""
from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .records import RecordStore

MAX_REQUEST_BYTES = 1024 * 1024
WEB_ROOT = Path(__file__).with_name("web")


def _strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("Non-finite JSON number")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


class RiskApplication:
    def __init__(self, bundle_dir, repository, records_dir, example_path=None,
                 backend="json", token=None, evaluator_factory=None):
        self.bundle_dir = Path(bundle_dir).resolve()
        self.repository = repository
        self.records = RecordStore(records_dir)
        self.backend = backend
        self.token = token
        self.example_path = Path(example_path).resolve() if example_path else None
        if evaluator_factory is None:
            from lvsp_eval import Evaluator
            evaluator_factory = Evaluator
        self.evaluator_factory = evaluator_factory
        config = _strict_json((self.bundle_dir / "config" / "graph.json").read_text(encoding="utf-8-sig"))
        self.graph_version = config["graph_version"]
        bindings_path = self.bundle_dir / "config" / "bindings.json"
        bindings = _strict_json(bindings_path.read_text(encoding="utf-8-sig")) if bindings_path.exists() else {}
        profile = bindings.get("bundle_profile")
        self.bundle_profile = (profile if profile in ("synthetic_demo", "archived_lab_evidence", "source_extracted_lab_evidence")
                               else "unclassified")

    def semantics(self):
        """Return the recorded extraction evidence, without inferring its source."""
        path = self.bundle_dir / "semantic_report.json"
        unavailable = {"available": False, "method": "curated_graph_import",
                       "notice": "尚未提供自动语义提取报告；已有节点边导入不能作为自动知识发现的证据。"}
        if not path.exists():
            return unavailable
        try:
            if path.resolve().parent != self.bundle_dir:
                raise ValueError("Semantic report leaves the bundle")
            report = _strict_json(path.read_text(encoding="utf-8-sig"))
            if not isinstance(report, dict):
                raise ValueError("Semantic report must be an object")
            if report.get("graph_version", self.graph_version) != self.graph_version:
                return {"available": False, "method": "unknown",
                        "notice": "语义报告的图版本与当前配置不一致，不能用于声明当前图的构建方式。",
                        "issues": [{"code": "semantic_report_graph_version_mismatch"}]}
            return dict(report, available=True)
        except (OSError, ValueError):
            return {"available": False, "method": "unknown",
                    "notice": "语义提取报告不可读取或格式无效，不能据此声明已完成自动提取。",
                    "issues": [{"code": "semantic_report_unreadable"}]}

    def graph(self, version=None):
        version = version or self.graph_version
        if not isinstance(version, str) or not version or len(version) > 160:
            raise ValueError("Invalid graph version")
        graph = self.repository.get_graph(version)
        if graph.get("graph_version") != version:
            raise ValueError("Repository returned a different graph version")
        return graph

    def health(self):
        try:
            graph = self.graph()
            ready = True
            count = {"nodes": len(graph.get("nodes", [])), "edges": len(graph.get("edges", []))}
        except Exception:
            ready, count = False, {}
        semantics = self.semantics()
        known_methods = {"deterministic_source_extraction", "curated_graph_import"}
        method = semantics.get("method")
        construction = (method if semantics.get("available") and isinstance(method, str)
                        and method in known_methods else "unknown")
        return {"status": "ready" if ready else "unavailable", "backend": self.backend,
                "graph_version": self.graph_version, "graph": count,
                "bundle_profile": self.bundle_profile,
                "graph_construction": construction,
                "semantic_report_available": semantics.get("available", False),
                "semantic_source_kind": semantics.get("source_kind") if semantics.get("available") else None,
                "capture_finished_at": semantics.get("capture_finished_at") if semantics.get("available") else None,
                "scope": "pre_execution_constraint_assessment", "control_writes": False,
                "trajectory_prediction": False}

    def example(self):
        if self.example_path is None:
            raise FileNotFoundError("No example configured")
        return {"notice": "示例输入仅用于演示或历史回放，不代表当前现场实测状态。",
                "request": _strict_json(self.example_path.read_text(encoding="utf-8-sig"))}

    def evaluate(self, request):
        required = {"command", "snapshot", "history", "graph_version"}
        if not isinstance(request, dict) or not required.issubset(request):
            raise ValueError("Request requires command, snapshot, history, graph_version")
        if set(request) - required:
            raise ValueError("Unsupported request fields")
        if not isinstance(request["graph_version"], str) or not request["graph_version"] or len(request["graph_version"]) > 160:
            raise ValueError("Invalid graph version")
        status = 200
        try:
            graph = self.graph(request["graph_version"])
        except Exception:
            status = 503
            result = {"schema_version": "1", "decision": "INDETERMINATE",
                      "graph_version": request["graph_version"], "constraints": [],
                      "query_trace": [], "evidence": [],
                      "input_issues": [{"code": "graph_backend_unavailable_or_invalid"}],
                      "completeness": {"complete": False,
                                       "gaps": ["graph_backend_unavailable_or_invalid"],
                                       "physical_safety_assessed": False}}
        else:
            evaluator = self.evaluator_factory(self.bundle_dir, graph_data=graph)
            result = evaluator.evaluate(request["command"], request["snapshot"],
                                        request["history"], request["graph_version"])
        record = self.records.append(request, result, backend=self.backend,
                                     bundle_profile=self.bundle_profile)
        return status, record


def _loopback(host):
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def create_server(app, host="127.0.0.1", port=8080):
    """Build server. Non-loopback binds require an explicitly configured token."""
    if not _loopback(host) and not app.token:
        raise ValueError("Non-loopback listener requires an explicit access token")
    local_only = _loopback(host)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ICS-RISK"

        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, format, *args):
            # Never log Authorization, payloads, query strings or credentials.
            return

        def _response(self, code, value, content_type="application/json; charset=utf-8"):
            if isinstance(value, bytes):
                body = value
            else:
                body = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(body)

        def _gate(self, api=False, write=False):
            host_header = self.headers.get("Host", "")
            try:
                host_parts = urlsplit("http://" + host_header)
                valid_host = bool(host_parts.hostname) and not host_parts.username and not host_parts.password
                valid_host = valid_host and not host_parts.path and not host_parts.query and not host_parts.fragment
                valid_host = valid_host and host_parts.port == self.server.server_port
                if local_only:
                    valid_host = valid_host and _loopback(host_parts.hostname)
            except ValueError:
                valid_host = False
            if not valid_host:
                self._response(403, {"error": "untrusted_host"})
                return False
            if api and app.token:
                supplied = self.headers.get("Authorization", "")
                if not hmac.compare_digest(supplied.encode("utf-8"), ("Bearer " + app.token).encode("utf-8")):
                    self._response(401, {"error": "authentication_required"})
                    return False
            if write:
                origin = self.headers.get("Origin")
                if origin is not None and origin != "http://" + host_header:
                    self._response(403, {"error": "cross_origin_request_rejected"})
                    return False
                if self.headers.get("Sec-Fetch-Site") == "cross-site":
                    self._response(403, {"error": "cross_origin_request_rejected"})
                    return False
            return True

        def do_GET(self):
            parsed = urlsplit(self.path)
            path = parsed.path
            if not self._gate(api=path.startswith("/api/")):
                return
            assets = {"/": ("index.html", "text/html; charset=utf-8"),
                      "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                      "/style.css": ("style.css", "text/css; charset=utf-8")}
            try:
                if path in assets:
                    filename, mime = assets[path]
                    self._response(200, (WEB_ROOT / filename).read_bytes(), mime)
                elif path == "/api/health":
                    result = app.health()
                    self._response(200 if result["status"] == "ready" else 503, result)
                elif path == "/api/graph":
                    query = parse_qs(parsed.query)
                    try:
                        result = app.graph(query.get("version", [None])[0])
                    except Exception:
                        self._response(503, {"error": "graph_backend_unavailable_or_invalid"})
                        return
                    self._response(200, result)
                elif path == "/api/example":
                    self._response(200, app.example())
                elif path == "/api/semantics":
                    self._response(200, app.semantics())
                elif path == "/api/records":
                    self._response(200, {"records": app.records.list()})
                elif path.startswith("/api/records/"):
                    self._response(200, app.records.get(path.removeprefix("/api/records/")))
                else:
                    self._response(404, {"error": "not_found"})
            except FileNotFoundError:
                self._response(404, {"error": "not_found"})
            except ValueError:
                self._response(400, {"error": "invalid_request"})
            except Exception:
                self._response(500, {"error": "service_error"})

        def do_POST(self):
            if not self._gate(api=True, write=True):
                return
            if self.path != "/api/evaluate":
                self._response(404, {"error": "not_found"})
                return
            if self.headers.get_content_type() != "application/json":
                self._response(415, {"error": "application_json_required"})
                return
            try:
                if self.headers.get("Transfer-Encoding"):
                    raise ValueError("Transfer-Encoding is not supported")
                length = int(self.headers.get("Content-Length", "-1"))
                if length < 0:
                    raise ValueError("Content-Length is required")
                if length > MAX_REQUEST_BYTES:
                    self._response(413, {"error": "request_too_large"})
                    return
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("Incomplete body")
                request = _strict_json(raw.decode("utf-8"))
                status, record = app.evaluate(request)
                self._response(status, record)
            except (ValueError, UnicodeDecodeError):
                self._response(400, {"error": "invalid_request"})
            except OSError:
                self._response(500, {"error": "record_write_failed"})
            except Exception:
                self._response(500, {"error": "evaluation_service_error"})

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def serve(app, host="127.0.0.1", port=8080):
    with create_server(app, host, port) as server:
        server.serve_forever()
