# 评估 API 与展示界面

本服务把图谱读取、纯约束计算和记录保存连接起来。它不负责 PLC 通信、不执行候选指令，不替换现有保护或恢复机制。当前不会预测液位轨迹，也不会把约束结果折算成未经验证的综合安全分数。

## 启动接口

```python
from ics_risk.service import RiskApplication, serve

app = RiskApplication(
    bundle_dir="/path/to/verified/bundle",
    repository=graph_repository,  # get_graph(version) -> JSON graph
    records_dir="/path/to/private/records",
    example_path="/path/to/example-request.json",
    backend="neo4j",             # explicitly selected; no automatic fallback
    token=None,                   # read an access token from environment if required
)
serve(app, host="127.0.0.1", port=8080)
```

`create_server(app, host, port)` 返回标准库 `ThreadingHTTPServer`，适合在测试中使用随机端口或由外层管理生命周期。非回环地址监听必须配置访问令牌。默认建议保持回环监听，通过 SSH 转发访问；标准库服务不提供 TLS、用户分级权限或互联网生产网关能力。

配置令牌后，所有 `/api/` 请求需要 `Authorization: Bearer <token>`。网页令牌输入仅保留在当前页面内存，不写入浏览器持久存储。令牌不得放在查询参数中。请求 `Host` 必须包含服务端口；本地监听只接受回环主机名或地址。POST 仅接受同源浏览器请求或无 Origin 的明确 API 客户端，必须使用 JSON，正文不超过 1 MiB。

## 端点

| 方法和路径 | 作用 |
| --- | --- |
| `GET /` | 中文工作台，展示图谱、评估输入、逐项结果、证据和历史记录 |
| `GET /api/health` | 当前后端、图版本、图是否可读、`bundle_profile`；不表示现场过程健康 |
| `GET /api/graph?version=...` | 读取指定版本的完整图快照；默认使用配置版本 |
| `GET /api/example` | 示例请求及“非当前实测”说明；保留原始时间戳 |
| `POST /api/evaluate` | 使用指定图版本评估并保存记录 |
| `GET /api/records` | 最近最多 50 条本地记录摘要 |
| `GET /api/records/<record_id>` | 查询一次完整评估记录 |

### 评估请求

正文严格包含四个字段：

```json
{
  "command": {},
  "snapshot": {},
  "history": {},
  "graph_version": "lvsp-constraints-v1"
}
```

字段内部使用评估核心的输入契约。`command` 为候选请求，`snapshot` 为独立观测，`history` 保留覆盖范围与完整性；本服务不修改其值或时间戳。实际可运行例子由 `/api/example` 返回。

返回完整记录：

```json
{
  "record_id": "a generated 32-character hexadecimal identifier",
  "recorded_at": "UTC storage time, distinct from observation time",
  "backend": "neo4j",
  "execution": "assessment_only_no_control_write",
  "request": {"command": {}, "snapshot": {}, "history": {}, "graph_version": "..."},
  "result": {
    "decision": "INDETERMINATE",
    "constraints": [],
    "query_trace": [],
    "evidence": [],
    "completeness": {"complete": false, "physical_safety_assessed": false}
  }
}
```

HTTP 200 表示评估记录已经产生，并不意味着请求获准执行。具体判定读取 `result.decision`：`ALLOW`、`BLOCK`、`INDETERMINATE`。

图后端不可用、版本错误或快照无法读取时，不回退 JSON，不调用计算核心伪造可用结果；返回 HTTP 503 和已保存的 `INDETERMINATE` 记录。原始数据库异常不会返回给调用方，避免泄漏连接信息。JSON 格式或顶层契约错误返回 400，不视为有效评估。记录写入失败返回 500，不声称记录已保存。

## 记录与范围

记录在外部目录以 UUID 独占创建，包含原始输入和完整结果。记录目录应保留在实验环境，不提交公开仓库。当前文件存储为追加式应用行为，不是防篡改审计系统；具备文件权限的人仍可修改它。页面只提供“评估”，不提供 PLC 执行或恢复按钮。

健康接口、页面和记录明确显示数据配置类型：`bindings.bundle_profile` 只有显式为 `synthetic_demo` 或 `archived_lab_evidence` 时，才分别标记合成演示或实验归档证据；缺少 bindings、缺少该字段或字段值无法识别时均标记 `unclassified`，不推断为归档或实时数据。图可读仅表示图后端就绪，不表示配置来源已核实。演示配置中的最小间隔规则仍未启用，因此其余四项通过时仍会返回评估不完整。
