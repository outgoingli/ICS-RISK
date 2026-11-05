# 图谱构建与查询模块

当前模型只有 Component、Point、Variable、ControlLoop、Constraint 五类节点，EXPOSES、MAPS_TO、HOSTED_BY、IN_LOOP、APPLIES_TO、REQUIRES 六类关系。图谱表达语义映射、约束适用范围与计算依赖，不推断因果效应或过程安全。

## 构建

`ics_risk.graph_build.build_graph(bundle_dir)` 从人工审定的 `config/graph.json` 和 `config/provenance.json` 构建候选图。它检查节点/关系类型、方向、ID、属性白名单、证据引用、路径范围和证据文件 SHA256。匹配 SHA256 表示文件与清单一致，不意味着来源真实或科学结论已验证。

所有阈值、点位地址、缩放比例、当前值与历史值留在图外。约束参数必须在 `constraints.json` 中单独核实。未核实的最小间隔节点可以保留，是否启用由约束配置决定。构建器不会自动读取 PLC 推断新边，也不会从观察数据生成规则。

```python
from ics_risk.graph_build import build_graph
from ics_risk.graph_query import Neo4jRepository

graph = build_graph(bundle_dir)
repository = Neo4jRepository.from_env()
publication = repository.publish(graph)
```

`publish` 是显式写入 Neo4j 的构建操作。它先验证结构，再将一个版本的节点与关系放进同一事务。相同版本和相同内容幂等返回 `unchanged`；同版本不同内容拒绝，修改应使用新版本。它没有删除、覆盖旧版本、清库或控制过程设备的操作。

## Neo4j 存储和隔离

每个领域节点直接使用五种领域标签之一，关系直接使用六种关系类型之一，没有额外领域节点。存储层增加 `_ics_scope`、`_ics_version`、`_ics_graph_sha256`、`_ics_schema_version`、`_ics_key` 字符串元数据；一个实际 Component 节点保存 `_ics_version_key`。元数据用于隔离项目、版本寻址和完整性校验，不是过程数值。

构建操作建立每种标签下 `_ics_key` 的唯一约束，以及 Component 的 `_ics_version_key` 唯一约束。一个版本的首个 Component 作为事务锁，防止两个发布者同时写入不同内容。该节点仍是原图中的实际组件，不增加第六类节点。历史图没有这些属性，因此不在查询和导入作用域内。不要在 Neo4j Browser 中手工修改已发布版本；读回摘要不一致会拒绝评估。

## 查询

```python
from ics_risk.graph_query import JsonRepository, Neo4jRepository

local = JsonRepository("bundle/config/graph.json")
database = Neo4jRepository.from_env()
graph_data = database.get_graph("lvsp-constraints-v1")
context = database.semantic_context("point:level_sp", "lvsp-constraints-v1")
```

两个后端返回相同五类节点、六类关系结构。Neo4j 后端用一条带 `scope` 与 `version` 参数的只读查询取得完整版本，并核对标签、关系端点、版本标识与内容摘要，再在冻结快照中执行显式路径查询。逐项路径保留在 `query_trace`。这种做法适合目前的小型回路图，保证一次评估不在不同查询间混用图版本；它不是依靠 Neo4j 自动推理。

语义查询路径为 `Point <-EXPOSES- Component`、`Point -MAPS_TO-> Variable`、`Variable -HOSTED_BY-> Component`、`Variable -IN_LOOP-> ControlLoop`，再逆向查找 `APPLIES_TO`，顺向查找 `REQUIRES`。数值计算从 snapshot/history 中读取对应变量。数据库不可用、版本缺失或图损坏会抛出明确异常，不悄悄改用本地旧图。上层评估服务应把异常记录为不完整，不能当成允许执行。

环境变量：`ICS_RISK_NEO4J_URI`（HTTP 地址）、`ICS_RISK_NEO4J_USER`、`ICS_RISK_NEO4J_PASSWORD`、`ICS_RISK_NEO4J_DATABASE`、`ICS_RISK_NEO4J_SCOPE`。密码只通过部署环境注入；不放进 URL、命令参数、源码或评估记录。HTTP 应限于受控实验网络或 SSH 隧道，跨不可信网络使用 HTTPS。

本适配器针对实验环境 Neo4j 5.20 使用标准库 HTTP 事务接口。该接口从 5.26 起弃用；升级数据库前应改用 Bolt 或 Query API，不能假定未来版本仍支持它。事务提交/回滚方式依据 [Neo4j HTTP 事务文档](https://neo4j.com/docs/http-api/current/transactions/)，唯一约束依据 [Neo4j 约束文档](https://neo4j.com/docs/cypher-manual/4.4/constraints/examples/)。

## 验证与限制

`python -m unittest discover -s tests -p test_graph_modules.py -v` 覆盖证据变更、非法节点/边、数值混入、路径缺失、版本错误、Neo4j 数据损坏、命名空间越界、幂等发布、冲突回滚和错误信息脱敏。测试使用显式合成数据，不替代现场集成验证。

现场验证应在独立 scope 下依次执行：构建证据包 → 首次发布 → 相同内容再次发布 → 读回摘要比对 → 与 JSON 后端查询/评估结果比对 → 用内存中的不同内容尝试相同版本，确认拒绝且原版本摘要未变。不要用删改现场图的方式验证故障；删除关系等破坏性测试在临时图副本中完成。
