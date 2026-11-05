# ICS-RISK

面向 GRFICS / TenEast 液位设定值写请求的图谱驱动执行前约束评估系统。包含图谱构建、图谱查询、约束量化、评估 API、中文页面、记录与回放测试。

当前版本不向 PLC/SCADA 下发控制指令，不预测过程轨迹，不把未核实规则当成物理安全边界。`INDETERMINATE` 是明确的评估结果，不是服务故障的代名词。

## 本地运行

需要 Python 3.10 或更高版本；核心和网页使用标准库，无需安装数据库即可运行演示。先进入仓库目录：

```sh
python -m unittest discover -s tests -v
python -m ics_risk validate
python -m ics_risk query
python -m ics_risk evaluate --input examples/request.json
python -m ics_risk serve
```

浏览器访问 `http://127.0.0.1:18081`。页面可查看图谱、编辑完整评估输入、查看逐项结果、证据和查询路径、浏览每次评估记录。

默认演示包 `examples/demo_bundle` 是重新构造的合成证据，版本 `lvsp-demo-v1`，不是现场实时数据。示例显示四项通过、最小操作间隔未启用，所以总体为 `INDETERMINATE`。真实证据包通过 `ICS_RISK_BUNDLE` 指定，不能用演示包替代。

## 使用 Neo4j

本版针对实验室已有 Neo4j 5.20 使用 HTTP 事务接口。凭据通过环境变量传入，不放入代码或命令行参数。参照 `.env.example` 设置环境；程序不会自动加载 `.env` 文件。

```sh
python -m ics_risk --bundle /path/to/private/lab_bundle validate
python -m ics_risk --bundle /path/to/private/lab_bundle publish-graph
python -m ics_risk --bundle /path/to/private/lab_bundle --backend neo4j query
python -m ics_risk --bundle /path/to/private/lab_bundle --backend neo4j serve
```

只有 `publish-graph` 显式写库；评估服务只读取图。发布使用独立 scope 和不可变版本，重复发布相同内容幂等，不覆盖旧图。同版本内容变化会拒绝，必须审核后使用新版本。数据库故障不会静默切换到 JSON。

## 项目布局

```text
ics_risk/
  graph_build/       审定知识、证据验证与发布
  graph_query/       JSON / Neo4j 存储和语义查询
  quantification/    范围、幅度、间隔、前置条件计算
  service.py         HTTP 接口
  records.py         逐次评估记录
  web/               中文界面
lvsp_eval/           既有评估编排、执行框架适配及回放兼容入口
examples/           合成演示证据和输入
tests/              独立用例、回归、服务与图后端测试
docs/               架构、接口、证据和部署说明
runtime/            私有证据和记录（不提交 Git）
```

详见 [架构与研究边界](docs/architecture.md)、[图谱模块](docs/graph.md)、[接口](docs/api.md)、[证据策略](docs/evidence-policy.md)、[部署](docs/deployment.md)。

## 维护原则

每次代码调整经过本地回归及 GitHub Actions；研究规则变化要记录来源、类别、参数核实状态及适用版本。生产证据、登录凭据、原始操作日志不进入公开仓库。评估结果按 UUID 保存输入、输出、版本、证据与查询路径，便于毕设复现与审查。
