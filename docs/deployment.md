# 部署与维护

## 数据与代码

GitHub 维护应用代码、测试、合成演示和文档。现场代码目录与私有证据、环境变量、记录目录分别管理。不要向公开仓库提交 `.env`、登录信息、真实采集日志或第三方原始代码归档。

建议目录：

```text
ICS-RISK/                 Git 工作副本
ICS-RISK-private/
  lab_bundle/config/      graph / bindings / constraints / provenance
  lab_bundle/evidence/    本地核实的证据副本
  normal_02_request.json  历史回放输入（保留原时戳）
  capture_unique/         新采集的原始来源与清单
  extracted_unique/       从真实来源生成的图谱、报告与图外配置
  observations_unique.json  按提取地址采集的原始只读报文
  candidate_unique.json   与实测分离的未执行候选请求
  service.env             仅当前用户可读的服务配置
  records/                每次评估的输入、结果、证据路径
```

## 连接现有数据库

先核对目标数据库版本、旧节点/关系计数以及部署程序身份。当前HTTP适配器针对 Neo4j 5.20 已设计，不需要替换或重启现有数据库。使用独立 `ICS_RISK_NEO4J_SCOPE`，不要导入到旧图的命名范围。

在授权账户的环境中提供 `.env.example` 所列变量；这份示例不包含凭据。CLI 不自动读取文件，部署工具需要显式提供环境。

```sh
python -m ics_risk --bundle /private/lab_bundle validate
python -m ics_risk --bundle /private/lab_bundle publish-graph
python -m ics_risk --bundle /private/lab_bundle --backend neo4j query
python -m ics_risk --bundle /private/lab_bundle --backend neo4j evaluate --input /private/normal_02_request.json
```

发布后核对所选包的图摘要及节点关系计数，重复发布应返回 unchanged。旧人工图是12节点14关系，本次来源提取图是20节点29关系，不能混用验收值。不要为了测试而删除线上边；缺边/数据库异常等情况在临时测试夹具验证。

## 常驻服务

仓库提供 Dockerfile；现场也可用独立服务管理器运行主机 Python。容器镜像不包含真实证据或凭据。

```sh
docker build -t ics-risk:0.2.0 .
docker run -d --name ics-risk-app --restart unless-stopped \
  --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --env-file /private/service.env \
  -v /private/extracted_unique:/data/bundle:ro \
  -v /private/candidate_unique.json:/data/example.json:ro \
  -v /private/records:/data/records:rw \
  ics-risk:0.2.0 serve
```

环境中将 bundle/records/example 路径设为容器内对应路径，服务监听127.0.0.1:18081。镜像以UID/GID 1000运行；部署时根据实际账户匹配记录目录权限，可用`--user`覆盖。`--network host` 示例适用于 Linux 仿真主机。

通过已经授权且验证主机密钥的SSH会话转发18081端口，再在本机打开 `http://127.0.0.1:18081`。本地和远端端口保持一致；服务校验 Host 和 Origin。不要直接把未配置令牌的服务暴露到公网。显式非本地监听必须设置 `ICS_RISK_API_TOKEN`，浏览器输入令牌仅保留在页面内存。

## 更新与回滚

1. 修改代码并跑完整测试；检查公开文件不包含私有证据或凭据，提交 Git。
2. 按已审阅提交构建新的应用镜像。先验证图谱读回、历史回放判定和健康接口。
3. 仅替换 `ics-risk-app` 应用容器，保留原镜像标签及证据/记录目录供回滚。不操作 PLC、SCADA、仿真器或原保护进程。
4. 规则或图结构变更必须采用新版本，并同步审核绑定和证据；不得复用旧版本改内容。

健康接口表示图后端可读取，不代表所有输入和约束完备，更不代表现场安全。页面中的历史请求用于演示评估流程，不会重新发出控制指令。

## 服务器不能直接访问 GitHub 时

不要改动全局网络配置来迁就一次部署。可从已推送的本地仓库创建 Git bundle，经已授权 SSH 传到私有部署目录，再在服务器工作副本读取它；提交身份保持一致。

```sh
git bundle create ICS-RISK.bundle main
# 将 bundle 传至服务器后，在目标 Git 工作副本中执行：
git fetch /private/ICS-RISK.bundle main:refs/remotes/origin/main
```

更新工作树前检查现有修改，按已审核提交部署；不要覆盖未知用户改动。部署后记录提交ID、镜像身份、图版本、回放结果。此流程属于手动维护，不是已配置的 GitHub 自动部署流水线。
