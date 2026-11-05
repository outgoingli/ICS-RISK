# 从真实来源提取语义与生成图谱

## 纠正旧版本的范围

最初版本读取人工整理的 `graph.json`，检查结构/证据并导入Neo4j。它没有自动分析PLC源码，不能称为自动知识抽取。已有部分真实历史请求用于日志回放；公开的合成示例只用于测试，这两类材料不能互相替代。

新增流水线以真实采集材料为输入，不读取政策包里的seed graph，也不使用变量名称作为PV/SP角色的答案。代码只能识别明确支持的源码结构；未知结构和映射冲突会拒绝生成可用于该评估的图谱。

## 输入与来源

- SCADA：经认证读取真实点位API，保存每个响应原始字节、独立采集时间、数据源目标主机和端口。数据源只保存明确允许的字段投影。
- PLC：活动程序指针、ST原始文件、Modbus服务端驱动、远程I/O驱动、配置及编译变量映射。采集结束再次比对程序指针与源码。
- 仿真器：桥接代码、安装中的寄存器上下文实现。它们将仿真生产字段连接到通信寄存器。
- 状态：按提取出的地址计划仅执行FC01/03/04读取，并保存实际请求、响应、解码值、壁钟与单调时钟。仿真器仅接收read请求。

源码、地址、阈值和观测均保存在私有证据包及报告中。图中仍只有五类节点、六类关系，不存过程数值。

## 提取算法

1. 解析已配置的PROGRAM实例及变量声明。声明初值不作为实测状态。
2. 在受限ST子集中内联函数、传播符号表达式，识别“同缩放操作数之差 × 增益 + 执行器反馈 → LIMIT → 逆编码输出”的结构。输入/内存绑定与实际数据流共同决定PV/SP角色；函数或变量改名不改变角色识别依据。
3. 分析顺序赋值、最终覆盖与布尔门控。被覆盖、存在无法分析的额外门控或语义不明的输出不能自动认定生效。
4. 从Python桥接AST提取生产JSON字段、编码和寄存器位置；结合远程I/O配置、驱动中的累积映射与编译变量绑定追溯到PLC输入。库地址转换也由已安装源码核查，不假定通用偏移。
5. 匹配SCADA数据源目标与捕获的PLC身份，按完整通信身份核对点位，核查设定点的启用、可写性和缩放。
6. 自动生成点位、变量、回路及关系，并附来源引用。SCADA提供点位（EXPOSES），PLC承载变量（HOSTED_BY）；二者不再被当成同一个组件。

物理含义来自仿真器生产字段契约，例如 `outputs.liquid_level`，不是从几列数值的相关性猜出来的。缩放值不能单独证明单位，工程单位仍来自明确的指令契约。源码分析也不能证明正在执行的二进制与源文件完全一致。

## 约束与状态如何接入

四种计算模板保持不变。已有研究要求和实现限制以独立政策包提供，包含参数、来源和核实状态；不会根据采样数值自动发明安全阈值。约束操作数重新绑定到提取出的角色，图中相关边由程序生成。

`e_stop` 是已有研究前置条件要求的仿真JSON依赖，不是PLC程序发现的门控。报告明确标为 `declared_policy_dependency`；准备输入时必须从实际响应核实该字段存在且为布尔值。不能把这部分宣称为纯源码自动发现。

采集计划包含PV、SP、控制输出、执行器反馈和运行门控。当前已有约束计算实际使用SP、运行门控与急停状态；PV与执行器数据用于语义/状态核对。尚无核实依据的PV物理风险阈值不会被添加。当前仍不进行过程轨迹预测。

## 运行

在授权实验主机中，通过环境提供 `ICS_RISK_SCADA_BASE`、`ICS_RISK_SCADA_USER`、`ICS_RISK_SCADA_PASSWORD`；不要把凭据写入命令行或Git。

```sh
python -m ics_risk capture --output /private/capture_unique
python -m ics_risk extract --capture /private/capture_unique \
  --policy-bundle /private/reviewed_policy_bundle --output /private/extracted_unique
python -m ics_risk --bundle /private/extracted_unique collect --output /private/observations_unique.json
python -m ics_risk --bundle /private/extracted_unique prepare-request \
  --observations /private/observations_unique.json --candidate-raw 29163 \
  --output /private/candidate_unique.json --mode replay
python -m ics_risk --bundle /private/extracted_unique publish-graph
python -m ics_risk --bundle /private/extracted_unique --backend neo4j evaluate --input /private/candidate_unique.json
```

命令中的候选数值是待评估输入，不是实测值，也不会下发。`replay` 明确使用观测结束时刻作为评估参考时间；`current` 使用调用时刻，观测过期应返回未知，不能改写旧数据时间使其看起来新鲜。

## 验证边界

重命名、交换操作数、改变偏移、删除证据、额外覆盖与损坏报文等独立测试使用自写合成夹具，它们只验证软件行为。现场验证使用单独保存的真实源码、配置和原始报文。当前实验环境只有一个已核查部署实例，不能把软件测试数量当作跨工厂泛化能力或抽取准确率。

小批量只读观测可验证可达性、解码和状态来源，不能独立验证命令的过程影响、事故概率或安全边界。
