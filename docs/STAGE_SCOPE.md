# 实现范围与研究阶段

本仓库是 CodeSentry-Gen 的阶段性源码版本。阶段边界为：核心依赖风险分析原型及既有规则已经形成，版本范围证据修复已完成，Candidate 与 LLM Proposal 接口可用于后续逐漏洞协作审核。

## 已纳入的实现

| 部分 | 实现与材料 | 当前解释边界 |
| --- | --- | --- |
| 依赖提取与包身份 | Python 依赖提取、import-to-distribution 映射、依赖声明上下文 | 包身份与可达性判断依赖对应上下文证据 |
| THO | 时态状态、安装可达性与 Risk Card | 时间证据不足时保留不确定性 |
| AVCS 第一层 | API、依赖声明与历史发布证据形成的版本约束 | API 历史证据不完整时不能推导严格版本边界 |
| AVCS 第二层 | 漏洞影响范围与可行版本集合的暴露分析 | resolved/unresolved 描述版本证据解析状态 |
| 既有第三层 | 六包案例支持的受限静态 Trigger 规则 | 命中属于风险辅助证据，仍需结合输入来源及审核 |
| SCEG v0 | 轻量证据图、显式关系和 Risk Card 关联 | 本阶段数据结构以 v0 Schema 与源码为准 |
| 知识与审核准备 | 六包 KB、API History、11 包目录、Candidate、语义片段与 LLM Proposal | 候选分类与人工审核状态分别记录 |
| 范围证据修复 | 多来源版本归一化、冲突与缺失处理、适用回归测试 | 保留来源差异与未知状态 |

研究总体设计文档中的 v2.1 为目标方案版本；本阶段实际采用的 SCEG 数据结构为轻量 v0。新第三层的联合语义求解属于后续研究方向，当前源码中的第三层能力以既有规则为准。

## 知识数据的统计口径

六包 Package KB 保存既有案例和规则，11 包 OSV 目录保存按漏洞身份归并后的证据。两者分别服务于规则示例和范围证据整理。

| 版本范围证据 | 漏洞组数 | resolved | unresolved |
| --- | ---: | ---: | ---: |
| 初始归一化存档 | 208 | 134 | 74 |
| 多来源范围修复后 | 208 | 171 | 37 |

resolved 表示在当前证据与归一化规则下可解析的范围，不表示逐漏洞人工 Trigger 审核已经完成。部分 API History 仍存在 unknown 或 blocked 的下界状态，应保留对应不确定性。

## Candidate、Proposal 与人工审核

Candidate 聚合漏洞身份、版本证据和来源引用；LLM Proposal 提供候选语义分类及可选静态规则。人工审核门采用独立字段：

```json
{
  "status": "requires_review",
  "review_required": true,
  "final_truth_created": false,
  "reviewer": null,
  "reviewed_at": null
}
```

现有接口验收验证请求构建、格式约束、来源登记和审核门保持。已有 Proposal 的合并示例使用当前构造并标注的临时验收上下文，具体过程见[运行与验证说明](VALIDATION.md)。

## 结果的适用范围

本阶段已完成 Windows Python 3.10 环境中的代表性离线验收，覆盖六包 KB 与候选格式、既有规则、范围修复和四条 THO→SCEG 受控输入。结论限定对应输入、路径与环境。

output 中的历史摘要按原有数据集口径保留。四条受控输入、历史自然生成样本、hard negatives 和历史 pre_mismatch 结果分别解释；正式论文主实验和性能评估按独立实验设计开展。

阶段来源和整理改动见[版本来源与记录口径](SOURCE_VERSIONS.md)。
