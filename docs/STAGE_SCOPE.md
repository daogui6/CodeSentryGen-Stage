# 功能范围与数据说明

本文说明本版本的模块能力、知识材料、结果口径和运行条件。版本来源及文件校验信息见[源码来源](SOURCE_VERSIONS.md)。

## 核心实现

本版本包含 THO、依赖提取与包身份、项目依赖事实、AVCS 第一层和第二层、SCEG 2.1、统一 Risk Card、时间视图及生成/恢复辅助模块。文件级来源见[清单](STAGE_FILE_MANIFEST.json)。

依赖与风险分析处理作用域遮蔽、动态 import 的不确定性、registry 新鲜度与来源哈希、生成时点证据、锁文件与安装目标上下文、API 版本排除证明和 OSV 多来源一致性。结果通过共享 IR 关联，并区分 formal 与 auxiliary 输出。

SCEG 2.1 是当前共享 IR；历史 `sceg_schema_v0` 和 v0 工件用于兼容与历史追溯，分别解释。

## 第三层范围

第三层提供六包 KB、受限静态 Trigger 匹配、HITL Candidate、语义证据片段及 LLM Proposal 样例。Candidate 的审核门为 `requires_review`、`review_required=true`、`final_truth_created=false`，审核人与审核日期为空。

Candidate 和 Proposal 用于组织触发条件及其证据，不构成人工确认的漏洞 Ground Truth。范围解析回归中的 KB 记录转换函数用于格式兼容，不改变候选的审核状态。

本版本采用受限静态规则进行触发分析；事实图与联合 Trigger Contract 求解不属于本版本的功能。

RQ1 材料包含80条 Candidate Fact 的正确性与 Trigger Utility 抽样复核。该复核以候选事实为单位，用于评价事实提取和触发条件的关联性；其统计不等同于逐漏洞的人工 Trigger 审核或漏洞知识准入。

## 知识与版本范围证据

| 材料 | 口径 |
| --- | --- |
| 六包 Package KB | 既有规则案例，不等于全量漏洞 KB |
| 11 包 OSV 目录 | 208 个按身份归并的漏洞组 |
| 修复前范围存档 | 134 resolved / 74 unresolved |
| 当前范围重放 | 171 resolved / 37 unresolved |

resolved 只描述版本证据解析状态。API History 中 unknown、blocked 的边界继续保留；没有严格排除证明时不能仅凭“某版本存在此 API”推断此前版本均不存在。

## 复现与实验范围

本仓库包含核心源码、运行依赖、必要 Schema、样例和离线回归。`scripts/run_stage_validation.py` 使用已分发材料执行离线验收。正式实验还需要匹配的冻结 KB、协议和实验 authority；这些完整运行材料未随本版本分发，统一入口保留相应的前置检查。

受控样例、历史 Pilot/负对照、范围证据重放和正式论文实验采用各自的结果口径。离线验收验证接口兼容、证据语义及回归行为，不能据此推算检测准确率、召回率或正式实验结论。
