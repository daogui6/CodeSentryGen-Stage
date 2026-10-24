# 实现范围与研究阶段

本快照以最新共享核心配合既有第三层规则组织源码。它描述分发范围，不代表完整原始研发历史，也不将阶段导入日期当作算法开发日期。

## 核心实现

THO、依赖提取与包身份、项目依赖事实、AVCS 第一层和第二层、SCEG 2.1、统一 Risk Card、时间视图及相关生成/恢复辅助实现，取自整合主线 `3b9ff7789078b14f4c91a80c3c264ab14449b7ef`。文件级来源见 [清单](STAGE_FILE_MANIFEST.json)。

当前实现保留：作用域遮蔽与动态 import 的不确定性、registry 新鲜度与来源哈希、生成时点证据、锁文件与安装目标上下文、API 版本排除证明、OSV 多来源一致性、formal/auxiliary 区分和共享 IR。它不是早期 v0 算法的重命名版本。

SCEG 2.1 是当前共享 IR；历史 `sceg_schema_v0` 和 v0 工件用于兼容与历史追溯，分别解释。

## 第三层范围

第三层保留此前阶段快照中的六包 KB、既有受限静态 Trigger 匹配、HITL Candidate、语义证据片段及 LLM Proposal 样例。Candidate 的审核门保持 `requires_review`、`review_required=true`、`final_truth_created=false`，审核人与审核日期为空。

本快照未纳入：逐漏洞人工审核结论、后续知识准入与扩展冻结成果、新事实图原型及联合 Trigger Contract 求解器。范围解析回归使用的 KB 记录转换函数属于运行配套源码，不携带审核记录，也不授权知识准入。

这份快照的第三层边界停在审核准备：候选与 Proposal 不能作为经过人工确认的 Ground Truth。

早期 RQ1 的80条 Candidate Fact 正确性/Trigger Utility 抽样复核属于已介绍的前期工作，相关原始材料继续保留。其单位是候选事实，不是后续逐漏洞 Trigger 审核，不能将这80条复核解释为后续漏洞知识准入已完成。

## 知识与版本范围证据

| 材料 | 口径 |
| --- | --- |
| 六包 Package KB | 既有规则案例，不等于全量漏洞 KB |
| 11 包 OSV 目录 | 208 个按身份归并的漏洞组 |
| 修复前范围存档 | 134 resolved / 74 unresolved |
| 当前范围重放 | 171 resolved / 37 unresolved |

resolved 只描述版本证据解析状态。API History 中 unknown、blocked 的边界继续保留；没有严格排除证明时不能仅凭“某版本存在此 API”推断此前版本均不存在。

## 分发与实验边界

分发包含核心源码、运行依赖、必要 Schema、历史样例和离线回归。正式实验的全部冻结 authority 与原始全量研发记录不作为这份阶段快照的运行输入。统一正式入口保留其原有前置条件；当前验收脚本覆盖可分发的离线路径。

受控样例、历史 Pilot/负对照、范围证据重放和正式论文实验分别解释。控制路径跑通不等于新第三层检测准确率、召回率或正式新算法实验已经完成。
