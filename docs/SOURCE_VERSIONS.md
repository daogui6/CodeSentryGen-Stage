# 版本来源与记录口径

本仓库以阶段源码快照组织代码和证据。当前 Git 历史记录阶段导入及后续维护，早期实现通过下列精确来源提交追溯。

## 来源提交

原开发仓库：[daogui6/CodeSentryGen-Pilot](https://github.com/daogui6/CodeSentryGen-Pilot)。

| 固定来源 | 按功能取用的内容 |
| --- | --- |
| [8e3b9376f62fe886aad1fb28597eda902efd8ffa](https://github.com/daogui6/CodeSentryGen-Pilot/commit/8e3b9376f62fe886aad1fb28597eda902efd8ffa) | 早期核心、六包 KB、Candidate/Proposal 接口及相应运行输入 |
| [cc81aaf599c12d85ac36c251b40591744ed94cb7](https://github.com/daogui6/CodeSentryGen-Pilot/commit/cc81aaf599c12d85ac36c251b40591744ed94cb7) | API History 扩充、11 包目录和审核准备样例及工具 |
| [34d43873435d49da6b928f53a76fdb316118a884](https://github.com/daogui6/CodeSentryGen-Pilot/commit/34d43873435d49da6b928f53a76fdb316118a884) | 多来源版本范围修复、必要消费者兼容与适用回归 |

上述来源引用用于定位相关文件。当前阶段的实际纳入范围见 [STAGE_SCOPE](STAGE_SCOPE.md)。

## 阶段整理改动

| 文件 | 整理方式 |
| --- | --- |
| [范围修复汇总](../output/osv_multisource_repair_v2_20261011/summary.json) | 保存带来源标识的范围统计摘录 |
| [范围修复回归](../tests/test_osv_multisource_release_ranges.py) | 保留适用于当前阶段的原测试断言 |
| [AVCS overlap 消费者](../src/evaluate_avcs_overlap.py) | 在早期实现中接入两个范围不确定性处理修改点 |

AVCS 消费者中的两个兼容点分别为：不支持的版本表达式保留未知交集；版本暴露为未知时进入 version_range_requires_review 状态。范围回归的覆盖以当前 tests 中的适用断言为准。

README、阶段范围、维护规范和复现说明由当前文档版本维护。设计参考原文及 output 下历史 Markdown 仅增加阅读定位，原始正文、数值和结论保留。

## 验收基线

2026-10-24 的代表性离线验收对应[功能基线 442d93b8c5729324ddc1e3db2fc206faece8e8ab](https://github.com/daogui6/CodeSentryGen-Stage/commit/442d93b8c5729324ddc1e3db2fc206faece8e8ab)，Git 树为：

```text
befe2833bc52d08975b9094c42b468c9848ee300
```

该基线包含 897 个文件。首次导出产生的 Windows 换行转换已在此基线恢复。后续文档修订沿用该功能源码，文档版本由对应 Git 提交记录；新增文档会改变文件数和完整树哈希。

## 历史结果的阅读方式

- [总体设计](../CodeSentry_Gen_Temporal_Dependency_Risk_v2_CCF-A.md)保留目标方案原文；实际实现以当前源码、Schema 和阶段说明为准。
- output 中的表格和字段对应各文件记录的输入。pre_mismatch 与后续声明一致性增强结果采用不同口径，分别解释。
- 早期真实生成负对照输入用于既有功能验证。历史文件名中的 100 与后续正式评测的 Test100 有不同的数据集含义。
- 部分语义片段仍保留上游工件的路径和哈希引用；对应历史材料未全部收集到本快照。当前 Proposal 接口验收使用已保存片段组成的临时上下文，覆盖范围见 [VALIDATION](VALIDATION.md)。

当前功能验收、历史记录和正式主实验按各自证据范围使用。
