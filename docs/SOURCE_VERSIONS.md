# 版本与来源

本仓库以功能快照组织源码、配置、样例和历史工件。Git 提交记录快照导入与维护；各文件的实现及证据来源按下列固定版本追溯。

| 来源 | 用途 |
| --- | --- |
| [整合主线 3b9ff778](https://github.com/daogui6/CodeSentryGen-Pilot/commit/3b9ff7789078b14f4c91a80c3c264ab14449b7ef) | 当前非第三层核心源码、共享 IR、时间与版本语义及依赖配置 |
| [样例基线 2bcddf01](https://github.com/daogui6/CodeSentryGen-Stage/commit/2bcddf01e7651f02a2e5b345160a2380d822be9c) | 六包 KB、静态 Trigger、Candidate/Proposal 和历史样例 |
| [输入与证据快照 8b9b20d4](https://github.com/daogui6/CodeSentryGen-Pilot/commit/8b9b20d42a62fb2e33a96b0c246dc2e0177c0e1a) | 样例和历史证据的分发来源 |

逐文件清单 [STAGE_FILE_MANIFEST.json](STAGE_FILE_MANIFEST.json) 保存 Git blob、SHA-256、来源提交和来源路径。新运行脚本与说明文档标为分发配套文件；它们不被描述为原始历史证据。

NumPy 的旧范围约束存档从整合主线 `output/osv_multisource_repair_v2_20261011/recovered_inputs/output/step7_osv_constraints_v0/numpy.json` 按原始字节恢复到常规读取路径。该文件是旧范围基线，不是重生成的历史结果。源路径、目标路径和原 Git blob 均在清单中登记。

源码、数据和日志中的日期保留原始含义，快照导入日期不代表算法开发日期。本仓库未复制全部原始 Git 历史；冻结提交与历史证据通过原始精确来源追溯，本仓库的提交哈希用于标识当前分发内容。

`.gitattributes` 在本快照关闭自动文本换行转换，使 Windows 与其他系统检出时保留同一文件字节。历史设计文档和输出正文保持原有证据口径，阅读说明与当前指南分开维护。
