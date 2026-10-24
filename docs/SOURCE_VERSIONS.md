# 版本来源与记录口径

本仓库是功能阶段源码快照。当前提交记录导入和维护，原始实现与历史工件按下列固定来源追溯。

| 来源 | 用途 |
| --- | --- |
| [整合主线 3b9ff778](https://github.com/daogui6/CodeSentryGen-Pilot/commit/3b9ff7789078b14f4c91a80c3c264ab14449b7ef) | 当前非第三层核心源码、共享 IR、时间与版本语义及依赖配置 |
| [阶段基线 2bcddf01](https://github.com/daogui6/CodeSentryGen-Stage/commit/2bcddf01e7651f02a2e5b345160a2380d822be9c) | 既有第三层范围、六包 KB、Candidate/Proposal 和历史样例 |
| [初始准备快照 8b9b20d4](https://github.com/daogui6/CodeSentryGen-Pilot/commit/8b9b20d42a62fb2e33a96b0c246dc2e0177c0e1a) | 早期阶段材料的分发来源 |

逐文件清单 [STAGE_FILE_MANIFEST.json](STAGE_FILE_MANIFEST.json) 保存 Git blob、SHA-256、来源提交和来源路径。新运行脚本与说明文档标为分发配套文件；它们不被描述为原始历史证据。

NumPy 的旧范围约束存档从整合主线 `output/osv_multisource_repair_v2_20261011/recovered_inputs/output/step7_osv_constraints_v0/numpy.json` 按原始字节恢复到常规读取路径。该文件是旧范围基线，不是重生成的历史结果。源路径、目标路径和原 Git blob 均在清单中登记。

源码、数据、日志日期均按实际内容保留。阶段快照没有对应的全部早期 Git 历史；涉及冻结提交与历史证据的引用，应转到其原始精确来源，而不能以本仓库的新提交哈希替代。

`.gitattributes` 在本快照关闭自动文本换行转换，使 Windows 与其他系统检出时保留同一文件字节。历史设计文档和输出正文保持原有证据口径，阅读说明与当前指南分开维护。
