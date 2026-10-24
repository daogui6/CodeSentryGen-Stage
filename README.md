# CodeSentry-Gen

CodeSentry-Gen 分析 LLM 生成代码中的依赖风险，结合代码、包身份、历史发布与漏洞证据，输出可追溯的 Risk Card。

本版本包括依赖提取、时态包分析、API 与漏洞版本约束、静态 Trigger 分析，以及共享证据图和统一风险输出。模块通过 SCEG 关联代码、依赖、版本证据和 Risk Card。

| 组成 | 当前实现 |
| --- | --- |
| 依赖提取与包身份 | 统一包身份、Python 作用域与动态 import 证据、项目依赖事实 |
| THO | 生成时点存在性、当前 registry 观察、时间不确定性与 R0–R4 可达性 |
| AVCS 第一层 | API-to-Version、显式版本排除证据、声明/锁文件约束 |
| AVCS 第二层 | 离散发布版本暴露、OSV 多来源范围归一化与未知状态 |
| SCEG | 2.1 共享 IR、依赖投影、证据与风险关联；保留历史 v0 兼容入口 |
| 统一输出 | Risk Card v2.1、时间视图、formal/auxiliary 分类 |
| AVCS 第三层 | 六包的受限静态 Trigger 规则、Candidate、LLM Proposal 样例与待审核门 |

Candidate 和 LLM Proposal 表达待审核的触发条件候选，不能直接作为人工确认的 Ground Truth。本版本第三层的分析边界、数据口径及限制见[功能范围与数据说明](docs/STAGE_SCOPE.md)。

## 安装与试运行

使用 Python 3.10；Windows 本地和 Linux CPython 3.10.20 均已通过离线验证。首次安装依赖需要联网，下面的验证流程使用仓库内材料离线执行。

Windows 命令行，在仓库根目录逐行运行：

```bat
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -X utf8 scripts\run_stage_validation.py
```

Linux/macOS：

```bash
python3.10 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -X utf8 scripts/run_stage_validation.py
```

验证入口检查文件清单，并在临时副本中运行当前回归、六包 KB 验证、AVCS 分步计算、旧 Trigger、四条 THO/SCEG 2.1 控制输入及 11 包 OSV 重放。运行记录保存在 `output/local_validation/` 下，不覆盖历史工件，不调用模型或启动正式实验。

## 阅读入口

- [运行与验证](docs/VALIDATION.md)：命令、实际覆盖及结果边界。
- [功能范围与数据说明](docs/STAGE_SCOPE.md)：模块能力、数据口径和适用边界。
- [源码来源](docs/SOURCE_VERSIONS.md)：精确来源提交与字节校验。
- [逐文件清单](docs/STAGE_FILE_MANIFEST.json)：文件来源、Git blob 与 SHA-256。
- [总体设计参考](CodeSentry_Gen_Temporal_Dependency_Risk_v2_CCF-A.md)：问题定义和研究设计原文。

核心代码从 `src/run_pilot.py`、`src/build_sceg_ir_v21.py`、`src/run_step8_unified_avcs.py` 和 `src/finalize_sceg_ir_v21.py` 阅读。`src/run_codesentry_gen_e2e.py` 是统一研究入口，其正式运行需要匹配的冻结 KB、协议和运行证据。当前分发材料支持的复现入口为上面的离线验证脚本；正式实验的材料要求见[运行与验证说明](docs/VALIDATION.md)。

本仓库以功能快照发布，版本来源及文件校验信息见[源码来源](docs/SOURCE_VERSIONS.md)。`output/` 中的记录按各自的输入、日期和算法版本解释。`scripts/` 下早期 PowerShell 文件用于历史流程参考；本版本的验收命令以本页和 VALIDATION 为准。
