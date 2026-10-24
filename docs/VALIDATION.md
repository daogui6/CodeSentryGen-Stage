# 运行与验证

本文说明本版本的运行入口、验证覆盖及结果含义。运行前请按 [README](../README.md) 安装 `requirements-dev.txt`；该文件引用精确核心依赖及工作流解析依赖。

## 当前验收命令

```bash
python -X utf8 scripts/run_stage_validation.py
```

脚本先验证分发文件 SHA-256，随后在临时副本运行，保存日志、受控输出和 `validation.json`。所有输出写入新建的 `output/local_validation/<运行标识>/`；历史文件不会被验收脚本覆盖。

| 检查 | 适用范围 |
| --- | --- |
| 当前回归测试 | 包身份、作用域/动态 import、时间视图、声明上下文、版本范围及前驱计数绑定 |
| 六包 KB | Schema 与已纳入文件引用 |
| AVCS minimal 与 Trigger 检查 | 既有工件的46项一致性检查及31项规则控制 |
| 新运行的 AVCS 分步链路 | 当前 API 抽取、版本约束、漏洞范围、交集、Risk Card 与既有 Trigger 的接口兼容 |
| 四条 THO→SCEG 2.1 控制输入 | canonical 依赖投影、时态分类、R0–R4、Risk Card 归一化、IR 完整性与 Schema |
| OSV 重放 | 11 包、208 组、171 resolved /37 unresolved |
| Candidate/Proposal | 格式及待审核门；不调用模型、不创建人工结论 |

2026-10-24，Windows Python 3.10 本地环境与 Linux CPython 3.10.20 的 GitHub Actions 均已通过上述验收入口。覆盖130项回归、六包 KB、Candidate/Proposal、AVCS 分步执行、静态 Trigger、四条 THO/SCEG 2.1 控制输入及 OSV 重放。验证过程调用模型次数为0，未启动正式实验。

## 结果解释

旧 API seed 记录了 API 出现证据，缺少严格版本排除证明。当前解析器对此返回 `resolved_non_excluding` / `api_constraint_unresolved`，不会为了复现旧告警而恢复较弱的推断。新运行示例的零张 AVCS 风险卡应结合该未知状态解释，不代表依赖已被证明安全。

旧 Trigger 的独立匹配控制显式提供受影响版本 `5.3.1`，用于验证 matcher 接口，不能用来补齐上面缺少的 API 版本证明。

四条 THO 控制输入生成四张归一化 Risk Card，其中当前 registry 缺失的两条进入 auxiliary，生成后才创建包的两条进入 formal。它们是控制样例的语义检查，不是自然样本阳性率。

## 其他入口

`src/run_codesentry_gen_e2e.py` 与 `src/run_step8_unified_avcs.py` 保留当前正式入口的冻结前置条件。未分发的正式 KB freeze、校准证据及实验 authority 不能用临时占位文件替代。正式全量实验应回到原始精确来源和完整运行材料。

早期 PowerShell 文件保留历史参考，其中部分参数和路径属于当时的 v0 流程。本版本复现以当前跨平台 Python 验收入口为准。

## 验证记录

| 环境 | 验证对象与记录 | 结果 |
| --- | --- | --- |
| Windows Python 3.10 | 本地检出，离线验收运行标识 `20261024T102513086154Z` | PASS；130项回归及完整离线链路 |
| Linux CPython 3.10.20 | 提交 [`ffee142`](https://github.com/daogui6/CodeSentryGen-Stage/commit/ffee142ac25f819e7bbf2fb9ca1ed7482546334f)，[GitHub Actions 40086080616](https://github.com/daogui6/CodeSentryGen-Stage/actions/runs/40086080616) | PASS；干净检出及同一验收入口 |

文件一致性由 [STAGE_FILE_MANIFEST.json](STAGE_FILE_MANIFEST.json) 和包含它的 Git 提交共同记录。文档维护后的执行状态以对应提交的 Actions 记录为准；历史输出仍按其原始输入和运行环境解释。
