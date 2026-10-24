# 运行与验证

本版将最新非第三层核心与既有第三层阶段材料组合。运行前请按 README 安装 `requirements-dev.txt`；该文件引用精确核心依赖及工作流解析依赖。

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

本轮在 Linux CPython 3.10.20 上已实际运行完整分发验收入口并通过，包括130项当前回归、六包 KB、Candidate/Proposal、AVCS 分步执行、旧 Trigger、四条 THO/SCEG 2.1 及 OSV 重放。整合原仓库另有304项完整离线 Core 回归；它的正式实验材料不全部分发，因此不能把304项原仓库结果直接当作本快照的验收数量。新版 Windows 检出仍需在本地运行上述同一命令；此前旧快照的 Windows PASS 不替代本版验证。

## 结果解释

旧 API seed 记录了 API 出现证据，缺少严格版本排除证明。当前解析器对此返回 `resolved_non_excluding` / `api_constraint_unresolved`，不会为了复现旧告警而恢复较弱的推断。新运行示例的零张 AVCS 风险卡应结合该未知状态解释，不代表依赖已被证明安全。

旧 Trigger 的独立匹配控制显式提供受影响版本 `5.3.1`，用于验证 matcher 接口，不能用来补齐上面缺少的 API 版本证明。

四条 THO 控制输入生成四张归一化 Risk Card，其中当前 registry 缺失的两条进入 auxiliary，生成后才创建包的两条进入 formal。它们是控制样例的语义检查，不是自然样本阳性率。

## 其他入口

`src/run_codesentry_gen_e2e.py` 与 `src/run_step8_unified_avcs.py` 保留当前正式入口的冻结前置条件。未分发的正式 KB freeze、校准证据及实验 authority 不能用临时占位文件替代。正式全量实验应回到原始精确来源和完整运行材料。

早期 PowerShell 文件保留历史参考，其中部分参数和路径属于当时的 v0 流程。本版本复现以当前跨平台 Python 验收入口为准。

## 干净检出复核记录

[GitHub Actions 40082183364](https://github.com/daogui6/CodeSentryGen-Pilot/actions/runs/40082183364) 对分发候选 `819867e76172b80d929e8f1ad5c290201eea3863` 干净检出，逐文件核对959项分发内容，并将199个核心文件与整合主线逐字节比较；130项回归及完整分发验收均通过。最终说明性文档与其清单另按提交记录维护，功能源码不因该说明更新而改变。
