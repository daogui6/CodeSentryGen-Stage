# CodeSentry-Gen v2.1：面向 LLM 生成代码的时态依赖风险检测

<!-- csg-reader-context:start; original-sha256=9430bf9332eb2847f74454ef4dad19284e1af4e539c69e3151e968f8e0ab8675 -->

> **文档定位：总体设计参考原文。** 本文保存问题定义、目标架构和评估方案，正文按来源原样保留。设计方案、当前 SCEG 2.1 共享 IR 与保留的历史 v0 工件分别说明于[实现范围](docs/STAGE_SCOPE.md)；当前源码入口和复现流程见 [README](README.md) 与[运行与验证说明](docs/VALIDATION.md)。

<!-- csg-reader-context:end -->

> 生成日期：2026-05-06
> 版本说明：多 sub-agent 两轮评审后收敛版
> 目标定位：优先投稿 FSE/ASE/ICSE Technical Track 或 SEIP；若转 Security 顶会，则进一步收敛为 package hallucination/slopsquatting 攻防论文
> 关键词：LLM-generated code, software supply chain, package hallucination, temporal SCA, API-to-version inference

---

## 0. 多评审共识

本 v2.1 版本根据 5 类 sub-agent 评审意见重构：

| 角色                  | 核心结论                                                                                                               |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Security 顶会审稿人   | 原方案像四篇论文拼盘，最强 novelty 是“生成时态 + 包名幻觉抢注窗口 + API 用法反推版本约束”。                          |
| SE 顶会审稿人         | 建议主投 SE 顶会，主线收敛为生成阶段 dependency risk，而非大一统供应链污染检测。                                       |
| 工业 DevSecOps 架构师 | 6-9 个月 MVP 应只覆盖 Python/npm，做 CLI/CI/IDE 增量扫描，Risk Card 必须可操作。                                       |
| 算法实现专家          | HalluGuard 和 TimeVulnTrace 是 SOTA 关键点；LicenseWeaver 和广义恶意溯源会拖累论文。                                   |
| 实证评估专家          | 需要硬 ground truth、时间视图 `as_of_tg/as_of_audit/oracle_now`、hard negative、强组合 baseline 和 paired 统计检验。 |

因此，v2.1 不再主张“统一检测所有供应链污染”。新的论文主线是：

> LLM 生成代码中的依赖风险不是静态 dependency scanning 问题，而是 **generation-time incomplete dependency specification** 问题：包名可能尚未存在，依赖可能尚未落盘，版本可能尚未解析，漏洞可能尚未公开，API 用法却已经暗示了版本约束。CodeSentry-Gen v2.1 用时间视图、安装可达性和代码 API 约束，把“尚未固定、尚未注册、尚未解析版本”的生成阶段依赖风险转化为可审计、可复现、可修复的风险实例。

---

## 1. 收敛后的论文主张

### 1.1 论文标题候选

1. **CodeSentry-Gen: Temporal Dependency Risk Detection for LLM-Generated Code**
2. **When Generated Code Meets a Moving Registry: Temporal Supply-Chain Risk Detection for LLM Coding Assistants**
3. **Beyond SCA: Detecting Temporal Dependency Risks in LLM-Generated Code**

### 1.2 核心贡献

**C1：生成时依赖规格不完整问题定义。**首次把 LLM 生成阶段依赖风险定义为一个由 `package identity uncertainty` 和 `version uncertainty` 共同构成的问题，而不是传统 project-level SCA 问题。核心风险包括：

- 生成时不存在或错误生态的包名。
- 生成后被注册/抢注的包名。
- install-reachable 的幻觉包和 typosquatting 候选。
- manifest 缺失或版本宽松时，由 API 用法暗示的过时/脆弱版本。
- 生成时安全但审计时变脆弱的 temporal drift。

**C2：统一时态依赖风险建模方法。**提出轻量 Supply Chain Evidence Graph (SCEG)，并在同一 IR 上处理两类不确定性：

- **THO**：针对 package identity uncertainty，联合 `t_g`、`t_pub`、`t_reg`、`t_install`、`t_audit` 与 install reachability，识别 current registry check 会漏掉的时态包名风险。
- **AVCS**：针对 version uncertainty，从 LLM 生成代码中的 API 调用、参数模式和 dependency manifest 反推可行版本集合，再与 OSV/GHSA/NVD 漏洞影响版本求交。

**C3：分层基准与可证实验。**
构建 GenDepRiskBench，区分真实生成、pilot prevalence、历史回放、受控注入和 hard negatives，报告人工一致性、时间泄漏控制、强组合 baseline、paired statistical tests 和小规模开发者效用研究。

Evidence Attribution 和 Risk Card 是解释与落地组件，不作为独立科学贡献；它们服务于复核、修复和 CI policy。

### 1.3 明确降级的内容

以下内容不作为主论文核心贡献：

- 片段级许可证来源恢复：降级为扩展讨论或离线 case study。
- 广义恶意模式和后门溯源：只保留 install-time suspicious behavior 的窄规则作为工程扩展。
- 训练语料来源证明：改为 public-code-neighbor evidence 或 memorization-like signal，不做因果断言。
- 通用跨生态覆盖：主实验只覆盖 Python/PyPI 和 JavaScript/npm；Maven/Go/Rust 作为外部有效性扩展。
- 重型图数据库和动态沙箱：不进入 MVP 主路径。

---

## 2. 问题定义

### 2.1 输入

```text
I = <C_gen, R, p, t_g, M, K>
```

其中：

- `C_gen`：LLM 生成并被开发者接受的代码片段、文件、补丁或 PR diff。
- `R`：目标仓库上下文，包括 manifest、lockfile、CI、Dockerfile、已有依赖和本地模块。
- `p`：可选 prompt 和对话上下文。
- `t_g`：生成时间；若不可得，使用接受 completion 时间、commit 时间或审计时间，并记录不确定区间 `Δ_t`。
- `M`：模型元数据，如模型名称、版本、temperature；若不可得，作为审计元数据缺失项。
- `K`：外部知识库快照，包括 registry、OSV/GHSA/NVD、deps.dev、API surface history、包名映射表、top package 列表。

### 2.2 输出

输出风险实例：

```text
r = <type, entity, location, severity, confidence, evidence, attribution, repair>
```

主风险类型收敛为三类，其他风险只作为子类型或 baseline-compatible 任务：

| 类型                                  | 定义                                                                                    |
| ------------------------------------- | --------------------------------------------------------------------------------------- |
| `temporal_package_hallucination`    | 包在 `t_g` 不存在、生态不匹配、当前不存在，或生成后才注册。                           |
| `api_induced_vulnerable_dependency` | API 用法显著收缩可行版本集合，且该集合与漏洞版本相交，传统 SCA 无法仅从 manifest 判定。 |
| `temporal_drift`                    | 生成时未公开风险，但审计时因 CVE/包状态变化成为风险。                                   |

子类型和扩展项：

- `hijackable_dependency`：作为 `temporal_package_hallucination` 的 severity subtype。
- `vulnerable_dependency`：作为传统 SCA 兼容任务和 baseline 连接点，不作为最强 novelty claim。
- `license_policy_risk`：仅做依赖许可证策略，不做片段级法律结论。
- `install_time_behavior_risk`：仅做安装期/构建期高危行为规则，不做通用恶意后门检测。

### 2.3 评估目标与运行约束

CodeSentry-Gen v2.1 不是端到端训练优化器，因此不使用装饰性目标函数。论文按以下评估目标和运行约束判断方法是否成立：

| 目标                                | 衡量方式                                                                                                     |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Temporal package detection          | `temporal_package_hallucination` 的 precision/recall/F1、created-after-`t_g` recall、high-risk precision |
| API-induced vulnerability detection | AVCS 在 curated high-risk libraries 上的 precision/recall/F1、SCA-missed hit rate、exposure precision        |
| False blocking control              | CI 阻断级 A 类 high/critical 的 false blocking rate                                                          |
| Evidence utility                    | 专家判定的 evidence sufficiency、developer triage time、correct repair rate                                  |
| Runtime feasibility                 | IDE 首屏延迟、CI P95 runtime、外部 API 查询数、缓存命中率                                                    |

---

## 3. 威胁模型与边界

### 3.1 攻击者能力

攻击者可以：

- 观察或预测 LLM 高频幻觉包名。
- 在公开 registry 注册尚不存在的包。
- 使用 typosquatting、dependency confusion 或相似命名诱导安装。
- 在包安装脚本或发布版本中加入恶意行为。
- 利用模型训练滞后或历史教程，使 LLM 推荐旧版本/API。

攻击者不能：

- 修改目标开发者的私有项目上下文。
- 直接控制 LLM 服务端模型参数。
- 假设所有开发者都会安装所有建议包；必须通过 install reachability 证明风险路径。

### 3.2 防御目标

系统在 IDE/CI 中尽早发现：

1. 当前 SCA 尚未能扫描的生成阶段包名风险。
2. current-only registry check 会误判的时态风险。
3. manifest 缺失或版本宽松时由 API 用法暴露的旧版本风险。
4. 生成代码和 prompt/context 中可解释的风险来源证据。

### 3.3 不做的事

- 不证明某段代码来自模型训练集。
- 不给出法律级许可证结论。
- 不检测所有恶意代码或所有后门。
- 不替代 SCA/SAST，而是作为生成阶段前置增强。

---

## 4. 系统架构

### 4.1 总体流程

```text
LLM accepted diff / generated project
        │
        ▼
Multi-source Dependency Entity Extraction
        │
        ▼
Supply Chain Evidence Graph (SCEG)
        │
        ├── HalluGuard-THO: Temporal Hijack Opportunity
        │
        ├── TimeVulnTrace-AVCS: API-to-Version Constraint Solving
        │
        └── Evidence Attribution and Calibration
        │
        ▼
Actionable Risk Cards + SARIF + CI policy decision
```

### 4.2 SCEG 轻量证据图

SCEG 不是重型知识图谱，而是可序列化的审计证据 IR：

```text
G = (V, E)
```

节点：

- `Package(name, ecosystem, normalized_name)`
- `Import(import_name, language, location)`
- `ManifestDep(package, specifier, location)`
- `InstallCommand(manager, package, location)`
- `APICall(package?, symbol, args, location)`
- `Version(version, released_at)`
- `Vulnerability(id, affected_range, disclosed_at, fixed_range)`
- `Evidence(kind, source, as_of, confidence)`
- `PromptMention(entity, location)`
- `ContextMention(entity, location)`

边：

- `maps_to(import, package)`
- `declares(manifest, package)`
- `installs(command, package)`
- `uses_api(code, api)`
- `requires_version(api, predicate)`
- `affected_by(version, vulnerability)`
- `introduced_by(package/api, prompt/context/generated_diff)`
- `supports(evidence, risk)`
- `contradicts(evidence, risk)`

每个 SCEG 文件必须包含可复现实验元数据：

```yaml
schema_version: "2.1"
extractor_version: string
source_snapshot_id: string
created_at: datetime
evidence:
  - evidence_id: string
    kind: registry|vulnerability|api_surface|manifest|code|prompt|context
    source_url: string|null
    db_revision: string|null
    queried_at: datetime
    as_of: datetime|null
    evidence_hash: sha256
```

同一包实体通过 `<ecosystem, normalized_name, source_scope>` 去重；同一风险通过 `<risk_type, package, location, time_view>` 去重。SARIF 输出时，每类风险映射到稳定 `rule_id`、`level`、`helpUri` 和可选 `fix`。

### 4.3 输入 Schema

```yaml
input:
  generated_files:
    - path: string
      language: python|javascript|json|shell|dockerfile|yaml
      content_hash: sha256
      content: string
  accepted_diff:
    source: ide|chat|agent|commit|unknown
    timestamp: datetime
  prompt:
    text: string|null
    timestamp: datetime|null
  repo_context:
    manifests: [path]
    lockfiles: [path]
    local_modules: [string]
    ci_files: [path]
  generation_time:
    value: datetime
    uncertainty_days: int
  ecosystems: [pypi, npm]
```

### 4.4 输出 Risk Card Schema

```yaml
schema_version: "2.1"
risk_id: string
title: string
type: temporal_package_hallucination|api_induced_vulnerable_dependency|temporal_drift
subtype: hijackable_dependency|vulnerable_dependency|license_policy_risk|install_time_behavior_risk|null
status: confirmed|probable|weak|unknown
severity: low|medium|high|critical
confidence: float
introduced_by:
  file: string
  line: int
  entity: string
install_reachability:
  level: none|import_only|manifest_declared|lockfile_resolved|ci_installable|install_script_executable
evidence:
  structural: []
  temporal: []
  ecosystem: []
  semantic: []
attribution:
  observable_labels: []
  hypotheses:
    - name: llm_hallucination|registry_hijack|prompt_induced|context_inherited|temporal_drift|unknown
      rank: int
      rationale: string
repair:
  action: replace|upgrade|pin|remove|migrate_api|review
  command: string|null
  patch: string|null
  verify: string|null
```

---

## 5. Stage 1：依赖实体抽取与规范化

### 5.1 抽取范围

MVP 覆盖 Python/PyPI 和 JavaScript/npm：

| 来源            | Python                                                              | JavaScript/npm                                                             |
| --------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| manifest        | `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| import          | `import x`, `from x import y`, `importlib.import_module`      | `import`, `require`, dynamic `import()`                              |
| install command | `pip install`, `python -m pip install`                          | `npm install`, `yarn add`, `pnpm add`                                |
| CI/Docker/shell | `RUN pip install`, GitHub Actions steps                           | `RUN npm ci`, `npm install`, package scripts                           |
| API call        | high-confidence package-bound symbols                               | high-confidence package-bound symbols                                      |

### 5.2 实体规范化

包名规范化函数：

```text
Normalize(e) -> {candidate_i = <ecosystem, package, confidence, evidence>}
```

规范化规则：

- PyPI：PEP 503 normalization，`-`、`_`、`.` 归一化。
- npm：保留 scoped package，如 `@scope/pkg`；大小写归一化。
- import-to-distribution：先查 curated mapping，如 `cv2 -> opencv-python`、`PIL -> Pillow`；再查 registry top packages 与代码搜索共现。
- 本地模块过滤：若包名与仓库内目录/文件匹配，标为 `local_module`，不进入 package hallucination 主评估。
- 私有包过滤：若命名空间在企业配置或 `.npmrc/pip.conf` 指向私有 registry，标为 `private_unknown`。

### 5.3 可达性分级

LLM 生成代码只提到包名不一定构成实际供应链风险。定义 install reachability：

| 等级                             | 条件                                    | CI 阻断策略   |
| -------------------------------- | --------------------------------------- | ------------- |
| R0 `mention_only`              | 只在注释/说明/prompt 出现               | 不阻断        |
| R1 `import_only`               | 代码 import，但无 manifest/install 证据 | 仅提示        |
| R2 `manifest_declared`         | 生成/修改 manifest 声明依赖             | 可高危        |
| R3 `lockfile_resolved`         | lockfile 中解析到具体版本               | 可阻断        |
| R4 `ci_installable`            | CI/Docker/shell 会安装该依赖            | 可阻断        |
| R5 `install_script_executable` | 包安装脚本或 setup hook 可执行          | critical 候选 |

实现上采用保守可达性规则：`requirements-dev.txt`、optional dependencies、npm workspaces、monorepo 子包、Docker multi-stage、GitHub Actions matrix、tox/nox/poetry 等情况若无法证明会在生产或 CI 中安装，则不直接升级为 R4/R5；只标为 `probable` 或 `review`。传递依赖在 MVP 中只在 lockfile confirmed 时进入传统 SCA 路径，不进入 THO 主判定。

---

## 6. 核心算法一：HalluGuard-THO

### 6.1 从加权打分改为时态机会判定

原始 `Hijackability = Σ α_i feature_i` 容易被认为是启发式拼接。v2.1 改为先分类、再排序：

1. **Temporal status classification**
2. **Install reachability analysis**
3. **Confusable package matching**
4. **Trust and registry evidence**
5. **Risk card calibration**

### 6.2 时态变量

| 符号          | 含义                                    |
| ------------- | --------------------------------------- |
| `t_g`       | LLM 生成/接受时间                       |
| `t_pub`     | 生成代码首次公开或进入 PR/commit 的时间 |
| `t_reg`     | 包首次在 registry 注册时间              |
| `t_rel(v)`  | 包版本 `v` 发布时间                   |
| `t_install` | CI 或开发者可能安装该依赖的时间         |
| `t_audit`   | 审计时间                                |
| `t_adv`     | 漏洞公告公开时间                        |

关键抢注窗口：

```text
Temporal Hijack Opportunity exists if:
    t_g < t_reg <= t_install
and package_name was generated before registry existence
and install_reachability >= R2
```

若 `t_pub < t_reg`，说明攻击者可能从公开生成代码或高频幻觉趋势中观察并注册。若 `t_g < t_reg` 但 `t_pub` 不可得，则仍可标为 `created_after_generation`，但 attribution 置信度降低。

`t_install` 通常不可精确观测，因此分三档处理：

| 档位      | 定义                                                            | 用途                                                                              |
| --------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| observed  | CI 日志、package-lock 更新、artifact build 记录显示实际安装时间 | 可用于 confirmed THO                                                              |
| scheduled | PR 合并、nightly build、release workflow 可推断下一次安装窗口   | 可用于 probable THO                                                               |
| unknown   | 只能证明 R2/R3 可安装，不能证明安装时间                         | 只报告 install-reachable temporal hallucination，不做 hijack opportunity 强 claim |

当 `t_reg` 落入 `[t_g - Δ_t, t_g + Δ_t]` 不确定区间时，状态标为 `temporal_unknown`，不进入主指标的 positive；仅作为 weak/review 证据。

### 6.2.1 Registry 时间源

`t_reg` 和 `t_rel(v)` 按生态定义：

| 生态 | `t_reg` 优先级                                                           | `t_rel(v)` 优先级                 | 缺失处理                                                    |
| ---- | -------------------------------------------------------------------------- | ----------------------------------- | ----------------------------------------------------------- |
| npm  | registry metadata `time.created`；若缺失，取最早 version time            | registry metadata `time[version]` | 标 `registry_unknown`，不做 confirmed                     |
| PyPI | 最早 release file upload time 近似项目出现时间；若有可信项目创建时间则优先 | release file upload time            | 只支持 release-level 判断，项目级 `created_at` 缺失时降级 |

历史视图优先使用自建每日 metadata snapshot；若没有完整 snapshot，则用 registry release timestamps 重建 `as_of_tg`。所有重建视图必须保存 raw JSON、查询时间、数据源版本和 reconstruction script。

### 6.3 Temporal Status

对包 `p`：

```text
TemporalStatus(p, t_g, t_audit) ∈ {
  nonexistent_now,
  nonexistent_at_tg,
  created_after_tg,
  existed_at_tg,
  deleted_or_yanked,
  wrong_ecosystem,
  local_or_private_unknown,
  registry_unknown
}
```

判定规则：

- `nonexistent_now`：审计时目标 registry 无包。
- `created_after_tg`：包存在，但最早 release 或 registry created time 晚于 `t_g + Δ_t`。
- `nonexistent_at_tg`：通过历史快照或最早 release 时间可证明 `t_g` 时无可用版本。
- `existed_at_tg`：至少一个可安装版本 `v` 满足 `t_rel(v) <= t_g`。
- `wrong_ecosystem`：同名包存在，但 import/API 语义与目标生态不匹配。
- `local_or_private_unknown`：可能为本地或私有包，不进入主指标。

### 6.4 Confusable Matching

对候选包 `p`，寻找相似真实包集合：

```text
Confusable(p) = {q | sim_name(p,q) ≥ θ_name and relevance(q, context) ≥ θ_ctx}
```

特征：

- 编辑距离、Jaro-Winkler、分隔符变换、大小写、复数/单复数。
- npm scope 是否相同或相近。
- 与 prompt/context 中功能词的 embedding 相似。
- 与 top packages 列表或项目已有依赖的相似度。

该模块不是直接判恶意，而是用于解释 “这个幻觉包为什么具有可信命名和被抢注价值”。

### 6.5 可执行伪代码

```text
Algorithm 1: HalluGuard-THO
Input : SCEG G, generation time t_g, audit time t_audit, registry snapshot K_reg
Output: package risk cards

1. P ← ExtractPackageNodes(G)
2. for each p in P:
3.     if IsLocalOrPrivate(p, G):
4.         mark p as local_or_private_unknown; continue
5.     meta_tg ← QueryOrReconstructRegistryView(p.ecosystem, p.name, as_of=t_g)
6.     meta_audit ← QueryRegistrySnapshot(p.ecosystem, p.name, as_of=t_audit)
7.     hist ← GetReleaseHistory(meta_audit)
8.     status ← ClassifyTemporalStatus(p, meta_tg, meta_audit, hist, t_g, Δ_t)
9.     reach ← ComputeInstallReachability(p, G)
10.    conf ← FindConfusablePackages(p, K_reg.top_packages, G.context)
11.    trust ← PackageTrustEvidence(meta_audit, as_of=t_audit)
12.    legit ← LegitimateNewPackageEvidence(meta_audit, prompt/context evidence)
13.    risk_level ← DecisionTable(status, reach, conf, trust, legit)
14.    if risk_level ≥ threshold:
15.        attrib ← RankAttribution(status, reach, prompt/context evidence, t_reg)
16.        emit RiskCard(p, type=risk_level.type,
                         evidence={status,hist,reach,conf,trust},
                         attribution=attrib,
                         repair=SuggestReplacementOrRemoval(p, conf))
```

### 6.6 Decision Table

| Temporal status              | Reachability | Confusable | Trust / legitimacy evidence                 | Risk                  |
| ---------------------------- | -----------: | ---------: | ------------------------------------------- | --------------------- |
| `nonexistent_now`          |        R2-R5 |        any | not private/local                           | high/critical         |
| `created_after_tg`         |        R2-R5 |        yes | weak trust, no prompt/context justification | high                  |
| `created_after_tg`         |        R2-R5 |        yes | strong maintainer/project evidence          | probable/review       |
| `created_after_tg`         |           R1 |        yes | any                                         | medium                |
| `nonexistent_at_tg`        |        R2-R5 |         no | not private/local                           | high                  |
| `wrong_ecosystem`          |        R2-R5 |        yes | any                                         | medium/high           |
| `temporal_unknown`         |          any |        any | any                                         | weak/review           |
| `existed_at_tg`            |          any |         no | any                                         | no hallucination risk |
| `local_or_private_unknown` |          any |        any | any                                         | unknown, no blocking  |

Confusable matching 只影响排序、严重性和解释，不作为包名幻觉 ground truth 的必要条件。主真值以时态存在性、规范化正确性、本地/私有过滤和可达性为准。

### 6.7 为什么能打败 baseline

| Baseline               | 盲区                                          | HalluGuard-THO 增量                           |
| ---------------------- | --------------------------------------------- | --------------------------------------------- |
| current registry check | 现在存在但生成时不存在的包会被误判安全        | 使用 `created_after_tg` 和历史 release 识别 |
| typosquat detector     | 不知道包是否来自 LLM 生成，也不知道是否可安装 | 加入 generated diff 和 install reachability   |
| SCA                    | manifest 之前或无版本生成片段无法扫描         | 直接扫描 accepted diff/import/install command |
| LLM self-check         | 易受幻觉影响，不可靠查询 registry             | 使用 registry snapshot 和可复查证据           |

---

## 7. 核心算法二：TimeVulnTrace-AVCS

### 7.1 核心问题

传统 SCA 需要 manifest/lockfile 中的版本信息：

```text
package + version range -> vulnerability match
```

LLM 生成代码经常只有：

- import 语句而无版本。
- 宽松版本范围，如 `*`、`^1.0.0`、`>=1.0`。
- 旧教程中的 API 调用。
- 被新版本移除/弃用的 API。

AVCS 的目标是：

```text
API call + manifest constraints + release history -> feasible versions -> vulnerability exposure
```

### 7.2 离散版本约束求解

避免连续区间的跨生态复杂性。对包 `p`，先取离散 release 集合：

```text
R_p(t) = {v | release_time(v) <= t}
```

每个约束是版本谓词：

```text
c(v) -> true/false/unknown
```

约束来源：

| 约束                | 示例                                    |
| ------------------- | --------------------------------------- |
| manifest            | `requests>=2.0,<3.0`                  |
| lockfile            | `lodash@4.17.15`                      |
| API existence       | `api_symbol exists in version v`      |
| API signature       | 参数名、参数数量、默认值存在            |
| deprecation/removal | `deprecated_since`, `removed_since` |
| vulnerability range | OSV affected ranges                     |
| generation time     | `release_time(v) <= t_g + Δ_t`       |

可行版本集合：

```text
V_feasible(p, t_view) =
  { v ∈ R_p(t_view) | ∀ c ∈ Ω_p, c(v) != false }
```

漏洞暴露：

```text
V_exposed = V_feasible ∩ V_affected
```

若 manifest 不存在，只允许在 API 约束强证据时报告 `api_induced_vulnerable_dependency`，避免把所有未 pin 依赖都报漏洞。`unknown` 约束不能主导 high severity：当多数版本因 API history 缺失而保持 `unknown` 时，系统只输出 triage evidence，不输出 confirmed risk。

### 7.2.1 强 API 约束与风险阈值

定义：

```text
Reduction = 1 - |V_feasible_after_API| / |V_feasible_before_API|
ExposureRatio = |V_exposed| / |V_feasible_after_API|
FixedExcluded = all fixed versions violate at least one high-confidence API constraint
```

报告 `api_induced_vulnerable_dependency` 需要满足至少一个条件：

- `Reduction ≥ θ_reduce` 且 `ExposureRatio ≥ θ_expose`。
- `FixedExcluded = true`，说明直接升级会破坏当前 API 用法，需要 API migration。
- API interval 的抽样人工校验准确率达到预设阈值，例如 90% 以上。

否则只把 API 约束作为 `semantic evidence` 附在传统 SCA 或 Risk Card 中。阈值在 dev set 上确定，test set 冻结后不得调整。

### 7.3 API History 构建

MVP 不做所有包的通用 API 历史。只对 10-20 个高频库构建离线 API surface：

Python 候选：

- `requests`, `urllib3`, `PyYAML`, `Django`, `Flask`, `cryptography`, `Pillow`, `lxml`, `numpy`, `pandas`

npm 候选：

- `lodash`, `axios`, `express`, `jsonwebtoken`, `node-fetch`, `webpack`, `minimist`, `serialize-javascript`, `yaml`, `tar`

构建流程：

1. 下载历史 release artifact。
2. 抽取最小 public API surface：top-level function/class、class method、constructor signature、keyword args、exports/subpath exports。
3. 对 TypeScript/npm 包抽取 `.d.ts`、exports、JSDoc。
4. 对 Python 包抽取 runtime introspection + stub + AST。
5. 记录 `exists(symbol,v)`、`signature(symbol,v)`、`deprecated_since`、`removed_since`。
6. 在抽样版本上人工校验 API interval 准确率。

API call 到 package 的绑定只采用高置信规则：Python 支持 direct import、from-import、alias 和同文件内简单 receiver 传播；JavaScript 支持 ES import、CommonJS destructuring、namespace import 和 package subpath export。复杂反射、跨文件动态类型恢复和 re-export 链默认标为 unknown，不进入 confirmed AVCS。

### 7.4 Insecure API Misuse Rules

为了保证可落地，系统保留 curated API misuse rules，但这些规则不属于 AVCS 主贡献，只作为 secondary semantic evidence 和 SAST baseline 对照：

| 生态   | 规则示例                                                   | 风险         |
| ------ | ---------------------------------------------------------- | ------------ |
| Python | `yaml.load(x)` without `SafeLoader`                    | 反序列化风险 |
| Python | `pickle.loads(untrusted)` / `joblib.load(untrusted)`   | 任意代码执行 |
| Python | `requests.get(..., verify=False)`                        | TLS 验证关闭 |
| Python | `tar.extractall` with untrusted archive                  | 路径穿越     |
| Python | `subprocess(..., shell=True)` with tainted input         | 命令注入     |
| npm    | `child_process.exec` with tainted input                  | 命令注入     |
| npm    | `eval`, `Function`, dynamic require with tainted input | 动态执行     |
| npm    | vulnerable `jsonwebtoken` verify patterns                | 认证绕过风险 |

这些规则作为 `vulnerable_api` 或 `api_misuse` evidence，不替代 API-to-version 主算法。RQ3 必须分别报告 `AVCS without misuse rules`、`AVCS with misuse evidence` 和 `SAST/API rules baseline`，避免 AVCS 的提升主要来自规则库。

### 7.5 可执行伪代码

```text
Algorithm 2: TimeVulnTrace-AVCS
Input : SCEG G, time view t_view, vulnerability DB K_vuln, API history K_api
Output: vulnerable dependency and API-induced risk cards

1. for each package p in G:
2.     releases ← ReleaseList(p, as_of=t_view)
3.     Ω ← {}
4.     Ω ← Ω ∪ ManifestConstraints(p, G)
5.     Ω ← Ω ∪ LockfileConstraints(p, G)
6.     calls ← ResolveAPICalls(p, G)
7.     for each call a in calls:
8.         if a.symbol in K_api[p]:
9.             Ω ← Ω ∪ APIExistenceAndSignatureConstraints(a, K_api[p])
10.        if MatchesInsecureRule(a):
11.            emit APIMisuseRisk(a)
12.    V_before_api ← SolveVersionSet(releases, Ω without API constraints)
13.    V_feasible ← SolveVersionSet(releases, Ω)
14.    affected ← QueryAffectedVersions(K_vuln, p)
15.    V_exposed ← V_feasible ∩ affected
16.    strength ← APIConstraintStrength(V_before_api, V_feasible, V_exposed, Ω)
17.    if IsActionableExposure(V_exposed, Ω, G, strength):
18.        repair ← MinimalCompatibleRepair(p, V_feasible, affected, K_api[p])
19.        emit DependencyRisk(p, V_exposed, Ω, repair)
```

### 7.6 Actionability 判定

避免无版本依赖误报：

| 情况                                  | 是否报告                                           |
| ------------------------------------- | -------------------------------------------------- |
| lockfile 固定版本受影响               | 报 `confirmed`                                   |
| manifest range 与 affected range 相交 | 报 `probable`，若可达 API 命中则升高             |
| 只有 import，无 manifest，无 API 约束 | 不报 CVE，仅提示 unresolved dependency             |
| API 约束强且可行版本集中在受影响版本  | 报 `api_induced_vulnerable_dependency`           |
| API 约束弱或 unknown 主导             | 仅作为 triage evidence，不计入 confirmed detection |
| CVE 在 `t_g` 后公开                 | 报 `temporal_drift` 而非 LLM 生成错误            |

`MinimalCompatibleRepair` 不能只选择不受影响版本，还必须满足 API/signature constraints；若所有 fixed versions 都不兼容，则输出 `migrate_api`，给出需要迁移的 API 和候选 replacement，而不是盲目升级。MVP 只处理 direct dependency；transitive dependency 仅在 lockfile confirmed 时走传统 SCA 路径。

### 7.7 为什么能打败 baseline

| Baseline                        | 盲区                                  | AVCS 增量                                            |
| ------------------------------- | ------------------------------------- | ---------------------------------------------------- |
| pip-audit/npm audit/osv-scanner | 无 manifest 或无具体版本时无法判断    | 用 API 约束和 release history 缩小可行版本           |
| SAST rules                      | 能找 API misuse，但不关联依赖版本/CVE | 联合 API、版本、漏洞时间线                           |
| LLM judge                       | 容易泛泛提示“升级依赖”              | 输出具体 `V_feasible`、`V_exposed`、最小安全版本 |

---

## 8. Evidence Attribution：解释组件，不做强因果

### 8.1 可观测标签

v2.1 将不可验证的“训练记忆来源”改成可观测证据：

| Observable label                      | 判定依据                                    |
| ------------------------------------- | ------------------------------------------- |
| `prompt_mentioned`                  | prompt 中明确出现包/API/版本                |
| `context_inherited`                 | 目标仓库上下文已有相同实体                  |
| `generated_only`                    | prompt/context 无实体，实体只在生成代码出现 |
| `created_after_generation`          | 包注册或首次 release 晚于 `t_g`           |
| `cve_after_generation`              | 漏洞公告晚于 `t_g`                        |
| `public_neighbor_before_generation` | 公开代码近邻早于 `t_g`，但不声称训练记忆  |
| `local_or_private_unknown`          | 可能为本地/私有依赖                         |

### 8.2 来源假设

输出仅为 hypothesis ranking。该部分不作为 SOTA 主指标，只用于解释、专家复核和受控 provenance 实验：

- `LLM_hallucination`
- `Registry_hijack`
- `Prompt_induced`
- `Context_inherited`
- `Temporal_drift`
- `Public_code_neighbor`
- `Unknown`

### 8.3 规则排序

```text
Algorithm 3: EvidenceAttribution
Input : risk r, SCEG G
Output: ranked source hypotheses

1. labels ← ExtractObservableLabels(r, G)
2. scores ← InitializeHypotheses()
3. if generated_only and nonexistent_at_tg:
4.     scores[LLM_hallucination] += high
5. if created_after_generation and install_reachable:
6.     scores[Registry_hijack] += medium/high
7. if prompt_mentioned:
8.     scores[Prompt_induced] += high
9. if context_inherited:
10.    scores[Context_inherited] += high
11. if cve_after_generation:
12.    scores[Temporal_drift] += high
13. if public_neighbor_before_generation:
14.    scores[Public_code_neighbor] += medium
15. return RankWithUncertainty(scores, missing_evidence)
```

### 8.4 反事实实验的降级定位

反事实重生成只用于论文实验，不进入 IDE/CI 主路径：

- 删除 prompt 中包名，观察风险实体生成率变化。
- 删除上下文依赖，观察模型是否仍生成。
- 替换相似官方包名，观察 API 语义是否一致。

报告 `risk score delta`，不声称因果证明。

---

## 9. Actionable Risk Card 与 IDE/CI 落地

### 9.1 设计原则

Risk Card 面向开发者，只回答五件事：

1. 哪一行引入了什么风险。
2. 为什么这是风险，证据来自哪里。
3. 是否会真的被安装、构建或运行。
4. 如何最小修复。
5. 修完如何验证。

### 9.2 示例

```yaml
title: Generated npm dependency did not exist at generation time
status: confirmed
severity: high
confidence: 0.93
introduced_by:
  file: package.json
  line: 18
  entity: fast-jwt-authz
why_it_matters: The package is install-reachable in CI and was first registered after the generated diff timestamp.
install_reachability:
  level: ci_installable
  evidence: "package.json dependency + npm ci in GitHub Actions"
evidence:
  temporal:
    - generation_time: 2026-02-10T13:20:00Z
    - first_release_time: 2026-03-02T08:10:00Z
  ecosystem:
    - registry: npm
    - similar_package: fast-jwt-auth
  structural:
    - package.json dependency line 18
attribution:
  observable_labels: [generated_only, created_after_generation]
  hypotheses:
    - name: llm_hallucination
      rank: 1
      rationale: "No prompt/context mention and package did not exist at generation time."
    - name: registry_hijack
      rank: 2
      rationale: "Package appeared after generated code became install-reachable."
repair:
  action: replace
  command: null
  suggestion: "Review candidate replacement fast-jwt-auth; apply only after API compatibility check."
  verify: "npm ci && npm test"
```

修复建议分两类：`known replacement` 可给出命令或 patch；`candidate replacement` 只能给 review 建议，避免把相似包误替换为不兼容依赖。AVCS 风险默认给 `upgrade` 或 `migrate_api` 建议，但初期不作为 CI 自动阻断条件。

### 9.3 IDE 扫描策略

- AI completion 被接受后扫描 accepted diff。
- 文件保存时扫描变更文件。
- manifest/lockfile/Dockerfile/CI 文件变更时触发依赖扫描。
- 终端出现 `pip install`、`npm install`、`curl | sh` 时轻量提示。
- 外部证据异步补齐，本地抽取目标 < 500ms，首屏告警目标 < 2s。

### 9.4 CI 策略

- PR diff scan：只扫新增/变更的 manifest、lockfile、安装脚本、CI 和生成代码 diff。
- Baseline mode：已有风险不阻断，只阻断 PR 新增 A 级 high/critical。
- 阻断策略：只阻断 `nonexistent_at_tg/created_after_tg + R2+ + 非 private/local + confirmed/probable high`；AVCS 初期只提示或需要安全工程师确认。
- Nightly full scan：刷新漏洞和 registry 状态，发现 temporal drift。
- Suppression 必须包含 `risk_id`、scope、原因、责任人、审批人、过期时间和证据 hash。

### 9.5 缓存策略

| 缓存                   | Key                                         | TTL      |
| ---------------------- | ------------------------------------------- | -------- |
| registry metadata      | ecosystem/package/as_of                     | 24h      |
| negative package cache | ecosystem/package                           | 1-6h     |
| vulnerability cache    | ecosystem/package/version_range/db_revision | 4-24h    |
| API surface            | package/version/artifact_hash               | 离线持久 |
| extraction graph       | file_hash/extractor_version                 | 持久     |
| advisory snapshot      | db_revision                                 | 持久     |

---

## 10. GenDepRiskBench：分层可复现基准

### 10.1 样本单位

主指标以 **risk instance** 为单位：

```text
<sample_id, risk_type, entity, location, evidence_level, time_view>
```

辅助报告 sample-level 是否有风险。

### 10.2 数据分层

| 子集                 | 目的                                   | 是否进入主结论         |
| -------------------- | -------------------------------------- | ---------------------- |
| Pilot Prevalence     | 估计真实生成中 THO/AVCS 风险自然发生率 | 是，作为 claim 边界    |
| Real LLM Generation  | 真实外部有效性                         | 是                     |
| Historical Replay    | 时态推理验证                           | 是                     |
| Controlled Injection | recall 压力测试                        | 分开报告               |
| Hard Negatives       | 误报控制                               | 是                     |
| Developer Triage Set | 工业可用性                             | 小规模 formative study |

### 10.3 推荐规模

完整论文目标规模：

- 生态：Python/PyPI、JavaScript/npm。
- 模型：4-6 个，覆盖闭源/开源、chat/code、agent/non-agent。
- 任务：120-200 个真实开发任务。
- 生成：每任务每模型 3-5 次。
- 主集：约 1,500-3,000 个生成样本。
- 历史回放/注入：300-500 个样本。
- THO 主任务保证足量 A/B 级 positive 与 hard negative；AVCS 只在 curated high-risk libraries 上保证足量 positive；temporal drift 作为 longitudinal analysis，不承诺每类等规模。

6-9 个月 MVP 规模：

- 50-100 个真实开发任务。
- 2-3 个模型。
- 500-800 个真实生成样本。
- 300 个 historical replay / controlled injection 样本。
- 100-200 个 hard negatives。

主结论必须先报告 Pilot Prevalence：真实生成样本中各类风险的自然发生率。Controlled Injection 只用于 recall stress test，不混入主要 effectiveness claim。

### 10.4 时间视图

每个样本保存三种视图：

| 时间视图        | 含义               | 用途                         |
| --------------- | ------------------ | ---------------------------- |
| `as_of_tg`    | 生成时可获得的信息 | 模拟生成时阻断               |
| `as_of_audit` | 审计时可获得的信息 | 发现抢注和 drift             |
| `oracle_now`  | 当前全量信息       | 事后分析，不用于生成时 claim |

对不同 claim 的信息使用限制：

| Claim              | 允许信息                                    |
| ------------------ | ------------------------------------------- |
| 生成时包名幻觉阻断 | `as_of_tg`                                |
| 生成后抢注检测     | `as_of_audit`，并标明事后检测             |
| temporal drift     | 比较 `t_g` 和 `t_adv`                   |
| API 过时           | API surface release history with timestamps |
| registry hijack    | 注册、版本发布、维护者变化时间线            |

### 10.5 Ground Truth 定义

#### 包名幻觉 positive

一个 `temporal_package_hallucination` 为真，当且仅当：

1. 生成代码中存在 import-reachable 或 install-reachable 包实体。
2. 规范化后，在 `t_g` 时目标 registry 不存在该包或不存在可满足代码使用方式的发行。
3. 不存在可靠 import-to-distribution 映射解释。
4. 不是本地模块、私有包、monorepo 子模块或内部 registry 包。
5. 人工复核确认不是 prompt/context 中明确给出的虚构占位符。

#### 脆弱依赖 positive

1. manifest/lock/API 约束得到的 `V_feasible` 非空。
2. `V_feasible ∩ V_affected` 非空。
3. 若缺少 manifest/lock，必须有 API 约束或高置信 API misuse。
4. 漏洞公告时间用于区分 `vulnerable_dependency` 与 `temporal_drift`。

#### Hard negatives

- 真实但 import 名不同的包，如 `cv2`/`opencv-python`。
- scoped npm 包和低下载量合法新包。
- 私有 registry 包。
- 本地模块。
- 仅注释/README 中出现的包。
- 安全教学或 CTF 中的危险 API。
- 生成后由合法维护者注册的新包。

### 10.6 人工标注流程

1. 自动工具只收集原始证据，不展示 CodeSentry-Gen 最终分数。
2. 每个样本至少两名独立标注员。
3. 分歧由第三名 senior reviewer 仲裁。
4. 标注指南预注册，包含 positive/negative/unknown 条件。
5. 冻结 test set 后再运行最终系统。

一致性指标：

| 标注对象      | 指标                                     |
| ------------- | ---------------------------------------- |
| 风险存在性    | Cohen's kappa + Gwet's AC1               |
| 多标签风险    | Jaccard agreement + Krippendorff's alpha |
| 严重性        | weighted kappa                           |
| span/location | IoU@0.5 / IoU@0.8                        |
| 来源排序      | MRR upper bound + pairwise agreement     |

---

## 11. 实验设计

### RQ1：Dependency Risk Detection

CodeSentry-Gen 是否能更准确识别 LLM 生成代码中的 dependency-level risks？

报告：

- entity-level precision/recall/F1。
- risk-instance F1。
- high-severity precision。
- false positives per generated sample。

### RQ2：Temporal Reasoning

生成时间、包发布时间、CVE 公开时间和版本发布时间是否提升检测？

关键比较：

- full vs current-only registry check。
- full vs no-time。
- created-after-`t_g` recall。
- temporal drift classification accuracy。

### RQ3：API-to-Version Inference

在 manifest 缺失或版本宽松时，AVCS 是否发现传统 SCA 漏掉的风险？

关键比较：

- SCA only。
- SCA + SAST。
- SCA + API misuse rules。
- CodeSentry-Gen with AVCS。

### RQ4：Evidence Attribution

系统是否能提供充分、正确、可复核的来源证据？

指标：

- observable attribution label agreement。
- explanation correctness。
- evidence sufficiency judged by experts。

Hypothesis ranking 的 MRR/NDCG 只在受控 provenance 数据上报告，不作为主 SOTA claim；不对训练记忆做强真值 claim。

### RQ5：Developer Utility

Risk Card 是否减少 triage time，提高修复正确率？

设计：

- 采用 within-subject counterbalanced design，目标 20-30 名有经验开发者或安全工程师。
- 参与者处理相同 LLM 生成 PR，但任务顺序和工具条件随机化以控制学习效应。
- 对比传统工具告警 vs Risk Card。
- Risk Card 与 baseline alert 的信息量保持公平：baseline 可看到工具原始证据，但没有 THO/AVCS 结构化解释。
- 指标：triage time、正确处置率、误删/误修率、correct suppression、correct repair、false blocking acceptance、修复后测试通过率、主观可信度。

---

## 12. Baseline 设计

### 12.1 SCA Baselines

- `pip-audit`
- `npm audit`
- `osv-scanner`
- Snyk/Dependabot，如果可用

仅在 manifest/lockfile 输入存在时公平运行。

### 12.2 Generation-stage Baselines

- current registry existence check。
- current registry + typo detector。
- package hallucination detection baseline。
- LLM self-check。

### 12.3 SAST/API Baselines

- Semgrep security rules。
- CodeQL。
- Bandit/ESLint security rules。
- SCA + SAST union。

### 12.4 LLM Baselines

三档输入：

1. code only。
2. code + manifest。
3. code + retrieved evidence。

若 CodeSentry-Gen 仍优于 LLM+evidence，说明结构化时态推理确有必要；若接近，则论文结论应改为“structured evidence improves LLM-assisted triage”。

### 12.5 Ablations

- `no-time`
- `no-api-version`
- `no-install-reachability`
- `no-provenance`
- `no-calibration`
- `current-only-registry`

---

## 13. 统计分析

必须使用 paired design：

- 对 paired binary detection：McNemar test。
- 对 F1/precision/recall：按任务或项目聚类的 stratified bootstrap 95% CI。
- 多 baseline 比较：Holm-Bonferroni 或 Benjamini-Hochberg。
- 排序指标：paired bootstrap 或 Wilcoxon signed-rank。
- 分层结果：mixed-effects logistic regression，任务/repo 作为 random effects。
- 置信度校准：reliability diagram、ECE、Brier score。

报告格式：

| 项       | 要求                                            |
| -------- | ----------------------------------------------- |
| 点估计   | 每类风险单独 precision/recall/F1                |
| 不确定性 | 95% CI                                          |
| 显著性   | paired p-value + effect size                    |
| 分层     | ecosystem、model、task、real vs injected        |
| 成本     | median/P95 runtime、API queries、cache hit rate |
| 失败案例 | FP/FN taxonomy                                  |

---

## 14. 可证 SOTA Claim

### Claim 1：时态 registry 视图降低 current-only 包名检测漏报

已有包名幻觉研究证明 LLM 会生成不存在包名。CodeSentry-Gen v2.1 的可证增量是：识别 `t_g` 时不存在但 `t_audit` 时存在的包，避免 current-only registry check 把生成后注册包误判为安全。

### Claim 2：install reachability 降低包名检测误阻断

相对 package-name-only detector，R0-R5 可达性分级能区分“只在说明中出现的包名”和“会被 CI/lockfile 安装的包名”，从而提升 high-risk precision，降低 false blocking。

### Claim 3：AVCS 在 curated high-risk libraries 上发现传统 SCA 漏掉的风险

传统 SCA 在依赖固定后工作。AVCS 的可证 claim 只限于 manifest 缺失或版本宽松、且 API history 可验证的高风险库：API 用法能够收缩可行版本集合，并发现 `SCA only`、`SCA + SAST` 或 `LLM + evidence` 漏掉的高精度、可修复风险。

### Claim 4：Risk Card 改善专家 triage 和修复

Risk Card 的 claim 不是“解释更好看”，而是在受控开发者研究中减少 triage time、提升 correct repair/suppression，并保持可接受 false blocking。

---

## 15. 6-9 个月 MVP 与 9-12 个月论文系统

### 阶段 1：0-2 个月

- Python/npm extractor。
- manifest/lockfile parser。
- import-to-package mapping。
- SCEG JSON schema。

### 阶段 2：2-4 个月

- PyPI/npm registry client。
- OSV/GHSA/deps.dev client。
- 缓存层和 snapshot 机制。
- SARIF + Markdown Risk Card。

### 阶段 3：4-6 个月

- HalluGuard-THO。
- TimeVulnTrace basic vulnerability matching。
- 10-20 个库的 API surface history。
- curated API misuse rules。

### 阶段 4：6-9 个月

- PR diff CI scanning。
- GenDepRiskBench v1，规模控制在 500-800 真实生成样本 + 300 historical/injection + 100-200 hard negatives。
- 小规模 formative triage study。

### 9-12 个月扩展

- VS Code 插件或 IDE prototype。
- 1,500-3,000 规模完整 benchmark。
- 10-20 个库 API surface history 完整人工校验。
- 20-30 人 within-subject developer study。

---

## 16. 风险控制

| 风险                     | 控制                                                                  |
| ------------------------ | --------------------------------------------------------------------- |
| registry 历史不完整      | 保存 raw JSON snapshot，使用 release time 近似并显式标 unknown        |
| import-to-package 误映射 | curated mapping + local/private filter + hard negatives               |
| API history 覆盖不足     | 只对高频库做主实验，报告 coverage                                     |
| AVCS unknown 约束过宽    | 设置 API constraint strength 阈值，unknown 主导时只做 triage evidence |
| 时间泄漏                 | 三时间视图，严格限制 claim 可用信息                                   |
| LLM-as-judge 污染标签    | LLM 只做 baseline 或候选辅助，不做最终真值                            |
| 误报阻断开发             | 只阻断 A 级 high/critical 新增风险                                    |
| 过度 claim 训练记忆      | 改为 public neighbor evidence，不做因果 claim                         |

---

## 17. 参考工作与数据源

代表性研究：

- Spracklen et al., **We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs**, USENIX Security 2025 / arXiv 2024, [https://arxiv.org/abs/2406.10279](https://arxiv.org/abs/2406.10279)
- Pearce et al., **Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions**, IEEE S&P 2022, [https://arxiv.org/abs/2108.09293](https://arxiv.org/abs/2108.09293)
- Perry et al., **Do Users Write More Insecure Code with AI Assistants?**, CCS 2023, [https://arxiv.org/abs/2211.03622](https://arxiv.org/abs/2211.03622)
- LiCoEval, **Evaluating LLMs on License Compliance in Code Generation**, [https://arxiv.org/abs/2408.02487](https://arxiv.org/abs/2408.02487)
- OWASP Top 10 for LLM Applications 2025, [https://owasp.org/www-project-top-10-for-large-language-model-applications/](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

数据源：

- OSV API: [https://osv.dev/](https://osv.dev/) and [https://google.github.io/osv.dev/post-v1-query/](https://google.github.io/osv.dev/post-v1-query/)
- GitHub Advisory Database: [https://docs.github.com/en/rest/security-advisories/global-advisories](https://docs.github.com/en/rest/security-advisories/global-advisories)
- NVD API 2.0: [https://nvd.nist.gov/developers/vulnerabilities](https://nvd.nist.gov/developers/vulnerabilities)
- deps.dev API: [https://docs.deps.dev/api/v3/](https://docs.deps.dev/api/v3/)
- OpenSSF Scorecard: [https://github.com/ossf/scorecard](https://github.com/ossf/scorecard)
- SPDX License List: [https://spdx.org/licenses/](https://spdx.org/licenses/)
- CycloneDX: [https://cyclonedx.org/capabilities/](https://cyclonedx.org/capabilities/)

---

## 18. 最终定位

CodeSentry-Gen v2.1 的最优可行定位是：

> 一个面向 LLM 生成阶段的时态依赖风险检测方法，而不是全能供应链污染扫描器。其 SOTA 潜力来自同一个核心问题的两个侧面：在 generation-time incomplete dependency specification 下，THO 处理 package identity uncertainty，AVCS 处理 version uncertainty。前者识别生成时不存在、生成后可被注册并且 install-reachable 的包名风险；后者在 manifest 缺失或版本宽松时，通过受限但可信的 API-to-version 约束求解发现传统 SCA 漏掉的脆弱依赖风险。

该定位更容易满足 CCF-A 论文标准：问题边界清晰，算法贡献可执行，ground truth 可构建，baseline 可公平比较，MVP 可在 6-9 个月内落地。
