# CodeSentry-Gen 阶段快照

这是限定研究阶段的整理快照，范围截至版本范围证据修复完成、准备开展逐漏洞协作审核。

包含此前介绍的依赖提取、THO、轻量 SCEG v0、AVCS 版本约束与漏洞暴露、旧第三层既有能力、六包 Package KB、五包 API History、11 包漏洞目录，以及 HITL Candidate、语义资料和 LLM Proposal 准备成果。

## 阅读入口

- THO：`src/run_pilot.py`、`src/enrich_temporal_status.py`、`src/enrich_reachability_v2.py`、`src/build_temporal_risk_cards.py`。
- SCEG：`src/build_pre_sceg_dependency_entities.py`、`src/build_sceg_v0.py`、对应 schema 和集成脚本。
- AVCS：`src/extract_api_calls.py`、版本/manifest/release 约束模块、暴露集合与强度模块。
- 旧第三层：`src/run_avcs_trigger_matcher.py` 和 `data/avcs_package_kb/` 中的六包既有案例。
- 候选准备：`src/build_trigger_hitl_candidate.py`、`src/build_trigger_llm_request.py`、`src/apply_trigger_llm_proposal.py`，以及 Pillow 准备样例。
- 范围修复：`src/osv_pypi_release_ranges.py`、OSV 目录/约束模块和范围修复测试。

## 环境与范围

按 `requirements.txt` 安装依赖。核心按对应阶段的分步入口使用；本快照不提供后续统一实验调度器。

`docs/STAGE_SCOPE.md` 说明研究边界，`docs/SOURCE_VERSIONS.md` 说明源码取用方式。历史文件保留其原有时间和不确定性；本次整理不改变历史实验结论。
