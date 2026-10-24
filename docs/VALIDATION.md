# 运行与验证说明

本说明给出当前阶段原型的代表性离线复现流程。以下命令从仓库根目录执行，使用已激活的 Python 3.10 独立环境。每行命令单独运行，发生错误时先检查该步的输入和输出。

## 1. 环境与工作副本

已验证环境为 Windows、新建 Python 3.10 venv；主要依赖版本为 requests 2.34.2、packaging 26.3、jsonschema 4.26.0。其他环境的执行结果按实际运行另行记录。

建议先建立独立工作副本：

```text
git clone -c core.autocrlf=false https://github.com/daogui6/CodeSentryGen-Stage.git CodeSentryGen-Validation
cd CodeSentryGen-Validation
```

Windows CMD 环境示例：

```cmd
python -m venv ../codesentry-validation-venv
call ..\codesentry-validation-venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python -m pip check
python -m pip freeze > ../codesentry-validation-dependencies.txt
```

部分既有检查器会在工作副本中重写验证 CSV。新生成的链路输出使用 output/stage_migration_verification_20261024 目录；历史来源文件保留在原阶段仓库中。

## 2. 知识库与候选格式

六包 KB 的 Schema 及既有语义检查：

```text
python -X utf8 -c "import subprocess,sys; from pathlib import Path; files=sorted(Path('data/avcs_package_kb').glob('*.json')); assert len(files)==6; codes=[subprocess.run([sys.executable,'-X','utf8','src/validate_avcs_package_kb.py','--schema','schemas/avcs_package_kb_schema_v0.json','--kb',str(p),'--repo-root','.']).returncode for p in files]; print('KB checked:',len(codes),'PASS:',codes.count(0),'FAIL:',len(codes)-codes.count(0)); sys.exit(any(codes))"
```

Pillow 原始 Candidate 的 Schema、引用和审核门检查：

```text
python -X utf8 src/validate_trigger_hitl_candidate.py --schema schemas/avcs_trigger_hitl_candidate_schema_v0.json --protocol schemas/avcs_trigger_eligibility_protocol_v0.json --candidate output/step7_hitl_batch_v0/step7_pillow_ghsa_45hq_cxwh_f6vc/candidate.json --repo-root .
```

已有 LLM Proposal 的 Schema 检查：

```text
python -X utf8 -c "import json; from pathlib import Path; from jsonschema import Draft202012Validator; schema=json.loads(Path('schemas/avcs_trigger_llm_proposal_schema_v0.json').read_text(encoding='utf-8')); proposal=json.loads(Path('output/step7_batch_review_v0/batch_004_llm_proposals_v1/step7_pillow_ghsa_45hq_cxwh_f6vc/llm_proposal.json').read_text(encoding='utf-8')); Draft202012Validator.check_schema(schema); Draft202012Validator(schema).validate(proposal); print('LLM PROPOSAL SCHEMA VALIDATION PASS')"
```

参考结果：六包 KB 为 6/6；原始 Candidate 与 Proposal Schema 通过。原始 Candidate 保持 requires_review，candidate_rule 为空。

## 3. AVCS 与范围修复回归

```text
python -X utf8 src/check_avcs_minimal_pipeline.py
python -X utf8 src/check_avcs_trigger_rule_matching.py
python -X utf8 -m unittest discover -s tests -p test_osv_multisource_release_ranges.py -v
```

参考结果分别为 46/46、31/31 和 29 个测试通过。第一项检查已有 AVCS 存档的一致性；后两项分别运行既有规则函数与范围修复回归。

## 4. THO→Risk Card→SCEG 实际链路

输入为四条已有受控记录，输出写入专用目录：

```text
python -X utf8 src/enrich_temporal_status.py --input output/risk_seed_validation_pilot_results.jsonl --output output/stage_migration_verification_20261024/temporal.jsonl --summary output/stage_migration_verification_20261024/temporal.md
python -X utf8 src/enrich_reachability_v2.py --input output/stage_migration_verification_20261024/temporal.jsonl --output output/stage_migration_verification_20261024/reachability.jsonl --summary output/stage_migration_verification_20261024/reachability.md --requirements-dir data/risk_seed_validation_requirements_files
python -X utf8 src/build_temporal_risk_cards.py --input output/stage_migration_verification_20261024/reachability.jsonl --output output/stage_migration_verification_20261024/risk_cards.jsonl --summary output/stage_migration_verification_20261024/risk_cards.md
python -X utf8 src/build_sceg_v0.py --input output/stage_migration_verification_20261024/reachability.jsonl --risk-cards output/stage_migration_verification_20261024/risk_cards.jsonl --out output/stage_migration_verification_20261024/sceg.jsonl --summary output/stage_migration_verification_20261024/sceg.md --dataset-label stage_migration_offline_control
```

检查数量、样本关联和新生成的 SCEG Schema：

```text
python -X utf8 -c "import json; from pathlib import Path; from collections import Counter; from jsonschema import Draft202012Validator; p=Path('output/stage_migration_verification_20261024'); read=lambda n:[json.loads(l) for l in (p/n).read_text(encoding='utf-8').splitlines() if l.strip()]; t=read('temporal.jsonl'); r=read('reachability.jsonl'); c=read('risk_cards.jsonl'); g=read('sceg.jsonl'); assert len(t)==len(r)==len(c)==len(g)==4; assert Counter(x['temporal_status_v2'] for x in t)=={'nonexistent_now':2,'created_after_tg':2}; ids={x['sample_id'] for x in t}; assert ids=={x['sample_id'] for x in r}=={x['sample_id'] for x in c}=={x['nodes']['sample']['sample_id'] for x in g}; assert all(len(x['risk_card_links'])==1 and x['analysis']['risk_card_count']==1 for x in g); s=json.loads(Path('schemas/sceg_schema_v0.json').read_text(encoding='utf-8')); Draft202012Validator.check_schema(s); v=Draft202012Validator(s); [v.validate(x) for x in g]; print('THO/SCEG controlled pipeline PASS: 4 records, 4 Risk Cards, 4 schema-valid SCEG records')"
```

参考结果为四条记录、四张 Risk Card、四条通过 Schema 的 SCEG；时间状态为两条 nonexistent_now 和两条 created_after_tg。受控输入用于验证处理链路。

## 5. 11 包冻结目录重放

```text
python -X utf8 -c "import sys,json; from pathlib import Path; sys.path.insert(0,'src'); from resolve_osv_package_catalog_constraints import resolve_catalog_constraints; files=sorted(Path('output/step7_osv_catalogs_v0').glob('*.json')); rows=[resolve_catalog_constraints(json.loads(p.read_text(encoding='utf-8')),p.stem) for p in files]; counts=tuple(sum(r[k] for r in rows) for k in ('vulnerability_group_count','resolved_vulnerability_count','unresolved_vulnerability_count')); assert len(files)==11 and counts==(208,171,37),counts; target=Path('output/stage_migration_verification_20261024/osv_replay_counts.json'); target.parent.mkdir(parents=True,exist_ok=True); target.write_text(json.dumps({'packages':[p.stem for p in files],'groups':counts[0],'resolved':counts[1],'unresolved':counts[2]},indent=2),encoding='utf-8'); print('OSV replay PASS: 11 packages, 208 groups, 171 resolved, 37 unresolved')"
```

命令在专用目录保存汇总，参考统计为 208 个漏洞组、171 resolved / 37 unresolved。

## 6. LLM 准备接口的离线重放

原始 Candidate 有两条来源，已有 Proposal 另引用三份已保存的语义片段。下面将这些来源登记到临时验收 Candidate，并标注其用途。该步骤使用仓库内已有文件。

```text
python -X utf8 -c "import json; from pathlib import Path; load=lambda p:json.loads(Path(p).read_text(encoding='utf-8')); c=load('output/step7_hitl_batch_v0/step7_pillow_ghsa_45hq_cxwh_f6vc/candidate.json'); q=load('output/step7_batch_review_v0/batch_004_llm_proposals_v1/step7_pillow_ghsa_45hq_cxwh_f6vc/llm_proposal.json'); refs=set(q['candidate_rule']['evidence_refs'])|{r for claim in q['claim_evidence_map'] for r in claim['evidence_refs']}; existing={s['source_id'] for s in c['evidence_sources']}; needed=sorted(refs-existing); sources=[(r,load(r)) for r in needed]; assert len(needed)==3; assert all(s['case_id']==c['case_id'] and s['vulnerability_id']==c['vulnerability']['vulnerability_id'] and s['semantic_boundary']['human_review_created'] is False and s['semantic_boundary']['trigger_truth_created'] is False for r,s in sources); c['evidence_sources'].extend({'source_id':r,'source_type':'stored_semantic_excerpt','path':r,'locator':'selected_units','claim':'Stored semantic excerpt registered for interface acceptance.'} for r,s in sources); c['review_gate']['notes']+=' Acceptance input assembled from included files; not an original historical packet.'; target=Path('output/stage_migration_verification_20261024/candidate_for_validation.json'); target.parent.mkdir(parents=True,exist_ok=True); target.write_text(json.dumps(c,ensure_ascii=False,indent=2),encoding='utf-8'); print('Acceptance candidate prepared: 5 registered evidence sources')"
```

构建请求并合并已有 Proposal：

```text
python -X utf8 src/build_trigger_llm_request.py --packet output/stage_migration_verification_20261024/candidate_for_validation.json --protocol schemas/avcs_trigger_eligibility_protocol_v0.json --proposal-schema schemas/avcs_trigger_llm_proposal_schema_v0.json --out output/stage_migration_verification_20261024/llm_request_for_validation.json
python -X utf8 src/apply_trigger_llm_proposal.py --packet output/stage_migration_verification_20261024/candidate_for_validation.json --proposal output/step7_batch_review_v0/batch_004_llm_proposals_v1/step7_pillow_ghsa_45hq_cxwh_f6vc/llm_proposal.json --proposal-schema schemas/avcs_trigger_llm_proposal_schema_v0.json --candidate-schema schemas/avcs_trigger_hitl_candidate_schema_v0.json --protocol schemas/avcs_trigger_eligibility_protocol_v0.json --repo-root . --out output/stage_migration_verification_20261024/proposal_merged_for_validation.json
python -X utf8 -c "import json; from pathlib import Path; load=lambda n:json.loads((Path('output/stage_migration_verification_20261024')/n).read_text(encoding='utf-8')); before=load('candidate_for_validation.json'); after=load('proposal_merged_for_validation.json'); g=after['review_gate']; assert g==before['review_gate']; assert g['status']=='requires_review' and g['review_required'] is True and g['final_truth_created'] is False and g['reviewer'] is None and g['reviewed_at'] is None; print('LLM PROPOSAL INTERFACE PASS: review_required=True, final_truth_created=False')"
```

合并后模型候选分类为 eligible，人工审核门仍为 requires_review、review_required=true、final_truth_created=false。临时输入和输出用于接口验收；原始历史整套请求与候选输入的完整重放未纳入本次结论。

## 7. 验收记录与历史存档

本轮代表性验收日期为 2026-10-24，对应[功能基线及来源说明](SOURCE_VERSIONS.md)。Windows 执行结果由实际运行者提供终端输出，远端文件树另经读取核对。

output 下既有 Markdown 保留其生成时点和数据口径。文件名中的 final、pre_mismatch 等标识属于各自历史流程；当前复现结果以本次运行输出为准。

部分语义片段元数据引用的历史上游工件未全部收集到本快照，包括所查来源提交中未找到的 review_packet.json。原引用保持原样。现有片段支持上述临时上下文中的接口验证，候选语义及漏洞触发条件仍按人工审核流程确认。

总体实现范围见 [STAGE_SCOPE](STAGE_SCOPE.md)。本轮功能级验收覆盖上述输入和路径；正式主实验及性能指标按独立实验设计组织。
