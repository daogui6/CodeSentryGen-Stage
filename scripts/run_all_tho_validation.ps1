powershell -ExecutionPolicy Bypass -File .\scripts\run_risk_seed_validation.ps1
python .\src\check_qwen37_100_negative_control.py
powershell -ExecutionPolicy Bypass -File .\scripts\run_hard_negative_validation.ps1
python .\src\make_tho_validation_final_summary_v2.py
powershell -ExecutionPolicy Bypass -File .\scripts\cleanup_run_pilot_byproducts.ps1
