FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN python -m pip install --no-cache-dir -r requirements.txt
CMD ["python", "risk_seed_created_after_tg_001.py"]
