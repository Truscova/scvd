FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# app code + openapi
COPY api/ /app/api/
COPY openapi.yaml /app/openapi.yaml

# bake the dataset into the image
COPY data/normalized/combined/all_findings.jsonl /app/data/normalized/combined/all_findings.jsonl
# optional snapshots if you have them
COPY data/snapshots/ /app/data/snapshots/

# envs your FastAPI code already reads
ENV SCVD_DATA_JSONL=/app/data/normalized/combined/all_findings.jsonl
ENV SCVD_SNAPSHOTS_DIR=/app/data/snapshots
# (optional) gate with an API key:
# ENV SCVD_API_KEY=change-me

ENV PORT=8080
EXPOSE 8080
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8080"]
