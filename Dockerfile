FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY ulpf_py/ ./ulpf_py/
RUN pip install --no-cache-dir wheel setuptools && \
    pip wheel --no-cache-dir --wheel-dir=/wheels ./ulpf_py && \
    pip wheel --no-cache-dir --wheel-dir=/wheels \
      fastapi \
      uvicorn \
      pydantic \
      duckdb \
      pyarrow \
      pandas \
      zstandard \
      cryptography \
      pyyaml \
      drain3 \
      blake3

# Final Distroless / Hardened Runner
FROM python:3.11-slim

WORKDIR /app

# Security Hardening: Non-root user
RUN groupadd -g 10001 ulpf && \
    useradd -u 10001 -g ulpf -s /bin/false -m ulpf

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

COPY core/ /app/core/
COPY storage/ /app/storage/
COPY parsers/ /app/parsers/
COPY api/ /app/api/
COPY collector/ /app/collector/
COPY dashboard/ /app/dashboard/
COPY testdata/ /app/testdata/

RUN mkdir -p /app/lake /app/storage/raw && \
    chown -R ulpf:ulpf /app

USER ulpf:ulpf

EXPOSE 8000 5140/udp

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
