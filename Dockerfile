# Dockerfile for RAE-Quality
# Enterprise Grade Python 3.14 Environment

FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    software-properties-common curl git build-essential \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y \
    python3.14 python3.14-dev python3.14-venv \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.14
RUN ln -sf /usr/bin/python3.14 /usr/bin/python3

WORKDIR /app
RUN python3.14 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY packages/rae-quality/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir fastapi uvicorn httpx structlog aiosqlite numpy pydantic-settings pytest-asyncio "mcp<2"

# STAGE 2: Final Runtime
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y \
    software-properties-common curl \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y python3.14 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 raequality || true

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY packages/rae-quality .

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000
CMD ["python", "main.py"]
