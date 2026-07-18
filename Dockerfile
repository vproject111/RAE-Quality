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
    && pip install --no-cache-dir fastapi uvicorn httpx structlog

# Install Gitleaks and Trivy to /opt in builder stage
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz | tar -xz -C /opt gitleaks
RUN curl -sSfL https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-64bit.tar.gz | tar -xz -C /opt trivy

# STAGE 2: Final Runtime
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y \
    software-properties-common curl \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y python3.14 git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /opt/trivy /usr/local/bin/trivy
COPY packages/rae-quality .

EXPOSE 8000
CMD ["python", "main.py"]
