
FROM python:3.11-slim as builder


ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1


RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app


COPY requirements.txt .


RUN pip install --no-cache-dir -r requirements.txt


FROM python:3.11-slim as production

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.local/bin:$PATH"


RUN apt-get update && apt-get install -y \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean


RUN groupadd -r cloudguard && useradd -r -g cloudguard cloudguard


WORKDIR /app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY cg.py .
COPY requirements.txt .


RUN mkdir -p /app/reports && chown -R cloudguard:cloudguard /app


USER cloudguard

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import boto3; print('CloudGuard is healthy')" || exit 1

ENTRYPOINT ["python", "cg.py"]
CMD ["--help"]


FROM python:3.11-slim as development


ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1


RUN apt-get update && apt-get install -y \
    git \
    curl \
    jq \
    vim \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app


COPY requirements.txt .
COPY requirements-dev.txt .

RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt


COPY . .


RUN mkdir -p /app/reports


CMD ["python", "cg.py", "--help"]
