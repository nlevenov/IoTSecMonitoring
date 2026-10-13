# ---- build: wheels only, nothing of this stage reaches the runtime image
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --wheel-dir /wheels .

# ---- runtime
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 HOME=/tmp

# tshark for the recommended capture backend (dumpcap is NOT made setuid)
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin iotsec

COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links=/wheels iotsec && rm -rf /wheels

WORKDIR /app
COPY config ./config
COPY feeds ./feeds
RUN mkdir -p var models data && chown iotsec:iotsec var models data

USER iotsec
EXPOSE 8501
CMD ["iotsec", "status"]
