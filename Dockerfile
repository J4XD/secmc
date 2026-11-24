# syntax=docker/dockerfile:1

FROM golang:1.26-bookworm AS tools
ARG HTTPX_VERSION=v1.12.0
ARG NUCLEI_VERSION=v3.11.1
ARG FFUF_VERSION=v2.3.0
ENV CGO_ENABLED=0 GOBIN=/out
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
    && go install github.com/ffuf/ffuf/v2@${FFUF_VERSION}

FROM python:3.11-slim-bookworm AS app
COPY --from=astral/uv:0.11.32 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY README.md LICENSE ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.11-slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates nmap \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 1000 secmcp && install -d /config
COPY --from=tools /out/ /usr/local/bin/
COPY --from=app /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH SECMCP_SCOPE=/config/scope.yaml
USER secmcp
# The data directory must exist with the right owner before a named volume is
# mounted on it, or Docker creates it owned by root.
RUN mkdir -p /home/secmcp/.local/share/secmcp
# nuclei exits 0 even when the download fails, so check the result.
RUN nuclei -update-templates -duc && test -d /home/secmcp/nuclei-templates
VOLUME /home/secmcp/.local/share/secmcp
ENTRYPOINT ["secmcp"]
