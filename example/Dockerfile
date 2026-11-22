# Build from the repository root, since p14g is built from crates/ (`docker compose` does this):
#     docker build -f example/Dockerfile .
#
# Follows uv's multistage example (https://docs.astral.sh/uv/guides/integration/docker/): build the virtualenv with
# uv, then copy it into a Python image without uv. Both stages must have Python at the same path.

FROM ghcr.io/astral-sh/uv:python3.15-trixie-slim AS builder

# Rust, to compile p14g
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/root/.cargo/bin:$PATH"

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_NO_DEV=1 UV_PYTHON_DOWNLOADS=0

WORKDIR /app/example

# Third-party dependencies first, in their own layer, so changing p14g or the example does not reinstall them
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=example/uv.lock,target=uv.lock \
    --mount=type=bind,source=example/pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-package p14g

COPY Cargo.toml Cargo.lock /app/
COPY crates/p14g /app/crates/p14g
COPY crates/p14g-python /app/crates/p14g-python
COPY example /app/example

# `--no-editable` copies p14g into the virtualenv, so the final image does not need crates/
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=cache,target=/root/.cargo/registry \
    uv sync --locked --no-editable


FROM python:3.15-slim-trixie

RUN groupadd --system --gid 999 nonroot \
    && useradd --system --gid 999 --uid 999 --create-home nonroot

COPY --from=builder --chown=nonroot:nonroot /app/example /app/example

ENV PATH="/app/example/.venv/bin:$PATH" PYTHONUNBUFFERED=1
USER nonroot
WORKDIR /app/example
EXPOSE 8000
CMD ["uvicorn", "p14g_example.main:app", "--host", "0.0.0.0", "--port", "8000"]
