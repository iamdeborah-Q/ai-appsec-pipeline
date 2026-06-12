# Golden Image: a hardened Python base that all teams build FROM.
# Start from an official, SLIM, version-pinned base.
FROM python:3.12-slim-bookworm

# Apply the latest security patches, then remove tools attackers abuse.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/bin/wget 2>/dev/null || true

    # Create a non-root user. Containers must NOT run as root.
RUN groupadd --system app && useradd --system --gid app --home /app app

# Set the working directory and hand ownership to the non-root user.
WORKDIR /app
RUN chown app:app /app


# Upgrade pip to patch known pip CVEs (CVE-2025-8869, etc.)
RUN pip install --upgrade pip

# Switch to the non-root user for everything that follows.
USER app




# Secure, sensible environment defaults.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Metadata so teams know what this image is and that it's security-maintained.
LABEL org.opencontainers.image.title="golden-python-base" \
      org.opencontainers.image.description="Hardened Python 3.12 base: non-root, patched, minimal. Scanned with Trivy." \
      org.opencontainers.image.vendor="security-team"