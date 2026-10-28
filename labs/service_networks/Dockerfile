# Official Python image resolved and pulled on 2026-10-26. Context is this lab
# directory only; project .env files, keys, data and HarborDesk are never copied.
FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 VULNASSESS_CONTAINER_LAB=1
WORKDIR /app
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::ForceIPv4=true -o Acquire::https::Timeout=20 -o Acquire::Retries=1 update \
    && apt-get -o Acquire::ForceIPv4=true -o Acquire::https::Timeout=20 -o Acquire::Retries=1 install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/lab-requirements.txt
RUN pip install --no-cache-dir -r /tmp/lab-requirements.txt
COPY . /app/labs/service_networks/
USER 10001:10001
ENTRYPOINT ["python", "-m", "labs.service_networks.container"]
