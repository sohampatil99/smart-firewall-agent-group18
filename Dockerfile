# Disposable test machine for Agent 18: a normal user plus a sudoers entry for exactly three iptables binaries.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv iptables sudo netbase ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m fw \
 && echo 'fw ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore' > /etc/sudoers.d/agent18 \
 && chmod 440 /etc/sudoers.d/agent18
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir "mcp[cli]>=1.9,<2" ollama "pydantic>=2" pytest \
 && /opt/venv/bin/pip install --no-cache-dir --only-binary=:all: llama-cpp-python \
      --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
USER fw
