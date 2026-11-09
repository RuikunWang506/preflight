FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && curl -fsSL -o /tmp/tool.tgz https://example.com/tool-1.2.0.tgz \
    && echo "0000000000000000000000000000000000000000000000000000000000000000  /tmp/tool.tgz" | sha256sum -c -
RUN pip install --no-cache-dir -e .
