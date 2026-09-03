FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin rdp-token
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY recovery /usr/local/bin/recovery
RUN chmod 755 /usr/local/bin/recovery
RUN mkdir -p /data /certs && chown -R rdp-token:rdp-token /app /data

USER rdp-token
EXPOSE 18081 60000-60999
CMD ["python", "-m", "app.main"]
