FROM python:3.13.2-slim

ARG APP_VERSION=unknown

LABEL org.opencontainers.image.title="TorBox Auto Downloader" \
      org.opencontainers.image.description="Watch-folder downloader for TorBox torrents and NZBs" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.source="https://github.com/MrJoiny/torbox-auto-downloader" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY api_client.py ./
COPY config.py ./
COPY download_tracker.py ./
COPY file_processor.py ./
COPY main.py ./
COPY version.py ./
COPY watcher.py ./
COPY webhook_notifier.py ./

CMD ["python", "main.py"]
