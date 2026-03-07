# TorBox Auto Downloader

Watch-folder downloader for TorBox torrents and NZBs.

## Docker

The default container flow uses the published image:

```bash
git clone https://github.com/MrJoiny/torbox-auto-downloader
cd torbox-auto-downloader
cp .env.example .env
```

Edit `.env` and set:

- `TORBOX_API_KEY`
- `HOST_WATCH_PATH`
- `HOST_DOWNLOAD_PATH`

Then start the container:

```bash
docker compose up -d
```

The default Compose file pulls `mrjoiny/torbox-auto-downloader:${IMAGE_TAG:-latest}`.

### Paths and ownership

Compose wiring variables are:

- `HOST_WATCH_PATH`
- `HOST_DOWNLOAD_PATH`
- `CONTAINER_WATCH_DIR`
- `CONTAINER_DOWNLOAD_DIR`
- `IMAGE_TAG`

The application itself reads:

- `WATCH_DIR`
- `DOWNLOAD_DIR`
- `TORBOX_API_KEY`
- the remaining TorBox/runtime settings listed below

`docker-compose.yml` maps `WATCH_DIR=${CONTAINER_WATCH_DIR}` and `DOWNLOAD_DIR=${CONTAINER_DOWNLOAD_DIR}` for you. The image keeps the default container user unchanged for compatibility with host-mounted volumes.

If you want stricter file ownership on your host, add a Compose `user:` override yourself:

```yaml
services:
  torbox:
    user: "1000:1000"
```

## Configuration

For local source runs, `.env` is loaded automatically when you start the app from the repo root. Real environment variables still win over values in `.env`.

### Variables

| Variable | Scope | Default | Description |
| --- | --- | --- | --- |
| `TORBOX_API_KEY` | Runtime | Required | TorBox API key. |
| `TORBOX_API_BASE` | Runtime | `https://api.torbox.app` | TorBox API base URL. |
| `TORBOX_API_VERSION` | Runtime | `v1` | TorBox API version. |
| `WATCH_DIR` | Runtime | `/app/watch` | Base watch directory consumed by the app. For Compose, this is set from `CONTAINER_WATCH_DIR`. |
| `DOWNLOAD_DIR` | Runtime | `/app/downloads` | Base download directory consumed by the app. For Compose, this is set from `CONTAINER_DOWNLOAD_DIR`. |
| `HOST_WATCH_PATH` | Compose | Required | Host path mounted into the container watch directory. |
| `HOST_DOWNLOAD_PATH` | Compose | Required | Host path mounted into the container download directory. |
| `CONTAINER_WATCH_DIR` | Compose | `/app/watch` | Container mount point that Compose passes into `WATCH_DIR`. |
| `CONTAINER_DOWNLOAD_DIR` | Compose | `/app/downloads` | Container mount point that Compose passes into `DOWNLOAD_DIR`. |
| `IMAGE_TAG` | Compose | `latest` | Image tag to pull from Docker Hub. |
| `RADARR_WATCH_SUBDIR` | Runtime | `radarr` when set | Enables dual-directory mode and appends a Radarr watch subdirectory. |
| `RADARR_DOWNLOAD_SUBDIR` | Runtime | `radarr` when set | Enables dual-directory mode and appends a Radarr download subdirectory. |
| `SONARR_WATCH_SUBDIR` | Runtime | `sonarr` when set | Enables dual-directory mode and appends a Sonarr watch subdirectory. |
| `SONARR_DOWNLOAD_SUBDIR` | Runtime | `sonarr` when set | Enables dual-directory mode and appends a Sonarr download subdirectory. |
| `WATCH_INTERVAL` | Runtime | `60` | Seconds between watch-folder scans. |
| `CHECK_INTERVAL` | Runtime | `300` | Minimum seconds between TorBox status polling passes. |
| `PROGRESS_INTERVAL` | Runtime | `15` | Seconds between local progress updates. |
| `MAX_TRACKING_IDLE_HOURS` | Runtime | `24` | Drops a tracked item only after this many idle hours. |
| `MAX_RETRIES` | Runtime | `2` | API retry limit. |
| `MAX_STATUS_CHECK_FAILURES` | Runtime | `5` | Consecutive status exception threshold before dropping a tracked item. |
| `MAX_NOT_FOUND_FAILURES` | Runtime | `3` | Consecutive "not found" threshold before dropping a tracked item. |
| `MAX_DOWNLOAD_LINK_FAILURES` | Runtime | `3` | Consecutive download-link failure threshold before dropping a tracked item. |
| `GENERIC_WEBHOOK_URLS` | Runtime | empty | Comma-separated generic webhook endpoints for `download_dropped` events. |
| `DISCORD_WEBHOOK_URLS` | Runtime | empty | Comma-separated Discord webhook URLs for `download_dropped` summaries. |
| `WEBHOOK_TIMEOUT_SECONDS` | Runtime | `5` | Per-webhook timeout in seconds. |
| `ALLOW_ZIP` | Runtime | `false` | Allows TorBox ZIP downloads when appropriate. |
| `SEED_PREFERENCE` | Runtime | `1` | Torrent seed preference for TorBox. |
| `POST_PROCESSING` | Runtime | `-1` | Usenet post-processing setting for TorBox. |
| `QUEUE_IMMEDIATELY` | Runtime | `false` | Whether submissions should enter TorBox's queue immediately. |

Setting any `*_SUBDIR` variable enables dual-directory mode. If you want a single watch/download pair, comment out all four subdirectory variables.

Tracked items emit an internal `download_dropped` event for terminal failures. Generic webhooks receive the full JSON body. Discord webhooks receive a compact text summary.

## Sonarr and Radarr

With the default Docker configuration:

- Radarr uses `/app/watch/radarr` and `/app/downloads/radarr`
- Sonarr uses `/app/watch/sonarr` and `/app/downloads/sonarr`

If you run Sonarr or Radarr in Docker too, mount the same host paths into those containers and point their blackhole folders at the matching in-container subdirectories.

## Local Source Run

Install dependencies and run from the repo root:

```bash
pip install -r requirements.txt
cp .env.example .env
python main.py
```

For local runs, update `WATCH_DIR` and `DOWNLOAD_DIR` in `.env` to real local paths instead of the Docker defaults.

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

CI runs the Python test suite on Windows and Ubuntu and also performs a Docker build smoke check on Ubuntu.

## Image Tags

Docker tags are derived from [`version.py`](version.py). Releases publish these tags:

- `<major>.<minor>.<patch>`
- `<major>.<minor>`
- `<major>`
- `latest`

Manual release steps are documented in [`RELEASING.md`](RELEASING.md).

## Contributor Build

If you want to build the image locally from source instead of pulling from Docker Hub:

```bash
docker build --build-arg APP_VERSION=$(python -c "from version import __version__; print(__version__)") -t torbox-auto-downloader:local .
```
