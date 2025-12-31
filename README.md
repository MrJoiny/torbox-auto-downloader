# TorBox Auto Downloader

This project automatically downloads torrents and NZBs from a watch directory using the TorBox API.

## Getting Started with Docker

### Prerequisites

*   Docker and Docker Compose installed.

### Configuration

1.  **Create a `.env` file** from the example template:

    ```bash
    cp .env.example .env
    ```

2.  **Edit the `.env` file** and configure:
    - Set your `TORBOX_API_KEY`
    - Update `HOST_WATCH_PATH` and `HOST_DOWNLOAD_PATH` to match your filesystem
    - Optionally customize `CONTAINER_WATCH_DIR` and `CONTAINER_DOWNLOAD_DIR` (defaults: `/app/watch` and `/app/downloads`)

    Example:
    ```bash
    TORBOX_API_KEY=your_actual_api_key_here
    HOST_WATCH_PATH=/mnt/user/downloads/temp
    HOST_DOWNLOAD_PATH=/mnt/user/downloads
    CONTAINER_WATCH_DIR=/app/watch
    CONTAINER_DOWNLOAD_DIR=/app/downloads
    ```

    The host paths will be mounted to the container paths specified.

**For Dual Directory Mode (Sonarr/Radarr):**
The default `.env.example` uses subdirectory names that get appended to the base container paths.
With the default configuration:
- Radarr will use `${CONTAINER_WATCH_DIR}/radarr` and `${CONTAINER_DOWNLOAD_DIR}/radarr`
- Sonarr will use `${CONTAINER_WATCH_DIR}/sonarr` and `${CONTAINER_DOWNLOAD_DIR}/sonarr`

Which with defaults becomes:
- Radarr: `/app/watch/radarr` and `/app/downloads/radarr`
- Sonarr: `/app/watch/sonarr` and `/app/downloads/sonarr`

You can customize the subdirectory names in your `.env` file:
```bash
RADARR_WATCH_SUBDIR=radarr
RADARR_DOWNLOAD_SUBDIR=radarr
SONARR_WATCH_SUBDIR=sonarr
SONARR_DOWNLOAD_SUBDIR=sonarr
```

**For Legacy Single Directory Mode:**
If you don't want to separate Sonarr/Radarr downloads, comment out all the `*_SUBDIR` variables in your `.env` file:
```bash
# RADARR_WATCH_SUBDIR=radarr
# RADARR_DOWNLOAD_SUBDIR=radarr
# SONARR_WATCH_SUBDIR=sonarr
# SONARR_DOWNLOAD_SUBDIR=sonarr
```
This will watch `${CONTAINER_WATCH_DIR}` and download to `${CONTAINER_DOWNLOAD_DIR}` only (no subdirectories created).

### Running
1.  Clone Repo

    ```bash
    git clone https://github.com/ArnoldWildt/torbox-auto-downloader
    ```
    
1.  Build the Docker image:

    ```bash
    docker build -t torbox_auto_downloader:local .
    ```

2.  Start the container using Docker Compose:

    ```bash
    docker compose up
    ```

    To run in detached mode (in the background):

    ```bash
    docker compose up -d
    ```

## Configuration (Environment Variables)

All configuration is managed via the `.env` file. Copy `.env.example` to `.env` and customize as needed.

| Variable                    | Default Value              | Description                                                                                                                                                                                                                            |
| --------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TORBOX_API_KEY`            | **(Required)**             | Your TorBox API key.                                                                                                                                                                                                                   |
| `TORBOX_API_BASE`           | `https://api.torbox.app`   | The base URL of the TorBox API.                                                                                                                                                                                                        |
| `TORBOX_API_VERSION`        | `v1`                       | The version of the TorBox API.                                                                                                                                                                                                         |
| `HOST_WATCH_PATH`           | **(Required)**             | Host path to mount as the watch directory (e.g., `/mnt/user/downloads/temp`).                                                                                                                                                        |
| `HOST_DOWNLOAD_PATH`        | **(Required)**             | Host path to mount as the download directory (e.g., `/mnt/user/downloads`).                                                                                                                                                          |
| `CONTAINER_WATCH_DIR`       | `/app/watch`               | Container path where `HOST_WATCH_PATH` is mounted. Base directory for watching files.                                                                                                                                                |
| `CONTAINER_DOWNLOAD_DIR`    | `/app/downloads`           | Container path where `HOST_DOWNLOAD_PATH` is mounted. Base directory for downloads.                                                                                                                                                  |
| `WATCH_DIR`                 | `/app/watch`               | (Deprecated) Use `CONTAINER_WATCH_DIR` instead. Kept for backward compatibility.                                                                                                                                                     |
| `DOWNLOAD_DIR`              | `/app/downloads`           | (Deprecated) Use `CONTAINER_DOWNLOAD_DIR` instead. Kept for backward compatibility.                                                                                                                                                  |
| `RADARR_WATCH_SUBDIR`       | `radarr`*                  | Subdirectory appended to `CONTAINER_WATCH_DIR` for Radarr. *Enables dual directory mode.                                                                                                                                             |
| `RADARR_DOWNLOAD_SUBDIR`    | `radarr`*                  | Subdirectory appended to `CONTAINER_DOWNLOAD_DIR` for Radarr. *Enables dual directory mode.                                                                                                                                          |
| `SONARR_WATCH_SUBDIR`       | `sonarr`*                  | Subdirectory appended to `CONTAINER_WATCH_DIR` for Sonarr. *Enables dual directory mode.                                                                                                                                             |
| `SONARR_DOWNLOAD_SUBDIR`    | `sonarr`*                  | Subdirectory appended to `CONTAINER_DOWNLOAD_DIR` for Sonarr. *Enables dual directory mode.                                                                                                                                          |
| `WATCH_INTERVAL`            | `60`                       | The interval (in seconds) between scans of the watch directories.                                                                                                                                                                     |
| `CHECK_INTERVAL`            | `300`                      | The interval (in seconds) between checks for the status of downloads.                                                                                                                                                                 |
| `MAX_RETRIES`               | `2`                        | The maximum number of retries for API calls.                                                                                                                                                                                           |
| `MAX_STATUS_CHECK_FAILURES` | `5`                        | Maximum consecutive failures when checking download status before removing from tracking. Prevents infinite retry loops on API errors.                                                                                                |
| `ALLOW_ZIP`                 | `false`                    | Whether to allow automatic ZIP compression of downloads from TorBox.                                                                                                                                                                  |
| `SEED_PREFERENCE`           | `1`                        | Seed preference for torrents (specific to TorBox API).                                                                                                                                                                                 |
| `POST_PROCESSING`           | `-1`                       | Post-processing setting for usenet downloads (specific to TorBox API).                                                                                                                                                                 |
| `QUEUE_IMMEDIATELY`         | `false`                    | Whether to queue downloads immediately or add them as paused (specific to TorBox API, behavior may depend on your Torbox subscription. If set to `false` downloads are added as paused, if `true` downloads are added to the queue). |
| `PROGRESS_INTERVAL`         | `15`                       | The interval (in seconds) for updating download/extraction progress.                                                                                                                                                                   |

**Note:** Setting any of the `*_SUBDIR` variables enables dual directory mode. When enabled, subdirectories are automatically appended to `CONTAINER_WATCH_DIR` and `CONTAINER_DOWNLOAD_DIR`.

## Local Development (without Docker)

1.  Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

2.  **Create a `.env` file** from the example template:

    ```bash
    cp .env.example .env
    ```

3.  **Edit the `.env` file** and set your `TORBOX_API_KEY` and other environment variables as needed.

4.  Run the application:

    ```bash
    python main.py
    ```

    Make sure you have created the `watch`, and `downloads` directories in your project root.

## Integration with Sonarr/Radarr

This project is designed to work with both Sonarr and Radarr simultaneously using separate watch and download directories for each.

**Configuration Steps for Radarr/Sonarr:**

1.  Go to **Settings** -> **Download Clients** in Radarr.
2.  Click the **+** button to add a new download client.
3.  Select **Torrent Blackhole** or **Usenet Blackhole** (or both, repeating these steps for each).
4.  Give the download client a descriptive name (e.g., "TorBox Torrent Blackhole").
5.  Set the **Torrent/Usenet Folder** to the Radarr or Sonarr watch directory (e.g., `/app/watch/radarr` for Radarr if using the default Docker configuration). This path must match the `RADARR_WATCH_DIR` or `SONARR_WATCH_DIR` environment variable inside the container.
6.  Set the **Watch Folder** to the Radarr or Sonarr downloads directory (e.g., `/app/downloads/radarr` for Radarr if using the default Docker configuration). This path must match the `RADARR_DOWNLOAD_DIR` or `SONARR_WATCH_DIR` environment variable inside the container.

**Note:** If you're running Sonarr/Radarr in Docker, make sure to mount the same host directories to both containers. For example, if you mount `/mnt/user/downloads/temp` to `/app/watch` in the TorBox container, you should mount the same `/mnt/user/downloads/temp` to a path in your Sonarr/Radarr containers and use the appropriate subdirectory paths.
