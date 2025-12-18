# TorBox Auto Downloader

This project automatically downloads torrents and NZBs from a watch directory using the TorBox API.

## Getting Started with Docker

### Prerequisites

*   Docker and Docker Compose installed.

### Configuration

1.  Set the `TORBOX_API_KEY` environment variable in your `docker-compose.yml` file. Replace the placeholder `API_KEY` with your actual Torbox API key.
2.  Update the volume paths in your `docker-compose.yml` file to match your local filesystem structure. 

**For Dual Directory Mode (Sonarr/Radarr):**
The default configuration uses separate directories for each:
- `/mnt/user/downloads/temp` mounted to `/app/watch` in the container
- `/mnt/user/downloads` mounted to `/app/downloads` in the container

The application will automatically create and watch subdirectories:
- `/app/watch/radarr` and `/app/watch/sonarr` for watch folders
- `/app/downloads/radarr` and `/app/downloads/sonarr` for completed downloads

**For Legacy Single Directory Mode:**
If you don't want to separate Sonarr/Radarr downloads, simply use `WATCH_DIR` and `DOWNLOAD_DIR` environment variables and the application will watch/download to those directories directly without creating subdirectories:
```yaml
environment:
  - WATCH_DIR=/app/watch
  - DOWNLOAD_DIR=/app/downloads
```
This will watch `/app/watch` and download to `/app/downloads` only (no subdirectories created).

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

| Variable                | Default Value              | Description                                                                                                                                                                                                                            |
| ----------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TORBOX_API_KEY`        | **(Required)**             | Your TorBox API key.                                                                                                                                                                                                                   |
| `TORBOX_API_BASE`       | `https://api.torbox.app`  | The base URL of the TorBox API.                                                                                                                                                                                                        |
| `TORBOX_API_VERSION`    | `v1`                       | The version of the TorBox API.                                                                                                                                                                                                         |
| `RADARR_WATCH_DIR`      | `/app/watch/radarr`*       | The directory to watch for Radarr torrent, magnet, and NZB files. *Enables dual directory mode.                                                                                                                                       |
| `RADARR_DOWNLOAD_DIR`   | `/app/downloads/radarr`*   | The directory where Radarr downloaded files will be stored. *Enables dual directory mode.                                                                                                                                              |
| `SONARR_WATCH_DIR`      | `/app/watch/sonarr`*       | The directory to watch for Sonarr torrent, magnet, and NZB files. *Enables dual directory mode.                                                                                                                                       |
| `SONARR_DOWNLOAD_DIR`   | `/app/downloads/sonarr`*   | The directory where Sonarr downloaded files will be stored. *Enables dual directory mode.                                                                                                                                              |
| `WATCH_DIR`             | `/app/watch`               | Legacy single directory mode: watches this directory only. Ignored if any Sonarr/Radarr variables are set.                                                                                                                            |
| `DOWNLOAD_DIR`          | `/app/downloads`           | Legacy single directory mode: downloads to this directory only. Ignored if any Sonarr/Radarr variables are set.                                                                                                                       |
| `WATCH_INTERVAL`        | `60`                       | The interval (in seconds) between scans of the watch directories.                                                                                                                                                                     |
| `CHECK_INTERVAL`        | `300`                      | The interval (in seconds) between checks for the status of downloads.                                                                                                                                                                 |
| `MAX_RETRIES`           | `2`                        | The maximum number of retries for API calls.                                                                                                                                                                                           |
| `MAX_STATUS_CHECK_FAILURES` | `5`                    | Maximum consecutive failures when checking download status before removing from tracking. Prevents infinite retry loops on API errors.                                                                                                |
| `ALLOW_ZIP`             | `false`                    | Whether to allow automatic ZIP compression of downloads from TorBox.                                                                                                                                                                  |
| `SEED_PREFERENCE`       | `1`                        | Seed preference for torrents (specific to TorBox API).                                                                                                                                                                                 |
| `POST_PROCESSING`       | `-1`                       | Post-processing setting for usenet downloads (specific to TorBox API).                                                                                                                                                                 |
| `QUEUE_IMMEDIATELY`     | `false`                    | Whether to queue downloads immediately or add them as paused (specific to TorBox API, behavior may depend on your Torbox subscription. If set to `false` downloads are added as paused, if `true` downloads are added to the queue). |
| `PROGRESS_INTERVAL`     | `15`                       | The interval (in seconds) for updating download/extraction progress.                                                                                                                                                                   |

**Note:** Setting any of `RADARR_WATCH_DIR`, `RADARR_DOWNLOAD_DIR`, `SONARR_WATCH_DIR`, or `SONARR_DOWNLOAD_DIR` enables dual directory mode and causes `WATCH_DIR` and `DOWNLOAD_DIR` to be ignored.

## Local Development (without Docker)

1.  Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

2.  Set the `TORBOX_API_KEY` environment variable and other environment variables as needed, for example in your shell before running.

3.  Run the application:

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
