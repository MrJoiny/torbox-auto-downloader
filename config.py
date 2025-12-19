import os
from pathlib import Path


class Config:
    """
    Configuration class to load settings from environment variables.
    """

    TORBOX_API_KEY = os.getenv("TORBOX_API_KEY")
    TORBOX_API_BASE = os.getenv("TORBOX_API_BASE", "https://api.torbox.app")
    TORBOX_API_VERSION = os.getenv("TORBOX_API_VERSION", "v1")
    
    # Base directories (container paths)
    _base_watch = os.getenv("WATCH_DIR", "/app/watch")
    _base_download = os.getenv("DOWNLOAD_DIR", "/app/downloads")
    
    # Subdirectory names (just the suffix, not full paths)
    _radarr_watch_subdir = os.getenv("RADARR_WATCH_SUBDIR")
    _radarr_download_subdir = os.getenv("RADARR_DOWNLOAD_SUBDIR")
    _sonarr_watch_subdir = os.getenv("SONARR_WATCH_SUBDIR")
    _sonarr_download_subdir = os.getenv("SONARR_DOWNLOAD_SUBDIR")
    
    # Determine if we're in dual directory mode
    DUAL_DIRECTORY_MODE = any([_radarr_watch_subdir, _radarr_download_subdir, _sonarr_watch_subdir, _sonarr_download_subdir])
    
    if DUAL_DIRECTORY_MODE:
        # Dual directory mode - append subdirectories to base paths
        RADARR_WATCH_DIR = Path(_base_watch) / (_radarr_watch_subdir or "radarr")
        RADARR_DOWNLOAD_DIR = Path(_base_download) / (_radarr_download_subdir or "radarr")
        SONARR_WATCH_DIR = Path(_base_watch) / (_sonarr_watch_subdir or "sonarr")
        SONARR_DOWNLOAD_DIR = Path(_base_download) / (_sonarr_download_subdir or "sonarr")
    else:
        # Legacy single directory mode - use base paths directly (no subdirectories)
        RADARR_WATCH_DIR = Path(_base_watch)
        RADARR_DOWNLOAD_DIR = Path(_base_download)
        SONARR_WATCH_DIR = Path(_base_watch)
        SONARR_DOWNLOAD_DIR = Path(_base_download)
    
    WATCH_INTERVAL = int(os.getenv("WATCH_INTERVAL", 60))
    CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", 300))
    MAX_RETRIES = int(os.getenv("MAX_RETRIES", 2))
    MAX_STATUS_CHECK_FAILURES = int(os.getenv("MAX_STATUS_CHECK_FAILURES", 5))
    ALLOW_ZIP = os.getenv("ALLOW_ZIP", "false").lower() == "true"
    SEED_PREFERENCE = int(os.getenv("SEED_PREFERENCE", 1))
    POST_PROCESSING = int(os.getenv("POST_PROCESSING", -1))
    QUEUE_IMMEDIATELY = os.getenv("QUEUE_IMMEDIATELY", "false").lower() == "true"
    PROGRESS_INTERVAL = int(os.getenv("PROGRESS_INTERVAL", 15))

    @staticmethod
    def validate():
        """
        Validates that the required environment variables are set.

        Raises:
            ValueError: If the TORBOX_API_KEY is not set.
        """
        if not Config.TORBOX_API_KEY:
            raise ValueError(
                "TORBOX_API_KEY is not set. Please provide a valid API key."
            )
