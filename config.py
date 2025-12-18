import os
from pathlib import Path


class Config:
    """
    Configuration class to load settings from environment variables.
    """

    TORBOX_API_KEY = os.getenv("TORBOX_API_KEY")
    TORBOX_API_BASE = os.getenv("TORBOX_API_BASE", "https://api.torbox.app")
    TORBOX_API_VERSION = os.getenv("TORBOX_API_VERSION", "v1")
    
    # Check if using dual directory mode (Sonarr/Radarr specific paths)
    # If any of the specific paths are set, we're in dual directory mode
    _radarr_watch = os.getenv("RADARR_WATCH_DIR")
    _radarr_download = os.getenv("RADARR_DOWNLOAD_DIR")
    _sonarr_watch = os.getenv("SONARR_WATCH_DIR")
    _sonarr_download = os.getenv("SONARR_DOWNLOAD_DIR")
    
    # Legacy single directory mode
    _legacy_watch = os.getenv("WATCH_DIR")
    _legacy_download = os.getenv("DOWNLOAD_DIR")
    
    # Determine if we're in dual directory mode
    DUAL_DIRECTORY_MODE = any([_radarr_watch, _radarr_download, _sonarr_watch, _sonarr_download])
    
    if DUAL_DIRECTORY_MODE:
        # Dual directory mode - separate paths for Radarr and Sonarr
        RADARR_WATCH_DIR = Path(_radarr_watch or "/app/watch/radarr")
        RADARR_DOWNLOAD_DIR = Path(_radarr_download or "/app/downloads/radarr")
        SONARR_WATCH_DIR = Path(_sonarr_watch or "/app/watch/sonarr")
        SONARR_DOWNLOAD_DIR = Path(_sonarr_download or "/app/downloads/sonarr")
    else:
        # Legacy single directory mode - use same paths for both (no subdirectories)
        RADARR_WATCH_DIR = Path(_legacy_watch or "/app/watch")
        RADARR_DOWNLOAD_DIR = Path(_legacy_download or "/app/downloads")
        SONARR_WATCH_DIR = Path(_legacy_watch or "/app/watch")
        SONARR_DOWNLOAD_DIR = Path(_legacy_download or "/app/downloads")
    
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
