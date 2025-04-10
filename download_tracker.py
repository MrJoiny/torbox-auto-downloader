import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class DownloadTracker:
    """
    Tracks submitted downloads and their types.
    """

    def __init__(self):
        """
        Initializes the DownloadTracker with an empty download tracking dictionary.
        """
        self.download_tracking = {}  # {identifier: tracking_info}

    def track_download(
        self,
        identifier,
        download_type,
        file_stem,
        original_file=None, # Made optional
        download_id=None,
        download_hash=None,
    ):
        """
        Tracks a new download. Uses the provided identifier as the primary key.

        Args:
            identifier (str): A unique identifier for the download (e.g., torrent ID or hash).
                               Must be provided and unique.
            download_type (str): The type of download ("torrent" or "usenet").
            file_stem (str): The name for the download (e.g., original file name without ext).
            original_file (str, optional): The path to the original file, if applicable. Defaults to None.
            download_id (str, optional): The download ID from the API (e.g., torrent_id). Defaults to None.
            download_hash (str, optional): The download hash from the API. Defaults to None.

        Returns:
            bool: True if tracking was successfully initiated, False if already tracked.
        """
        if str(identifier) in self.download_tracking:
            logger.warning(f"Attempted to track already tracked identifier: {identifier}")
            return False

        self.download_tracking[str(identifier)] = {
            "type": download_type,
            "name": file_stem,
            "submitted_at": datetime.now().isoformat(),
            "original_file": str(original_file) if original_file else None,
            "id": download_id, # Store the specific API ID if provided
            "hash": download_hash, # Store the hash if provided
        }
        logger.info(
            f"Tracking new {download_type} download: Identifier: {identifier}, Name: {file_stem}"
        )
        return True

    def get_tracked_downloads(self):
        """
        Returns all tracked downloads.

        Returns:
            dict: A dictionary containing tracking information for all downloads.
        """
        return self.download_tracking

    def remove_tracked_download(self, download_id):
        """
        Removes a download from tracking.

        Args:
            download_id (str): The identifier of the download to remove.
        """
        if download_id in self.download_tracking:
            del self.download_tracking[download_id]
            logger.info(f"Stopped tracking download identifier: {download_id}")

    def get_download_info(self, identifier):
        """
        Retrieves tracking information for a given download identifier.

        Args:
            identifier (str): The identifier of the download.

        Returns:
            dict: Tracking information for the download, or None if not found.
        """
        return self.download_tracking.get(str(identifier))
