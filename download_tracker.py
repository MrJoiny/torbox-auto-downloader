import logging
from datetime import datetime, timedelta

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
        queued_id=None,
        download_hash=None,
        download_dir=None,
        is_multi_file=False,
        state="active",
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
            queued_id (str, optional): The queued download ID from the API. Defaults to None.
            download_hash (str, optional): The download hash from the API. Defaults to None.
            download_dir (Path, optional): The destination directory for this download. Defaults to None.
            is_multi_file (bool, optional): Whether this download contains multiple files. Defaults to False.
            state (str, optional): Tracking state ("queued" or "active"). Defaults to "active".

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
            "state": state,
            "id": download_id, # Store the specific API ID if provided
            "queued_id": queued_id, # Store queued API ID if provided
            "hash": download_hash, # Store the hash if provided
            "download_dir": str(download_dir) if download_dir else None,
            "failure_count": 0,  # Track consecutive failures
            "is_multi_file": is_multi_file,  # Track if this is a multi-file download
        }
        logger.info(
            f"Tracking new {download_type} download: Identifier: {identifier}, Name: {file_stem}, Dest: {download_dir}"
        )
        return True

    def update_tracking_reference(
        self,
        identifier,
        state=None,
        queued_id=None,
        download_id=None,
        download_hash=None,
    ):
        """
        Updates the tracking reference for an existing download without changing its tracker key.

        Args:
            identifier (str): The stable tracker key for the download.
            state (str, optional): Updated tracking state.
            queued_id (str, optional): Updated queued ID.
            download_id (str, optional): Updated active download ID.
            download_hash (str, optional): Updated download hash.

        Returns:
            bool: True if the entry was updated, False if the download is unknown.
        """
        tracking_info = self.download_tracking.get(str(identifier))
        if not tracking_info:
            logger.warning(f"Cannot update tracking reference for unknown identifier: {identifier}")
            return False

        changes = []
        if state and tracking_info.get("state") != state:
            changes.append(f"state {tracking_info.get('state')} -> {state}")
            tracking_info["state"] = state

        if queued_id is not None and tracking_info.get("queued_id") != queued_id:
            changes.append(f"queued_id {tracking_info.get('queued_id')} -> {queued_id}")
            tracking_info["queued_id"] = queued_id

        if download_id is not None and tracking_info.get("id") != download_id:
            changes.append(f"id {tracking_info.get('id')} -> {download_id}")
            tracking_info["id"] = download_id

        if download_hash and tracking_info.get("hash") != download_hash:
            changes.append("hash updated")
            tracking_info["hash"] = download_hash

        if changes:
            logger.info(f"Updated tracking reference for {identifier}: {', '.join(changes)}")

        return True

    def increment_failure_count(self, identifier):
        """
        Increments the failure count for a download.

        Args:
            identifier (str): The identifier of the download.

        Returns:
            int: The new failure count, or None if download not found.
        """
        if str(identifier) in self.download_tracking:
            self.download_tracking[str(identifier)]["failure_count"] += 1
            return self.download_tracking[str(identifier)]["failure_count"]
        return None

    def reset_failure_count(self, identifier):
        """
        Resets the failure count for a download (on successful check).

        Args:
            identifier (str): The identifier of the download.
        """
        if str(identifier) in self.download_tracking:
            self.download_tracking[str(identifier)]["failure_count"] = 0

    def update_filename(self, identifier, filename, is_multi_file=False):
        """
        Updates the filename for a tracked download.

        Args:
            identifier (str): The identifier of the download.
            filename (str): The new filename to use.
            is_multi_file (bool): Whether this is a multi-file download (for forcing ZIP).
        """
        if str(identifier) in self.download_tracking:
            old_name = self.download_tracking[str(identifier)]["name"]
            self.download_tracking[str(identifier)]["name"] = filename
            self.download_tracking[str(identifier)]["is_multi_file"] = is_multi_file
            logger.info(f"Updated filename for {identifier}: {old_name} -> {filename}{' (multi-file)' if is_multi_file else ''}")
        else:
            logger.warning(f"Cannot update filename for unknown identifier: {identifier}")

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

    def cleanup_old_downloads(self, max_age_hours=24):
        """
        Removes downloads that have been tracked for longer than max_age_hours.
        This prevents memory leaks from downloads that never complete.

        Args:
            max_age_hours (int): Maximum age in hours before removing a download. Defaults to 24.

        Returns:
            int: Number of downloads removed.
        """
        now = datetime.now()
        to_remove = []
        
        for identifier, info in self.download_tracking.items():
            try:
                submitted_at = datetime.fromisoformat(info["submitted_at"])
                age = now - submitted_at
                
                if age > timedelta(hours=max_age_hours):
                    to_remove.append(identifier)
                    logger.warning(
                        f"Removing stale download {identifier} ({info['name']}) - "
                        f"tracked for {age.total_seconds()/3600:.1f} hours"
                    )
            except (KeyError, ValueError) as e:
                logger.error(f"Error checking age of download {identifier}: {e}")
        
        for identifier in to_remove:
            del self.download_tracking[identifier]
        
        if to_remove:
            logger.info(f"Cleaned up {len(to_remove)} stale downloads")
        
        return len(to_remove)
