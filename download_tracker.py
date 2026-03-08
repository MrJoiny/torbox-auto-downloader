import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

FAILURE_COUNT_REASONS = ("status_exception", "not_found", "download_link")


class DownloadTracker:
    """
    Tracks submitted downloads and their lifecycle metadata.
    """

    def __init__(self):
        """
        Initializes an empty in-memory tracking table keyed by local identifier.
        """
        self.download_tracking = {}

    def _now_iso(self):
        """
        Returns the current local timestamp in ISO 8601 format.

        Returns:
            str: Current local timestamp.
        """
        return datetime.now().isoformat()

    def track_download(
        self,
        identifier,
        download_type,
        file_stem,
        original_file=None,
        download_id=None,
        queued_id=None,
        queue_auth_id=None,
        download_hash=None,
        download_dir=None,
        is_multi_file=False,
        state="active",
    ):
        """
        Registers a new tracked download with lifecycle metadata and counters.

        Args:
            identifier (str): Stable local identifier for the tracked item.
            download_type (str): Download type, such as ``torrent`` or ``usenet``.
            file_stem (str): Display name for the tracked item.
            original_file (str | Path, optional): Source file path if one exists.
            download_id (str, optional): Active TorBox download ID.
            queued_id (str, optional): TorBox queued item ID.
            queue_auth_id (str, optional): Queue-derived auth bridge used for queued usenet promotion.
            download_hash (str, optional): TorBox download hash.
            download_dir (str | Path, optional): Destination directory for the local download.
            is_multi_file (bool, optional): Whether the download should be treated as multi-file.
            state (str, optional): Current tracker state, usually ``queued`` or ``active``.

        Returns:
            bool: ``True`` when the download was newly tracked, otherwise ``False``.
        """
        if str(identifier) in self.download_tracking:
            logger.warning("Attempted to track already tracked identifier: %s", identifier)
            return False

        timestamp = self._now_iso()
        self.download_tracking[str(identifier)] = {
            "type": download_type,
            "name": file_stem,
            "submitted_at": timestamp,
            "last_activity_at": timestamp,
            "original_file": str(original_file) if original_file else None,
            "state": state,
            "id": download_id,
            "queued_id": queued_id,
            "queue_auth_id": queue_auth_id,
            "hash": download_hash,
            "download_dir": str(download_dir) if download_dir else None,
            "failure_counts": {reason: 0 for reason in FAILURE_COUNT_REASONS},
            "is_multi_file": is_multi_file,
        }
        logger.info(
            "Tracking new %s download: Identifier: %s, Name: %s, Dest: %s",
            download_type,
            identifier,
            file_stem,
            download_dir,
        )
        return True

    def update_tracking_reference(
        self,
        identifier,
        state=None,
        queued_id=None,
        queue_auth_id=None,
        download_id=None,
        download_hash=None,
    ):
        """
        Updates the API-side identifiers and state for an existing tracked item.

        Args:
            identifier (str): Stable local identifier for the tracked item.
            state (str, optional): Updated tracker state.
            queued_id (str, optional): Updated queued item ID.
            queue_auth_id (str, optional): Updated queue-derived auth bridge for queued usenet items.
            download_id (str, optional): Updated active download ID.
            download_hash (str, optional): Updated download hash.

        Returns:
            bool: ``True`` when the tracked item exists, otherwise ``False``.
        """
        tracking_info = self.download_tracking.get(str(identifier))
        if not tracking_info:
            logger.warning("Cannot update tracking reference for unknown identifier: %s", identifier)
            return False

        changes = []
        if state and tracking_info.get("state") != state:
            changes.append(f"state {tracking_info.get('state')} -> {state}")
            tracking_info["state"] = state

        if queued_id is not None and tracking_info.get("queued_id") != queued_id:
            changes.append(f"queued_id {tracking_info.get('queued_id')} -> {queued_id}")
            tracking_info["queued_id"] = queued_id

        if queue_auth_id is not None and tracking_info.get("queue_auth_id") != queue_auth_id:
            changes.append("queue_auth_id updated")
            tracking_info["queue_auth_id"] = queue_auth_id

        if download_id is not None and tracking_info.get("id") != download_id:
            changes.append(f"id {tracking_info.get('id')} -> {download_id}")
            tracking_info["id"] = download_id

        if download_hash and tracking_info.get("hash") != download_hash:
            changes.append("hash updated")
            tracking_info["hash"] = download_hash

        if changes:
            logger.info("Updated tracking reference for %s: %s", identifier, ", ".join(changes))

        return True

    def mark_activity(self, identifier):
        """
        Refreshes the tracked item's last-activity timestamp.

        Args:
            identifier (str): Stable local identifier for the tracked item.

        Returns:
            bool: ``True`` if the tracked item exists, otherwise ``False``.
        """
        tracking_info = self.download_tracking.get(str(identifier))
        if not tracking_info:
            return False

        tracking_info["last_activity_at"] = self._now_iso()
        return True

    def increment_failure_count(self, identifier, reason):
        """
        Increments a single reason-specific failure counter for a tracked item.

        Args:
            identifier (str): Stable local identifier for the tracked item.
            reason (str): Failure counter key to increment.

        Returns:
            int | None: The updated counter value, or ``None`` if the item is unknown.

        Raises:
            ValueError: If ``reason`` is not a supported failure counter.
        """
        if reason not in FAILURE_COUNT_REASONS:
            raise ValueError(f"Unknown failure count reason: {reason}")

        tracking_info = self.download_tracking.get(str(identifier))
        if not tracking_info:
            return None

        tracking_info["failure_counts"][reason] += 1
        return tracking_info["failure_counts"][reason]

    def reset_failure_count(self, identifier, reason=None):
        """
        Resets one failure counter or all counters for a tracked item.

        Args:
            identifier (str): Stable local identifier for the tracked item.
            reason (str, optional): Specific failure counter key to reset. When omitted,
                all failure counters are reset.

        Returns:
            bool: ``True`` if the tracked item exists, otherwise ``False``.

        Raises:
            ValueError: If ``reason`` is not a supported failure counter.
        """
        tracking_info = self.download_tracking.get(str(identifier))
        if not tracking_info:
            return False

        if reason is None:
            for key in FAILURE_COUNT_REASONS:
                tracking_info["failure_counts"][key] = 0
            return True

        if reason not in FAILURE_COUNT_REASONS:
            raise ValueError(f"Unknown failure count reason: {reason}")

        tracking_info["failure_counts"][reason] = 0
        return True

    def update_filename(self, identifier, filename, is_multi_file=False):
        """
        Updates the resolved output filename stored for a tracked item.

        Args:
            identifier (str): Stable local identifier for the tracked item.
            filename (str): Resolved filename to store.
            is_multi_file (bool, optional): Whether the download should be treated as multi-file.
        """
        if str(identifier) in self.download_tracking:
            old_name = self.download_tracking[str(identifier)]["name"]
            self.download_tracking[str(identifier)]["name"] = filename
            self.download_tracking[str(identifier)]["is_multi_file"] = is_multi_file
            logger.info(
                "Updated filename for %s: %s -> %s%s",
                identifier,
                old_name,
                filename,
                " (multi-file)" if is_multi_file else "",
            )
        else:
            logger.warning("Cannot update filename for unknown identifier: %s", identifier)

    def get_tracked_downloads(self):
        """
        Returns the full mutable tracking dictionary.

        Returns:
            dict: Mapping of tracked identifiers to tracking metadata.
        """
        return self.download_tracking

    def pop_download(self, identifier):
        """
        Removes and returns a tracked item by identifier.

        Args:
            identifier (str): Stable local identifier for the tracked item.

        Returns:
            dict | None: Removed tracking metadata, or ``None`` if the item is unknown.
        """
        tracking_info = self.download_tracking.pop(str(identifier), None)
        if tracking_info:
            logger.info("Stopped tracking download identifier: %s", identifier)
        return tracking_info

    def remove_tracked_download(self, identifier):
        """
        Removes a tracked item without returning it.

        Args:
            identifier (str): Stable local identifier for the tracked item.
        """
        self.pop_download(identifier)

    def get_download_info(self, identifier):
        """
        Returns tracking metadata for a single identifier, if present.

        Args:
            identifier (str): Stable local identifier for the tracked item.

        Returns:
            dict | None: Tracking metadata, or ``None`` if the item is unknown.
        """
        return self.download_tracking.get(str(identifier))

    def get_stale_download_identifiers(self, max_idle_hours=24, now=None):
        """
        Returns identifiers whose idle time exceeds the configured threshold.

        Args:
            max_idle_hours (int, optional): Idle threshold in hours.
            now (datetime, optional): Timestamp used for the idle-time comparison.

        Returns:
            list[str]: Identifiers whose ``last_activity_at`` is older than the threshold.
        """
        current_time = now or datetime.now()
        stale_identifiers = []

        for identifier, info in self.download_tracking.items():
            try:
                last_activity_at = datetime.fromisoformat(info["last_activity_at"])
                idle_time = current_time - last_activity_at
                if idle_time > timedelta(hours=max_idle_hours):
                    stale_identifiers.append(identifier)
                    logger.warning(
                        "Found stale download %s (%s) idle for %.1f hours",
                        identifier,
                        info["name"],
                        idle_time.total_seconds() / 3600,
                    )
            except (KeyError, ValueError) as exc:
                logger.error("Error checking age of download %s: %s", identifier, exc)

        return stale_identifiers
