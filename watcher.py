import time
import logging
from pathlib import Path
import json
import os
from datetime import datetime, timezone

from config import Config
from api_client import TorBoxAPIClient
from file_processor import FileProcessor
from download_tracker import DownloadTracker
from webhook_notifier import WebhookNotifier

# Configure logging (moved here as it's the main entry)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("TorBoxWatcher")
logger.setLevel(logging.DEBUG)  # Set global log level here if needed


class TorBoxWatcherApp:
    """
    Orchestrates the TorBox watching, processing, and downloading.
    """

    def __init__(self, config: Config):
        """
        Initializes the TorBoxWatcherApp with the given configuration.

        Args:
            config (Config): The configuration object.
        """
        self.config = config
        self.api_client = TorBoxAPIClient(
            config.TORBOX_API_BASE,
            config.TORBOX_API_VERSION,
            config.TORBOX_API_KEY,
            config.MAX_RETRIES,
        )
        self.file_processor = FileProcessor(
            config.PROGRESS_INTERVAL,
        )
        self.download_tracker = DownloadTracker()
        self.webhook_notifier = WebhookNotifier(config)
        self.active_downloads = (
            {}
        )  # Track active downloads here, passed to file_processor
        self.last_status_check_at = None
        self._monotonic = time.monotonic

        # Ensure directories exist
        config.RADARR_WATCH_DIR.mkdir(parents=True, exist_ok=True)
        config.RADARR_DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
        
        # Only create separate Sonarr directories if in dual directory mode
        if config.DUAL_DIRECTORY_MODE:
            config.SONARR_WATCH_DIR.mkdir(parents=True, exist_ok=True)
            config.SONARR_DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"Initialized TorBox Watcher with API base: {self.api_client.api_base}"
        )
        
        if config.DUAL_DIRECTORY_MODE:
            logger.info(f"Running in dual directory mode")
            logger.info(f"Watching Radarr directory: {config.RADARR_WATCH_DIR} -> {config.RADARR_DOWNLOAD_DIR}")
            logger.info(f"Watching Sonarr directory: {config.SONARR_WATCH_DIR} -> {config.SONARR_DOWNLOAD_DIR}")
        else:
            logger.info(f"Running in single directory mode")
            logger.info(f"Watching directory: {config.RADARR_WATCH_DIR}")
            logger.info(f"Download directory: {config.RADARR_DOWNLOAD_DIR}")
        
        logger.info(f"Progress updates every {config.PROGRESS_INTERVAL} seconds")

    def _build_drop_event(self, identifier, tracking_info, reason, details=None):
        """
        Builds the structured internal event payload for a terminal drop.

        Args:
            identifier (str): Stable local identifier for the tracked item.
            tracking_info (dict): Tracking metadata captured before removal.
            reason (str): Terminal drop reason code.
            details (str, optional): Human-readable detail string.

        Returns:
            dict: Structured `download_dropped` event payload.
        """
        return {
            "event": "download_dropped",
            "reason": reason,
            "download_type": tracking_info.get("type"),
            "identifier": identifier,
            "name": tracking_info.get("name"),
            "state": tracking_info.get("state"),
            "queued_id": tracking_info.get("queued_id"),
            "download_id": tracking_info.get("id"),
            "download_hash": tracking_info.get("hash"),
            "download_dir": tracking_info.get("download_dir"),
            "failure_counts": dict(tracking_info.get("failure_counts", {})),
            "submitted_at": tracking_info.get("submitted_at"),
            "last_activity_at": tracking_info.get("last_activity_at"),
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _complete_tracked_download(self, identifier):
        """
        Finalizes a tracked download after successful local processing.

        Args:
            identifier (str): Stable local identifier for the tracked item.

        Returns:
            bool: ``True`` when the tracked item existed and was removed, otherwise ``False``.
        """
        tracking_info = self.download_tracker.pop_download(identifier)
        if not tracking_info:
            logger.warning("Attempted to complete unknown tracked download: %s", identifier)
            return False

        logger.info(
            "Completed tracked %s download: %s (%s)",
            tracking_info.get("type"),
            tracking_info.get("name"),
            identifier,
        )
        return True

    def _drop_tracked_download(self, identifier, reason, details=None):
        """
        Removes a tracked download for a terminal failure and emits a webhook event.

        Args:
            identifier (str): Stable local identifier for the tracked item.
            reason (str): Terminal drop reason code.
            details (str, optional): Human-readable detail string.

        Returns:
            bool: ``True`` when the tracked item existed and was dropped, otherwise ``False``.
        """
        tracking_info = self.download_tracker.pop_download(identifier)
        if not tracking_info:
            logger.warning(
                "Attempted to drop unknown tracked download: %s (reason=%s)",
                identifier,
                reason,
            )
            return False

        logger.error(
            "Dropping tracked %s download %s (%s): %s",
            tracking_info.get("type"),
            tracking_info.get("name"),
            identifier,
            reason,
        )
        self.webhook_notifier.notify_download_dropped(
            self._build_drop_event(identifier, tracking_info, reason, details=details)
        )
        return True

    def _increment_failure_and_maybe_drop(
        self,
        identifier,
        failure_reason,
        max_failures,
        drop_reason,
        details,
    ):
        """
        Increments a reason-specific counter and drops once its threshold is reached.

        Args:
            identifier (str): Stable local identifier for the tracked item.
            failure_reason (str): Failure counter key to increment.
            max_failures (int): Threshold that triggers a terminal drop.
            drop_reason (str): Terminal drop reason code.
            details (str): Human-readable detail string for the drop event.

        Returns:
            bool: ``True`` if the item was dropped, otherwise ``False``.
        """
        failure_count = self.download_tracker.increment_failure_count(identifier, failure_reason)
        if failure_count is None:
            return False

        if failure_count >= max_failures:
            self._drop_tracked_download(identifier, drop_reason, details=details)
            return True

        return False

    def _should_run_status_check(self, now=None):
        """
        Returns whether the next status-polling pass is due.

        Args:
            now (float, optional): Monotonic timestamp override used for testing.

        Returns:
            bool: ``True`` when status polling should run, otherwise ``False``.
        """
        current_time = self._monotonic() if now is None else now
        return (
            self.last_status_check_at is None
            or (current_time - self.last_status_check_at) >= self.config.CHECK_INTERVAL
        )

    def _run_scheduled_status_check(self, now=None):
        """
        Runs a status pass only when the configured polling interval has elapsed.

        Args:
            now (float, optional): Monotonic timestamp override used for testing.

        Returns:
            bool: ``True`` if a status pass was run, otherwise ``False``.
        """
        current_time = self._monotonic() if now is None else now
        if not self._should_run_status_check(now=current_time):
            return False

        self.check_download_status()
        self.last_status_check_at = current_time
        return True

    def cleanup_stale_downloads(self, now=None):
        """
        Drops tracked items that have been idle past the configured timeout.

        Args:
            now (datetime, optional): Timestamp override used for idle-time comparisons.

        Returns:
            int: Number of stale tracked items dropped during the pass.
        """
        stale_identifiers = self.download_tracker.get_stale_download_identifiers(
            max_idle_hours=self.config.MAX_TRACKING_IDLE_HOURS,
            now=now,
        )

        dropped = 0
        for identifier in stale_identifiers:
            if identifier in self.active_downloads:
                logger.debug("Skipping stale cleanup for locally active download: %s", identifier)
                continue

            details = (
                "No activity observed for more than "
                f"{self.config.MAX_TRACKING_IDLE_HOURS} hours."
            )
            if self._drop_tracked_download(
                identifier,
                "stale_tracking_timeout",
                details=details,
            ):
                dropped += 1

        return dropped

    def scan_watch_directory(self):
        """
        Scans both watch directories for torrent, magnet, and NZB files.
        Processes each file found according to its type.
        In single directory mode, scans only one directory.
        """
        if self.config.DUAL_DIRECTORY_MODE:
            # Scan both Radarr and Sonarr directories separately
            logger.info(f"Scanning Radarr watch directory: {self.config.RADARR_WATCH_DIR}")
            self._scan_directory(self.config.RADARR_WATCH_DIR, self.config.RADARR_DOWNLOAD_DIR)
            
            logger.info(f"Scanning Sonarr watch directory: {self.config.SONARR_WATCH_DIR}")
            self._scan_directory(self.config.SONARR_WATCH_DIR, self.config.SONARR_DOWNLOAD_DIR)
        else:
            # single directory mode: scan single directory
            logger.info(f"Scanning watch directory: {self.config.RADARR_WATCH_DIR}")
            self._scan_directory(self.config.RADARR_WATCH_DIR, self.config.RADARR_DOWNLOAD_DIR)

    def _scan_directory(self, watch_dir, download_dir):
        """
        Scans a specific watch directory for torrent, magnet, and NZB files.
        
        Args:
            watch_dir (Path): The directory to watch
            download_dir (Path): The destination directory for downloads
        """
        for file_path in sorted(watch_dir.glob("*"), key=lambda path: path.name.lower()):
            if file_path.is_file():
                file_extension = file_path.suffix.lower()
                success = False
                
                if file_extension in [".torrent", ".magnet"]:
                    success, _, _ = self.process_torrent_file(file_path, download_dir)
                elif file_extension == ".nzb":
                    success, _, _ = self.process_nzb_file(file_path, download_dir)
                
                # Delete the file after successful processing
                if success:
                    try:
                        os.remove(file_path)
                        logger.info(f"Deleted file: {file_path}")
                    except Exception as e:
                        logger.error(f"Error deleting file {file_path}: {e}")

    def _make_tracker_key(self, download_type, queued_id=None, download_id=None, download_hash=None):
        """
        Creates a stable local tracker key for a download.

        Args:
            download_type (str): Either "torrent" or "usenet".
            queued_id (str, optional): Queued download ID.
            download_id (str, optional): Active download ID.
            download_hash (str, optional): Download hash.

        Returns:
            str | None: Stable local tracker key, or None if no identifying data exists.
        """
        if queued_id is not None:
            return f"{download_type}:queued:{queued_id}"
        if download_id is not None:
            return f"{download_type}:id:{download_id}"
        if download_hash:
            return f"{download_type}:hash:{download_hash}"
        return None

    def _extract_tracking_reference(self, response_data, download_type):
        """
        Extracts tracking reference information from an API response.

        Args:
            response_data (dict): API response data.
            download_type (str): Either "torrent" or "usenet".

        Returns:
            dict | None: Tracking reference details, or None if no identifying data exists.
        """
        data = response_data.get("data")
        if not isinstance(data, dict):
            return None

        download_id = None
        queued_id = data.get("queued_id")
        download_hash = None
        if download_type == "torrent":
            download_id = data.get("torrent_id", data.get("id"))
        else:  # usenet
            download_id = data.get("usenetdownload_id", data.get("id"))
        download_hash = data.get("hash")

        state = "queued" if queued_id is not None and download_id is None else "active"
        identifier = self._make_tracker_key(
            download_type,
            queued_id=queued_id if state == "queued" else None,
            download_id=download_id,
            download_hash=download_hash,
        )
        if not identifier:
            return None

        return {
            "identifier": identifier,
            "state": state,
            "download_type": download_type,
            "queued_id": queued_id,
            "download_id": download_id,
            "download_hash": download_hash,
        }

    def _extract_items_from_response(self, response_data):
        """
        Normalizes API response payloads to a list of items.

        Args:
            response_data (dict): API response data.

        Returns:
            list: Response items.
        """
        data = response_data.get("data")
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []

    def _extract_queued_item_id(self, item):
        """
        Extracts a queued item ID from queue responses.
        """
        for key in ("queued_id", "queue_id", "id"):
            if item.get(key) is not None:
                return item.get(key)
        return None

    def _extract_active_download_id(self, item, download_type, allow_generic_id=True):
        """
        Extracts an active download ID from list or queue responses.
        """
        keys = []
        if download_type == "torrent":
            keys.extend(["torrent_id", "download_id"])
        else:
            keys.extend(["usenetdownload_id", "usenet_id", "download_id"])

        if allow_generic_id:
            keys.append("id")

        for key in keys:
            if item.get(key) is not None:
                return item.get(key)
        return None

    def _find_queued_item(self, response_data, queued_id):
        """
        Finds a specific queued item in a queue response.
        """
        for item in self._extract_items_from_response(response_data):
            if str(self._extract_queued_item_id(item)) == str(queued_id):
                return item
        return None

    def _find_active_download_data(self, response_data, tracking_info, download_type):
        """
        Finds a matching active download item from list responses.
        """
        for item in self._extract_items_from_response(response_data):
            item_id = self._extract_active_download_id(item, download_type, allow_generic_id=True)
            item_hash = item.get("hash")

            if tracking_info.get("id") is not None and str(item_id) == str(tracking_info.get("id")):
                return item

            if tracking_info.get("hash") and item_hash == tracking_info.get("hash"):
                return item

        return None

    def _sync_tracking_from_active_item(self, identifier, tracking_info, download_data, download_type):
        """
        Syncs tracker metadata from an active download item.
        """
        download_id = self._extract_active_download_id(
            download_data,
            download_type,
            allow_generic_id=True,
        )
        download_hash = download_data.get("hash") or tracking_info.get("hash")
        self.download_tracker.update_tracking_reference(
            identifier,
            state="active",
            download_id=download_id,
            download_hash=download_hash,
        )

    def _get_active_status_data(self, identifier, tracking_info, download_type):
        """
        Retrieves active download status data for a tracked download.
        """
        query_param = None
        query_description = "unfiltered list lookup"
        if tracking_info.get("id") is not None:
            query_param = f"id={tracking_info['id']}"
            query_description = query_param
        elif tracking_info.get("hash"):
            query_description = f"hash={tracking_info['hash']} via unfiltered list lookup"
        else:
            logger.warning(
                f"No active ID or hash available for {download_type} identifier {identifier}."
            )
            return None, query_description

        logger.debug(f"Checking {download_type} status using query: {query_description}")
        if download_type == "torrent":
            status_data = self.api_client.get_torrent_list(query_param)
        else:
            status_data = self.api_client.get_usenet_list(query_param)

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"{download_type.capitalize()} status response: {json.dumps(status_data)}")

        download_data = self._find_active_download_data(status_data, tracking_info, download_type)
        return download_data, query_description

    def _check_queued_status(self, identifier, tracking_info, download_type):
        """
        Checks the status of a queued download and promotes it to active once TorBox assigns an active ID.
        """
        queued_id = tracking_info.get("queued_id")
        if queued_id is None:
            logger.warning(
                f"No queued ID found for queued {download_type} identifier: {identifier}. Falling back to active lookup."
            )
            return self._check_active_status(identifier, tracking_info, download_type)

        logger.debug(f"Checking queued {download_type} status using queued_id={queued_id}")
        status_data = self.api_client.get_queued_list(download_type, queued_id=queued_id)

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Queued {download_type} status response: {json.dumps(status_data)}")

        queue_item = self._find_queued_item(status_data, queued_id)
        if not queue_item:
            logger.info(
                f"Queued {download_type} item {queued_id} not found in queue response. Checking active list."
            )
            return self._check_active_status(identifier, tracking_info, download_type)

        self.download_tracker.mark_activity(identifier)
        self.download_tracker.reset_failure_count(identifier, "not_found")

        active_id = self._extract_active_download_id(
            queue_item,
            download_type,
            allow_generic_id=False,
        )
        download_hash = queue_item.get("hash") or tracking_info.get("hash")
        if active_id is not None:
            self.download_tracker.update_tracking_reference(
                identifier,
                state="active",
                queued_id=queued_id,
                download_id=active_id,
                download_hash=download_hash,
            )
            logger.info(
                f"{download_type.capitalize()} [{identifier}] promoted from queued ID {queued_id} to active ID {active_id}"
            )
            refreshed_tracking_info = self.download_tracker.get_download_info(identifier) or tracking_info
            return self._check_active_status(identifier, refreshed_tracking_info, download_type)

        queue_state = queue_item.get("download_state") or queue_item.get("state") or queue_item.get("status") or "queued"
        logger.info(
            f"{download_type.capitalize()} [{identifier}]: {tracking_info['name']} | "
            f"Queue Status: {str(queue_state).upper()} | Queued ID: {queued_id}"
        )
        return False

    def _check_active_status(self, identifier, tracking_info, download_type):
        """
        Checks the status of an active download.
        """
        download_data, query_description = self._get_active_status_data(
            identifier,
            tracking_info,
            download_type,
        )
        if not download_data:
            logger.warning(
                f"Could not find {download_type} with identifier {identifier} using {query_description}."
            )
            self._increment_failure_and_maybe_drop(
                identifier,
                "not_found",
                self.config.MAX_NOT_FOUND_FAILURES,
                "status_not_found",
                (
                    f"{download_type.capitalize()} identifier {identifier} was not found "
                    f"using {query_description}."
                ),
            )
            return False

        self.download_tracker.mark_activity(identifier)
        self.download_tracker.reset_failure_count(identifier, "not_found")
        self._sync_tracking_from_active_item(identifier, tracking_info, download_data, download_type)
        tracking_info = self.download_tracker.get_download_info(identifier) or tracking_info

        download_state = download_data.get("download_state", "")
        progress = download_data.get("progress", 0)
        progress_percentage = float(progress) * 100
        size_formatted = download_data.get("size", 0)

        logger.info(
            f"{download_type.capitalize()} [{identifier}]: {tracking_info['name']} | "
            f"Status: {download_state.upper()} | Progress: {progress_percentage:.1f}% | Size: {size_formatted}"
        )

        if download_data.get("download_present", False):
            files = download_data.get("files", [])

            if files and len(files) > 0:
                download_name = download_data.get("name", tracking_info["name"])

                if len(files) == 1:
                    actual_filename = files[0].get("short_name") or files[0].get("name", "")
                    if actual_filename:
                        actual_filename = Path(actual_filename).name
                        logger.info(f"Single file detected: {actual_filename}")
                        self.download_tracker.update_filename(identifier, actual_filename, is_multi_file=False)
                else:
                    logger.info(f"Multiple files detected ({len(files)} files) - forcing ZIP download")
                    actual_filename = f"{download_name}.zip"
                    self.download_tracker.update_filename(identifier, actual_filename, is_multi_file=True)

            if download_type == "torrent":
                return self.request_torrent_download(identifier)
            return self.request_usenet_download(identifier)

        return False

    def process_torrent_file(self, file_path: Path, download_dir: Path):
        """
        Processes a torrent file or magnet link.

        Sends the torrent/magnet to the TorBox API and tracks the download.

        Args:
            file_path (Path): The path to the torrent file or magnet link.
            download_dir (Path): The destination directory for this download.
        """
        file_name = file_path.name
        logger.info(f"Processing torrent file: {file_name}")
        payload = {
            "seed": self.config.SEED_PREFERENCE,
            "allow_zip": self.config.ALLOW_ZIP,
            "name": file_path.stem,
            "as_queued": self.config.QUEUE_IMMEDIATELY,
        }
        try:
            if file_path.suffix.lower() == ".torrent":
                response_data = self.api_client.create_torrent(
                    file_name, file_path, payload
                )
            else:  # .magnet
                with open(file_path, "r") as f:
                    magnet_link = f.read().strip()
                    payload["magnet"] = magnet_link
                response_data = self.api_client.create_torrent_from_magnet(payload)

            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Torrent API response: {json.dumps(response_data)}")

            tracking_reference = self._extract_tracking_reference(response_data, "torrent")

            if tracking_reference:
                identifier = tracking_reference["identifier"]
                logger.info(
                    f"Successfully submitted torrent: {file_name}, tracker key: {identifier}, "
                    f"state: {tracking_reference['state']}"
                )
                success = self.download_tracker.track_download(
                    identifier=identifier,
                    download_type="torrent",
                    file_stem=file_path.stem,
                    original_file=file_path,
                    download_id=tracking_reference["download_id"],
                    queued_id=tracking_reference["queued_id"],
                    download_hash=tracking_reference["download_hash"],
                    download_dir=download_dir,
                    state=tracking_reference["state"],
                )
                return success, file_path, identifier
            else:
                logger.error(
                    f"Failed to get download ID for: {file_name}. Response: {json.dumps(response_data) if logger.isEnabledFor(logging.DEBUG) else 'enable debug for details'}"
                )
                return False, file_path, None

        except Exception as e:
            logger.error(f"Error processing torrent file {file_name}: {e}")
            return False, file_path, None

    def _check_download_status_common(self, identifier, download_type):
        """
        Common logic for checking download status (torrent or usenet).

        Args:
            identifier: The identifier of the download.
            download_type: Either "torrent" or "usenet".

        Returns:
            bool: True if download is ready and request was initiated, False otherwise.
        """
        tracking_info = self.download_tracker.get_download_info(identifier)
        if not tracking_info:
            logger.warning(f"No tracking info found for {download_type} identifier: {identifier}")
            return False

        try:
            if tracking_info.get("state") == "queued":
                result = self._check_queued_status(identifier, tracking_info, download_type)
            else:
                result = self._check_active_status(identifier, tracking_info, download_type)

            self.download_tracker.reset_failure_count(identifier, "status_exception")
            return result

        except Exception as e:
            logger.error(f"Error checking {download_type} status for identifier {identifier}: {e}")
            self._increment_failure_and_maybe_drop(
                identifier,
                "status_exception",
                self.config.MAX_STATUS_CHECK_FAILURES,
                "status_check_exception",
                f"Error checking {download_type} status for identifier {identifier}: {e}",
            )
        
        return False

    def check_torrent_status(self, download_id):
        """
        Checks the status of a torrent download.

        Args:
            download_id: The ID of the torrent download (can be torrent_id or hash).
        """
        return self._check_download_status_common(download_id, "torrent")

    def _request_download_common(self, identifier, download_type):
        """
        Common logic for requesting download links (torrent or usenet).

        Args:
            identifier: The identifier of the download.
            download_type: Either "torrent" or "usenet".
        """
        tracking_info = self.download_tracker.get_download_info(identifier)
        if not tracking_info:
            logger.warning(
                f"No tracking info found for {download_type} identifier: {identifier} for download request."
            )
            return False

        if tracking_info.get("state") == "queued":
            logger.info(
                f"Skipping download request for queued {download_type} identifier {identifier} until TorBox assigns an active ID."
            )
            return False

        request_id = tracking_info.get("id")
        if request_id is None:
            logger.info(
                f"Resolving active ID for {download_type} identifier {identifier} before requesting download."
            )
            download_data, _ = self._get_active_status_data(identifier, tracking_info, download_type)
            if download_data:
                self._sync_tracking_from_active_item(
                    identifier,
                    tracking_info,
                    download_data,
                    download_type,
                )
            refreshed_tracking_info = self.download_tracker.get_download_info(identifier) or tracking_info
            request_id = refreshed_tracking_info.get("id")
            tracking_info = refreshed_tracking_info
            if request_id is None:
                logger.warning(
                    f"Unable to resolve active ID for {download_type} identifier {identifier}. Skipping download request."
                )
                return False
        
        # Get the download directory from tracking info
        download_dir = Path(tracking_info.get("download_dir")) if tracking_info.get("download_dir") else None
        if not download_dir:
            logger.error(f"No download directory found for {download_type} identifier {identifier}")
            self._drop_tracked_download(
                identifier,
                "local_download_failed",
                details=f"No download directory found for {download_type} identifier {identifier}.",
            )
            return False

        # Check if this is a multi-file download - if so, force zip_link=true
        is_multi_file = tracking_info.get("is_multi_file", False)
        if is_multi_file:
            zip_link = True
            logger.info(f"Multi-file download detected for {identifier} - forcing ZIP download")
        else:
            zip_link = self.config.ALLOW_ZIP

        try:
            # Call appropriate API method with zip_link parameter
            if download_type == "torrent":
                download_link_data = self.api_client.request_torrent_download_link(
                    request_id, 
                    zip_link=zip_link
                )
            else:  # usenet
                download_link_data = self.api_client.request_usenet_download_link(
                    request_id,
                    zip_link=zip_link
                )

            if download_link_data.get("success", False) and "data" in download_link_data:
                download_url = download_link_data["data"]
                logger.info(
                    f"Got download URL for {download_type} identifier {identifier} (request_id: {request_id}): {download_url}"
                )
                self.download_tracker.reset_failure_count(identifier, "download_link")
                self.download_tracker.mark_activity(identifier)
                download_path = download_dir / tracking_info["name"]
                return self.file_processor.download_file(
                    download_url,
                    download_path,
                    tracking_info["name"],
                    identifier,
                    self.active_downloads,
                    download_dir,
                    on_complete=self._complete_tracked_download,
                    on_failure=self._drop_tracked_download,
                )
            logger.error(
                f"Failed to get download URL for {download_type} identifier {identifier} "
                f"(request_id: {request_id}): {json.dumps(download_link_data) if logger.isEnabledFor(logging.DEBUG) else 'enable debug for details'}"
            )
            self._increment_failure_and_maybe_drop(
                identifier,
                "download_link",
                self.config.MAX_DOWNLOAD_LINK_FAILURES,
                "download_link_request_failed",
                (
                    f"Failed to get download URL for {download_type} identifier {identifier} "
                    f"(request_id: {request_id})."
                ),
            )
            return False

        except Exception as e:
            logger.error(f"Error requesting {download_type} download for identifier {identifier}: {e}")
            self._increment_failure_and_maybe_drop(
                identifier,
                "download_link",
                self.config.MAX_DOWNLOAD_LINK_FAILURES,
                "download_link_request_failed",
                f"Error requesting {download_type} download for identifier {identifier}: {e}",
            )
            return False

    def request_torrent_download(self, identifier):
        """
        Requests a download link for a completed torrent.

        Args:
            identifier: The identifier of the torrent download used for tracking.
        """
        return self._request_download_common(identifier, "torrent")

    def process_nzb_file(self, file_path: Path, download_dir: Path):
        """
        Processes an NZB file.

        Sends the NZB file to the TorBox API and tracks the download.

        Args:
            file_path (Path): The path to the NZB file.
            download_dir (Path): The destination directory for this download.
        """
        file_name = file_path.name
        logger.info(f"Processing NZB file: {file_name}")
        payload = {
            "name": file_path.stem,
            "post_processing": self.config.POST_PROCESSING,
            "as_queued": self.config.QUEUE_IMMEDIATELY,
        }
        try:
            response_data = self.api_client.create_usenet_download(
                file_name, file_path, payload
            )
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Usenet API response: {json.dumps(response_data)}")

            tracking_reference = self._extract_tracking_reference(response_data, "usenet")

            if tracking_reference:
                identifier = tracking_reference["identifier"]
                logger.info(
                    f"Successfully submitted NZB: {file_name}, tracker key: {identifier}, "
                    f"state: {tracking_reference['state']}"
                )
                success = self.download_tracker.track_download(
                    identifier=identifier,
                    download_type="usenet",
                    file_stem=file_path.stem,
                    original_file=file_path,
                    download_id=tracking_reference["download_id"],
                    queued_id=tracking_reference["queued_id"],
                    download_hash=tracking_reference["download_hash"],
                    download_dir=download_dir,
                    state=tracking_reference["state"],
                )
                return success, file_path, identifier
            else:
                logger.error(
                    f"Failed to get download ID or hash for NZB: {file_name}. Response: {json.dumps(response_data) if logger.isEnabledFor(logging.DEBUG) else 'enable debug for details'}"
                )
                return False, file_path, None

        except Exception as e:
            logger.error(f"Error processing NZB file {file_name}: {e}")
            return False, file_path, None

    def check_usenet_status(self, download_id):
        """
        Checks the status of a usenet download.

        Args:
            download_id: The ID of the usenet download (can be usenetdownload_id or hash).
        """
        return self._check_download_status_common(download_id, "usenet")

    def request_usenet_download(self, identifier):
        """
        Requests a download link for a completed usenet download.

        Args:
            identifier: The identifier of the usenet download used for tracking.
        """
        return self._request_download_common(identifier, "usenet")

    def check_download_status(self):
        """
        Checks the status of all tracked downloads (both torrent and usenet).
        """
        tracked_downloads = self.download_tracker.get_tracked_downloads()
        if not tracked_downloads:
            return

        logger.info(f"Checking status of {len(tracked_downloads)} tracked downloads")
        identifiers = list(tracked_downloads.keys())  # Iterate over a copy of keys

        for identifier in identifiers:
            # Check if download is already active locally before querying API again
            if identifier in self.active_downloads:
                 logger.debug(f"Skipping status check for locally active download: {identifier}")
                 continue

            download_info = tracked_downloads.get(identifier) # Use .get for safety
            if not download_info:
                logger.warning(f"Tracking info disappeared for identifier: {identifier}. Skipping check.")
                continue

            download_type = download_info["type"]

            try:
                if download_type == "torrent":
                    self.check_torrent_status(identifier)
                elif download_type == "usenet":
                    self.check_usenet_status(identifier)
            except Exception as e:
                logger.error(f"Error checking status for identifier {identifier}: {e}")

    def run(self):
        """
        Main execution loop of the TorBoxWatcherApp.

        Continuously scans the watch directory, checks download statuses,
        and sleeps for a configured interval.
        """
        logger.info("Starting TorBox Watcher")
        while True:
            try:
                self.scan_watch_directory()
                self._run_scheduled_status_check()
                self.cleanup_stale_downloads()
                
                logger.info(
                    f"Waiting {self.config.WATCH_INTERVAL} seconds until next scan"
                )
                time.sleep(self.config.WATCH_INTERVAL)

            except KeyboardInterrupt:
                logger.info("Received keyboard interrupt. Shutting down...")
                break
            except Exception as e:
                logger.error(f"Unexpected error in main loop: {e}")
                time.sleep(5)  # Wait before next loop in case of error
