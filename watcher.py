import time
import logging
from pathlib import Path
import json
import os

from config import Config
from api_client import TorBoxAPIClient
from file_processor import FileProcessor
from download_tracker import DownloadTracker

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
        self.active_downloads = (
            {}
        )  # Track active downloads here, passed to file_processor

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
        results = []
        for file_path in watch_dir.glob("*"):
            if file_path.is_file():
                file_extension = file_path.suffix.lower()
                if file_extension in [".torrent", ".magnet"]:
                    result = self.process_torrent_file(file_path, download_dir)
                    results.append(result)
                elif file_extension == ".nzb":
                    result = self.process_nzb_file(file_path, download_dir)
                    results.append(result)

        for success, file_path, download_id in results:
            if success:
                try:
                    os.remove(file_path)
                    logger.info(f"Deleted file: {file_path}")
                except Exception as e:
                    logger.error(f"Error deleting file {file_path}: {e}")

    def _extract_identifier_from_response(self, response_data, download_type):
        """
        Extracts download ID and hash from API response.

        Args:
            response_data (dict): API response data.
            download_type (str): Either "torrent" or "usenet".

        Returns:
            tuple: (identifier, download_id, download_hash)
        """
        download_id = None
        download_hash = None
        
        if "data" in response_data and isinstance(response_data["data"], dict):
            if download_type == "torrent":
                if "torrent_id" in response_data["data"]:
                    download_id = response_data["data"]["torrent_id"]
                if "hash" in response_data["data"]:
                    download_hash = response_data["data"]["hash"]
            else:  # usenet
                if "usenetdownload_id" in response_data["data"]:
                    download_id = response_data["data"]["usenetdownload_id"]
                elif "id" in response_data["data"]:
                    download_id = response_data["data"]["id"]
                if "hash" in response_data["data"]:
                    download_hash = response_data["data"]["hash"]
        
        identifier = download_id if download_id else download_hash
        return identifier, download_id, download_hash

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

            logger.debug(f"Torrent API response: {json.dumps(response_data)}")

            identifier, download_id, download_hash = self._extract_identifier_from_response(
                response_data, "torrent"
            )

            if identifier:
                logger.info(f"Successfully submitted torrent: {file_name}, ID: {identifier}")
                success = self.download_tracker.track_download(
                    identifier=identifier,
                    download_type="torrent",
                    file_stem=file_path.stem,
                    original_file=file_path,
                    download_id=download_id,
                    download_hash=download_hash,
                    download_dir=download_dir
                )
                return success, file_path, identifier
            else:
                logger.error(
                    f"Failed to get download ID for: {file_name}. Response: {json.dumps(response_data)}"
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

        # Prefer the specific API 'id' if stored, otherwise use the identifier
        query_id = tracking_info.get("id") or identifier
        query_param = f"id={query_id}"

        try:
            logger.debug(f"Checking {download_type} status using query: {query_param}")
            
            # Call appropriate API method
            if download_type == "torrent":
                status_data = self.api_client.get_torrent_list(query_param)
            else:  # usenet
                status_data = self.api_client.get_usenet_list(query_param)
            
            logger.debug(f"{download_type.capitalize()} status response: {json.dumps(status_data)}")

            # Reset failure count on successful API call
            self.download_tracker.reset_failure_count(identifier)

            # Extract download data from response
            download_data = None
            if "data" in status_data:
                if isinstance(status_data["data"], dict):
                    download_data = status_data["data"]
                elif isinstance(status_data["data"], list) and len(status_data["data"]) > 0:
                    # Find the correct item in the list
                    for item in status_data["data"]:
                        api_id_match = tracking_info.get("id") and str(item.get("id", "")) == str(tracking_info.get("id"))
                        hash_match = tracking_info.get("hash") and item.get("hash") == tracking_info.get("hash")
                        identifier_hash_match = not tracking_info.get("id") and item.get("hash") == identifier

                        if api_id_match or hash_match or identifier_hash_match:
                            download_data = item
                            break

            if download_data:
                download_state = download_data.get("download_state", "")
                progress = download_data.get("progress", 0)
                progress_percentage = float(progress) * 100
                size_formatted = download_data.get("size", 0)

                logger.info(
                    f"{download_type.capitalize()} [{identifier}]: {tracking_info['name']} | "
                    f"Status: {download_state.upper()} | Progress: {progress_percentage:.1f}% | Size: {size_formatted}"
                )

                # Check if download is ready
                if download_data.get("download_present", False):
                    if download_type == "torrent":
                        self.request_torrent_download(identifier)
                    else:  # usenet
                        self.request_usenet_download(identifier)
                    return True
            else:
                logger.warning(
                    f"Could not find {download_type} with identifier {identifier} (query_id: {query_id}) in status response."
                )

        except Exception as e:
            logger.error(f"Error checking {download_type} status for identifier {identifier}: {e}")
            
            # Increment failure count
            failure_count = self.download_tracker.increment_failure_count(identifier)
            
            if failure_count and failure_count >= self.config.MAX_STATUS_CHECK_FAILURES:
                logger.error(
                    f"Max status check failures ({self.config.MAX_STATUS_CHECK_FAILURES}) reached for "
                    f"{download_type} identifier {identifier}. Removing from tracking."
                )
                self.download_tracker.remove_tracked_download(identifier)
        
        return False

    def check_torrent_status(self, download_id):
        """
        Checks the status of a torrent download.

        Args:
            download_id: The ID of the torrent download (can be torrent_id or hash).
        """
        self._check_download_status_common(download_id, "torrent")

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
            return

        # Prefer the specific API 'id' if stored, otherwise use the identifier
        request_id = tracking_info.get("id") or identifier
        
        # Get the download directory from tracking info
        download_dir = Path(tracking_info.get("download_dir")) if tracking_info.get("download_dir") else None
        if not download_dir:
            logger.error(f"No download directory found for {download_type} identifier {identifier}")
            return

        try:
            # Call appropriate API method with zip_link parameter
            if download_type == "torrent":
                download_link_data = self.api_client.request_torrent_download_link(
                    request_id, 
                    zip_link=self.config.ALLOW_ZIP
                )
            else:  # usenet
                download_link_data = self.api_client.request_usenet_download_link(
                    request_id,
                    zip_link=self.config.ALLOW_ZIP
                )

            if download_link_data.get("success", False) and "data" in download_link_data:
                download_url = download_link_data["data"]
                logger.info(
                    f"Got download URL for {download_type} identifier {identifier} (request_id: {request_id}): {download_url}"
                )
                download_path = download_dir / tracking_info["name"]
                self.file_processor.download_file(
                    download_url,
                    download_path,
                    tracking_info["name"],
                    identifier,
                    self.download_tracker.get_tracked_downloads(),
                    self.active_downloads,
                    download_dir,
                )
            else:
                logger.error(
                    f"Failed to get download URL for {download_type} identifier {identifier} "
                    f"(request_id: {request_id}): {json.dumps(download_link_data)}"
                )

        except Exception as e:
            logger.error(f"Error requesting {download_type} download for identifier {identifier}: {e}")

    def request_torrent_download(self, identifier):
        """
        Requests a download link for a completed torrent.

        Args:
            identifier: The identifier of the torrent download used for tracking.
        """
        self._request_download_common(identifier, "torrent")

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
            logger.debug(f"Usenet API response: {json.dumps(response_data)}")

            identifier, download_id, download_hash = self._extract_identifier_from_response(
                response_data, "usenet"
            )

            if identifier:
                logger.info(f"Successfully submitted NZB: {file_name}, ID: {identifier}")
                success = self.download_tracker.track_download(
                    identifier=identifier,
                    download_type="usenet",
                    file_stem=file_path.stem,
                    original_file=file_path,
                    download_id=download_id,
                    download_hash=download_hash,
                    download_dir=download_dir
                )
                return success, file_path, identifier
            else:
                logger.error(
                    f"Failed to get download ID or hash for NZB: {file_name}. Response: {json.dumps(response_data)}"
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
        self._check_download_status_common(download_id, "usenet")

    def request_usenet_download(self, identifier):
        """
        Requests a download link for a completed usenet download.

        Args:
            identifier: The identifier of the usenet download used for tracking.
        """
        self._request_download_common(identifier, "usenet")

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

    def add_item_to_track(self, item_id, item_type, item_name, item_hash=None, download_dir=None):
        """
        Adds an item from the web UI to the download tracker.

        Args:
            item_id (str): The specific ID from the TorBox API (e.g., torrent_id, usenetdownload_id).
            item_type (str): 'torrent' or 'usenet'.
            item_name (str): The name of the download item.
            item_hash (str, optional): The hash of the item, if available.
            download_dir (Path, optional): The destination directory. Defaults to RADARR_DOWNLOAD_DIR if not specified.

        Returns:
            bool: True if tracking was initiated, False otherwise (e.g., already tracked).
        """
        # Use the specific ID if available, otherwise fall back to hash as the primary identifier
        # Ensure identifier is a string
        identifier = str(item_id) if item_id else str(item_hash)
        if not identifier:
            logger.error(f"Cannot track item '{item_name}': Missing both ID and Hash.")
            return False
        
        # Default to Radarr download directory if not specified
        if not download_dir:
            download_dir = self.config.RADARR_DOWNLOAD_DIR

        logger.info(f"Attempting to track item via Web UI: Identifier={identifier}, Type={item_type}, Name={item_name}, Dest={download_dir}")

        # Call the updated track_download method
        # Pass None for original_file as it's not applicable here
        # Pass both item_id and item_hash so they are stored in tracking_info
        success = self.download_tracker.track_download(
            identifier=identifier,
            download_type=item_type,
            file_stem=item_name,
            original_file=None,
            download_id=item_id,
            download_hash=item_hash,
            download_dir=download_dir
        )
        return success

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
                self.check_download_status()
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
