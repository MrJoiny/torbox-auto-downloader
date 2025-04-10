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
            config.DOWNLOAD_DIR,
            config.PROGRESS_INTERVAL,
        )
        self.download_tracker = DownloadTracker()
        self.active_downloads = (
            {}
        )  # Track active downloads here, passed to file_processor

        # Ensure directories exist
        config.WATCH_DIR.mkdir(exist_ok=True)
        config.DOWNLOAD_DIR.mkdir(exist_ok=True)

        logger.info(
            f"Initialized TorBox Watcher with API base: {self.api_client.api_base}"
        )
        logger.info(f"Watching directory: {config.WATCH_DIR}")
        logger.info(f"Download directory: {config.DOWNLOAD_DIR}")
        logger.info(f"Progress updates every {config.PROGRESS_INTERVAL} seconds")

    def scan_watch_directory(self):
        """
        Scans the watch directory for torrent, magnet, and NZB files.
        Processes each file found according to its type.
        """
        logger.info(f"Scanning watch directory: {self.config.WATCH_DIR}")
        results = []
        for file_path in self.config.WATCH_DIR.glob("*"):
            if file_path.is_file():
                file_extension = file_path.suffix.lower()
                if file_extension in [".torrent", ".magnet"]:
                    result = self.process_torrent_file(file_path)
                    results.append(result)
                elif file_extension == ".nzb":
                    result = self.process_nzb_file(file_path)
                    results.append(result)

        for success, file_path, download_id in results:
            if success:
                try:
                    os.remove(file_path)
                    logger.info(f"Deleted file: {file_path}")
                except Exception as e:
                    logger.error(f"Error deleting file {file_path}: {e}")

    def process_torrent_file(self, file_path: Path):
        """
        Processes a torrent file or magnet link.

        Sends the torrent/magnet to the TorBox API and tracks the download.

        Args:
            file_path (Path): The path to the torrent file or magnet link.
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

            download_id = None
            torrent_hash = None
            if "data" in response_data and isinstance(response_data["data"], dict):
                if "torrent_id" in response_data["data"]:
                    download_id = response_data["data"]["torrent_id"]
                if "hash" in response_data["data"]:
                    torrent_hash = response_data["data"]["hash"]

            if download_id or torrent_hash:
                identifier = download_id if download_id else torrent_hash
                logger.info(
                    f"Successfully submitted torrent: {file_name}, ID: {identifier}"
                )
                self.download_tracker.track_download(
                    identifier,
                    "torrent",
                    file_path.stem,
                    file_path,
                    identifier, # Use the determined identifier
                    "torrent",
                    file_path.stem,
                    file_path,
                    download_id, # Pass specific ID
                    torrent_hash, # Pass hash
                )
                # track_download now returns True/False
                return True, file_path, identifier # Keep returning True for file deletion logic
            else:
                logger.error(
                    f"Failed to get download ID for: {file_name}. Response: {json.dumps(response_data)}"
                )
                return False, file_path, None

        except Exception as e:
            logger.error(f"Error processing torrent file {file_name}: {e}")
            return False, file_path, None

    def check_torrent_status(self, download_id):
        """
        Checks the status of a torrent download.

        Args:
            download_id: The ID of the torrent download (can be torrent_id or hash).
        """
        tracking_info = self.download_tracker.get_download_info(download_id)
        # The 'download_id' parameter here is actually the 'identifier' used for tracking
        identifier = download_id
        tracking_info = self.download_tracker.get_download_info(identifier)
        if not tracking_info:
            logger.warning(f"No tracking info found for download identifier: {identifier}")
            return

        # Prefer the specific API 'id' if stored, otherwise use the identifier (which might be the hash)
        query_id = tracking_info.get("id") or identifier
        query_param = f"id={query_id}"

        try:
            logger.debug(f"Checking torrent status using query: {query_param}")
            status_data = self.api_client.get_torrent_list(query_param)
            logger.debug(f"Torrent status response: {json.dumps(status_data)}")

            torrent_data = None
            if "data" in status_data:
                if isinstance(status_data["data"], dict):
                    torrent_data = status_data["data"]
                elif isinstance(status_data["data"], list) and len(status_data["data"]) > 0:
                    # If the API returns a list even when querying by ID/hash, find the correct one
                    for torrent in status_data["data"]:
                        api_id_match = tracking_info.get("id") and str(torrent.get("id", "")) == str(tracking_info.get("id"))
                        hash_match = tracking_info.get("hash") and torrent.get("hash") == tracking_info.get("hash")
                        # Also check if the identifier itself matches the hash if no specific ID was stored
                        identifier_hash_match = not tracking_info.get("id") and torrent.get("hash") == identifier

                        if api_id_match or hash_match or identifier_hash_match:
                            torrent_data = torrent
                            break

            if torrent_data:
                download_state = torrent_data.get("download_state", "")
                progress = torrent_data.get("progress", 0)
                progress_percentage = float(progress) * 100
                size_formatted = torrent_data.get("size", 0)

                logger.info(
                    f"Torrent [{download_id}]: {tracking_info['name']} | Status: {download_state.upper()} | Progress: {progress_percentage:.1f}% | Size: {size_formatted}"
                )

                if torrent_data.get("download_present", False):
                    self.request_torrent_download(download_id)

            else:
                logger.warning(
                    f"Could not find torrent with identifier {identifier} (query_id: {query_id}) in status response."
                )

        except Exception as e:
            logger.error(f"Error checking torrent status for identifier {identifier}: {e}")

    def request_torrent_download(self, identifier):
        """
        Requests a download link for a completed torrent.

        Args:
            identifier: The identifier of the torrent download used for tracking.
        """
        tracking_info = self.download_tracker.get_download_info(identifier)
        if not tracking_info:
            logger.warning(
                f"No tracking info found for download identifier: {identifier} for download request."
            )
            return

        # Prefer the specific API 'id' if stored, otherwise use the identifier
        request_id = tracking_info.get("id") or identifier

        try:
            download_link_data = self.api_client.request_torrent_download_link(
                request_id
            )

            if (
                download_link_data.get("success", False)
                and "data" in download_link_data
            ):
                download_url = download_link_data["data"]
                logger.info(
                    f"Got download URL for torrent identifier {identifier} (request_id: {request_id}): {download_url}"
                )
                download_path = (
                    self.config.DOWNLOAD_DIR / tracking_info["name"]
                )  # Initial path, filename adjusted in downloader
                self.file_processor.download_file(
                    download_url,
                    download_path,
                    tracking_info["name"],
                    identifier, # Pass the tracking identifier
                    self.download_tracker.get_tracked_downloads(),
                    self.active_downloads,
                )
                # Successfully requested, remove from tracking? Or let FileProcessor handle removal?
                # Assuming FileProcessor handles removal upon completion/failure for now.
                # self.download_tracker.remove_tracked_download(identifier)
            else:
                logger.error(
                    f"Failed to get download URL for torrent identifier {identifier} (request_id: {request_id}): {json.dumps(download_link_data)}"
                )

        except Exception as e:
            logger.error(f"Error requesting torrent download for identifier {identifier}: {e}")

    def process_nzb_file(self, file_path: Path):
        """
        Processes an NZB file.

        Sends the NZB file to the TorBox API and tracks the download.

        Args:
            file_path (Path): The path to the NZB file.
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

            identifier = None
            download_id = None
            download_hash = None

            if "data" in response_data and isinstance(response_data["data"], dict):
                if "usenetdownload_id" in response_data["data"]:
                    identifier = response_data["data"]["usenetdownload_id"]
                    download_id = identifier
                elif "id" in response_data["data"]:
                    identifier = response_data["data"]["id"]
                    download_id = identifier
                elif "hash" in response_data["data"]:
                    identifier = response_data["data"]["hash"]
                    download_hash = identifier

            if identifier:
                logger.info(
                    f"Successfully submitted NZB: {file_name}, ID: {identifier}"
                )
                self.download_tracker.track_download(
                    identifier,
                    "usenet",
                    file_path.stem,
                    file_path,
                    identifier, # Use the determined identifier
                    "usenet",
                    file_path.stem,
                    file_path,
                    download_id, # Pass specific ID
                    download_hash, # Pass hash
                )
                # track_download now returns True/False
                return True, file_path, identifier # Keep returning True for file deletion logic
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
        tracking_info = self.download_tracker.get_download_info(download_id)
        # The 'download_id' parameter here is actually the 'identifier' used for tracking
        identifier = download_id
        tracking_info = self.download_tracker.get_download_info(identifier)
        if not tracking_info:
            logger.warning(
                f"No tracking info found for usenet download identifier: {identifier}"
            )
            return

        # Prefer the specific API 'id' if stored, otherwise use the identifier (which might be the hash)
        query_id = tracking_info.get("id") or identifier
        query_param = f"id={query_id}"

        try:
            logger.debug(f"Checking usenet status using query: {query_param}")
            status_data = self.api_client.get_usenet_list(query_param)
            logger.debug(f"Usenet status response: {json.dumps(status_data)}")

            usenet_data = None
            if "data" in status_data:
                if isinstance(status_data["data"], dict):
                    usenet_data = status_data["data"]
                elif isinstance(status_data["data"], list) and len(status_data["data"]) > 0:
                     # If the API returns a list even when querying by ID/hash, find the correct one
                    for usenet in status_data["data"]:
                        api_id_match = tracking_info.get("id") and str(usenet.get("id", "")) == str(tracking_info.get("id"))
                        hash_match = tracking_info.get("hash") and usenet.get("hash") == tracking_info.get("hash")
                        # Also check if the identifier itself matches the hash if no specific ID was stored
                        identifier_hash_match = not tracking_info.get("id") and usenet.get("hash") == identifier

                        if api_id_match or hash_match or identifier_hash_match:
                            usenet_data = usenet
                            break

            if usenet_data:
                download_state = usenet_data.get("download_state", "")
                download_present = usenet_data.get("download_present", False)
                download_finished = usenet_data.get("download_finished", False)
                progress = usenet_data.get("progress", 0)
                progress_percentage = float(progress) * 100
                size_formatted = usenet_data.get("size", 0)

                logger.info(
                    f"Usenet [{download_id}]: {tracking_info['name']} | Status: {download_state.upper()} | Progress: {progress_percentage:.1f}% | Size: {size_formatted}"
                )

                if download_present:
                    self.request_usenet_download(download_id)

            else:
                logger.warning(
                    f"Could not find usenet download with identifier {identifier} (query_id: {query_id}) in status response."
                )

        except Exception as e:
            logger.error(f"Error checking usenet status for identifier {identifier}: {e}")

    def request_usenet_download(self, identifier):
        """
        Requests a download link for a completed usenet download.

        Args:
            identifier: The identifier of the usenet download used for tracking.
        """
        tracking_info = self.download_tracker.get_download_info(identifier)
        if not tracking_info:
            logger.warning(
                f"No tracking info found for usenet identifier: {identifier} for download request."
            )
            return

        # Prefer the specific API 'id' if stored, otherwise use the identifier
        request_id = tracking_info.get("id") or identifier

        try:
            download_link_data = self.api_client.request_usenet_download_link(
                request_id
            )

            if (
                download_link_data.get("success", False)
                and "data" in download_link_data
            ):
                download_url = download_link_data["data"]
                logger.info(
                    f"Got download URL for usenet identifier {identifier} (request_id: {request_id}): {download_url}"
                )
                download_path = (
                    self.config.DOWNLOAD_DIR / tracking_info["name"]
                )  # Initial path, filename adjusted in downloader
                self.file_processor.download_file(
                    download_url,
                    download_path,
                    tracking_info["name"],
                    identifier, # Pass the tracking identifier
                    self.download_tracker.get_tracked_downloads(),
                    self.active_downloads,
                )
                # Successfully requested, remove from tracking? Or let FileProcessor handle removal?
                # Assuming FileProcessor handles removal upon completion/failure for now.
                # self.download_tracker.remove_tracked_download(identifier)

            else:
                logger.error(
                    f"Failed to get download URL for usenet identifier {identifier} (request_id: {request_id}): {json.dumps(download_link_data)}"
                )

        except Exception as e:
            logger.error(f"Error requesting usenet download for identifier {identifier}: {e}")

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

    def add_item_to_track(self, item_id, item_type, item_name, item_hash=None):
        """
        Adds an item from the web UI to the download tracker.

        Args:
            item_id (str): The specific ID from the TorBox API (e.g., torrent_id, usenetdownload_id).
            item_type (str): 'torrent' or 'usenet'.
            item_name (str): The name of the download item.
            item_hash (str, optional): The hash of the item, if available.

        Returns:
            bool: True if tracking was initiated, False otherwise (e.g., already tracked).
        """
        # Use the specific ID if available, otherwise fall back to hash as the primary identifier
        # Ensure identifier is a string
        identifier = str(item_id) if item_id else str(item_hash)
        if not identifier:
            logger.error(f"Cannot track item '{item_name}': Missing both ID and Hash.")
            return False

        logger.info(f"Attempting to track item via Web UI: Identifier={identifier}, Type={item_type}, Name={item_name}")

        # Call the updated track_download method
        # Pass None for original_file as it's not applicable here
        # Pass both item_id and item_hash so they are stored in tracking_info
        success = self.download_tracker.track_download(
            identifier=identifier,
            download_type=item_type,
            file_stem=item_name,
            original_file=None,
            download_id=item_id,
            download_hash=item_hash
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
