import logging
from flask import Flask, jsonify, request, send_from_directory
from pathlib import Path
from datetime import datetime

# Assuming TorBoxWatcherApp and its methods will be passed or accessible
# This is a placeholder; actual integration will happen in main.py modification step
watcher_app_instance = None

logger = logging.getLogger("WebServer")

# Define static and template folder paths relative to this file's location
static_folder_path = Path(__file__).parent / "static"
template_folder_path = Path(__file__).parent / "templates"

app = Flask(__name__, static_folder=str(static_folder_path), template_folder=str(template_folder_path))

@app.route('/')
def index():
    """Serves the main HTML page."""
    # Use send_from_directory for explicit control, especially in Docker
    return send_from_directory(app.template_folder, 'index.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serves static files (CSS, JS)."""
    return send_from_directory(app.static_folder, filename)

def _fetch_download_list(api_method, download_type, query_params="bypass_cache=true&limit=1000"):
    """
    Helper function to fetch and parse download list from TorBox API.

    Args:
        api_method: The API method to call (get_torrent_list or get_usenet_list).
        download_type (str): Either "torrent" or "usenet".
        query_params (str): Query parameters for the API call.

    Returns:
        list: List of parsed download items.
    """
    items = []
    try:
        logger.info(f"Fetching {download_type} list from TorBox API...")
        data = api_method(query_params)
        if data.get("success") and isinstance(data.get("data"), list):
            for item in data["data"]:
                items.append({
                    "id": item.get("id"),
                    "hash": item.get("hash"),
                    "name": item.get("name", "N/A"),
                    "status": item.get("download_state", "N/A"),
                    "progress": float(item.get("progress", 0)) * 100,
                    "size": item.get("size", 0),
                    "type": download_type,
                    "created_at": item.get("created_at")
                })
        else:
            logger.warning(f"Failed to fetch or parse {download_type} list: {data.get('detail', 'Unknown error')}")
    except Exception as e:
        logger.error(f"Error fetching {download_type} list: {e}")
    
    return items

def _parse_datetime_safe(date_str):
    """
    Safely parse datetime string, returning datetime.min on failure.

    Args:
        date_str (str): ISO format datetime string.

    Returns:
        datetime: Parsed datetime or datetime.min.
    """
    if date_str:
        try:
            return datetime.fromisoformat(date_str.split('+')[0])
        except (ValueError, TypeError):
            logger.warning(f"Could not parse date string: {date_str}")
    return datetime.min

@app.route('/api/downloads', methods=['GET'])
def get_downloads():
    """
    API endpoint to get the combined list of torrents and usenet downloads
    from the TorBox API.
    """
    if not watcher_app_instance or not hasattr(watcher_app_instance, 'api_client'):
        logger.error("Watcher app instance or API client not available.")
        return jsonify({"error": "Server not properly configured"}), 500

    try:
        combined_list = []
        
        # Fetch torrents and usenet downloads
        combined_list.extend(_fetch_download_list(
            watcher_app_instance.api_client.get_torrent_list, "torrent"
        ))
        combined_list.extend(_fetch_download_list(
            watcher_app_instance.api_client.get_usenet_list, "usenet"
        ))

        # Sort by created_at date, newest first
        combined_list.sort(
            key=lambda item: _parse_datetime_safe(item.get('created_at')),
            reverse=True
        )

        logger.info(f"Returning {len(combined_list)} sorted items from API.")
        return jsonify(combined_list)

    except Exception as e:
        logger.error(f"Error fetching downloads from TorBox API: {e}", exc_info=True)
        return jsonify({"error": "Failed to fetch downloads from TorBox"}), 500


@app.route('/api/track', methods=['POST'])
def track_download():
    """
    API endpoint to add a specific download (by ID and type) to the
    local tracking system managed by TorBoxWatcherApp.
    """
    if not watcher_app_instance or not hasattr(watcher_app_instance, 'add_item_to_track'):
         logger.error("Watcher app instance or add_item_to_track method not available.")
         return jsonify({"error": "Server not properly configured"}), 500

    data = request.get_json()
    if not data or 'id' not in data or 'type' not in data or 'name' not in data:
        logger.warning(f"Invalid track request received: {data}")
        return jsonify({"error": "Missing 'id', 'type', or 'name' in request"}), 400

    item_id = data['id']
    item_type = data['type']
    item_name = data['name']
    item_hash = data.get('hash') # Get hash if available

    logger.info(f"Received request to track item: ID={item_id}, Type={item_type}, Name={item_name}, Hash={item_hash}")

    try:
        # Call the tracking method on the watcher app instance
        # Pass hash along if available, the tracking method needs to handle it
        success = watcher_app_instance.add_item_to_track(item_id, item_type, item_name, item_hash)
        if success:
            logger.info(f"Successfully initiated tracking for item ID: {item_id}")
            return jsonify({"message": f"Tracking initiated for {item_name}"}), 200
        else:
            logger.warning(f"Failed to initiate tracking for item ID: {item_id} (already tracked or error).")
            # Be more specific if the tracking method returns reasons
            return jsonify({"error": f"Failed to initiate tracking for {item_name}. Maybe already tracked?"}), 409 # Conflict

    except Exception as e:
        logger.error(f"Error calling add_item_to_track for ID {item_id}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error during tracking request"}), 500

# Function to set the watcher app instance (will be called from main.py)
def set_watcher_app(instance):
    global watcher_app_instance
    logger.info("Setting watcher_app_instance in web_server.")
    watcher_app_instance = instance

# Note: Running the app (app.run()) will be handled in main.py
# to allow running the watcher in a separate thread.
