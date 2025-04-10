import logging
import threading
import sys
import os # Import os to access environment variables
from config import Config
from watcher import TorBoxWatcherApp
import web_server # Import the web server module

logger = logging.getLogger(__name__)


def main():
    """Main entry point for the TorBox Watcher application.

    Initializes and runs the TorBoxWatcherApp in a background thread
    and starts the Flask web server in the main thread. Handles
    configuration validation and potential startup errors.

    Raises:
        ValueError: If there is a configuration error.
        Exception: For any other application startup errors.
    """
    watcher_app = None # Initialize to None
    watcher_thread = None

    try:
        Config.validate()
        config = Config()
        watcher_app = TorBoxWatcherApp(config)

        # Pass the watcher app instance to the web server module
        web_server.set_watcher_app(watcher_app)

        # Create and start the watcher thread
        logger.info("Starting watcher thread...")
        watcher_thread = threading.Thread(target=watcher_app.run, daemon=True)
        watcher_thread.start()

        # Start the Flask web server (blocking)
        # Use host='0.0.0.0' to make it accessible outside the container
        # Use debug=False for production-like environment inside Docker
        # Consider using a production server like gunicorn later
        web_port = os.environ.get('WEB_PORT', '5151') # Default to 5151 if not set
        try:
            port_num = int(web_port)
        except ValueError:
            logger.error(f"Invalid WEB_PORT value: '{web_port}'. Must be an integer. Using default 5151.")
            port_num = 5151

        logger.info(f"Starting Flask web server on port {port_num}...")
        web_server.app.run(host='0.0.0.0', port=port_num, debug=False)

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1) # Exit if config fails
    except Exception as e:
        logger.error(f"Application startup error: {e}")
        sys.exit(1) # Exit on other startup errors
    finally:
        # Although the watcher thread is daemon, explicit cleanup might be needed
        # depending on how graceful shutdown is handled.
        # For now, relying on daemon thread property.
        logger.info("Web server stopped.")
        if watcher_thread and watcher_thread.is_alive():
             logger.info("Watcher thread may still be running (daemon).")


if __name__ == "__main__":
    main()
