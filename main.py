import logging
import sys
from config import Config
from watcher import TorBoxWatcherApp
from version import __version__, __app_name__

logger = logging.getLogger(__name__)


def main():
    """Main entry point for the TorBox Watcher application.

    Initializes and runs the TorBoxWatcherApp. Handles
    configuration validation and potential startup errors.

    Raises:
        ValueError: If there is a configuration error.
        Exception: For any other application startup errors.
    """
    # Display version information
    logger.info("=" * 60)
    logger.info(f"{__app_name__} v{__version__}")
    logger.info("=" * 60)

    try:
        Config.validate()
        config = Config()
        watcher_app = TorBoxWatcherApp(config)

        # Run the watcher (blocking)
        logger.info("Starting watcher...")
        watcher_app.run()

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Application startup error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
