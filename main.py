import logging
import signal
import sys
from config import Config
from watcher import TorBoxWatcherApp
from version import __version__, __app_name__

logger = logging.getLogger(__name__)


def _create_signal_handler(watcher_app):
    """Creates a signal handler that requests graceful watcher shutdown."""

    def _handle_signal(signum, _frame):
        signal_name = signal.Signals(signum).name
        logger.info("Received %s. Requesting shutdown...", signal_name)
        watcher_app.request_stop()

    return _handle_signal


def _install_signal_handlers(watcher_app):
    """Registers SIGINT and SIGTERM handlers when supported by the runtime."""
    handler = _create_signal_handler(watcher_app)
    for signal_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, signal_name, None)
        if sig is not None:
            signal.signal(sig, handler)


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
        _install_signal_handlers(watcher_app)

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
