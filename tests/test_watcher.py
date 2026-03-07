from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from watcher import TorBoxWatcherApp


class RecordingNotifier:
    def __init__(self):
        self.events = []

    def notify_download_dropped(self, event):
        self.events.append(event)


@pytest.fixture
def config(tmp_path):
    return SimpleNamespace(
        TORBOX_API_BASE="https://api.torbox.app",
        TORBOX_API_VERSION="v1",
        TORBOX_API_KEY="test-key",
        MAX_RETRIES=0,
        PROGRESS_INTERVAL=0.01,
        RADARR_WATCH_DIR=tmp_path / "watch",
        RADARR_DOWNLOAD_DIR=tmp_path / "downloads",
        SONARR_WATCH_DIR=tmp_path / "watch-sonarr",
        SONARR_DOWNLOAD_DIR=tmp_path / "downloads-sonarr",
        DUAL_DIRECTORY_MODE=False,
        WATCH_INTERVAL=1,
        CHECK_INTERVAL=10,
        MAX_STATUS_CHECK_FAILURES=2,
        MAX_NOT_FOUND_FAILURES=2,
        MAX_DOWNLOAD_LINK_FAILURES=2,
        MAX_TRACKING_IDLE_HOURS=24,
        ALLOW_ZIP=False,
        SEED_PREFERENCE=1,
        POST_PROCESSING=-1,
        QUEUE_IMMEDIATELY=False,
        GENERIC_WEBHOOK_URLS=[],
        DISCORD_WEBHOOK_URLS=[],
        WEBHOOK_TIMEOUT_SECONDS=5,
    )


@pytest.fixture
def app(config):
    application = TorBoxWatcherApp(config)
    application.webhook_notifier = RecordingNotifier()
    return application


def track_download(
    app,
    *,
    identifier="torrent:id:1",
    download_type="torrent",
    state="active",
    download_id="1",
    queued_id=None,
    name="Example Release",
):
    app.download_tracker.track_download(
        identifier=identifier,
        download_type=download_type,
        file_stem=name,
        download_id=download_id,
        queued_id=queued_id,
        download_dir=app.config.RADARR_DOWNLOAD_DIR,
        state=state,
    )
    return identifier


def test_tracker_entry_removed_on_local_download_failure_and_webhook_fired_once(app):
    identifier = track_download(app)
    app.api_client.request_torrent_download_link = lambda request_id, zip_link=False: {
        "success": True,
        "data": "https://example.invalid/file",
    }

    def fail_download(
        download_url,
        download_path,
        download_name,
        download_id,
        active_downloads,
        download_dir,
        on_complete=None,
        on_failure=None,
    ):
        on_failure(download_id, "local_download_failed", "disk full")
        return False

    app.file_processor.download_file = fail_download

    assert app._request_download_common(identifier, "torrent") is False
    assert app.download_tracker.get_download_info(identifier) is None
    assert len(app.webhook_notifier.events) == 1
    assert app.webhook_notifier.events[0]["reason"] == "local_download_failed"


def test_tracker_entry_completed_on_successful_download_without_webhook(app):
    identifier = track_download(app)
    app.api_client.request_torrent_download_link = lambda request_id, zip_link=False: {
        "success": True,
        "data": "https://example.invalid/file",
    }

    def complete_download(
        download_url,
        download_path,
        download_name,
        download_id,
        active_downloads,
        download_dir,
        on_complete=None,
        on_failure=None,
    ):
        on_complete(download_id)
        return True

    app.file_processor.download_file = complete_download

    assert app._request_download_common(identifier, "torrent") is True
    assert app.download_tracker.get_download_info(identifier) is None
    assert app.webhook_notifier.events == []


def test_zip_extraction_failure_fires_webhook(app):
    identifier = track_download(app, name="archive.zip")
    app.api_client.request_torrent_download_link = lambda request_id, zip_link=False: {
        "success": True,
        "data": "https://example.invalid/file.zip",
    }

    def fail_zip(
        download_url,
        download_path,
        download_name,
        download_id,
        active_downloads,
        download_dir,
        on_complete=None,
        on_failure=None,
    ):
        on_failure(download_id, "zip_extraction_failed", "corrupt archive")
        return False

    app.file_processor.download_file = fail_zip

    assert app._request_download_common(identifier, "torrent") is False
    assert app.download_tracker.get_download_info(identifier) is None
    assert len(app.webhook_notifier.events) == 1
    assert app.webhook_notifier.events[0]["reason"] == "zip_extraction_failed"


def test_repeated_status_api_exceptions_drop_after_max(app):
    identifier = track_download(app)

    def boom(query_param=None):
        raise RuntimeError("status down")

    app.api_client.get_torrent_list = boom

    assert app._check_download_status_common(identifier, "torrent") is False
    assert (
        app.download_tracker.get_download_info(identifier)["failure_counts"]["status_exception"]
        == 1
    )

    assert app._check_download_status_common(identifier, "torrent") is False
    assert app.download_tracker.get_download_info(identifier) is None
    assert app.webhook_notifier.events[-1]["reason"] == "status_check_exception"


def test_repeated_not_found_drops_after_max(app):
    identifier = track_download(app)
    app.api_client.get_torrent_list = lambda query_param=None: {"data": []}

    assert app._check_download_status_common(identifier, "torrent") is False
    assert app.download_tracker.get_download_info(identifier)["failure_counts"]["not_found"] == 1

    assert app._check_download_status_common(identifier, "torrent") is False
    assert app.download_tracker.get_download_info(identifier) is None
    assert app.webhook_notifier.events[-1]["reason"] == "status_not_found"


@pytest.mark.parametrize(
    "request_link",
    [
        lambda request_id, zip_link=False: {"success": False},
        lambda request_id, zip_link=False: (_ for _ in ()).throw(RuntimeError("requestdl failed")),
    ],
)
def test_repeated_failed_requestdl_drops_after_max(app, request_link):
    identifier = track_download(app)
    app.api_client.request_torrent_download_link = request_link

    assert app._request_download_common(identifier, "torrent") is False
    assert app.download_tracker.get_download_info(identifier)["failure_counts"]["download_link"] == 1

    assert app._request_download_common(identifier, "torrent") is False
    assert app.download_tracker.get_download_info(identifier) is None
    assert app.webhook_notifier.events[-1]["reason"] == "download_link_request_failed"


def test_long_running_queued_item_does_not_drop_while_activity_is_seen(app):
    identifier = track_download(
        app,
        identifier="torrent:queued:q1",
        state="queued",
        download_id=None,
        queued_id="q1",
    )
    original_last_activity = app.download_tracker.get_download_info(identifier)["last_activity_at"]
    app.api_client.get_queued_list = lambda queue_type, queued_id=None: {
        "data": [{"queued_id": queued_id, "download_state": "queued"}]
    }

    for _ in range(5):
        assert app._check_download_status_common(identifier, "torrent") is False

    info = app.download_tracker.get_download_info(identifier)
    assert info is not None
    assert info["failure_counts"] == {
        "status_exception": 0,
        "not_found": 0,
        "download_link": 0,
    }
    assert info["last_activity_at"] >= original_last_activity
    assert app.webhook_notifier.events == []


def test_idle_stale_item_drops_and_fires_webhook(app):
    identifier = track_download(app)
    stale_time = datetime.now() - timedelta(hours=25)
    app.download_tracker.get_download_info(identifier)["last_activity_at"] = stale_time.isoformat()

    assert app.cleanup_stale_downloads(now=datetime.now()) == 1
    assert app.download_tracker.get_download_info(identifier) is None
    assert app.webhook_notifier.events[-1]["reason"] == "stale_tracking_timeout"


def test_check_interval_gates_status_polling(app):
    calls = []
    app.check_download_status = lambda: calls.append("checked")

    assert app._run_scheduled_status_check(now=0) is True
    assert app._run_scheduled_status_check(now=5) is False
    assert app._run_scheduled_status_check(now=10) is True
    assert calls == ["checked", "checked"]
