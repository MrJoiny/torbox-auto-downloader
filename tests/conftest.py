from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


TORBOX_ENV_KEYS = (
    "TORBOX_API_KEY",
    "TORBOX_API_BASE",
    "TORBOX_API_VERSION",
    "WATCH_DIR",
    "DOWNLOAD_DIR",
    "RADARR_WATCH_SUBDIR",
    "RADARR_DOWNLOAD_SUBDIR",
    "SONARR_WATCH_SUBDIR",
    "SONARR_DOWNLOAD_SUBDIR",
    "WATCH_INTERVAL",
    "CHECK_INTERVAL",
    "MAX_RETRIES",
    "MAX_STATUS_CHECK_FAILURES",
    "MAX_NOT_FOUND_FAILURES",
    "MAX_DOWNLOAD_LINK_FAILURES",
    "MAX_TRACKING_IDLE_HOURS",
    "GENERIC_WEBHOOK_URLS",
    "DISCORD_WEBHOOK_URLS",
    "WEBHOOK_TIMEOUT_SECONDS",
    "ALLOW_ZIP",
    "SEED_PREFERENCE",
    "POST_PROCESSING",
    "QUEUE_IMMEDIATELY",
    "PROGRESS_INTERVAL",
)


class FakeResponse:
    def __init__(
        self,
        *,
        json_data=None,
        status_code=200,
        headers=None,
        text="",
        raise_error=None,
        chunks=None,
    ):
        self._json_data = json_data if json_data is not None else {}
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.raise_error = raise_error
        self._chunks = list(chunks or [])

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.raise_error:
            raise self.raise_error

    def iter_content(self, chunk_size=1):
        del chunk_size
        yield from self._chunks

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeSession:
    def __init__(self, *, get_responses=None, post_responses=None, head_responses=None):
        self.headers = {}
        self.get_calls = []
        self.post_calls = []
        self.head_calls = []
        self._queued = {
            "get": list(get_responses or []),
            "post": list(post_responses or []),
            "head": list(head_responses or []),
        }

    def _dispatch(self, method, call, response_queue):
        if response_queue:
            response = response_queue.pop(0)
        else:
            response = FakeResponse()

        if callable(response):
            response = response(call)
        if isinstance(response, BaseException):
            raise response
        return response

    def get(self, url, params=None, stream=False, headers=None, timeout=None):
        call = {
            "url": url,
            "params": params,
            "stream": stream,
            "headers": headers or {},
            "timeout": timeout,
        }
        self.get_calls.append(call)
        return self._dispatch("get", call, self._queued["get"])

    def post(self, url, data=None, files=None, json=None, timeout=None):
        call = {
            "url": url,
            "data": data,
            "files": files,
            "json": json,
            "timeout": timeout,
        }
        self.post_calls.append(call)
        return self._dispatch("post", call, self._queued["post"])

    def head(self, url, timeout=None):
        call = {
            "url": url,
            "timeout": timeout,
        }
        self.head_calls.append(call)
        return self._dispatch("head", call, self._queued["head"])


class RecordingNotifier:
    def __init__(self):
        self.events = []

    def notify_download_dropped(self, event):
        self.events.append(event)


class DeterministicClock:
    def __init__(self, start=1_700_000_000.0):
        self.current = float(start)
        self.sleep_calls = []

    def time(self):
        return self.current

    def advance(self, seconds):
        self.current += seconds
        return self.current

    def sleep(self, seconds):
        self.sleep_calls.append(seconds)
        self.advance(seconds)


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for key in TORBOX_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def load_config_module(monkeypatch):
    def _load(**env):
        for key, value in env.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, str(value))

        import config

        return importlib.reload(config)

    return _load


@pytest.fixture
def fake_response_factory():
    return FakeResponse


@pytest.fixture
def fake_session_factory():
    return FakeSession


@pytest.fixture
def deterministic_clock():
    return DeterministicClock()


@pytest.fixture
def fast_file_processor_runtime(monkeypatch, deterministic_clock):
    import file_processor

    class FakeThread:
        def __init__(self, target=None, args=None, kwargs=None, daemon=None):
            self.target = target
            self.args = args or ()
            self.kwargs = kwargs or {}
            self.daemon = daemon
            self.started = False

        def start(self):
            self.started = True

    monkeypatch.setattr(file_processor.time, "time", deterministic_clock.time)
    monkeypatch.setattr(file_processor.time, "sleep", deterministic_clock.sleep)
    monkeypatch.setattr(file_processor.threading, "Thread", FakeThread)
    monkeypatch.setattr(
        file_processor.FileProcessor,
        "_stats_update_thread",
        lambda self, download_id, stats, active_downloads: None,
    )
    return deterministic_clock


@pytest.fixture
def deferred_stats_thread_runtime(monkeypatch, deterministic_clock):
    import file_processor

    class DeferredThreadController:
        def __init__(self):
            self.pending = []

        def run_all(self):
            while self.pending:
                thread = self.pending.pop(0)
                thread.target(*thread.args, **thread.kwargs)

    controller = DeferredThreadController()

    class FakeThread:
        def __init__(self, target=None, args=None, kwargs=None, daemon=None):
            self.target = target
            self.args = args or ()
            self.kwargs = kwargs or {}
            self.daemon = daemon
            self.started = False

        def start(self):
            self.started = True
            controller.pending.append(self)

    monkeypatch.setattr(file_processor.time, "time", deterministic_clock.time)
    monkeypatch.setattr(file_processor.time, "sleep", deterministic_clock.sleep)
    monkeypatch.setattr(file_processor.threading, "Thread", FakeThread)
    return controller


@pytest.fixture
def temp_config(tmp_path):
    def _build(**overrides):
        config = SimpleNamespace(
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
        for key, value in overrides.items():
            setattr(config, key, value)
        return config

    return _build


@pytest.fixture
def fake_notifier():
    return RecordingNotifier()


@pytest.fixture
def watcher_app(temp_config, fake_notifier):
    from watcher import TorBoxWatcherApp

    app = TorBoxWatcherApp(temp_config())
    app.webhook_notifier = fake_notifier
    return app


@pytest.fixture
def track_download():
    def _track(
        app,
        *,
        identifier="torrent:id:1",
        download_type="torrent",
        state="active",
        download_id="1",
        queued_id=None,
        download_hash=None,
        name="Example Release",
        download_dir=None,
        is_multi_file=False,
    ):
        destination = download_dir if download_dir is not None else app.config.RADARR_DOWNLOAD_DIR
        app.download_tracker.track_download(
            identifier=identifier,
            download_type=download_type,
            file_stem=name,
            download_id=download_id,
            queued_id=queued_id,
            download_hash=download_hash,
            download_dir=destination,
            is_multi_file=is_multi_file,
            state=state,
        )
        return identifier

    return _track
