import pytest
import signal

import main


def test_main_successful_startup_validates_config_constructs_app_and_runs(monkeypatch):
    calls = []

    class FakeConfig:
        @staticmethod
        def validate():
            calls.append("validate")

    class FakeWatcherApp:
        def __init__(self, config):
            calls.append(("init", config))

        def run(self):
            calls.append("run")

    monkeypatch.setattr(main, "Config", FakeConfig)
    monkeypatch.setattr(main, "TorBoxWatcherApp", FakeWatcherApp)

    main.main()

    assert calls[0] == "validate"
    assert calls[1][0] == "init"
    assert isinstance(calls[1][1], FakeConfig)
    assert calls[2] == "run"


def test_main_exits_with_status_one_on_validation_error(monkeypatch):
    class FakeConfig:
        @staticmethod
        def validate():
            raise ValueError("missing api key")

    monkeypatch.setattr(main, "Config", FakeConfig)

    with pytest.raises(SystemExit) as exc_info:
        main.main()

    assert exc_info.value.code == 1


def test_main_exits_with_status_one_on_unexpected_startup_error(monkeypatch):
    class FakeConfig:
        @staticmethod
        def validate():
            return None

    class FakeWatcherApp:
        def __init__(self, config):
            raise RuntimeError("boom")

    monkeypatch.setattr(main, "Config", FakeConfig)
    monkeypatch.setattr(main, "TorBoxWatcherApp", FakeWatcherApp)

    with pytest.raises(SystemExit) as exc_info:
        main.main()

    assert exc_info.value.code == 1


def test_main_installs_signal_handlers_that_request_shutdown(monkeypatch):
    calls = []
    installed_handlers = {}
    watcher_app_holder = {}

    class FakeConfig:
        @staticmethod
        def validate():
            calls.append("validate")

    class FakeWatcherApp:
        def __init__(self, config):
            del config
            watcher_app_holder["app"] = self
            self.stop_requests = 0

        def request_stop(self):
            self.stop_requests += 1

        def run(self):
            calls.append("run")

    monkeypatch.setattr(main, "Config", FakeConfig)
    monkeypatch.setattr(main, "TorBoxWatcherApp", FakeWatcherApp)
    monkeypatch.setattr(
        main.signal,
        "signal",
        lambda sig, handler: installed_handlers.setdefault(sig, handler),
    )

    main.main()

    assert signal.SIGINT in installed_handlers
    assert signal.SIGTERM in installed_handlers

    installed_handlers[signal.SIGTERM](signal.SIGTERM, None)

    assert watcher_app_holder["app"].stop_requests == 1
