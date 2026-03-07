from datetime import datetime, timedelta


def test_build_drop_event_contains_expected_schema(watcher_app, track_download):
    identifier = track_download(watcher_app)
    tracking_info = watcher_app.download_tracker.get_download_info(identifier)

    event = watcher_app._build_drop_event(
        identifier,
        tracking_info,
        "status_not_found",
        details="missing",
    )

    assert event["event"] == "download_dropped"
    assert event["reason"] == "status_not_found"
    assert event["identifier"] == identifier
    assert event["download_type"] == "torrent"
    assert event["name"] == tracking_info["name"]
    assert event["failure_counts"] == tracking_info["failure_counts"]
    assert event["details"] == "missing"
    assert "timestamp" in event


def test_drop_tracked_download_removes_item_and_emits_one_webhook(watcher_app, track_download):
    identifier = track_download(watcher_app)

    assert watcher_app._drop_tracked_download(identifier, "status_not_found", details="missing")
    assert watcher_app.download_tracker.get_download_info(identifier) is None
    assert len(watcher_app.webhook_notifier.events) == 1
    assert watcher_app.webhook_notifier.events[0]["reason"] == "status_not_found"


def test_complete_tracked_download_removes_item_and_is_harmless_for_unknown_identifier(
    watcher_app,
    track_download,
):
    identifier = track_download(watcher_app)

    assert watcher_app._complete_tracked_download(identifier) is True
    assert watcher_app._complete_tracked_download("missing") is False


def test_increment_failure_and_maybe_drop_only_drops_at_threshold(watcher_app, track_download):
    identifier = track_download(watcher_app)

    assert (
        watcher_app._increment_failure_and_maybe_drop(
            identifier,
            "status_exception",
            2,
            "status_check_exception",
            "boom",
        )
        is False
    )
    assert watcher_app.download_tracker.get_download_info(identifier) is not None
    assert (
        watcher_app._increment_failure_and_maybe_drop(
            identifier,
            "status_exception",
            2,
            "status_check_exception",
            "boom",
        )
        is True
    )
    assert watcher_app.download_tracker.get_download_info(identifier) is None


def test_scan_watch_directory_routes_single_and_dual_directory_modes(temp_config, fake_notifier, monkeypatch):
    from watcher import TorBoxWatcherApp

    single_app = TorBoxWatcherApp(temp_config(DUAL_DIRECTORY_MODE=False))
    single_app.webhook_notifier = fake_notifier
    single_calls = []
    monkeypatch.setattr(
        single_app,
        "_scan_directory",
        lambda watch_dir, download_dir: single_calls.append((watch_dir, download_dir)),
    )
    single_app.scan_watch_directory()

    dual_app = TorBoxWatcherApp(temp_config(DUAL_DIRECTORY_MODE=True))
    dual_app.webhook_notifier = fake_notifier
    dual_calls = []
    monkeypatch.setattr(
        dual_app,
        "_scan_directory",
        lambda watch_dir, download_dir: dual_calls.append((watch_dir, download_dir)),
    )
    dual_app.scan_watch_directory()

    assert single_calls == [(single_app.config.RADARR_WATCH_DIR, single_app.config.RADARR_DOWNLOAD_DIR)]
    assert dual_calls == [
        (dual_app.config.RADARR_WATCH_DIR, dual_app.config.RADARR_DOWNLOAD_DIR),
        (dual_app.config.SONARR_WATCH_DIR, dual_app.config.SONARR_DOWNLOAD_DIR),
    ]


def test_scan_directory_processes_supported_files_and_deletes_only_successes(
    watcher_app,
    tmp_path,
    monkeypatch,
):
    watch_dir = tmp_path / "watch"
    download_dir = tmp_path / "downloads"
    watch_dir.mkdir(exist_ok=True)
    download_dir.mkdir(exist_ok=True)
    torrent_ok = watch_dir / "ok.torrent"
    magnet_fail = watch_dir / "fail.magnet"
    nzb_ok = watch_dir / "ok.nzb"
    ignored = watch_dir / "ignored.txt"
    torrent_ok.write_text("torrent", encoding="utf-8")
    magnet_fail.write_text("magnet", encoding="utf-8")
    nzb_ok.write_text("nzb", encoding="utf-8")
    ignored.write_text("ignore", encoding="utf-8")
    calls = []
    monkeypatch.setattr(
        watcher_app,
        "process_torrent_file",
        lambda file_path, destination: calls.append(("torrent", file_path.name, destination))
        or (file_path.name == "ok.torrent", file_path, "tracker"),
    )
    monkeypatch.setattr(
        watcher_app,
        "process_nzb_file",
        lambda file_path, destination: calls.append(("nzb", file_path.name, destination))
        or (True, file_path, "tracker"),
    )

    watcher_app._scan_directory(watch_dir, download_dir)

    assert calls == [
        ("torrent", "fail.magnet", download_dir),
        ("nzb", "ok.nzb", download_dir),
        ("torrent", "ok.torrent", download_dir),
    ]
    assert torrent_ok.exists() is False
    assert nzb_ok.exists() is False
    assert magnet_fail.exists() is True
    assert ignored.exists() is True


def test_scan_directory_processes_supported_files_in_case_insensitive_filename_order(
    watcher_app,
    tmp_path,
    monkeypatch,
):
    watch_dir = tmp_path / "watch"
    download_dir = tmp_path / "downloads"
    watch_dir.mkdir(exist_ok=True)
    download_dir.mkdir(exist_ok=True)

    for name in ["zeta.nzb", "Alpha.torrent", "beta.magnet", "notes.txt"]:
        (watch_dir / name).write_text(name, encoding="utf-8")

    calls = []
    monkeypatch.setattr(
        watcher_app,
        "process_torrent_file",
        lambda file_path, destination: calls.append(("torrent", file_path.name, destination))
        or (False, file_path, "tracker"),
    )
    monkeypatch.setattr(
        watcher_app,
        "process_nzb_file",
        lambda file_path, destination: calls.append(("nzb", file_path.name, destination))
        or (False, file_path, "tracker"),
    )

    watcher_app._scan_directory(watch_dir, download_dir)

    assert calls == [
        ("torrent", "Alpha.torrent", download_dir),
        ("torrent", "beta.magnet", download_dir),
        ("nzb", "zeta.nzb", download_dir),
    ]


def test_cleanup_stale_downloads_skips_locally_active_identifiers(watcher_app, track_download):
    identifier = track_download(watcher_app)
    stale_time = datetime.now() - timedelta(hours=25)
    watcher_app.download_tracker.get_download_info(identifier)["last_activity_at"] = stale_time.isoformat()
    watcher_app.active_downloads[identifier] = object()

    assert watcher_app.cleanup_stale_downloads(now=datetime.now()) == 0
    assert watcher_app.download_tracker.get_download_info(identifier) is not None


def test_run_performs_one_iteration_and_exits_cleanly_on_keyboard_interrupt(
    watcher_app,
    monkeypatch,
):
    calls = []
    monkeypatch.setattr(watcher_app, "scan_watch_directory", lambda: calls.append("scan"))
    monkeypatch.setattr(
        watcher_app,
        "_run_scheduled_status_check",
        lambda: calls.append("status") or True,
    )
    monkeypatch.setattr(
        watcher_app,
        "cleanup_stale_downloads",
        lambda: calls.append("cleanup") or 0,
    )
    monkeypatch.setattr(
        watcher_app,
        "_wait_for_stop",
        lambda seconds: calls.append(("wait", seconds)) or (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    watcher_app.run()

    assert calls == ["scan", "status", "cleanup", ("wait", watcher_app.config.WATCH_INTERVAL)]


def test_run_sleeps_five_seconds_after_unexpected_loop_error(watcher_app, monkeypatch):
    wait_calls = []
    attempts = {"count": 0}

    def fake_scan_watch_directory():
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("boom")
        watcher_app.request_stop()

    monkeypatch.setattr(watcher_app, "scan_watch_directory", fake_scan_watch_directory)
    monkeypatch.setattr(
        watcher_app,
        "_wait_for_stop",
        lambda seconds: wait_calls.append(seconds) or False,
    )

    watcher_app.run()

    assert wait_calls == [5]


def test_run_exits_promptly_when_stop_is_requested_during_wait(watcher_app, monkeypatch):
    calls = []
    monkeypatch.setattr(watcher_app, "scan_watch_directory", lambda: calls.append("scan"))
    monkeypatch.setattr(
        watcher_app,
        "_run_scheduled_status_check",
        lambda: calls.append("status") or True,
    )
    monkeypatch.setattr(
        watcher_app,
        "cleanup_stale_downloads",
        lambda: calls.append("cleanup") or 0,
    )
    monkeypatch.setattr(
        watcher_app,
        "_wait_for_stop",
        lambda seconds: calls.append(("wait", seconds)) or watcher_app.request_stop() or True,
    )

    watcher_app.run()

    assert watcher_app.stop_requested is True
    assert calls == ["scan", "status", "cleanup", ("wait", watcher_app.config.WATCH_INTERVAL)]


def test_shutdown_signals_active_progress_entries_to_stop(watcher_app):
    stats = type("Stats", (), {"should_stop": False})()
    watcher_app.active_downloads["torrent:id:1"] = stats

    watcher_app.shutdown()

    assert stats.should_stop is True
