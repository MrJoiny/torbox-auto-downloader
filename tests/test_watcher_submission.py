import pytest


def test_torrent_submission_builds_payload_and_tracks_identifier(watcher_app, tmp_path):
    torrent_path = tmp_path / "movie.torrent"
    torrent_path.write_bytes(b"torrent")
    calls = {}
    watcher_app.api_client.create_torrent = lambda file_name, file_path, payload: calls.update(
        {"file_name": file_name, "file_path": file_path, "payload": payload}
    ) or {"data": {"torrent_id": "7", "hash": "hash7"}}

    success, returned_path, identifier = watcher_app.process_torrent_file(
        torrent_path,
        watcher_app.config.RADARR_DOWNLOAD_DIR,
    )

    assert success is True
    assert returned_path == torrent_path
    assert identifier == "torrent:id:7"
    assert calls["file_name"] == "movie.torrent"
    assert calls["file_path"] == torrent_path
    assert calls["payload"] == {
        "seed": watcher_app.config.SEED_PREFERENCE,
        "allow_zip": watcher_app.config.ALLOW_ZIP,
        "name": "movie",
        "as_queued": watcher_app.config.QUEUE_IMMEDIATELY,
    }
    assert watcher_app.download_tracker.get_download_info(identifier)["id"] == "7"


def test_magnet_submission_reads_contents_and_calls_create_from_magnet(watcher_app, tmp_path):
    magnet_path = tmp_path / "movie.magnet"
    magnet_path.write_text(" magnet:?xt=urn:btih:123 ", encoding="utf-8")
    payloads = []
    watcher_app.api_client.create_torrent_from_magnet = lambda payload: payloads.append(payload) or {
        "data": {"queued_id": "q1", "hash": "hash1"}
    }

    success, _, identifier = watcher_app.process_torrent_file(
        magnet_path,
        watcher_app.config.RADARR_DOWNLOAD_DIR,
    )

    assert success is True
    assert identifier == "torrent:queued:q1"
    assert payloads == [
        {
            "seed": watcher_app.config.SEED_PREFERENCE,
            "allow_zip": watcher_app.config.ALLOW_ZIP,
            "name": "movie",
            "as_queued": watcher_app.config.QUEUE_IMMEDIATELY,
            "magnet": "magnet:?xt=urn:btih:123",
        }
    ]


def test_nzb_submission_builds_payload_and_tracks_identifier(watcher_app, tmp_path):
    nzb_path = tmp_path / "episode.nzb"
    nzb_path.write_text("<nzb />", encoding="utf-8")
    calls = {}
    watcher_app.api_client.create_usenet_download = lambda file_name, file_path, payload: calls.update(
        {"file_name": file_name, "file_path": file_path, "payload": payload}
    ) or {"data": {"usenetdownload_id": "5", "hash": "hash5"}}

    success, returned_path, identifier = watcher_app.process_nzb_file(
        nzb_path,
        watcher_app.config.SONARR_DOWNLOAD_DIR,
    )

    assert success is True
    assert returned_path == nzb_path
    assert identifier == "usenet:id:5"
    assert calls["payload"] == {
        "name": "episode",
        "post_processing": watcher_app.config.POST_PROCESSING,
        "as_queued": watcher_app.config.QUEUE_IMMEDIATELY,
    }
    assert watcher_app.download_tracker.get_download_info(identifier)["download_dir"] == str(
        watcher_app.config.SONARR_DOWNLOAD_DIR
    )


@pytest.mark.parametrize(
    ("method_name", "file_name"),
    [
        ("process_torrent_file", "bad.torrent"),
        ("process_nzb_file", "bad.nzb"),
    ],
)
def test_invalid_tracking_reference_returns_failure_without_tracking(
    watcher_app,
    tmp_path,
    method_name,
    file_name,
):
    path = tmp_path / file_name
    path.write_text("data", encoding="utf-8")
    if method_name == "process_torrent_file":
        watcher_app.api_client.create_torrent = lambda *args, **kwargs: {"data": {}}
    else:
        watcher_app.api_client.create_usenet_download = lambda *args, **kwargs: {"data": {}}

    success, returned_path, identifier = getattr(watcher_app, method_name)(
        path,
        watcher_app.config.RADARR_DOWNLOAD_DIR,
    )

    assert success is False
    assert returned_path == path
    assert identifier is None
    assert watcher_app.download_tracker.get_tracked_downloads() == {}


@pytest.mark.parametrize(
    ("method_name", "file_name", "setup"),
    [
        (
            "process_torrent_file",
            "broken.torrent",
            lambda app: setattr(
                app.api_client,
                "create_torrent",
                lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
            ),
        ),
        (
            "process_nzb_file",
            "broken.nzb",
            lambda app: setattr(
                app.api_client,
                "create_usenet_download",
                lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
            ),
        ),
    ],
)
def test_submission_api_exceptions_return_failure_cleanly(
    watcher_app,
    tmp_path,
    method_name,
    file_name,
    setup,
):
    path = tmp_path / file_name
    path.write_text("data", encoding="utf-8")
    setup(watcher_app)

    success, returned_path, identifier = getattr(watcher_app, method_name)(
        path,
        watcher_app.config.RADARR_DOWNLOAD_DIR,
    )

    assert success is False
    assert returned_path == path
    assert identifier is None


def test_request_download_skips_queued_items(watcher_app, track_download):
    identifier = track_download(
        watcher_app,
        identifier="torrent:queued:q1",
        state="queued",
        download_id=None,
        queued_id="q1",
    )

    assert watcher_app.request_torrent_download(identifier) is False


def test_request_download_resolves_missing_active_id_before_requesting_link(
    watcher_app,
    track_download,
):
    identifier = track_download(
        watcher_app,
        identifier="torrent:hash:hash1",
        download_id=None,
        download_hash="hash1",
    )
    watcher_app._get_active_status_data = lambda inner_identifier, tracking_info, download_type: (
        {"torrent_id": "99", "hash": "hash1"},
        "lookup",
    )
    calls = {}
    watcher_app.api_client.request_torrent_download_link = lambda request_id, zip_link=False: calls.update(
        {"request_id": request_id, "zip_link": zip_link}
    ) or {"success": True, "data": "https://example.invalid/file"}
    watcher_app.file_processor.download_file = lambda *args, **kwargs: True

    assert watcher_app.request_torrent_download(identifier) is True
    assert calls == {"request_id": "99", "zip_link": False}


def test_missing_download_dir_drops_tracker_with_local_download_failed(watcher_app, track_download):
    identifier = track_download(watcher_app, download_dir=None)
    watcher_app.download_tracker.get_download_info(identifier)["download_dir"] = None

    assert watcher_app.request_torrent_download(identifier) is False
    assert watcher_app.download_tracker.get_download_info(identifier) is None
    assert watcher_app.webhook_notifier.events[-1]["reason"] == "local_download_failed"


@pytest.mark.parametrize(
    ("download_type", "identifier", "request_method"),
    [
        ("torrent", "torrent:id:1", "request_torrent_download_link"),
        ("usenet", "usenet:id:2", "request_usenet_download_link"),
    ],
)
def test_request_download_paths_call_correct_api_method(
    watcher_app,
    track_download,
    download_type,
    identifier,
    request_method,
):
    track_download(
        watcher_app,
        identifier=identifier,
        download_type=download_type,
        download_id=identifier.split(":")[-1],
    )
    calls = []
    setattr(
        watcher_app.api_client,
        request_method,
        lambda request_id, zip_link=False: calls.append((request_id, zip_link)) or {
            "success": True,
            "data": "https://example.invalid/file",
        },
    )
    watcher_app.file_processor.download_file = lambda *args, **kwargs: True

    if download_type == "torrent":
        assert watcher_app.request_torrent_download(identifier) is True
    else:
        assert watcher_app.request_usenet_download(identifier) is True

    assert calls == [(identifier.split(":")[-1], False)]


def test_successful_local_download_removes_tracker_via_completion_callback(watcher_app, track_download):
    identifier = track_download(watcher_app)
    watcher_app.api_client.request_torrent_download_link = lambda request_id, zip_link=False: {
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

    watcher_app.file_processor.download_file = complete_download

    assert watcher_app.request_torrent_download(identifier) is True
    assert watcher_app.download_tracker.get_download_info(identifier) is None


@pytest.mark.parametrize(
    "request_link",
    [
        lambda request_id, zip_link=False: {"success": False},
        lambda request_id, zip_link=False: (_ for _ in ()).throw(RuntimeError("requestdl failed")),
    ],
)
def test_repeated_failed_request_download_link_drops_after_threshold(
    watcher_app,
    track_download,
    request_link,
):
    identifier = track_download(watcher_app)
    watcher_app.api_client.request_torrent_download_link = request_link

    assert watcher_app.request_torrent_download(identifier) is False
    assert watcher_app.download_tracker.get_download_info(identifier)["failure_counts"]["download_link"] == 1
    assert watcher_app.request_torrent_download(identifier) is False
    assert watcher_app.download_tracker.get_download_info(identifier) is None
    assert watcher_app.webhook_notifier.events[-1]["reason"] == "download_link_request_failed"
