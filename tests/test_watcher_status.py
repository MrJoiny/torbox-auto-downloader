import pytest


@pytest.mark.parametrize(
    ("queued_id", "download_id", "download_hash", "expected"),
    [
        ("q1", "1", "hash1", "torrent:queued:q1"),
        (None, "1", "hash1", "torrent:id:1"),
        (None, None, "hash1", "torrent:hash:hash1"),
        (None, None, None, None),
    ],
)
def test_make_tracker_key_precedence(watcher_app, queued_id, download_id, download_hash, expected):
    assert (
        watcher_app._make_tracker_key(
            "torrent",
            queued_id=queued_id,
            download_id=download_id,
            download_hash=download_hash,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("download_type", "payload", "expected"),
    [
        (
            "torrent",
            {"data": {"torrent_id": "1", "hash": "h1"}},
            {
                "identifier": "torrent:id:1",
                "state": "active",
                "download_type": "torrent",
                "queued_id": None,
                "download_id": "1",
                "download_hash": "h1",
            },
        ),
        (
            "torrent",
            {"data": {"queued_id": "q1", "hash": "h1"}},
            {
                "identifier": "torrent:queued:q1",
                "state": "queued",
                "download_type": "torrent",
                "queued_id": "q1",
                "download_id": None,
                "download_hash": "h1",
            },
        ),
        (
            "usenet",
            {"data": {"usenetdownload_id": "2", "hash": "h2"}},
            {
                "identifier": "usenet:id:2",
                "state": "active",
                "download_type": "usenet",
                "queued_id": None,
                "download_id": "2",
                "download_hash": "h2",
            },
        ),
        (
            "torrent",
            {"data": {"hash": "h3"}},
            {
                "identifier": "torrent:hash:h3",
                "state": "active",
                "download_type": "torrent",
                "queued_id": None,
                "download_id": None,
                "download_hash": "h3",
            },
        ),
        ("torrent", {"data": []}, None),
    ],
)
def test_extract_tracking_reference_shapes_expected_values(watcher_app, download_type, payload, expected):
    assert watcher_app._extract_tracking_reference(payload, download_type) == expected


def test_response_item_helpers_cover_queued_and_active_lookups(watcher_app):
    list_payload = {"data": [{"queued_id": "q1"}, {"queue_id": "q2"}, {"id": "q3"}]}
    active_payload = {
        "data": [
            {"torrent_id": "1", "hash": "ha"},
            {"id": "2", "hash": "hb"},
        ]
    }

    assert watcher_app._extract_items_from_response(list_payload) == list_payload["data"]
    assert watcher_app._extract_items_from_response({"data": {"id": "1"}}) == [{"id": "1"}]
    assert watcher_app._extract_items_from_response({"data": None}) == []
    assert watcher_app._extract_queued_item_id({"queued_id": "q1"}) == "q1"
    assert watcher_app._extract_queued_item_id({"queue_id": "q2"}) == "q2"
    assert watcher_app._extract_queued_item_id({"id": "q3"}) == "q3"
    assert watcher_app._extract_active_download_id({"torrent_id": "1"}, "torrent") == "1"
    assert watcher_app._extract_active_download_id({"usenetdownload_id": "2"}, "usenet") == "2"
    assert watcher_app._find_queued_item(list_payload, "q2") == {"queue_id": "q2"}
    assert (
        watcher_app._find_active_download_data(
            active_payload,
            {"id": None, "hash": "hb"},
            "torrent",
        )
        == {"id": "2", "hash": "hb"}
    )


def test_check_download_status_keeps_queued_item_queued_when_no_active_id_assigned(
    watcher_app,
    track_download,
):
    identifier = track_download(
        watcher_app,
        identifier="torrent:queued:q1",
        state="queued",
        download_id=None,
        queued_id="q1",
    )
    watcher_app.api_client.get_queued_list = lambda queue_type, queued_id=None: {
        "data": [{"queued_id": queued_id, "download_state": "queued"}]
    }

    watcher_app.check_download_status()

    assert watcher_app.download_tracker.get_download_info(identifier)["state"] == "queued"
    assert watcher_app.download_tracker.get_download_info(identifier)["id"] is None


def test_check_download_status_promotes_queued_item_and_requests_public_download(
    watcher_app,
    track_download,
):
    identifier = track_download(
        watcher_app,
        identifier="torrent:queued:q1",
        state="queued",
        download_id=None,
        queued_id="q1",
    )
    watcher_app.api_client.get_queued_list = lambda queue_type, queued_id=None: {
        "data": [{"queued_id": queued_id, "torrent_id": "9", "hash": "hash9"}]
    }
    watcher_app.api_client.get_torrent_list = lambda query_param=None: {
        "data": [
            {
                "torrent_id": "9",
                "hash": "hash9",
                "download_state": "completed",
                "progress": 1,
                "size": "1 GB",
                "download_present": True,
                "files": [{"short_name": "folder/movie.mkv"}],
                "name": "Release",
            }
        ]
    }
    calls = []
    watcher_app.request_torrent_download = lambda inner_identifier: calls.append(inner_identifier) or True

    watcher_app.check_download_status()

    info = watcher_app.download_tracker.get_download_info(identifier)
    assert info["state"] == "active"
    assert info["id"] == "9"
    assert info["hash"] == "hash9"
    assert calls == [identifier]


def test_missing_queued_item_falls_back_to_active_lookup(watcher_app, track_download, monkeypatch):
    identifier = track_download(
        watcher_app,
        identifier="torrent:queued:q1",
        state="queued",
        download_id=None,
        queued_id="q1",
    )
    watcher_app.api_client.get_queued_list = lambda queue_type, queued_id=None: {"data": []}
    calls = []
    monkeypatch.setattr(
        watcher_app,
        "_check_active_status",
        lambda inner_identifier, tracking_info, download_type: calls.append(
            (inner_identifier, tracking_info["queued_id"], download_type)
        )
        or False,
    )

    assert watcher_app._check_queued_status(
        identifier,
        watcher_app.download_tracker.get_download_info(identifier),
        "torrent",
    ) is False
    assert calls == [(identifier, "q1", "torrent")]


def test_check_download_status_updates_single_file_name_and_requests_download(
    watcher_app,
    track_download,
):
    identifier = track_download(watcher_app)
    watcher_app.api_client.get_torrent_list = lambda query_param=None: {
        "data": [
            {
                "torrent_id": "1",
                "hash": "hash1",
                "download_state": "completed",
                "progress": 1,
                "size": "1 GB",
                "download_present": True,
                "files": [{"short_name": "folder/movie.mkv"}],
                "name": "Release",
            }
        ]
    }
    calls = []
    watcher_app.request_torrent_download = lambda inner_identifier: calls.append(inner_identifier) or True

    watcher_app.check_download_status()

    info = watcher_app.download_tracker.get_download_info(identifier)
    assert info["name"] == "movie.mkv"
    assert info["is_multi_file"] is False
    assert calls == [identifier]


def test_active_status_with_multiple_files_forces_zip_request_path(watcher_app, track_download):
    identifier = track_download(watcher_app)
    watcher_app.api_client.get_torrent_list = lambda query_param=None: {
        "data": [
            {
                "torrent_id": "1",
                "hash": "hash1",
                "download_state": "completed",
                "progress": 1,
                "size": "1 GB",
                "download_present": True,
                "files": [{"name": "one.mkv"}, {"name": "two.srt"}],
                "name": "Bundle",
            }
        ]
    }
    calls = []
    watcher_app.request_torrent_download = lambda inner_identifier: calls.append(inner_identifier) or True

    assert watcher_app._check_active_status(
        identifier,
        watcher_app.download_tracker.get_download_info(identifier),
        "torrent",
    )
    info = watcher_app.download_tracker.get_download_info(identifier)
    assert info["name"] == "Bundle.zip"
    assert info["is_multi_file"] is True
    assert calls == [identifier]


def test_hash_based_active_lookup_works_without_active_id(watcher_app, track_download):
    identifier = track_download(
        watcher_app,
        identifier="torrent:hash:hash1",
        download_id=None,
        download_hash="hash1",
    )
    queries = []
    watcher_app.api_client.get_torrent_list = lambda query_param=None: queries.append(query_param) or {
        "data": [
            {
                "id": "44",
                "hash": "hash1",
                "download_state": "downloading",
                "progress": 0.5,
                "size": "2 GB",
                "download_present": False,
            }
        ]
    }

    assert watcher_app._check_active_status(
        identifier,
        watcher_app.download_tracker.get_download_info(identifier),
        "torrent",
    ) is False
    assert queries == [None]
    assert watcher_app.download_tracker.get_download_info(identifier)["id"] == "44"


def test_check_download_status_skips_locally_active_items_and_tolerates_disappearing_entries(
    watcher_app,
    track_download,
    monkeypatch,
):
    locally_active = track_download(watcher_app, identifier="torrent:id:1", download_id="1")
    trigger = track_download(watcher_app, identifier="torrent:id:2", download_id="2")
    disappearing = track_download(
        watcher_app,
        identifier="usenet:id:3",
        download_type="usenet",
        download_id="3",
    )
    watcher_app.active_downloads[locally_active] = object()
    calls = []

    def fake_check_torrent_status(identifier):
        calls.append(("torrent", identifier))
        watcher_app.download_tracker.remove_tracked_download(disappearing)

    monkeypatch.setattr(watcher_app, "check_torrent_status", fake_check_torrent_status)
    monkeypatch.setattr(
        watcher_app,
        "check_usenet_status",
        lambda identifier: calls.append(("usenet", identifier)),
    )

    watcher_app.check_download_status()

    assert calls == [("torrent", trigger)]


def test_repeated_status_exceptions_drop_after_threshold(watcher_app, track_download):
    identifier = track_download(watcher_app)

    def boom(query_param=None):
        raise RuntimeError("status down")

    watcher_app.api_client.get_torrent_list = boom

    assert watcher_app._check_download_status_common(identifier, "torrent") is False
    assert (
        watcher_app.download_tracker.get_download_info(identifier)["failure_counts"]["status_exception"]
        == 1
    )
    assert watcher_app._check_download_status_common(identifier, "torrent") is False
    assert watcher_app.download_tracker.get_download_info(identifier) is None
    assert watcher_app.webhook_notifier.events[-1]["reason"] == "status_check_exception"


def test_repeated_not_found_drops_after_threshold(watcher_app, track_download):
    identifier = track_download(watcher_app)
    watcher_app.api_client.get_torrent_list = lambda query_param=None: {"data": []}

    assert watcher_app._check_download_status_common(identifier, "torrent") is False
    assert watcher_app.download_tracker.get_download_info(identifier)["failure_counts"]["not_found"] == 1
    assert watcher_app._check_download_status_common(identifier, "torrent") is False
    assert watcher_app.download_tracker.get_download_info(identifier) is None
    assert watcher_app.webhook_notifier.events[-1]["reason"] == "status_not_found"
