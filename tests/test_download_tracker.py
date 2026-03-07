from datetime import datetime, timedelta

import pytest

from download_tracker import DownloadTracker


@pytest.fixture
def tracker():
    return DownloadTracker()


def test_track_download_stores_metadata_and_rejects_duplicates(tracker):
    assert tracker.track_download(
        identifier="torrent:id:1",
        download_type="torrent",
        file_stem="Release",
        original_file="release.torrent",
        download_id="1",
        queued_id="q1",
        download_hash="hash1",
        download_dir="/downloads",
        is_multi_file=True,
        state="queued",
    )

    info = tracker.get_download_info("torrent:id:1")
    assert info["type"] == "torrent"
    assert info["name"] == "Release"
    assert info["original_file"] == "release.torrent"
    assert info["id"] == "1"
    assert info["queued_id"] == "q1"
    assert info["hash"] == "hash1"
    assert info["download_dir"] == "/downloads"
    assert info["is_multi_file"] is True
    assert info["state"] == "queued"
    assert info["failure_counts"] == {
        "status_exception": 0,
        "not_found": 0,
        "download_link": 0,
    }
    assert tracker.track_download(
        identifier="torrent:id:1",
        download_type="torrent",
        file_stem="Release",
    ) is False


def test_update_tracking_reference_updates_known_identifier_only(tracker):
    tracker.track_download("torrent:id:1", "torrent", "Release", download_id="1")

    assert tracker.update_tracking_reference(
        "torrent:id:1",
        state="queued",
        queued_id="q1",
        download_id="2",
        download_hash="hash2",
    )
    assert tracker.update_tracking_reference("missing", state="active") is False

    info = tracker.get_download_info("torrent:id:1")
    assert info["state"] == "queued"
    assert info["queued_id"] == "q1"
    assert info["id"] == "2"
    assert info["hash"] == "hash2"


def test_mark_activity_updates_timestamp_and_handles_unknown_identifier(tracker):
    tracker.track_download("torrent:id:1", "torrent", "Release")
    original = tracker.get_download_info("torrent:id:1")["last_activity_at"]

    assert tracker.mark_activity("torrent:id:1") is True
    assert tracker.mark_activity("missing") is False
    assert tracker.get_download_info("torrent:id:1")["last_activity_at"] >= original


def test_failure_counters_increment_and_reset(tracker):
    tracker.track_download("torrent:id:1", "torrent", "Release")

    assert tracker.increment_failure_count("torrent:id:1", "status_exception") == 1
    assert tracker.increment_failure_count("torrent:id:1", "status_exception") == 2
    assert tracker.increment_failure_count("missing", "status_exception") is None
    assert tracker.reset_failure_count("torrent:id:1", "status_exception") is True
    assert tracker.get_download_info("torrent:id:1")["failure_counts"]["status_exception"] == 0

    tracker.increment_failure_count("torrent:id:1", "not_found")
    tracker.increment_failure_count("torrent:id:1", "download_link")
    assert tracker.reset_failure_count("torrent:id:1") is True
    assert tracker.get_download_info("torrent:id:1")["failure_counts"] == {
        "status_exception": 0,
        "not_found": 0,
        "download_link": 0,
    }


def test_invalid_failure_reason_raises_value_error(tracker):
    tracker.track_download("torrent:id:1", "torrent", "Release")

    with pytest.raises(ValueError):
        tracker.increment_failure_count("torrent:id:1", "bad-reason")

    with pytest.raises(ValueError):
        tracker.reset_failure_count("torrent:id:1", "bad-reason")


def test_filename_pop_remove_and_lookup_behave_correctly(tracker):
    tracker.track_download("torrent:id:1", "torrent", "Release")

    tracker.update_filename("torrent:id:1", "Release.mkv", is_multi_file=False)
    assert tracker.get_download_info("torrent:id:1")["name"] == "Release.mkv"

    popped = tracker.pop_download("torrent:id:1")
    assert popped["name"] == "Release.mkv"
    assert tracker.get_download_info("torrent:id:1") is None

    tracker.track_download("torrent:id:2", "torrent", "Another")
    tracker.remove_tracked_download("torrent:id:2")
    assert tracker.get_download_info("torrent:id:2") is None


def test_get_stale_download_identifiers_detects_stale_and_ignores_bad_timestamps(tracker):
    tracker.track_download("fresh", "torrent", "Fresh")
    tracker.track_download("stale", "torrent", "Stale")
    tracker.track_download("broken", "torrent", "Broken")

    now = datetime(2026, 3, 7, 12, 0, 0)
    tracker.get_download_info("fresh")["last_activity_at"] = (now - timedelta(hours=1)).isoformat()
    tracker.get_download_info("stale")["last_activity_at"] = (now - timedelta(hours=30)).isoformat()
    tracker.get_download_info("broken")["last_activity_at"] = "not-a-timestamp"

    assert tracker.get_stale_download_identifiers(max_idle_hours=24, now=now) == ["stale"]
