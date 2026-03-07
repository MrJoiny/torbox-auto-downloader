from pathlib import Path

import pytest
import requests

from file_processor import DownloadStats, ExtractStats, FileProcessor, _format_time


def test_format_time_handles_short_and_long_durations():
    assert _format_time(5) == "00:05"
    assert _format_time(125) == "02:05"
    assert _format_time(7_325) == "122:05"


def test_download_stats_calculations_with_patched_time(monkeypatch, deterministic_clock):
    import file_processor

    monkeypatch.setattr(file_processor.time, "time", deterministic_clock.time)
    stats = DownloadStats("movie.mkv", total_size=200)

    stats.update(50)
    deterministic_clock.advance(5)
    speed = stats.get_speed()

    assert speed == 10
    assert stats.get_progress() == 25
    assert stats.get_elapsed() == 5

    stats.update(50)
    deterministic_clock.advance(5)
    assert stats.get_speed() == 10


def test_extract_stats_calculations_with_patched_time(monkeypatch, deterministic_clock, tmp_path):
    import file_processor

    monkeypatch.setattr(file_processor.time, "time", deterministic_clock.time)
    stats = ExtractStats(tmp_path / "archive.zip", total_files=4, total_size=400)

    stats.update(100)
    deterministic_clock.advance(5)

    assert stats.get_progress() == 25
    assert stats.get_elapsed() == 5
    assert stats.get_speed() == 20


def test_download_stats_eta_uses_remaining_bytes_and_speed(monkeypatch, deterministic_clock):
    import file_processor

    call_times = iter([deterministic_clock.time(), deterministic_clock.time() + 5, deterministic_clock.time() + 10])
    monkeypatch.setattr(file_processor.time, "time", lambda: next(call_times))
    stats = DownloadStats("movie.mkv", total_size=100)
    stats.update(50)

    assert stats.get_eta() == 5


def test_download_stats_print_stats_logs_progress_summary(monkeypatch, deterministic_clock, caplog):
    import file_processor

    monkeypatch.setattr(file_processor.time, "time", deterministic_clock.time)
    stats = DownloadStats("movie.mkv", total_size=200)
    stats.update(100)
    deterministic_clock.advance(5)

    with caplog.at_level("INFO"):
        stats.print_stats()

    assert "File: movie.mkv" in caplog.text
    assert "Progress: 50.0%" in caplog.text
    assert "Downloaded:" in caplog.text
    assert "Total:" in caplog.text


def test_extract_stats_print_stats_logs_extract_summary(monkeypatch, deterministic_clock, tmp_path, caplog):
    import file_processor

    monkeypatch.setattr(file_processor.time, "time", deterministic_clock.time)
    stats = ExtractStats(tmp_path / "archive.zip", total_files=4, total_size=400)
    stats.update(100)
    deterministic_clock.advance(5)

    with caplog.at_level("INFO"):
        stats.print_stats()

    assert "Extracting: archive.zip" in caplog.text
    assert "Elapsed: 00:05" in caplog.text
    assert "Total files: 4" in caplog.text


def test_download_file_succeeds_and_invokes_on_complete(
    fake_response_factory,
    fake_session_factory,
    fast_file_processor_runtime,
    tmp_path,
):
    processor = FileProcessor(progress_interval=0)
    processor.session = fake_session_factory(
        head_responses=[fake_response_factory(headers={"content-length": "6"})],
        get_responses=[fake_response_factory(status_code=200, chunks=[b"abc", b"def"])],
    )
    completed = []

    result = processor.download_file(
        "https://example.invalid/file",
        tmp_path / "movie.mkv",
        "movie.mkv",
        "torrent:id:1",
        {},
        tmp_path,
        on_complete=completed.append,
    )

    assert result is True
    assert completed == ["torrent:id:1"]
    assert (tmp_path / "movie.mkv").read_bytes() == b"abcdef"


def test_download_file_uses_range_for_resume(
    fake_response_factory,
    fake_session_factory,
    fast_file_processor_runtime,
    tmp_path,
):
    target = tmp_path / "movie.mkv"
    target.write_bytes(b"abc")
    processor = FileProcessor(progress_interval=0)
    processor.session = fake_session_factory(
        head_responses=[fake_response_factory(headers={"content-length": "6"})],
        get_responses=[fake_response_factory(status_code=206, chunks=[b"def"])],
    )

    result = processor.download_file(
        "https://example.invalid/file",
        target,
        "movie.mkv",
        "torrent:id:1",
        {},
        tmp_path,
    )

    assert result is True
    assert processor.session.get_calls[0]["headers"]["Range"] == "bytes=3-"
    assert target.read_bytes() == b"abcdef"


def test_download_file_restarts_when_resume_is_ignored(
    fake_response_factory,
    fake_session_factory,
    fast_file_processor_runtime,
    tmp_path,
):
    target = tmp_path / "movie.mkv"
    target.write_bytes(b"partial")
    processor = FileProcessor(progress_interval=0)
    processor.session = fake_session_factory(
        head_responses=[fake_response_factory(headers={"content-length": "3"})],
        get_responses=[fake_response_factory(status_code=200, chunks=[b"xyz"])],
    )

    result = processor.download_file(
        "https://example.invalid/file",
        target,
        "movie.mkv",
        "torrent:id:1",
        {},
        tmp_path,
    )

    assert result is True
    assert target.read_bytes() == b"xyz"


def test_download_file_request_failure_triggers_on_failure(
    fake_session_factory,
    fast_file_processor_runtime,
    tmp_path,
):
    processor = FileProcessor(progress_interval=0)
    processor.session = fake_session_factory(
        head_responses=[requests.Timeout("timed out")],
    )
    failures = []

    result = processor.download_file(
        "https://example.invalid/file",
        tmp_path / "movie.mkv",
        "movie.mkv",
        "torrent:id:1",
        {},
        tmp_path,
        on_failure=lambda *args: failures.append(args),
    )

    assert result is False
    assert failures == [("torrent:id:1", "local_download_failed", "timed out")]


def test_download_file_non_success_status_triggers_on_failure(
    fake_response_factory,
    fake_session_factory,
    deferred_stats_thread_runtime,
    tmp_path,
):
    active_downloads = {}
    processor = FileProcessor(progress_interval=0)
    processor.session = fake_session_factory(
        head_responses=[fake_response_factory(headers={"content-length": "6"})],
        get_responses=[
            fake_response_factory(
                status_code=500,
                raise_error=requests.HTTPError("bad response"),
            )
        ],
    )
    failures = []

    result = processor.download_file(
        "https://example.invalid/file",
        tmp_path / "movie.mkv",
        "movie.mkv",
        "torrent:id:1",
        active_downloads,
        tmp_path,
        on_failure=lambda *args: failures.append(args),
    )

    deferred_stats_thread_runtime.run_all()

    assert result is False
    assert failures == [("torrent:id:1", "local_download_failed", "bad response")]
    assert active_downloads == {}


def test_download_file_retries_after_partial_timeout_and_resumes_successfully(
    fake_response_factory,
    fake_session_factory,
    fast_file_processor_runtime,
    tmp_path,
):
    class PartialTimeoutResponse:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size=1):
            del chunk_size
            yield b"abc"
            raise requests.Timeout("timed out mid-stream")

    target = tmp_path / "movie.mkv"
    processor = FileProcessor(progress_interval=0)
    processor.session = fake_session_factory(
        head_responses=[fake_response_factory(headers={"content-length": "6"})],
        get_responses=[
            PartialTimeoutResponse(),
            fake_response_factory(status_code=206, chunks=[b"def"]),
        ],
    )

    result = processor.download_file(
        "https://example.invalid/file",
        target,
        "movie.mkv",
        "torrent:id:1",
        {},
        tmp_path,
    )

    assert result is True
    assert processor.session.get_calls[0]["headers"] == {}
    assert processor.session.get_calls[1]["headers"]["Range"] == "bytes=3-"
    assert target.read_bytes() == b"abcdef"


def test_download_file_exhausts_retries_and_calls_on_failure(
    fake_response_factory,
    fake_session_factory,
    deferred_stats_thread_runtime,
    tmp_path,
):
    active_downloads = {}
    processor = FileProcessor(progress_interval=0)
    processor.session = fake_session_factory(
        head_responses=[fake_response_factory(headers={"content-length": "6"})],
        get_responses=[requests.ConnectionError("offline")] * 10,
    )
    failures = []

    result = processor.download_file(
        "https://example.invalid/file",
        tmp_path / "movie.mkv",
        "movie.mkv",
        "torrent:id:1",
        active_downloads,
        tmp_path,
        on_failure=lambda *args: failures.append(args),
    )

    deferred_stats_thread_runtime.run_all()

    assert result is False
    assert failures == [("torrent:id:1", "local_download_failed", "offline")]
    assert len(processor.session.get_calls) == 10
    assert active_downloads == {}


def test_download_file_successful_cleanup_removes_active_entry_after_stop(
    fake_response_factory,
    fake_session_factory,
    deferred_stats_thread_runtime,
    tmp_path,
):
    active_downloads = {}
    processor = FileProcessor(progress_interval=0)
    processor.session = fake_session_factory(
        head_responses=[fake_response_factory(headers={"content-length": "6"})],
        get_responses=[fake_response_factory(status_code=200, chunks=[b"abc", b"def"])],
    )

    result = processor.download_file(
        "https://example.invalid/file",
        tmp_path / "movie.mkv",
        "movie.mkv",
        "torrent:id:1",
        active_downloads,
        tmp_path,
    )

    assert result is True
    assert "torrent:id:1" in active_downloads
    assert active_downloads["torrent:id:1"].should_stop is True

    deferred_stats_thread_runtime.run_all()

    assert active_downloads == {}


def test_zip_download_success_calls_extract_zip(
    fake_response_factory,
    fake_session_factory,
    fast_file_processor_runtime,
    monkeypatch,
    tmp_path,
):
    processor = FileProcessor(progress_interval=0)
    processor.session = fake_session_factory(
        head_responses=[fake_response_factory(headers={"content-length": "3"})],
        get_responses=[fake_response_factory(status_code=200, chunks=[b"zip"])],
    )
    extracted = []
    completed = []
    monkeypatch.setattr(
        processor,
        "extract_zip",
        lambda zip_path, active_downloads, download_dir: extracted.append((zip_path, download_dir)) or True,
    )

    result = processor.download_file(
        "https://example.invalid/file.zip",
        tmp_path / "archive.zip",
        "archive.zip",
        "torrent:id:1",
        {},
        tmp_path,
        on_complete=completed.append,
    )

    assert result is True
    assert extracted == [(tmp_path / "archive.zip", tmp_path)]
    assert completed == ["torrent:id:1"]


def test_zip_download_extraction_failure_calls_on_failure_and_cleans_active_downloads(
    fake_response_factory,
    fake_session_factory,
    deferred_stats_thread_runtime,
    monkeypatch,
    tmp_path,
):
    active_downloads = {}
    processor = FileProcessor(progress_interval=0)
    processor.session = fake_session_factory(
        head_responses=[fake_response_factory(headers={"content-length": "3"})],
        get_responses=[fake_response_factory(status_code=200, chunks=[b"zip"])],
    )
    failures = []
    monkeypatch.setattr(processor, "extract_zip", lambda *args, **kwargs: False)

    result = processor.download_file(
        "https://example.invalid/file.zip",
        tmp_path / "archive.zip",
        "archive.zip",
        "torrent:id:1",
        active_downloads,
        tmp_path,
        on_failure=lambda *args: failures.append(args),
    )

    deferred_stats_thread_runtime.run_all()

    assert result is False
    assert failures == [
        (
            "torrent:id:1",
            "zip_extraction_failed",
            "Failed to extract ZIP archive: archive.zip",
        )
    ]
    assert active_downloads == {}


def test_extract_zip_handles_single_top_level_directory(
    fast_file_processor_runtime,
    tmp_path,
):
    zip_path = tmp_path / "single.zip"
    processor = FileProcessor(progress_interval=0)
    _build_zip(zip_path, {"release/movie.mkv": b"movie"})

    result = processor.extract_zip(zip_path, {}, tmp_path / "downloads")

    assert result is True
    assert (tmp_path / "downloads" / "release" / "movie.mkv").read_bytes() == b"movie"
    assert zip_path.exists() is False


def test_extract_zip_handles_multi_root_archives(
    fast_file_processor_runtime,
    tmp_path,
):
    zip_path = tmp_path / "bundle.zip"
    processor = FileProcessor(progress_interval=0)
    _build_zip(zip_path, {"movie.mkv": b"movie", "extras/info.txt": b"info"})

    result = processor.extract_zip(zip_path, {}, tmp_path / "downloads")

    extract_dir = tmp_path / "downloads" / "bundle"
    assert result is True
    assert (extract_dir / "movie.mkv").read_bytes() == b"movie"
    assert (extract_dir / "extras" / "info.txt").read_bytes() == b"info"
    assert zip_path.exists() is False


def test_extract_zip_failure_returns_false_and_cleans_active_downloads(
    fast_file_processor_runtime,
    monkeypatch,
    tmp_path,
):
    import zipfile
    import file_processor

    zip_path = tmp_path / "broken.zip"
    _build_zip(zip_path, {"movie.mkv": b"movie"})
    processor = FileProcessor(progress_interval=0)
    active_downloads = {}
    original_zipfile = zipfile.ZipFile

    class BrokenZipFile(original_zipfile):
        def extract(self, member, path=None, pwd=None):
            raise RuntimeError("boom")

    monkeypatch.setattr(file_processor.zipfile, "ZipFile", BrokenZipFile)

    result = processor.extract_zip(zip_path, active_downloads, tmp_path / "downloads")

    assert result is False
    assert active_downloads == {}


def test_stats_update_thread_removes_active_entry_once_stopped():
    processor = FileProcessor(progress_interval=0)
    stats = DownloadStats("movie.mkv", total_size=100)
    stats.should_stop = True
    active_downloads = {"torrent:id:1": stats}

    processor._stats_update_thread("torrent:id:1", stats, active_downloads)

    assert active_downloads == {}


def _build_zip(zip_path: Path, files):
    import zipfile

    with zipfile.ZipFile(zip_path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
