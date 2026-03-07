from types import SimpleNamespace

import requests

from webhook_notifier import WebhookNotifier


class FakeResponse:
    def __init__(self, should_raise=False):
        self.should_raise = should_raise

    def raise_for_status(self):
        if self.should_raise:
            raise requests.HTTPError("webhook failed")


class RecordingSession:
    def __init__(self, failing_urls=None):
        self.calls = []
        self.failing_urls = set(failing_urls or [])

    def post(self, url, json, timeout):
        self.calls.append({"url": url, "json": json, "timeout": timeout})
        return FakeResponse(should_raise=url in self.failing_urls)


def sample_event():
    return {
        "event": "download_dropped",
        "reason": "status_not_found",
        "download_type": "torrent",
        "identifier": "torrent:id:1",
        "name": "Example Release",
        "state": "active",
        "queued_id": None,
        "download_id": "1",
        "download_hash": None,
        "download_dir": "/downloads",
        "failure_counts": {
            "status_exception": 0,
            "not_found": 3,
            "download_link": 0,
        },
        "submitted_at": "2026-03-07T00:00:00",
        "last_activity_at": "2026-03-07T01:00:00",
        "details": "Missing from TorBox list response.",
        "timestamp": "2026-03-07T02:00:00Z",
    }


def test_generic_target_receives_full_json_payload():
    session = RecordingSession()
    notifier = WebhookNotifier(
        SimpleNamespace(
            GENERIC_WEBHOOK_URLS=["https://generic.example/webhook"],
            DISCORD_WEBHOOK_URLS=[],
            WEBHOOK_TIMEOUT_SECONDS=5,
        ),
        session=session,
    )

    event = sample_event()
    notifier.notify_download_dropped(event)

    assert session.calls == [
        {
            "url": "https://generic.example/webhook",
            "json": event,
            "timeout": 5,
        }
    ]


def test_discord_target_receives_content_payload():
    session = RecordingSession()
    notifier = WebhookNotifier(
        SimpleNamespace(
            GENERIC_WEBHOOK_URLS=[],
            DISCORD_WEBHOOK_URLS=["https://discord.example/webhook"],
            WEBHOOK_TIMEOUT_SECONDS=5,
        ),
        session=session,
    )

    notifier.notify_download_dropped(sample_event())

    assert session.calls[0]["url"] == "https://discord.example/webhook"
    assert session.calls[0]["timeout"] == 5
    assert list(session.calls[0]["json"]) == ["content"]
    assert "download_dropped" in session.calls[0]["json"]["content"]
    assert "status_not_found" in session.calls[0]["json"]["content"]


def test_failing_webhook_target_does_not_block_remaining_targets():
    session = RecordingSession(failing_urls={"https://generic.example/bad"})
    notifier = WebhookNotifier(
        SimpleNamespace(
            GENERIC_WEBHOOK_URLS=[
                "https://generic.example/bad",
                "https://generic.example/good",
            ],
            DISCORD_WEBHOOK_URLS=["https://discord.example/webhook"],
            WEBHOOK_TIMEOUT_SECONDS=5,
        ),
        session=session,
    )

    notifier.notify_download_dropped(sample_event())

    assert [call["url"] for call in session.calls] == [
        "https://generic.example/bad",
        "https://generic.example/good",
        "https://discord.example/webhook",
    ]
