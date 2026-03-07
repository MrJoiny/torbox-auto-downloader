from types import SimpleNamespace

import requests

from webhook_notifier import (
    DiscordWebhookTarget,
    GenericWebhookTarget,
    WebhookNotifier,
    _build_discord_summary,
    _parse_urls,
)


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


def test_parse_urls_handles_strings_sequences_and_empty_values():
    assert _parse_urls(" https://one.test , , https://two.test ") == [
        "https://one.test",
        "https://two.test",
    ]
    assert _parse_urls([" https://one.test ", "", "https://two.test "]) == [
        "https://one.test",
        "https://two.test",
    ]
    assert _parse_urls(()) == []
    assert _parse_urls(None) == []


def test_build_discord_summary_includes_expected_fields_and_truncates():
    event = sample_event()
    event["details"] = "x" * 5_000

    summary = _build_discord_summary(event)

    assert "[download_dropped]" in summary
    assert "torrent" in summary
    assert "Example Release" in summary
    assert "status_not_found" in summary
    assert "torrent:id:1" in summary
    assert len(summary) == 2_000


def test_generic_target_payload_for_returns_full_event_payload():
    event = sample_event()
    target = GenericWebhookTarget("https://generic.example/webhook", 5)

    assert target.payload_for(event) is event


def test_discord_target_payload_for_returns_content_payload():
    target = DiscordWebhookTarget("https://discord.example/webhook", 5)

    payload = target.payload_for(sample_event())

    assert list(payload) == ["content"]
    assert "download_dropped" in payload["content"]


def test_generic_target_receives_full_json_payload(fake_session_factory, fake_response_factory):
    session = fake_session_factory(post_responses=[fake_response_factory()])
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

    assert session.post_calls == [
        {
            "url": "https://generic.example/webhook",
            "data": None,
            "files": None,
            "json": event,
            "timeout": 5,
        }
    ]


def test_discord_target_receives_content_payload(fake_session_factory, fake_response_factory):
    session = fake_session_factory(post_responses=[fake_response_factory()])
    notifier = WebhookNotifier(
        SimpleNamespace(
            GENERIC_WEBHOOK_URLS=[],
            DISCORD_WEBHOOK_URLS=["https://discord.example/webhook"],
            WEBHOOK_TIMEOUT_SECONDS=5,
        ),
        session=session,
    )

    notifier.notify_download_dropped(sample_event())

    assert session.post_calls[0]["url"] == "https://discord.example/webhook"
    assert session.post_calls[0]["timeout"] == 5
    assert list(session.post_calls[0]["json"]) == ["content"]
    assert "download_dropped" in session.post_calls[0]["json"]["content"]
    assert "status_not_found" in session.post_calls[0]["json"]["content"]


def test_failing_webhook_target_does_not_block_remaining_targets(fake_session_factory, fake_response_factory):
    error = requests.HTTPError("webhook failed")
    session = fake_session_factory(
        post_responses=[
            fake_response_factory(raise_error=error),
            fake_response_factory(),
            fake_response_factory(),
        ]
    )
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

    assert [call["url"] for call in session.post_calls] == [
        "https://generic.example/bad",
        "https://generic.example/good",
        "https://discord.example/webhook",
    ]
