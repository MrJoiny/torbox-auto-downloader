import logging
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)


def _parse_urls(value):
    """
    Normalizes a string or sequence of webhook URLs into a cleaned list.

    Args:
        value (str | list | tuple | None): Raw configured webhook URLs.

    Returns:
        list[str]: Cleaned webhook URL list with empty entries removed.
    """
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if value:
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _build_discord_summary(event):
    """
    Builds a compact human-readable summary for Discord webhook delivery.

    Args:
        event (dict): Structured internal event payload.

    Returns:
        str: Discord-compatible summary string capped at 2000 characters.
    """
    summary = (
        f"[download_dropped] {event.get('download_type', 'download')} "
        f"'{event.get('name', 'unknown')}' dropped: {event.get('reason', 'unknown')} "
        f"(state={event.get('state', 'unknown')}, identifier={event.get('identifier', 'unknown')})"
    )
    if event.get("details"):
        summary = f"{summary} | {event['details']}"
    return summary[:2000]


@dataclass(frozen=True)
class GenericWebhookTarget:
    url: str
    timeout_seconds: int

    def payload_for(self, event):
        """
        Returns the full structured event payload for generic JSON targets.

        Args:
            event (dict): Structured internal event payload.

        Returns:
            dict: Unmodified event payload.
        """
        return event


@dataclass(frozen=True)
class DiscordWebhookTarget:
    url: str
    timeout_seconds: int

    def payload_for(self, event):
        """
        Returns the Discord webhook payload for a dropped-download event.

        Args:
            event (dict): Structured internal event payload.

        Returns:
            dict: Discord webhook payload containing a ``content`` field.
        """
        return {"content": _build_discord_summary(event)}


class WebhookNotifier:
    """
    Best-effort synchronous webhook dispatcher for internal app events.
    """

    def __init__(self, config, session=None):
        """
        Builds the configured generic and Discord webhook target list.

        Args:
            config: Configuration object providing webhook URLs and timeout.
            session (requests.Session, optional): Session override for testing or reuse.
        """
        self.session = session or requests.Session()
        self.targets = []

        timeout_seconds = int(getattr(config, "WEBHOOK_TIMEOUT_SECONDS", 5))
        for url in _parse_urls(getattr(config, "GENERIC_WEBHOOK_URLS", [])):
            self.targets.append(GenericWebhookTarget(url=url, timeout_seconds=timeout_seconds))

        for url in _parse_urls(getattr(config, "DISCORD_WEBHOOK_URLS", [])):
            self.targets.append(DiscordWebhookTarget(url=url, timeout_seconds=timeout_seconds))

    def notify_download_dropped(self, event):
        """
        Delivers a dropped-download event to all configured targets without raising.

        Args:
            event (dict): Structured internal event payload.

        Returns:
            None: Delivery is best-effort and failures are only logged.
        """
        for target in self.targets:
            try:
                response = self.session.post(
                    target.url,
                    json=target.payload_for(event),
                    timeout=target.timeout_seconds,
                )
                response.raise_for_status()
            except Exception as exc:
                logger.error(
                    "Webhook delivery failed for %s target %s: %s",
                    type(target).__name__,
                    target.url,
                    exc,
                )
