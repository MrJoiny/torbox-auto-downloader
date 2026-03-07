from pathlib import Path

import pytest


def test_parse_csv_env_trims_and_drops_empty_entries(load_config_module):
    config_module = load_config_module()

    assert config_module._parse_csv_env(" alpha, ,beta ,, gamma ") == [
        "alpha",
        "beta",
        "gamma",
    ]


def test_validate_fails_without_api_key(load_config_module):
    config_module = load_config_module(TORBOX_API_KEY=None)

    with pytest.raises(ValueError):
        config_module.Config.validate()


def test_single_directory_mode_uses_base_paths_when_no_subdirs(load_config_module):
    config_module = load_config_module(
        TORBOX_API_KEY="key",
        WATCH_DIR="/base/watch",
        DOWNLOAD_DIR="/base/downloads",
    )

    assert config_module.Config.DUAL_DIRECTORY_MODE is False
    assert config_module.Config.RADARR_WATCH_DIR == Path("/base/watch")
    assert config_module.Config.RADARR_DOWNLOAD_DIR == Path("/base/downloads")
    assert config_module.Config.SONARR_WATCH_DIR == Path("/base/watch")
    assert config_module.Config.SONARR_DOWNLOAD_DIR == Path("/base/downloads")


def test_dual_directory_mode_appends_configured_subdirs(load_config_module):
    config_module = load_config_module(
        TORBOX_API_KEY="key",
        WATCH_DIR="/base/watch",
        DOWNLOAD_DIR="/base/downloads",
        RADARR_WATCH_SUBDIR="movies-in",
        RADARR_DOWNLOAD_SUBDIR="movies-out",
        SONARR_WATCH_SUBDIR="shows-in",
        SONARR_DOWNLOAD_SUBDIR="shows-out",
    )

    assert config_module.Config.DUAL_DIRECTORY_MODE is True
    assert config_module.Config.RADARR_WATCH_DIR == Path("/base/watch/movies-in")
    assert config_module.Config.RADARR_DOWNLOAD_DIR == Path("/base/downloads/movies-out")
    assert config_module.Config.SONARR_WATCH_DIR == Path("/base/watch/shows-in")
    assert config_module.Config.SONARR_DOWNLOAD_DIR == Path("/base/downloads/shows-out")


def test_config_parses_boolean_integer_and_webhook_env_values(load_config_module):
    config_module = load_config_module(
        TORBOX_API_KEY="key",
        ALLOW_ZIP="TrUe",
        QUEUE_IMMEDIATELY="TRUE",
        WATCH_INTERVAL="12",
        CHECK_INTERVAL="34",
        MAX_RETRIES="5",
        MAX_STATUS_CHECK_FAILURES="6",
        MAX_NOT_FOUND_FAILURES="7",
        MAX_DOWNLOAD_LINK_FAILURES="8",
        MAX_TRACKING_IDLE_HOURS="9",
        WEBHOOK_TIMEOUT_SECONDS="10",
        SEED_PREFERENCE="11",
        POST_PROCESSING="12",
        PROGRESS_INTERVAL="13",
        GENERIC_WEBHOOK_URLS=" https://one.test , , https://two.test ",
        DISCORD_WEBHOOK_URLS=" https://discord.one , https://discord.two ",
    )

    assert config_module.Config.ALLOW_ZIP is True
    assert config_module.Config.QUEUE_IMMEDIATELY is True
    assert config_module.Config.WATCH_INTERVAL == 12
    assert config_module.Config.CHECK_INTERVAL == 34
    assert config_module.Config.MAX_RETRIES == 5
    assert config_module.Config.MAX_STATUS_CHECK_FAILURES == 6
    assert config_module.Config.MAX_NOT_FOUND_FAILURES == 7
    assert config_module.Config.MAX_DOWNLOAD_LINK_FAILURES == 8
    assert config_module.Config.MAX_TRACKING_IDLE_HOURS == 9
    assert config_module.Config.WEBHOOK_TIMEOUT_SECONDS == 10
    assert config_module.Config.SEED_PREFERENCE == 11
    assert config_module.Config.POST_PROCESSING == 12
    assert config_module.Config.PROGRESS_INTERVAL == 13
    assert config_module.Config.GENERIC_WEBHOOK_URLS == [
        "https://one.test",
        "https://two.test",
    ]
    assert config_module.Config.DISCORD_WEBHOOK_URLS == [
        "https://discord.one",
        "https://discord.two",
    ]
