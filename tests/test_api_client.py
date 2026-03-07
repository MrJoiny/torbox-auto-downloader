from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from tenacity import wait_none

from api_client import TorBoxAPIClient


@pytest.fixture
def api_client(fake_session_factory):
    client = TorBoxAPIClient("https://api.example", "v9", "secret-token", 0)
    client.session = fake_session_factory()
    return client


@pytest.fixture
def api_client_with_retries(fake_session_factory, monkeypatch):
    import api_client as api_client_module

    monkeypatch.setattr(api_client_module, "wait_fixed", lambda seconds: wait_none())
    client = TorBoxAPIClient("https://api.example", "v9", "secret-token", 1)
    client.session = fake_session_factory()
    return client


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("", None),
        (None, None),
        ("id=1", {"id": "1"}),
        ("id=1&status=ready", {"id": "1", "status": "ready"}),
        ("name=alpha=beta", {"name": "alpha=beta"}),
    ],
)
def test_parse_query_string_handles_supported_shapes(api_client, query, expected):
    assert api_client._parse_query_string(query) == expected


def test_get_calls_expected_endpoint_with_params(api_client, fake_response_factory):
    api_client.session = api_client.session.__class__(get_responses=[fake_response_factory(json_data={"ok": True})])

    response = api_client._get("/queued/getqueued", params={"type": "torrent", "id": "7"})

    assert response == {"ok": True}
    assert api_client.session.get_calls == [
        {
            "url": "https://api.example/v9/api/queued/getqueued",
            "params": {"type": "torrent", "id": "7"},
            "stream": False,
            "headers": {},
            "timeout": None,
        }
    ]


def test_post_calls_expected_endpoint_with_payload_and_files(api_client, fake_response_factory):
    files = {"file": ("sample.torrent", object(), "application/x-bittorrent")}
    api_client.session = api_client.session.__class__(post_responses=[fake_response_factory(json_data={"ok": True})])

    response = api_client._post("/torrents/createtorrent", payload={"name": "sample"}, files=files)

    assert response == {"ok": True}
    assert api_client.session.post_calls[0]["url"] == "https://api.example/v9/api/torrents/createtorrent"
    assert api_client.session.post_calls[0]["data"] == {"name": "sample"}
    assert api_client.session.post_calls[0]["files"] == files


def test_request_download_link_methods_send_expected_identifiers(api_client, fake_response_factory):
    api_client.session = api_client.session.__class__(
        get_responses=[
            fake_response_factory(json_data={"data": "torrent"}),
            fake_response_factory(json_data={"data": "usenet"}),
        ]
    )

    torrent_response = api_client.request_torrent_download_link("11", zip_link=True)
    usenet_response = api_client.request_usenet_download_link("22", zip_link=False)

    assert torrent_response == {"data": "torrent"}
    assert usenet_response == {"data": "usenet"}
    assert api_client.session.get_calls[0]["params"] == {
        "torrent_id": "11",
        "zip_link": "true",
        "token": "secret-token",
    }
    assert api_client.session.get_calls[1]["params"] == {
        "usenet_id": "22",
        "zip_link": "false",
        "token": "secret-token",
    }


def test_client_initialization_sets_bearer_header_on_session():
    client = TorBoxAPIClient("https://api.example", "v9", "secret-token", 0)

    assert client.headers == {"Authorization": "Bearer secret-token"}
    assert client.session.headers["Authorization"] == "Bearer secret-token"


def test_list_methods_shape_query_parameters(api_client, fake_response_factory):
    api_client.session = api_client.session.__class__(
        get_responses=[
            fake_response_factory(json_data={"data": []}),
            fake_response_factory(json_data={"data": []}),
            fake_response_factory(json_data={"data": []}),
            fake_response_factory(json_data={"data": []}),
        ]
    )

    api_client.get_torrent_list("id=1&status=done")
    api_client.get_usenet_list("id=2")
    api_client.get_queued_list("torrent")
    api_client.get_queued_list("usenet", queued_id="9")

    assert api_client.session.get_calls[0]["params"] == {"id": "1", "status": "done"}
    assert api_client.session.get_calls[1]["params"] == {"id": "2"}
    assert api_client.session.get_calls[2]["params"] == {"type": "torrent"}
    assert api_client.session.get_calls[3]["params"] == {"type": "usenet", "id": "9"}


def test_create_torrent_opens_file_and_attaches_bittorrent_mime(api_client, tmp_path):
    torrent_path = tmp_path / "sample.torrent"
    torrent_path.write_bytes(b"torrent-data")

    response = api_client.create_torrent(
        "sample.torrent",
        torrent_path,
        {"seed": 1},
    )

    assert response == {}
    call = api_client.session.post_calls[0]
    assert call["data"] == {"seed": 1}
    assert call["files"]["file"][0] == "sample.torrent"
    assert call["files"]["file"][2] == "application/x-bittorrent"


def test_create_usenet_download_opens_file_and_attaches_nzb_mime(api_client, tmp_path):
    nzb_path = tmp_path / "sample.nzb"
    nzb_path.write_text("<xml />", encoding="utf-8")

    response = api_client.create_usenet_download(
        "sample.nzb",
        nzb_path,
        {"name": "sample"},
    )

    assert response == {}
    call = api_client.session.post_calls[0]
    assert call["data"] == {"name": "sample"}
    assert call["files"]["file"][0] == "sample.nzb"
    assert call["files"]["file"][2] == "application/x-nzb"


@pytest.mark.parametrize(
    ("method_name", "session_method", "response"),
    [
        (
            "_get",
            "get",
            requests.HTTPError("bad response"),
        ),
        (
            "_post",
            "post",
            requests.RequestException("network failed"),
        ),
    ],
)
def test_http_and_request_exceptions_are_reraised(
    api_client,
    fake_session_factory,
    method_name,
    session_method,
    response,
):
    if isinstance(response, requests.HTTPError):
        response.response = SimpleNamespace(text="failure")

    kwargs = {f"{session_method}_responses": [response]}
    api_client.session = fake_session_factory(**kwargs)

    with pytest.raises(type(response)):
        if method_name == "_get":
            api_client._get("/failing")
        else:
            api_client._post("/failing")


def test_get_retries_once_after_transient_request_exception_and_succeeds(
    api_client_with_retries,
    fake_response_factory,
    fake_session_factory,
):
    api_client_with_retries.session = fake_session_factory(
        get_responses=[
            requests.RequestException("network failed"),
            fake_response_factory(json_data={"ok": True}),
        ]
    )

    response = api_client_with_retries._get("/queued/getqueued", params={"type": "torrent"})

    assert response == {"ok": True}
    assert len(api_client_with_retries.session.get_calls) == 2


def test_post_retries_once_after_transient_request_exception_and_succeeds(
    api_client_with_retries,
    fake_response_factory,
    fake_session_factory,
):
    api_client_with_retries.session = fake_session_factory(
        post_responses=[
            requests.RequestException("network failed"),
            fake_response_factory(json_data={"ok": True}),
        ]
    )

    response = api_client_with_retries._post("/torrents/createtorrent", payload={"name": "sample"})

    assert response == {"ok": True}
    assert len(api_client_with_retries.session.post_calls) == 2


@pytest.mark.parametrize(
    ("method_name", "session_key"),
    [
        ("_get", "get_responses"),
        ("_post", "post_responses"),
    ],
)
def test_retry_exhaustion_reraises_original_request_exception(
    api_client_with_retries,
    fake_session_factory,
    method_name,
    session_key,
):
    error = requests.RequestException("still down")
    api_client_with_retries.session = fake_session_factory(
        **{session_key: [error, error]}
    )

    with pytest.raises(requests.RequestException, match="still down"):
        if method_name == "_get":
            api_client_with_retries._get("/failing")
        else:
            api_client_with_retries._post("/failing")
