from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

import github_oidc_federation.http_client as http_client
from github_oidc_federation.http_client import fetch_with_retries


@pytest.fixture(autouse=True)
def mock_session():
    session = MagicMock(spec=aiohttp.ClientSession)
    original = http_client.SESSION
    http_client.SESSION = session
    yield session
    http_client.SESSION = original


def _make_context_manager(status: int, body: bytes):
    """Return an async context manager that yields a response-like mock."""
    resp = MagicMock()
    resp.ok = status < 400
    resp.status = status
    resp.reason = 'OK' if status < 400 else 'Error'
    resp.read = AsyncMock(return_value=body)
    resp.request_info = MagicMock()
    resp.history = ()

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _ok_cm(json_data=None):
    import json as _json

    body = _json.dumps(json_data or {}).encode()
    return _make_context_manager(200, body)


def _error_cm(status_code=500):
    return _make_context_manager(status_code, b'')


# --- fetch_with_retries ---


async def test_get_on_no_body(mock_session):
    mock_session.request.return_value = _ok_cm({'key': 'value'})
    result = await fetch_with_retries(url='https://example.com/jwks')
    mock_session.request.assert_called_once_with(
        method='GET',
        url='https://example.com/jwks',
        json=None,
        data=None,
        headers=None,
    )
    assert result.to_json() == {'key': 'value'}


async def test_post_when_json_body_provided(mock_session):
    mock_session.request.return_value = _ok_cm()
    await fetch_with_retries(url='https://example.com/token', json={'foo': 'bar'})
    assert mock_session.request.call_args.kwargs['method'] == 'POST'


async def test_post_when_data_body_provided(mock_session):
    mock_session.request.return_value = _ok_cm()
    await fetch_with_retries(url='https://example.com/token', data={'foo': 'bar'})
    assert mock_session.request.call_args.kwargs['method'] == 'POST'


async def test_returns_immediately_on_ok(mock_session):
    mock_session.request.return_value = _ok_cm()
    await fetch_with_retries(url='https://example.com')
    assert mock_session.request.call_count == 1


async def test_retries_on_error_response_then_succeeds(mock_session):
    mock_session.request.side_effect = [_error_cm(), _ok_cm({'ok': True})]
    result = await fetch_with_retries(url='https://example.com', retries=2)
    assert mock_session.request.call_count == 2
    assert result.to_json() == {'ok': True}


async def test_exhausts_retries_and_raises(mock_session):
    mock_session.request.side_effect = [_error_cm(), _error_cm(), _error_cm()]
    with pytest.raises(aiohttp.ClientResponseError):
        await fetch_with_retries(url='https://example.com', retries=2)
    assert mock_session.request.call_count == 3  # 1 initial + 2 retries


async def test_retries_on_exception_then_succeeds(mock_session):
    mock_session.request.side_effect = [ConnectionError('timeout'), _ok_cm()]
    result = await fetch_with_retries(url='https://example.com', retries=2)
    assert mock_session.request.call_count == 2
    assert result.ok


async def test_raises_after_all_exception_retries(mock_session):
    mock_session.request.side_effect = ConnectionError('always fails')
    with pytest.raises(ConnectionError):
        await fetch_with_retries(url='https://example.com', retries=2)
    assert mock_session.request.call_count == 3


async def test_zero_retries_raises_immediately_on_exception(mock_session):
    mock_session.request.side_effect = ConnectionError('fail')
    with pytest.raises(ConnectionError):
        await fetch_with_retries(url='https://example.com', retries=0)
    assert mock_session.request.call_count == 1


async def test_headers_forwarded(mock_session):
    mock_session.request.return_value = _ok_cm()
    await fetch_with_retries(url='https://example.com', headers={'Authorization': 'Bearer tok'})
    assert mock_session.request.call_args.kwargs['headers'] == {'Authorization': 'Bearer tok'}
