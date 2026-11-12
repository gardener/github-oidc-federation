import json
import unittest.mock

import pytest

import github_oidc_federation.app as app_module
import github_oidc_federation.cache_invalidation_handler as cache_invalidation_handler


WEBHOOK_SECRET = 'test-webhook-secret'

# a push payload whose commits touch the oidc-federation config file
CONFIG_PUSH_BODY = json.dumps({'commits': [{'modified': ['oidc-federation.yaml']}]}).encode()

# a push payload that does NOT touch the config file
UNRELATED_PUSH_BODY = json.dumps({'commits': [{'modified': ['README.md']}]}).encode()


def _sign(body: bytes, secret: str = WEBHOOK_SECRET) -> str:
    return cache_invalidation_handler.sign_body(secret, body)


@pytest.fixture
def clear_cache_mock():
    with unittest.mock.patch.object(
        cache_invalidation_handler.oidc_config,
        'clear_config_cache',
    ) as m:
        yield m


@pytest.fixture
async def client(aiohttp_client, clear_cache_mock):
    application = app_module.build_app(
        github_app_credentials=[],
        expected_audience='github-oidc-federation',
        # no SA → broadcast path is skipped, so we don't touch the network
        k8s_sa_token=None,
        k8s_namespace=None,
        webhook_secret=WEBHOOK_SECRET,
    )
    return await aiohttp_client(application)


@pytest.fixture
async def client_without_secret(aiohttp_client, clear_cache_mock):
    application = app_module.build_app(
        github_app_credentials=[],
        expected_audience='github-oidc-federation',
        webhook_secret=None,
    )
    return await aiohttp_client(application)


# --- signature helpers ---


def test_sign_body_round_trips():
    body = b'{"internal":true}'
    header = cache_invalidation_handler.sign_body(WEBHOOK_SECRET, body)
    assert header.startswith('sha256=')
    assert cache_invalidation_handler._is_valid_signature(WEBHOOK_SECRET, body, header)


def test_is_valid_signature_rejects_wrong_secret():
    body = b'{"internal":true}'
    header = cache_invalidation_handler.sign_body('other-secret', body)
    assert not cache_invalidation_handler._is_valid_signature(WEBHOOK_SECRET, body, header)


def test_is_valid_signature_rejects_missing_and_malformed_header():
    body = b'x'
    assert not cache_invalidation_handler._is_valid_signature(WEBHOOK_SECRET, body, None)
    assert not cache_invalidation_handler._is_valid_signature(WEBHOOK_SECRET, body, '')
    assert not cache_invalidation_handler._is_valid_signature(WEBHOOK_SECRET, body, 'deadbeef')


def test_is_valid_signature_rejects_body_tampering():
    header = cache_invalidation_handler.sign_body(WEBHOOK_SECRET, b'original')
    assert not cache_invalidation_handler._is_valid_signature(WEBHOOK_SECRET, b'tampered', header)


# --- endpoint auth ---


async def test_no_secret_configured_rejects_even_signed_request(client_without_secret):
    resp = await client_without_secret.post(
        '/invalidate-cache',
        data=CONFIG_PUSH_BODY,
        headers={'X-Hub-Signature-256': _sign(CONFIG_PUSH_BODY)},
    )
    assert resp.status == 401


async def test_missing_signature_returns_401(client, clear_cache_mock):
    resp = await client.post('/invalidate-cache', data=CONFIG_PUSH_BODY)
    assert resp.status == 401
    clear_cache_mock.assert_not_called()


async def test_invalid_signature_returns_401(client, clear_cache_mock):
    resp = await client.post(
        '/invalidate-cache',
        data=CONFIG_PUSH_BODY,
        headers={'X-Hub-Signature-256': 'sha256=deadbeef'},
    )
    assert resp.status == 401
    clear_cache_mock.assert_not_called()


async def test_forged_internal_header_without_signature_returns_401(client, clear_cache_mock):
    # X-Internal-Broadcast is not trusted on its own; without a valid signature
    # the request is rejected.
    resp = await client.post(
        '/invalidate-cache',
        data=b'',
        headers={'X-Internal-Broadcast': 'true'},
    )
    assert resp.status == 401
    clear_cache_mock.assert_not_called()


# --- endpoint behaviour on valid signatures ---


async def test_valid_signature_config_push_clears_cache(client, clear_cache_mock):
    resp = await client.post(
        '/invalidate-cache',
        data=CONFIG_PUSH_BODY,
        headers={'X-Hub-Signature-256': _sign(CONFIG_PUSH_BODY)},
    )
    assert resp.status == 204
    clear_cache_mock.assert_called_once()


async def test_valid_signature_unrelated_push_does_not_clear_cache(client, clear_cache_mock):
    resp = await client.post(
        '/invalidate-cache',
        data=UNRELATED_PUSH_BODY,
        headers={'X-Hub-Signature-256': _sign(UNRELATED_PUSH_BODY)},
    )
    assert resp.status == 204
    clear_cache_mock.assert_not_called()


async def test_signed_internal_broadcast_clears_without_rebroadcast(client, clear_cache_mock):
    # a signed sibling broadcast: the push-filter is skipped (internal), the
    # cache is cleared, and no further broadcast is attempted (no SA configured,
    # but we also assert the broadcast helper is never invoked).
    body = cache_invalidation_handler._INTERNAL_BROADCAST_BODY
    with unittest.mock.patch.object(
        cache_invalidation_handler,
        '_broadcast_to_siblings',
        new=unittest.mock.AsyncMock(),
    ) as broadcast_mock:
        resp = await client.post(
            '/invalidate-cache',
            data=body,
            headers={
                'X-Internal-Broadcast': 'true',
                'X-Hub-Signature-256': _sign(body),
            },
        )
    assert resp.status == 204
    clear_cache_mock.assert_called_once()
    broadcast_mock.assert_not_called()
