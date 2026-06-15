import base64
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp.web
import pytest

import github
import github_oidc_federation.github_api as github_api_module
from github_oidc_federation.github_api import (
    _extract_private_key,
    _get_api_url,
    find_credential,
    fetch_installation_token,
    fetch_raw_oidc_config,
    _get_installation_id_for_org,
)
from github_oidc_federation.models import TokenRequest


REPO_URL = 'github.com/my-org/.github-oidc'
HOST = 'github.com'
ORG = 'my-org'
APP_ID = 42
PRIVATE_KEY = b'dummy-key'


@pytest.fixture(autouse=True)
def clear_installation_id_cache():
    _get_installation_id_for_org.cache_clear()
    yield
    _get_installation_id_for_org.cache_clear()


@pytest.fixture
def credential():
    cred = MagicMock(spec=github.GitHubAppCredentials)
    cred.app_id = APP_ID
    cred.private_key = PRIVATE_KEY
    cred.host = HOST
    cred.matches.return_value = True
    return cred


@pytest.fixture
def token_request(credential):
    return TokenRequest(
        jwt='tok',
        host=HOST,
        organization=ORG,
        permissions={'contents': 'read'},
        requested_repositories=['my-repo'],
        issuer='https://token.actions.githubusercontent.com',
        repo_url=REPO_URL,
        credential=credential,
    )


def _mock_response(json_data: dict) -> MagicMock:
    res = MagicMock()
    res.to_json.return_value = json_data
    return res


# --- find_credential ---


def test_find_credential_returns_matching(credential):
    github_api_module.GITHUB_APP_CREDENTIALS = [credential]
    result = find_credential(REPO_URL)
    assert result is credential


def test_find_credential_no_match_raises_500():
    cred = MagicMock(spec=github.GitHubAppCredentials)
    cred.matches.return_value = False
    github_api_module.GITHUB_APP_CREDENTIALS = [cred]
    with pytest.raises(aiohttp.web.HTTPInternalServerError):
        find_credential(REPO_URL)


def test_find_credential_empty_list_raises_500():
    github_api_module.GITHUB_APP_CREDENTIALS = []
    with pytest.raises(aiohttp.web.HTTPInternalServerError):
        find_credential(REPO_URL)


# --- _extract_private_key ---


def test_extract_private_key_from_bytes(credential):
    credential.private_key = b'bytes-key'
    assert _extract_private_key(credential) == b'bytes-key'


def test_extract_private_key_from_str(credential):
    credential.private_key = 'str-key'
    assert _extract_private_key(credential) == b'str-key'


# --- _get_api_url ---


def test_get_api_url_github_com():
    assert _get_api_url('github.com') == 'https://api.github.com'


def test_get_api_url_ghe():
    assert _get_api_url('github.example.com') == 'https://github.example.com/api/v3'


# --- _get_installation_id_for_org ---


async def test_get_installation_id_for_org_returns_id():
    with (
        patch(
            'github_oidc_federation.github_api.fetch_with_retries',
            new=AsyncMock(return_value=_mock_response({'id': 99})),
        ),
        patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        result = await _get_installation_id_for_org(HOST, ORG, APP_ID, PRIVATE_KEY)
    assert result == 99


async def test_get_installation_id_for_org_fetch_failure_raises_500():
    with (
        patch(
            'github_oidc_federation.github_api.fetch_with_retries',
            new=AsyncMock(side_effect=ConnectionError('timeout')),
        ),
        patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        with pytest.raises(
            aiohttp.web.HTTPInternalServerError, match='Failed to fetch installation ID'
        ):
            await _get_installation_id_for_org(HOST, ORG, APP_ID, PRIVATE_KEY)


async def test_get_installation_id_uses_correct_api_url_for_ghe():
    mock_fetch = AsyncMock(return_value=_mock_response({'id': 7}))
    with patch('github_oidc_federation.github_api.fetch_with_retries', new=mock_fetch):
        with patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'):
            await _get_installation_id_for_org('ghe.example.com', ORG, APP_ID, PRIVATE_KEY)
    url = mock_fetch.call_args.kwargs['url']
    assert url.startswith('https://ghe.example.com/api/v3')


# --- fetch_raw_oidc_config ---


async def test_fetch_raw_oidc_config_returns_yaml_content(credential):
    yaml_content = (
        '- issuer: https://example.com\n  subject: s\n  permissions:\n    contents: read\n'
    )
    encoded = base64.b64encode(yaml_content.encode()).decode()

    call_count = [0]

    def _side_effect(url, **_):
        call_count[0] += 1
        if '/installation' in url and '/orgs/' in url:
            return _mock_response({'id': 10})
        if '/access_tokens' in url:
            return _mock_response({'token': 'install-tok'})
        if '/contents/' in url:
            return _mock_response({'content': encoded})
        return _mock_response({})

    with (
        patch(
            'github_oidc_federation.github_api.fetch_with_retries',
            new=AsyncMock(side_effect=_side_effect),
        ),
        patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        result = await fetch_raw_oidc_config(REPO_URL, HOST, credential)

    assert result == yaml_content


async def test_fetch_raw_oidc_config_falls_back_to_json(credential):
    json_content = '[{"issuer": "x", "subject": "s", "permissions": {}}]'
    encoded = base64.b64encode(json_content.encode()).decode()

    def _side_effect(url, **_):
        if '/orgs/' in url:
            return _mock_response({'id': 10})
        if '/access_tokens' in url:
            return _mock_response({'token': 'install-tok'})
        if 'oidc-federation.yaml' in url:
            req_info = MagicMock()
            raise aiohttp.ClientResponseError(req_info, (), status=404, message='Not Found')
        if 'oidc-federation.json' in url:
            return _mock_response({'content': encoded})
        return _mock_response({})

    with (
        patch(
            'github_oidc_federation.github_api.fetch_with_retries',
            new=AsyncMock(side_effect=_side_effect),
        ),
        patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        result = await fetch_raw_oidc_config(REPO_URL, HOST, credential)

    assert result == json_content


async def test_fetch_raw_oidc_config_neither_file_raises_500(credential):
    def _side_effect(url, **_):
        if '/orgs/' in url:
            return _mock_response({'id': 10})
        if '/access_tokens' in url:
            return _mock_response({'token': 'install-tok'})
        req_info = MagicMock()
        raise aiohttp.ClientResponseError(req_info, (), status=404, message='Not Found')

    with (
        patch(
            'github_oidc_federation.github_api.fetch_with_retries',
            new=AsyncMock(side_effect=_side_effect),
        ),
        patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        with pytest.raises(aiohttp.web.HTTPInternalServerError):
            await fetch_raw_oidc_config(REPO_URL, HOST, credential)


async def test_fetch_raw_oidc_config_non_404_error_raises_500(credential):
    def _side_effect(url, **_):
        if '/orgs/' in url:
            return _mock_response({'id': 10})
        if '/access_tokens' in url:
            return _mock_response({'token': 'install-tok'})
        req_info = MagicMock()
        raise aiohttp.ClientResponseError(req_info, (), status=500, message='Server Error')

    with (
        patch(
            'github_oidc_federation.github_api.fetch_with_retries',
            new=AsyncMock(side_effect=_side_effect),
        ),
        patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        with pytest.raises(
            aiohttp.web.HTTPInternalServerError, match='Failed to fetch oidc-federation-config'
        ):
            await fetch_raw_oidc_config(REPO_URL, HOST, credential)


# --- fetch_installation_token ---


async def test_fetch_installation_token_returns_token_dict(token_request):
    expected = {'token': 'ghs_abc', 'permissions': {'contents': 'read'}}

    def _side_effect(url, **_):
        if '/orgs/' in url:
            return _mock_response({'id': 5})
        return _mock_response(expected)

    with (
        patch(
            'github_oidc_federation.github_api.fetch_with_retries',
            new=AsyncMock(side_effect=_side_effect),
        ),
        patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        result = await fetch_installation_token(
            token_request, sub='repo:my-org/my-repo:ref:refs/heads/main'
        )

    assert result == expected


async def test_fetch_installation_token_passes_permissions_and_repos(token_request):
    call_args = {}

    def _side_effect(url, **kwargs):
        if '/orgs/' in url:
            return _mock_response({'id': 5})
        call_args.update(kwargs)
        return _mock_response({'token': 'ghs_xyz'})

    with (
        patch(
            'github_oidc_federation.github_api.fetch_with_retries',
            new=AsyncMock(side_effect=_side_effect),
        ),
        patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        await fetch_installation_token(token_request, sub='sub')

    assert call_args['json']['repositories'] == ['my-repo']
    assert call_args['json']['permissions'] == {'contents': 'read'}


async def test_fetch_installation_token_replaces_hyphens_in_permission_names(token_request):
    token_request.permissions = {'secret-scanning': 'read'}
    call_args = {}

    def _side_effect(url, **kwargs):
        if '/orgs/' in url:
            return _mock_response({'id': 5})
        call_args.update(kwargs)
        return _mock_response({'token': 'tok'})

    with (
        patch(
            'github_oidc_federation.github_api.fetch_with_retries',
            new=AsyncMock(side_effect=_side_effect),
        ),
        patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        await fetch_installation_token(token_request, sub='sub')

    assert 'secret_scanning' in call_args['json']['permissions']
    assert 'secret-scanning' not in call_args['json']['permissions']
