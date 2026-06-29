import base64
import unittest.mock

import aiohttp.web
import pytest

import github_oidc_federation.github_api as github_api
import github_oidc_federation.models as models


REPO_URL = 'github.com/my-org/.github-oidc'
HOST = 'github.com'
ORG = 'my-org'
APP_ID = 42
PRIVATE_KEY = 'dummy-key'


@pytest.fixture(autouse=True)
def clear_installation_id_cache():
    github_api._get_installation_id_for_org.cache_clear()
    yield
    github_api._get_installation_id_for_org.cache_clear()


@pytest.fixture
def credential():
    cred = unittest.mock.MagicMock(spec=models.GitHubAppCredentials)
    cred.app_id = APP_ID
    cred.private_key = PRIVATE_KEY
    cred.host = HOST
    cred.matches.return_value = True
    return cred


@pytest.fixture
def token_request(credential):
    return models.TokenRequest(
        raw_jwt='tok',
        host=HOST,
        organization=ORG,
        permissions={'contents': 'read'},
        requested_repositories=['my-repo'],
        issuer='https://token.actions.githubusercontent.com',
        repo_url=REPO_URL,
        credential=credential,
    )


def _mock_response(json_data: dict) -> unittest.mock.MagicMock:
    res = unittest.mock.MagicMock()
    res.to_json.return_value = json_data
    return res


# --- find_credential ---


def test_find_credential_returns_matching(credential):
    result = github_api.find_credential(REPO_URL, [credential])
    assert result is credential


def test_find_credential_no_match_returns_none():
    cred = unittest.mock.MagicMock(spec=models.GitHubAppCredentials)
    cred.matches.return_value = False
    assert github_api.find_credential(REPO_URL, [cred]) is None


def test_find_credential_empty_list_returns_none():
    assert github_api.find_credential(REPO_URL, []) is None


# --- _get_api_url ---


def test_get_api_url_github_com():
    assert github_api._get_api_url('github.com') == 'https://api.github.com'


def test_get_api_url_ghe():
    assert github_api._get_api_url('github.example.com') == 'https://github.example.com/api/v3'


# --- _get_installation_id_for_org ---


async def test_get_installation_id_for_org_returns_id():
    with (
        unittest.mock.patch(
            'github_oidc_federation.github_api.http_client.fetch_with_retries',
            new=unittest.mock.AsyncMock(return_value=_mock_response({'id': 99})),
        ),
        unittest.mock.patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        result = await github_api._get_installation_id_for_org(HOST, ORG, APP_ID, PRIVATE_KEY)
    assert result == 99


async def test_get_installation_id_for_org_fetch_failure_raises_500():
    with (
        unittest.mock.patch(
            'github_oidc_federation.github_api.http_client.fetch_with_retries',
            new=unittest.mock.AsyncMock(side_effect=ConnectionError('timeout')),
        ),
        unittest.mock.patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        with pytest.raises(
            aiohttp.web.HTTPInternalServerError, match='Failed to fetch installation ID'
        ):
            await github_api._get_installation_id_for_org(HOST, ORG, APP_ID, PRIVATE_KEY)


async def test_get_installation_id_uses_correct_api_url_for_ghe():
    mock_fetch = unittest.mock.AsyncMock(return_value=_mock_response({'id': 7}))
    with unittest.mock.patch(
        'github_oidc_federation.github_api.http_client.fetch_with_retries', new=mock_fetch
    ):
        with unittest.mock.patch(
            'github_oidc_federation.github_api._create_jwt', return_value='jwt'
        ):
            await github_api._get_installation_id_for_org(
                'ghe.example.com', ORG, APP_ID, PRIVATE_KEY
            )
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
        unittest.mock.patch(
            'github_oidc_federation.github_api.http_client.fetch_with_retries',
            new=unittest.mock.AsyncMock(side_effect=_side_effect),
        ),
        unittest.mock.patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        result = await github_api.fetch_raw_oidc_config(REPO_URL, HOST, credential)

    assert result == yaml_content


async def test_fetch_raw_oidc_config_neither_file_raises_500(credential):
    def _side_effect(url, **_):
        if '/orgs/' in url:
            return _mock_response({'id': 10})
        if '/access_tokens' in url:
            return _mock_response({'token': 'install-tok'})
        req_info = unittest.mock.MagicMock()
        raise aiohttp.ClientResponseError(req_info, (), status=404, message='Not Found')

    with (
        unittest.mock.patch(
            'github_oidc_federation.github_api.http_client.fetch_with_retries',
            new=unittest.mock.AsyncMock(side_effect=_side_effect),
        ),
        unittest.mock.patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        with pytest.raises(aiohttp.web.HTTPInternalServerError):
            await github_api.fetch_raw_oidc_config(REPO_URL, HOST, credential)


async def test_fetch_raw_oidc_config_non_404_error_raises_500(credential):
    def _side_effect(url, **_):
        if '/orgs/' in url:
            return _mock_response({'id': 10})
        if '/access_tokens' in url:
            return _mock_response({'token': 'install-tok'})
        req_info = unittest.mock.MagicMock()
        raise aiohttp.ClientResponseError(req_info, (), status=500, message='Server Error')

    with (
        unittest.mock.patch(
            'github_oidc_federation.github_api.http_client.fetch_with_retries',
            new=unittest.mock.AsyncMock(side_effect=_side_effect),
        ),
        unittest.mock.patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        with pytest.raises(
            aiohttp.web.HTTPInternalServerError, match='Failed to fetch oidc-federation-config'
        ):
            await github_api.fetch_raw_oidc_config(REPO_URL, HOST, credential)


# --- fetch_installation_token ---


async def test_fetch_installation_token_returns_token_dict(token_request):
    expected = {'token': 'ghs_abc', 'permissions': {'contents': 'read'}}

    def _side_effect(url, **_):
        if '/orgs/' in url:
            return _mock_response({'id': 5})
        return _mock_response(expected)

    with (
        unittest.mock.patch(
            'github_oidc_federation.github_api.http_client.fetch_with_retries',
            new=unittest.mock.AsyncMock(side_effect=_side_effect),
        ),
        unittest.mock.patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        result = await github_api.fetch_installation_token(
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
        unittest.mock.patch(
            'github_oidc_federation.github_api.http_client.fetch_with_retries',
            new=unittest.mock.AsyncMock(side_effect=_side_effect),
        ),
        unittest.mock.patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        await github_api.fetch_installation_token(token_request, sub='sub')

    assert call_args['json_body']['repositories'] == ['my-repo']
    assert call_args['json_body']['permissions'] == {'contents': 'read'}


async def test_fetch_installation_token_replaces_hyphens_in_permission_names(token_request):
    token_request.permissions = {'secret-scanning': 'read'}
    call_args = {}

    def _side_effect(url, **kwargs):
        if '/orgs/' in url:
            return _mock_response({'id': 5})
        call_args.update(kwargs)
        return _mock_response({'token': 'tok'})

    with (
        unittest.mock.patch(
            'github_oidc_federation.github_api.http_client.fetch_with_retries',
            new=unittest.mock.AsyncMock(side_effect=_side_effect),
        ),
        unittest.mock.patch('github_oidc_federation.github_api._create_jwt', return_value='jwt'),
    ):
        await github_api.fetch_installation_token(token_request, sub='sub')

    assert 'secret_scanning' in call_args['json_body']['permissions']
    assert 'secret-scanning' not in call_args['json_body']['permissions']
