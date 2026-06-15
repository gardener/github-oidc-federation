import json
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import github
import github_oidc_federation.github_api as github_api
import github_oidc_federation.jwt_verifier as jwt_verifier
import github_oidc_federation.token_request_handler as token_request_handler
from github_oidc_federation.app import build_app


ISSUER = 'https://token.actions.githubusercontent.com'
AUDIENCE = 'github-oidc-federation'
SUBJECT = 'repo:my-org/my-repo:ref:refs/heads/main'
HOST = 'github.com'
ORG = 'my-org'

OIDC_CONFIG_YAML = f"""
- issuer: {ISSUER}
  subject: {SUBJECT}
  permissions:
    contents: write
    actions: read
  repositories:
    - my-repo
    - other-repo

- issuer: {ISSUER}
  principals:
    - repository: my-org/my-repo
      ref: refs/heads/main
  permissions:
    contents: write
    pull_requests: write

- issuer: https://other-issuer.example.com
  subject: repo:other-org/other-repo:ref:refs/heads/main
  permissions:
    contents: read
"""


@pytest.fixture(scope='module')
def rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_key, public_key, private_pem


@pytest.fixture(scope='module')
def kid():
    return 'integration-key-id'


@pytest.fixture(scope='module')
def valid_jwt(rsa_key_pair, kid):
    _, _, private_pem = rsa_key_pair
    return pyjwt.encode(
        {
            'iss': ISSUER,
            'sub': SUBJECT,
            'aud': AUDIENCE,
            'repository': 'my-org/my-repo',
            'ref': 'refs/heads/main',
        },
        private_pem,
        algorithm='RS256',
        headers={'kid': kid},
    )


@pytest.fixture(scope='module')
def jwks(rsa_key_pair, kid):
    import jwt as _jwt

    _, public_key, _ = rsa_key_pair
    jwk = json.loads(_jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk['kid'] = kid
    return {'keys': [jwk]}


@pytest.fixture(autouse=True)
def reset_module_state():
    original_hosts = token_request_handler.ALLOWED_HOSTS
    original_creds = github_api.GITHUB_APP_CREDENTIALS
    original_audience = jwt_verifier.EXPECTED_AUDIENCE
    jwt_verifier._fetch_public_key.cache_clear()
    github_api._get_installation_id_for_org.cache_clear()

    token_request_handler.ALLOWED_HOSTS = {HOST}
    jwt_verifier.EXPECTED_AUDIENCE = AUDIENCE

    credential = MagicMock(spec=github.GitHubAppCredentials)
    credential.host = HOST
    credential.app_id = 123
    credential.private_key = b'dummy'
    credential.matches.return_value = True
    github_api.GITHUB_APP_CREDENTIALS = [credential]

    yield

    token_request_handler.ALLOWED_HOSTS = original_hosts
    github_api.GITHUB_APP_CREDENTIALS = original_creds
    jwt_verifier.EXPECTED_AUDIENCE = original_audience
    jwt_verifier._fetch_public_key.cache_clear()
    github_api._get_installation_id_for_org.cache_clear()


@pytest.fixture
async def client(aiohttp_client, jwks):
    app = build_app()

    def _mock_fetch_side_effect(url, **_):
        res = MagicMock()
        if 'openid-configuration' in url:
            res.to_json.return_value = {'jwks_uri': f'{ISSUER}/jwks'}
        elif url.endswith('/jwks'):
            res.to_json.return_value = jwks
        elif '/orgs/' in url and '/installation' in url:
            res.to_json.return_value = {'id': 42}
        elif '/access_tokens' in url:
            res.to_json.return_value = {
                'token': 'ghs_installation_token',
                'permissions': {'contents': 'write'},
                'repositories': [],
            }
        elif '/contents/' in url:
            import base64

            encoded = base64.b64encode(OIDC_CONFIG_YAML.encode()).decode()
            res.to_json.return_value = {'content': encoded, 'encoding': 'base64'}
        return res

    with (
        patch(
            'github_oidc_federation.github_api.fetch_with_retries',
            new=AsyncMock(side_effect=_mock_fetch_side_effect),
        ),
        patch(
            'github_oidc_federation.jwt_verifier.fetch_with_retries',
            new=AsyncMock(side_effect=_mock_fetch_side_effect),
        ),
        patch('github_oidc_federation.github_api._create_jwt', return_value='app.jwt.token'),
    ):
        yield await aiohttp_client(app)


# --- Happy path ---


async def test_valid_request_returns_installation_token(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': HOST,
            'organization': ORG,
            'permissions': {'contents': 'read'},
            'repositories': ['my-repo'],
        },
    )
    assert resp.status == 200
    body = await resp.json()
    assert body['token'] == 'ghs_installation_token'


async def test_valid_request_with_repositories(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': HOST,
            'organization': ORG,
            'permissions': {'contents': 'read'},
            'repositories': ['my-repo'],
        },
    )
    assert resp.status == 200


# --- Validation failures ---


async def test_missing_token_returns_400(client):
    resp = await client.post(
        '/token-exchange',
        json={
            'host': HOST,
            'organization': ORG,
            'permissions': {'contents': 'read'},
        },
    )
    assert resp.status == 400


async def test_missing_host_returns_400(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'organization': ORG,
            'permissions': {'contents': 'read'},
        },
    )
    assert resp.status == 400


async def test_missing_organization_returns_400(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': HOST,
            'permissions': {'contents': 'read'},
        },
    )
    assert resp.status == 400


async def test_missing_permissions_returns_400(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': HOST,
            'organization': ORG,
        },
    )
    assert resp.status == 400


async def test_disallowed_host_returns_401(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': 'evil.example.com',
            'organization': ORG,
            'permissions': {'contents': 'read'},
        },
    )
    assert resp.status == 401


async def test_invalid_repository_name_returns_401(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': HOST,
            'organization': ORG,
            'permissions': {'contents': 'read'},
            'repositories': ['../evil'],
        },
    )
    assert resp.status == 401


# --- Authorization failures ---


async def test_permission_level_too_high_returns_401(client, valid_jwt):
    # OIDC config only grants write; requesting admin should fail
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': HOST,
            'organization': ORG,
            'permissions': {'contents': 'admin'},
        },
    )
    assert resp.status == 401


async def test_unknown_permission_returns_401(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': HOST,
            'organization': ORG,
            'permissions': {'actions': 'read'},
        },
    )
    assert resp.status == 401


async def test_org_permission_with_repositories_returns_401(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': HOST,
            'organization': ORG,
            'permissions': {'organization_secrets': 'read'},
            'repositories': ['my-repo'],
        },
    )
    assert resp.status == 401
