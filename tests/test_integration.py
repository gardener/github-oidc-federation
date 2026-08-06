import base64
import json
import unittest.mock

import cryptography.hazmat.primitives.asymmetric.rsa as crypto_rsa
import cryptography.hazmat.primitives.serialization as crypto_serialization
import jwt as pyjwt
import pytest

import github_oidc_federation.app as app_module
import github_oidc_federation.github_api as github_api
import github_oidc_federation.jwt_verifier as jwt_verifier
import github_oidc_federation.models as models
import github_oidc_federation.oidc_config as oidc_config


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
    private_key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=crypto_serialization.NoEncryption(),
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
def clear_caches():
    jwt_verifier._fetch_public_key.cache_clear()
    github_api._get_installation_id_for_org.cache_clear()
    oidc_config.clear_config_cache()
    yield
    jwt_verifier._fetch_public_key.cache_clear()
    github_api._get_installation_id_for_org.cache_clear()
    oidc_config.clear_config_cache()


@pytest.fixture
async def client(aiohttp_client, jwks):
    credential = unittest.mock.MagicMock(spec=models.GitHubAppCredentials)
    credential.host = HOST
    credential.app_id = 123
    credential.private_key = 'dummy'
    credential.matches.return_value = True

    application = app_module.build_app(
        github_app_credentials=[credential],
        expected_audience=AUDIENCE,
    )

    def _mock_fetch_side_effect(url, **_):
        res = unittest.mock.MagicMock()
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
            encoded = base64.b64encode(OIDC_CONFIG_YAML.encode()).decode()
            res.to_json.return_value = {'content': encoded, 'encoding': 'base64'}
        return res

    with (
        unittest.mock.patch(
            'github_oidc_federation.github_api.http_client.fetch_with_retries',
            new=unittest.mock.AsyncMock(side_effect=_mock_fetch_side_effect),
        ),
        unittest.mock.patch(
            'github_oidc_federation.jwt_verifier.http_client.fetch_with_retries',
            new=unittest.mock.AsyncMock(side_effect=_mock_fetch_side_effect),
        ),
        unittest.mock.patch(
            'github_oidc_federation.github_api._create_jwt', return_value='app.jwt.token'
        ),
    ):
        yield await aiohttp_client(application)


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


async def test_invalid_jwt_returns_401(client, rsa_key_pair, kid):
    _, _, private_pem = rsa_key_pair
    expired_jwt = pyjwt.encode(
        {
            'iss': ISSUER,
            'sub': SUBJECT,
            'aud': AUDIENCE,
            'exp': 1,  # expired in 1970
        },
        private_pem,
        algorithm='RS256',
        headers={'kid': kid},
    )
    resp = await client.post(
        '/token-exchange',
        json={
            'token': expired_jwt,
            'host': HOST,
            'organization': ORG,
            'permissions': {'contents': 'read'},
            'repositories': ['my-repo'],
        },
    )
    assert resp.status == 401


async def test_disallowed_host_returns_403(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': 'evil.example.com',
            'organization': ORG,
            'permissions': {'contents': 'read'},
        },
    )
    assert resp.status == 403


async def test_invalid_repository_name_returns_400(client, valid_jwt):
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
    assert resp.status == 400


# --- Authorization failures ---


async def test_permission_level_too_high_returns_403(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': HOST,
            'organization': ORG,
            'permissions': {'contents': 'admin'},
        },
    )
    assert resp.status == 403


async def test_permission_not_granted_by_any_matching_entry_returns_403(client, valid_jwt):
    resp = await client.post(
        '/token-exchange',
        json={
            'token': valid_jwt,
            'host': HOST,
            'organization': ORG,
            'permissions': {'actions': 'read'},
        },
    )
    assert resp.status == 403


async def test_org_permission_with_repositories_returns_403(client, valid_jwt):
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
    assert resp.status == 403


# --- Cache invalidation ---


async def test_invalidate_cache_returns_204(client):
    resp = await client.post('/invalidate-cache')
    assert resp.status == 204
