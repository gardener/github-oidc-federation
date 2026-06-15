import json
import unittest.mock

import aiohttp.web
import jwt
import jwt.algorithms
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import github_oidc_federation.jwt_verifier as jwt_verifier
from github_oidc_federation.jwt_verifier import extract_issuer, verify_jwt


ISSUER = 'https://token.actions.githubusercontent.com'
AUDIENCE = 'github-oidc-federation'
SUBJECT = 'repo:org/repo:ref:refs/heads/main'


@pytest.fixture(autouse=True)
def clear_public_key_cache():
    jwt_verifier._fetch_public_key.cache_clear()
    yield
    jwt_verifier._fetch_public_key.cache_clear()


@pytest.fixture(autouse=True)
def set_audience():
    original = jwt_verifier.EXPECTED_AUDIENCE
    jwt_verifier.EXPECTED_AUDIENCE = AUDIENCE
    yield
    jwt_verifier.EXPECTED_AUDIENCE = original


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
    return 'test-key-id'


def _make_token(private_pem: bytes, kid: str, claims_override=None):
    claims = {
        'iss': ISSUER,
        'sub': SUBJECT,
        'aud': AUDIENCE,
        **(claims_override or {}),
    }
    return pyjwt.encode(claims, private_pem, algorithm='RS256', headers={'kid': kid})


def _make_jwks(public_key, kid: str) -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk['kid'] = kid
    return {'keys': [jwk]}


_SENTINEL = object()


def _mock_response(json_data: dict):
    res = unittest.mock.MagicMock()
    res.ok = True
    res.to_json.return_value = json_data
    return res


def _mock_fetch(jwks_payload: dict, openid_cfg=_SENTINEL):
    default_cfg = {'jwks_uri': f'{ISSUER}/jwks'}

    async def _side_effect(url, **_):
        if 'openid-configuration' in url:
            return _mock_response(default_cfg if openid_cfg is _SENTINEL else openid_cfg)
        return _mock_response(jwks_payload)

    return _side_effect


# --- extract_issuer ---


def test_extract_issuer_from_unverified_token(rsa_key_pair, kid):
    _, _, private_pem = rsa_key_pair
    token = _make_token(private_pem, kid)
    assert extract_issuer(token) == ISSUER


def test_extract_issuer_missing_raises_bad_request():
    token = pyjwt.encode({'sub': SUBJECT}, 'secret-key-long-enough-for-hmac-256', algorithm='HS256')
    with pytest.raises(aiohttp.web.HTTPBadRequest, match='Missing issuer'):
        extract_issuer(token)


# --- verify_jwt ---


async def test_verify_jwt_valid_token_returns_claims(rsa_key_pair, kid):
    _, public_key, private_pem = rsa_key_pair
    token = _make_token(private_pem, kid)
    jwks = _make_jwks(public_key, kid)

    with unittest.mock.patch(
        'github_oidc_federation.jwt_verifier.fetch_with_retries',
        side_effect=_mock_fetch(jwks),
    ):
        claims = await verify_jwt(token, ISSUER)

    assert claims['sub'] == SUBJECT
    assert claims['iss'] == ISSUER


async def test_verify_jwt_wrong_issuer_raises_unauthorized(rsa_key_pair, kid):
    _, public_key, private_pem = rsa_key_pair
    token = _make_token(private_pem, kid)
    jwks = _make_jwks(public_key, kid)

    with unittest.mock.patch(
        'github_oidc_federation.jwt_verifier.fetch_with_retries',
        side_effect=_mock_fetch(jwks),
    ):
        with pytest.raises(aiohttp.web.HTTPUnauthorized, match='Token verification failed'):
            await verify_jwt(token, 'https://evil.example.com')


async def test_verify_jwt_unknown_kid_raises_unauthorized(rsa_key_pair, kid):
    _, public_key, private_pem = rsa_key_pair
    token = _make_token(private_pem, kid)
    jwks = _make_jwks(public_key, 'other-kid')

    with unittest.mock.patch(
        'github_oidc_federation.jwt_verifier.fetch_with_retries',
        side_effect=_mock_fetch(jwks),
    ):
        with pytest.raises(aiohttp.web.HTTPUnauthorized):
            await verify_jwt(token, ISSUER)


async def test_verify_jwt_missing_sub_claim_raises_bad_request(rsa_key_pair, kid):
    _, public_key, private_pem = rsa_key_pair
    jwks = _make_jwks(public_key, kid)
    token_no_sub = pyjwt.encode(
        {'iss': ISSUER, 'aud': AUDIENCE},
        private_pem,
        algorithm='RS256',
        headers={'kid': kid},
    )

    with unittest.mock.patch(
        'github_oidc_federation.jwt_verifier.fetch_with_retries',
        side_effect=_mock_fetch(jwks),
    ):
        with pytest.raises(aiohttp.web.HTTPBadRequest, match='Missing sub claim'):
            await verify_jwt(token_no_sub, ISSUER)


async def test_verify_jwt_missing_jwks_uri_raises_bad_request(rsa_key_pair, kid):
    _, _, private_pem = rsa_key_pair
    token = _make_token(private_pem, kid)

    with unittest.mock.patch(
        'github_oidc_federation.jwt_verifier.fetch_with_retries',
        side_effect=_mock_fetch({}, openid_cfg={}),
    ):
        with pytest.raises(aiohttp.web.HTTPBadRequest, match='Missing jwks_uri'):
            await verify_jwt(token, ISSUER)


async def test_verify_jwt_fetch_failure_raises_500(rsa_key_pair, kid):
    _, _, private_pem = rsa_key_pair
    token = _make_token(private_pem, kid)

    with unittest.mock.patch(
        'github_oidc_federation.jwt_verifier.fetch_with_retries',
        side_effect=ConnectionError('network error'),
    ):
        with pytest.raises(aiohttp.web.HTTPInternalServerError):
            await verify_jwt(token, ISSUER)
