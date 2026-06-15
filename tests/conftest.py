import unittest.mock

import pytest

from github_oidc_federation.models import OidcFederationEntry, PermissionLevel, TokenRequest


@pytest.fixture
def make_entry():
    def _make(
        issuer='https://token.actions.githubusercontent.com',
        subject='repo:org/repo:ref:refs/heads/main',
        permissions=None,
        repositories=None,
        principals=None,
    ):
        return OidcFederationEntry(
            issuer=issuer,
            subject=subject,
            permissions=permissions or {'contents': PermissionLevel.READ},
            repositories=repositories,
            principals=principals,
        )

    return _make


@pytest.fixture
def make_token_request():
    def _make(
        jwt='tok',
        host='github.com',
        organization='my-org',
        permissions=None,
        requested_repositories=None,
        issuer='https://token.actions.githubusercontent.com',
        repo_url='github.com/my-org/.github-oidc',
        credential=None,
    ):
        return TokenRequest(
            jwt=jwt,
            host=host,
            organization=organization,
            permissions=permissions or {'contents': 'read'},
            requested_repositories=requested_repositories,
            issuer=issuer,
            repo_url=repo_url,
            credential=credential or unittest.mock.MagicMock(),
        )

    return _make
