import pytest
import aiohttp.web

import github_oidc_federation.token_request_handler as handler
from github_oidc_federation.models import OidcFederationEntry, PermissionLevel
from github_oidc_federation.token_request_handler import (
    _check_matching_repositories,
    _check_no_org_permissions_with_repositories,
    _check_permissions,
    _is_request_authorized,
    _validate_request,
)


ISSUER = 'https://token.actions.githubusercontent.com'


@pytest.fixture(autouse=True)
def allowed_hosts():
    original = handler.ALLOWED_HOSTS
    handler.ALLOWED_HOSTS = {'github.com'}
    yield
    handler.ALLOWED_HOSTS = original


def _entry(permissions, repositories=None, subject='repo:org/repo:ref:refs/heads/main'):
    return OidcFederationEntry(
        issuer=ISSUER,
        subject=subject,
        permissions={k: PermissionLevel(v) for k, v in permissions.items()},
        repositories=repositories,
        principals=None,
    )


# --- _validate_request ---


def test_validate_request_missing_token_raises():
    with pytest.raises(aiohttp.web.HTTPBadRequest, match='Missing token'):
        _validate_request(None, 'github.com', 'org', {'contents': 'read'}, None)


def test_validate_request_missing_host_raises():
    with pytest.raises(aiohttp.web.HTTPBadRequest, match='Missing host'):
        _validate_request('tok', None, 'org', {'contents': 'read'}, None)


def test_validate_request_disallowed_host_raises():
    with pytest.raises(aiohttp.web.HTTPUnauthorized, match='not supported'):
        _validate_request('tok', 'evil.example.com', 'org', {'contents': 'read'}, None)


def test_validate_request_missing_organization_raises():
    with pytest.raises(aiohttp.web.HTTPBadRequest, match='Missing organization'):
        _validate_request('tok', 'github.com', None, {'contents': 'read'}, None)


def test_validate_request_missing_permissions_raises():
    with pytest.raises(aiohttp.web.HTTPBadRequest, match='Permissions'):
        _validate_request('tok', 'github.com', 'org', None, None)


def test_validate_request_permissions_not_dict_raises():
    with pytest.raises(aiohttp.web.HTTPBadRequest, match='Permissions'):
        _validate_request('tok', 'github.com', 'org', ['contents'], None)


def test_validate_request_repositories_not_list_raises():
    with pytest.raises(aiohttp.web.HTTPBadRequest, match='array'):
        _validate_request('tok', 'github.com', 'org', {'contents': 'read'}, 'my-repo')


def test_validate_request_repository_with_invalid_chars_raises():
    with pytest.raises(aiohttp.web.HTTPUnauthorized, match='not supported'):
        _validate_request('tok', 'github.com', 'org', {'contents': 'read'}, ['../evil'])


def test_validate_request_valid_passes():
    _validate_request('tok', 'github.com', 'org', {'contents': 'read'}, ['my-repo'])


# --- _check_matching_repositories ---


def test_check_matching_repositories_no_entry_repos_always_passes(make_token_request):
    req = make_token_request(requested_repositories=['repo-a'])
    assert _check_matching_repositories(req, _entry({'contents': 'read'})) is True


def test_check_matching_repositories_entry_repos_require_request_repos(make_token_request):
    req = make_token_request(requested_repositories=None)
    assert _check_matching_repositories(req, _entry({'contents': 'read'}, ['repo-a'])) is False


def test_check_matching_repositories_all_requested_in_entry_passes(make_token_request):
    req = make_token_request(requested_repositories=['repo-a'])
    assert (
        _check_matching_repositories(req, _entry({'contents': 'read'}, ['repo-a', 'repo-b'])) is True
    )


def test_check_matching_repositories_requested_not_in_entry_fails(make_token_request):
    req = make_token_request(requested_repositories=['repo-c'])
    assert _check_matching_repositories(req, _entry({'contents': 'read'}, ['repo-a'])) is False


# --- _check_permissions ---


def test_check_permissions_requested_within_allowed_passes(make_token_request):
    req = make_token_request(permissions={'contents': 'read'})
    assert _check_permissions(req, _entry({'contents': 'write'})) is True


def test_check_permissions_requested_equal_to_allowed_passes(make_token_request):
    req = make_token_request(permissions={'contents': 'write'})
    assert _check_permissions(req, _entry({'contents': 'write'})) is True


def test_check_permissions_requested_exceeds_allowed_fails(make_token_request):
    req = make_token_request(permissions={'contents': 'admin'})
    assert _check_permissions(req, _entry({'contents': 'write'})) is False


def test_check_permissions_permission_not_in_entry_fails(make_token_request):
    req = make_token_request(permissions={'actions': 'read'})
    assert _check_permissions(req, _entry({'contents': 'read'})) is False


def test_check_permissions_multiple_all_valid_passes(make_token_request):
    req = make_token_request(permissions={'contents': 'read', 'actions': 'read'})
    assert _check_permissions(req, _entry({'contents': 'write', 'actions': 'admin'})) is True


def test_check_permissions_multiple_one_invalid_fails(make_token_request):
    req = make_token_request(permissions={'contents': 'write', 'actions': 'admin'})
    assert _check_permissions(req, _entry({'contents': 'write', 'actions': 'read'})) is False


# --- _check_no_org_permissions_with_repositories ---


def test_check_no_org_permissions_no_repos_passes(make_token_request):
    req = make_token_request(
        permissions={'organization_secrets': 'read'},
        requested_repositories=None,
    )
    assert _check_no_org_permissions_with_repositories(req) is True


def test_check_no_org_permissions_repos_with_org_permission_fails(make_token_request):
    req = make_token_request(
        permissions={'organization_secrets': 'read'},
        requested_repositories=['repo-a'],
    )
    assert _check_no_org_permissions_with_repositories(req) is False


def test_check_no_org_permissions_repos_without_org_permission_passes(make_token_request):
    req = make_token_request(permissions={'contents': 'read'}, requested_repositories=['repo-a'])
    assert _check_no_org_permissions_with_repositories(req) is True


# --- _is_request_authorized ---


def test_is_request_authorized_fully_authorized(make_token_request):
    req = make_token_request(permissions={'contents': 'read'}, requested_repositories=['repo-a'])
    assert (
        _is_request_authorized(req, _entry({'contents': 'write'}, repositories=['repo-a'])) is True
    )


def test_is_request_authorized_repository_mismatch(make_token_request):
    req = make_token_request(permissions={'contents': 'read'}, requested_repositories=['repo-b'])
    assert (
        _is_request_authorized(req, _entry({'contents': 'write'}, repositories=['repo-a'])) is False
    )


def test_is_request_authorized_permission_level_exceeded(make_token_request):
    req = make_token_request(permissions={'contents': 'admin'})
    assert _is_request_authorized(req, _entry({'contents': 'read'})) is False


def test_is_request_authorized_org_permission_with_repo(make_token_request):
    req = make_token_request(
        permissions={'organization_secrets': 'read'},
        requested_repositories=['repo-a'],
    )
    assert _is_request_authorized(req, _entry({'organization_secrets': 'admin'})) is False
