import pytest

from github_oidc_federation.models import OidcFederationEntry, PermissionLevel


# --- PermissionLevel ---


def test_permission_level_ordering():
    assert PermissionLevel.READ < PermissionLevel.WRITE
    assert PermissionLevel.WRITE < PermissionLevel.ADMIN


def test_permission_level_string_value():
    assert PermissionLevel.READ == 'read'
    assert PermissionLevel.WRITE == 'write'
    assert PermissionLevel.ADMIN == 'admin'


# --- OidcFederationEntry ---


def test_oidc_federation_entry_valid_with_subject_only():
    entry = OidcFederationEntry(
        issuer='https://example.com',
        subject='repo:org/repo:ref:refs/heads/main',
        permissions={'contents': PermissionLevel.READ},
        repositories=None,
        principals=None,
    )
    assert entry.issuer == 'https://example.com'


def test_oidc_federation_entry_valid_with_principals_only():
    entry = OidcFederationEntry(
        issuer='https://example.com',
        subject=None,
        permissions={'contents': PermissionLevel.WRITE},
        repositories=['my-repo'],
        principals=[{'repository': 'org/repo'}],
    )
    assert entry.principals == [{'repository': 'org/repo'}]


def test_oidc_federation_entry_neither_subject_nor_principals_raises():
    with pytest.raises(ValueError, match='Either subject or principals must be specified'):
        OidcFederationEntry(
            issuer='https://example.com',
            subject=None,
            permissions={'contents': PermissionLevel.READ},
            repositories=None,
            principals=None,
        )


def test_oidc_federation_entry_none_permission_value_raises():
    with pytest.raises(ValueError, match='Permission levels must not be None'):
        OidcFederationEntry(
            issuer='https://example.com',
            subject='repo:org/repo:ref:refs/heads/main',
            permissions={'contents': None},
            repositories=None,
            principals=None,
        )


def test_oidc_federation_entry_empty_permissions_allowed():
    entry = OidcFederationEntry(
        issuer='https://example.com',
        subject='repo:org/repo:ref:refs/heads/main',
        permissions={},
        repositories=None,
        principals=None,
    )
    assert entry.permissions == {}
