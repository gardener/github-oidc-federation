import pytest

import github_oidc_federation.models as models


# --- PermissionLevel ---


def test_permission_level_ordering():
    assert models.PermissionLevel.READ < models.PermissionLevel.WRITE
    assert models.PermissionLevel.WRITE < models.PermissionLevel.ADMIN


def test_permission_level_string_value():
    assert models.PermissionLevel.READ == 'read'
    assert models.PermissionLevel.WRITE == 'write'
    assert models.PermissionLevel.ADMIN == 'admin'


# --- OidcFederationEntry ---


def test_oidc_federation_entry_valid_with_subject_only():
    entry = models.OidcFederationEntry(
        issuer='https://example.com',
        subject='repo:org/repo:ref:refs/heads/main',
        permissions={'contents': models.PermissionLevel.READ},
        repositories=None,
        principals=None,
    )
    assert entry.issuer == 'https://example.com'


def test_oidc_federation_entry_valid_with_principals_only():
    entry = models.OidcFederationEntry(
        issuer='https://example.com',
        subject=None,
        permissions={'contents': models.PermissionLevel.WRITE},
        repositories=['my-repo'],
        principals=[{'repository': 'org/repo'}],
    )
    assert entry.principals == [{'repository': 'org/repo'}]


def test_oidc_federation_entry_neither_subject_nor_principals_raises():
    with pytest.raises(ValueError, match='Either subject or principals must be specified'):
        models.OidcFederationEntry(
            issuer='https://example.com',
            subject=None,
            permissions={'contents': models.PermissionLevel.READ},
            repositories=None,
            principals=None,
        )


def test_oidc_federation_entry_none_permission_value_raises():
    with pytest.raises(ValueError, match='Permission levels must not be None'):
        models.OidcFederationEntry(
            issuer='https://example.com',
            subject='repo:org/repo:ref:refs/heads/main',
            permissions={'contents': None},
            repositories=None,
            principals=None,
        )


def test_oidc_federation_entry_empty_permissions_allowed():
    entry = models.OidcFederationEntry(
        issuer='https://example.com',
        subject='repo:org/repo:ref:refs/heads/main',
        permissions={},
        repositories=None,
        principals=None,
    )
    assert entry.permissions == {}
