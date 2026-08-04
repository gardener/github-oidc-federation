import pytest
import aiohttp.web

import github_oidc_federation.models as models
import github_oidc_federation.oidc_config as oidc_config


ISSUER = 'https://token.actions.githubusercontent.com'
SUBJECT = 'repo:org/repo:ref:refs/heads/main'


def _create_entry(subject=SUBJECT, issuer=ISSUER, principals=None, repositories=None):
    return models.OidcFederationEntry(
        issuer=issuer,
        subject=subject,
        permissions={'contents': models.PermissionLevel.READ},
        repositories=repositories,
        principals=principals,
    )


# --- _parse_raw_oidc_config ---


def test_parse_raw_oidc_config_subject_entry():
    raw = """
- issuer: https://token.actions.githubusercontent.com
  subject: repo:org/repo:ref:refs/heads/main
  permissions:
    contents: read
"""
    entries = oidc_config._parse_raw_oidc_config(raw)
    assert len(entries) == 1
    assert entries[0].issuer == ISSUER
    assert entries[0].subject == SUBJECT
    assert entries[0].permissions == {'contents': models.PermissionLevel.READ}


def test_parse_raw_oidc_config_principals_entry():
    raw = """
- issuer: https://token.actions.githubusercontent.com
  principals:
    - repository: org/repo
  permissions:
    actions: write
"""
    entries = oidc_config._parse_raw_oidc_config(raw)
    assert entries[0].principals == [{'repository': 'org/repo'}]
    assert entries[0].subject is None


def test_parse_raw_oidc_config_multiple_entries():
    raw = """
- issuer: https://a.example.com
  subject: repo:a/b:ref:refs/heads/main
  permissions:
    contents: read
- issuer: https://b.example.com
  subject: repo:c/d:ref:refs/heads/main
  permissions:
    contents: write
"""
    entries = oidc_config._parse_raw_oidc_config(raw)
    assert len(entries) == 2
    assert entries[1].permissions == {'contents': models.PermissionLevel.WRITE}


def test_parse_raw_oidc_config_invalid_yaml_raises_http_500():
    with pytest.raises(aiohttp.web.HTTPInternalServerError):
        oidc_config._parse_raw_oidc_config('not: valid: yaml: [[[')


def test_parse_raw_oidc_config_missing_required_field_raises_http_500():
    raw = """
- issuer: https://example.com
  permissions:
    contents: read
"""
    with pytest.raises(aiohttp.web.HTTPInternalServerError):
        oidc_config._parse_raw_oidc_config(raw)


# --- _entry_matches_claims ---


def test_entry_matches_claims_matching_subject():
    entry = _create_entry(subject=SUBJECT)
    assert oidc_config._entry_matches_claims(entry, {'sub': SUBJECT})


def test_entry_matches_claims_non_matching_subject():
    entry = _create_entry(subject=SUBJECT)
    assert not oidc_config._entry_matches_claims(
        entry, {'sub': 'repo:other/repo:ref:refs/heads/main'}
    )


def test_entry_matches_claims_principals_all_match():
    entry = _create_entry(
        subject=None,
        principals=[{'repository': 'org/repo', 'ref': 'refs/heads/main'}],
    )
    claims = {'sub': SUBJECT, 'repository': 'org/repo', 'ref': 'refs/heads/main', 'extra': 'x'}
    assert oidc_config._entry_matches_claims(entry, claims)


def test_entry_matches_claims_principals_partial_match_in_claims():
    entry = _create_entry(subject=None, principals=[{'repository': 'org/repo'}])
    claims = {'sub': SUBJECT, 'repository': 'org/repo', 'ref': 'refs/heads/main'}
    assert oidc_config._entry_matches_claims(entry, claims)


def test_entry_matches_claims_principals_no_match():
    entry = _create_entry(subject=None, principals=[{'repository': 'org/other'}])
    assert not oidc_config._entry_matches_claims(entry, {'sub': SUBJECT, 'repository': 'org/repo'})


def test_entry_matches_claims_principals_one_of_multiple_matches():
    entry = _create_entry(
        subject=None,
        principals=[{'repository': 'org/other'}, {'repository': 'org/repo'}],
    )
    assert oidc_config._entry_matches_claims(entry, {'sub': SUBJECT, 'repository': 'org/repo'})


# --- find_matching_entry ---

_always_authorized = lambda req, entry: True  # noqa: E731


def test_find_matching_entry_finds_match(make_token_request):
    req = make_token_request(issuer=ISSUER)
    entry = _create_entry(subject=SUBJECT)
    result = oidc_config.find_matching_entry(req, [entry], {'sub': SUBJECT}, _always_authorized)
    assert result is entry


def test_find_matching_entry_skips_wrong_issuer(make_token_request):
    req = make_token_request(issuer=ISSUER)
    wrong_issuer_entry = _create_entry(issuer='https://other.example.com')
    matching = _create_entry(issuer=ISSUER, subject=SUBJECT)
    result = oidc_config.find_matching_entry(
        req, [wrong_issuer_entry, matching], {'sub': SUBJECT}, _always_authorized
    )
    assert result is matching


def test_find_matching_entry_no_match_raises_http_403(make_token_request):
    req = make_token_request(issuer=ISSUER)
    entry = _create_entry(subject='repo:other/repo:ref:refs/heads/main')
    with pytest.raises(aiohttp.web.HTTPForbidden):
        oidc_config.find_matching_entry(req, [entry], {'sub': SUBJECT}, _always_authorized)


def test_find_matching_entry_empty_config_raises_http_403(make_token_request):
    req = make_token_request(issuer=ISSUER)
    with pytest.raises(aiohttp.web.HTTPForbidden):
        oidc_config.find_matching_entry(req, [], {'sub': SUBJECT}, _always_authorized)


def test_find_matching_entry_skips_unauthorized_entry(make_token_request):
    # mirrors the real-world scenario: same principal in two entries with different repositories;
    # the request targets repos from the second entry, so the first must be skipped
    req = make_token_request(issuer=ISSUER, requested_repositories=['repo-b'])
    entry_a = _create_entry(subject=SUBJECT, repositories=['repo-a'])
    entry_b = _create_entry(subject=SUBJECT, repositories=['repo-b'])

    def is_authorized(r, e):
        return e.repositories and all(repo in e.repositories for repo in r.requested_repositories)

    result = oidc_config.find_matching_entry(
        req, [entry_a, entry_b], {'sub': SUBJECT}, is_authorized
    )
    assert result is entry_b
