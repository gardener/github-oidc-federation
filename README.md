# GitHub OIDC Federation

The GitHub OIDC Federation service provides the capability to exchange an OIDC identity token for
a short-lived GitHub access token. Hence, it allows cross GitHub instance/organization/repository
access without the need for static credentials (e.g. GitHub service accounts, GitHub App private
keys). The short-lived GitHub access tokens are created by a central GitHub App for the individual
requesters. The federated access is managed in the `.github` repository of the target GitHub
organization, via a `oidc-federation.(yaml|json)` file.

> [!NOTE]  
> By design, the central GitHub App must be granted all the permissions requesters should be able to
> request, and must be installed into the target GitHub organization with access to its repositories
> (including the `.github` repository).

## OIDC Federation Configuration

To configure the federated access, a `oidc-federation.(yaml|json)` file is required in the target
organization's `.github` repository. It is used to map the supported issuer and subject to the
allowed repositories and permissions. Example:

```yaml
- issuer: https://token.actions.githubusercontent.com
  subject: repo:gardener/github-oidc-federation:ref:refs/heads/main
  permissions: # can be omitted for full access
    contents: read
  repositories: # can be omitted for global organization access
    - github-oidc-federation
```

## Token Request

To request a short-lived GitHub access token, a POST request to the `/token-exchange` endpoint must
be done including the desired GitHub `host` and `organization` as well as the identity `token` and
requested `permissions`. Optionally, the GitHub `repositories` can be specified to limit the scope
of the access token. Example:

```bash
curl -sLS -X POST "<token-server-url>/token-exchange" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "github.com",
    "organization": "gardener",
    "token": "<identity-token>",
    "repositories": ["github-oidc-federation"],
    "permissions": {
      "contents": "read"
    }
  }'
```

## Supported Permissions

The supported permissions are mapped to the permissions of the central GitHub App in use. For a full
list of available permissions for GitHub Apps, please refer to the
[documentation](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps).
The permission names are expected to be in snake_case format.

## Usage in GitHub Actions

To generate a short-lived GitHub access token from within GitHub Actions, please use the available
[gardener/cc-utils/.github/actions/github-auth@master](https://github.com/gardener/cc-utils/tree/master/.github/actions/github-auth)
Action. Example:

```yaml
- uses: gardener/cc-utils/.github/actions/github-auth@master
  id: token
  with:
    token-server: ${{ vars.FEDERATED_GITHUB_ACCESS_TOKEN_SERVER }}
    host: github.com # defaults to current GitHub host
    organization: gardener # defaults to current GitHub owner
    repositories: # defaults to all repositories of the specified `organization`
        github-oidc-federation
        cc-utils
    permissions: | # defaults to `contents: read`
      contents: read
      pull_requests: write
- shell: bash
  run: |
    echo "${{ steps.token.outputs.token }}"
```

## Deployment

An instance of the GitHub OIDC Federation server can be installed using the provided Helm chart.
However, the contained Deployment expects a Secret `github-oidc-federation` to be available which
contains the reference(s) to the central GitHub App(s) (`host`, `app_id`, and `private_key`).
Example:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: github-oidc-federation
stringData:
  github-com: |
    host: github.com
    app_id: 1234567
    private_key: |
      -----BEGIN RSA PRIVATE KEY-----
      <truncated>
      -----END RSA PRIVATE KEY-----
```

## Local Development

### Prerequisites

- Python `3.12` or greater is installed (qualification is always done using the Python3 version from
  `alpine:edge`)
- (optional) Create a new [virtual env](https://docs.python.org/3/library/venv.html) in your local
  repository and activate it:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```
- Install Python dependencies:
  ```bash
  # assuming the PWD is the repository root
  pip3 install --upgrade -r requirements.txt
  ```
- Fill-in the `test/github-com.yaml` file with the GitHub App credentials and/or add similar files
  for the desired GitHub instances

### Start-Up

```bash
# assuming the PWD is the repository root
python3 app.py --github-app-credentials-path test
```
