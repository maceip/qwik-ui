# CI/CD Security Audit Report — Additional Findings

**Date:** 2026-07-24
**Scope:** `.github/workflows/`, `.github/actions/`, and related CI configuration
**Severity threshold:** MEDIUM and above with real exploitable impact

> This report covers findings **not** already documented in the prior audit
> (Nx Cloud token, `ad-m/github-push-action@master`, CLA PAT exposure, test
> workflow PR-controlled composite actions).

---

## Finding 1 — `website.yml`: Cloudflare API Token Interpolated Directly into Shell Command (MEDIUM)

| Field | Detail |
|---|---|
| **File** | `.github/workflows/website.yml` |
| **Lines** | 17-20 |
| **Severity** | MEDIUM |

### Description

The deployment step sets the `CLOUDFLARE_API_TOKEN` correctly via the `env:` block
(line 17-18) but **also** interpolates the raw secret directly into the `run:`
command on line 20:

```yaml
      - name: Deploy
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
        shell: bash
        run: CLOUDFLARE_API_TOKEN=${{ secrets.CLOUDFLARE_API_TOKEN }} npx nx deploy website
```

The `${{ secrets.CLOUDFLARE_API_TOKEN }}` expression is evaluated by the GitHub
Actions runner **before** the shell is invoked, so the literal token value is
embedded in the shell command string.

### Attack Chain

1. GitHub Actions substitutes the secret value directly into the shell command text before execution.
2. The secret appears as a command-line argument visible via `/proc/<pid>/cmdline` on the Linux runner.
3. Any concurrent step, post-job hook, or compromised third-party action running in the same job can read `/proc/*/cmdline` to extract the Cloudflare token.
4. The Nx Cloud remote cache in this repo uses a **read-write** access token (prior finding #1). If that cache is poisoned, a malicious cached `deploy` task could harvest the Cloudflare token from the process table.
5. If shell tracing (`set -x`) or Nx verbose logging is ever enabled, the literal token is printed to workflow logs.

### Impact

Compromise of the Cloudflare API token allows an attacker to modify DNS records, deploy malicious content to the project website, or reconfigure the Cloudflare account.

### Remediation

Remove the inline secret from the `run:` command. The `env:` block already makes it available as `$CLOUDFLARE_API_TOKEN`:

```yaml
      - name: Deploy
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
        shell: bash
        run: npx nx deploy website
```

---

## Finding 2 — All Workflows Missing `permissions` Block — Overly Broad GITHUB_TOKEN Scope (MEDIUM)

| Field | Detail |
|---|---|
| **Files** | `website.yml`, `test.yml`, `release.yml`, `cla.yml` |
| **Severity** | MEDIUM |

### Description

None of the four workflow files declare a `permissions` key at the workflow or
job level. When omitted, the `GITHUB_TOKEN` inherits the repository's default
permission set, which is typically **read-write on all scopes** (`contents`,
`packages`, `actions`, `deployments`, `issues`, `pull-requests`, etc.).

### Attack Chain

1. `test.yml` triggers on every `push` event (no branch filter), granting the GITHUB_TOKEN full default write permissions.
2. The token is passed explicitly to `styfle/cancel-workflow-action` (line 20) and to the composite test action (line 30).
3. Third-party actions pinned to mutable tags (Finding 3) receive this overpermissioned token.
4. If any action is supply-chain-compromised, the attacker gains `contents: write` (push code, create releases), `actions: write` (modify workflows), `packages: write` (publish packages), and more.
5. With `contents: write` the attacker can push directly to `main` if branch protection rules are absent or weak.

### Impact

The overly broad token scope amplifies the blast radius of any supply-chain compromise from a single step/action into full repository takeover.

### Remediation

Add explicit minimal `permissions` to each workflow. For example:

```yaml
# test.yml
permissions:
  contents: read
  checks: write      # only if danger/checks need it
  statuses: write    # only if needed

# release.yml
permissions:
  contents: write
  packages: write

# website.yml
permissions:
  contents: read
```

---

## Finding 3 — Third-Party Actions Pinned to Mutable Tags Receiving Sensitive Tokens (MEDIUM)

| Field | Detail |
|---|---|
| **Files** | `test.yml:17`, `actions/test/action.yml:34`, `actions/setup/action.yml:15,26,31` |
| **Severity** | MEDIUM |

> **Note:** The prior audit (finding #2) covers only `ad-m/github-push-action@master`
> in the release composite action. The actions below are in **different workflows
> and composite actions** and are not covered by that finding.

### Affected Actions

| Action | Ref | File:Line | Token Exposure |
|---|---|---|---|
| `styfle/cancel-workflow-action` | `@0.11.0` | `test.yml:17` | Receives `GITHUB_TOKEN` explicitly |
| `cypress-io/github-action` | `@v5` | `actions/test/action.yml:34` | Runs in job with persisted git credentials |
| `pnpm/action-setup` | `@v2.2.4` | `actions/setup/action.yml:26` | Runs early; controls the pnpm binary |
| `actions/checkout` | `@v3` | Multiple files | Stores GITHUB_TOKEN in git config |
| `actions/setup-node` | `@v3` | `actions/setup/action.yml:31` | Configures npm auth; creates `.npmrc` |

### Attack Chain (example: `styfle/cancel-workflow-action`)

1. Attacker compromises the `styfle/cancel-workflow-action` repository or the maintainer's account.
2. The `0.11.0` git tag is moved to a malicious commit (tags are mutable).
3. On the next `push` or `pull_request` event, `test.yml` fetches and executes the malicious action.
4. The action receives `access_token: ${{ secrets.GITHUB_TOKEN }}` with broad default permissions (Finding 2).
5. The attacker exfiltrates the token or uses it to push malicious code to the repository.

### Attack Chain (example: `pnpm/action-setup`)

1. The `v2.2.4` tag on `pnpm/action-setup` is moved to a compromised commit.
2. The compromised action replaces the `pnpm` binary with a trojanized version.
3. All subsequent `pnpm install` commands install attacker-controlled packages.
4. The release workflow later publishes these compromised packages to npm with `NPM_TOKEN`.

### Attack Chain (example: `cypress-io/github-action@v5`)

1. Pinned to `v5` — a major-version tag spanning many releases, trivially movable.
2. A compromised version executes in the test job with full environment access.
3. Persisted git credentials (Finding 4) allow silent pushes to the repository.

### Remediation

Pin all third-party actions to full commit SHAs:

```yaml
- uses: styfle/cancel-workflow-action@01ce38bf961b4e243a6342cbade0dbc234e993c0  # v0.11.0
- uses: cypress-io/github-action@<full-sha>  # v5
- uses: pnpm/action-setup@<full-sha>         # v2.2.4
- uses: actions/checkout@<full-sha>           # v3
- uses: actions/setup-node@<full-sha>         # v3
```

---

## Finding 4 — `actions/checkout` with Default `persist-credentials: true` Across All Workflows (MEDIUM)

| Field | Detail |
|---|---|
| **Files** | `website.yml:13`, `test.yml:21`, `release.yml:15,34`, `actions/setup/action.yml:15` |
| **Severity** | MEDIUM |

### Description

Every `actions/checkout` step uses the default `persist-credentials: true`.
This stores the `GITHUB_TOKEN` in the `.git/config` of the checked-out
repository, making it readable by **all** subsequent steps in the job — including
third-party actions and user-controlled composite actions.

The setup composite action (`actions/setup/action.yml:15`) performs a **second**
checkout with `fetch-depth: 0`, refreshing the persisted credential and also
making the full git history available. This compounds the risk: any later step
can both read the credential AND scan the full commit history for accidentally
committed secrets.

### Attack Chain

1. `actions/checkout@v3` stores the GITHUB_TOKEN in `.git/config` (the `http.extraheader` or credential helper).
2. The setup composite action re-checkouts with `fetch-depth: 0`, persisting the token again with full history.
3. Any subsequent step can extract the token by reading `.git/config` or by running `git config --get-regexp http`.
4. A compromised third-party action (e.g., one of the mutable-tag actions from Finding 3) reads the token.
5. With the token and `contents: write` default permissions (Finding 2), the attacker can push malicious commits or create releases.
6. The `fetch-depth: 0` checkout also exposes full git history; if secrets were ever committed and later removed, they are recoverable via `git log`.

### Remediation

Add `persist-credentials: false` to all checkout steps:

```yaml
- uses: actions/checkout@v3
  with:
    persist-credentials: false
    fetch-depth: 0  # only where needed
```

When git push is needed (e.g., release workflow), pass the token explicitly to the push step rather than relying on persisted credentials.

---

## Summary of Compounding Risks

These four findings interact to create a chain of escalating risk:

```
Mutable-tag action compromised (Finding 3)
  → Reads persisted git credentials (Finding 4)
  → Token has overly broad write permissions (Finding 2)
  → Attacker pushes code / modifies workflows / publishes packages
  → Deployment step leaks Cloudflare token via process table (Finding 1)
  → Full website takeover
```

Mitigating any single finding breaks part of the chain, but all four should be
addressed for defense-in-depth.
