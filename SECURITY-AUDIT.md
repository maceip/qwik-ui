# Security Audit Report — qwik-ui

**Date:** 2026-07-24
**Scope:** Dependencies, configurations, CI/CD, infrastructure security

---

## Finding 1 — HIGH: Nx Cloud Read-Write Access Token Committed to Repository

**File:** `nx.json`, line 14
**Token (base64-decoded):** `35b3750d-0426-47a7-9b2f-ab8db1abcc17|read-write`

The Nx Cloud access token is hardcoded in `nx.json` with **read-write** permissions. Anyone with repository access (public or cloned) can use this token to:
- Poison the Nx remote cache with malicious build artifacts
- Read cached build outputs that may contain sensitive data
- Disrupt CI/CD by manipulating cached results

**Remediation:** Move the token to a CI secret/environment variable. If the repo is public, rotate the token immediately and use a read-only token for public access, keeping the read-write token in CI secrets only.

---

## Finding 2 — HIGH: Root Monorepo Package Marked as Non-Private

**File:** `package.json`, line 8

```json
"private": false,
```

The root monorepo `package.json` has `"private": false`. This means running `npm publish` or `pnpm publish` at the root would publish the entire monorepo as the package `qwik-ui-repo` to npm. An accidental publish could:
- Expose internal source code, configuration, and secrets
- Cause a package name squatting issue if an attacker publishes first under a similar name

**Remediation:** Set `"private": true` in the root `package.json`. Only sub-packages intended for publishing should have `"private": false`.

---

## Finding 3 — HIGH: CI Workflow Exposes Cloudflare API Token in Command Line

**File:** `.github/workflows/website.yml`, line 20

```yaml
run: CLOUDFLARE_API_TOKEN=${{ secrets.CLOUDFLARE_API_TOKEN }} npx nx deploy website
```

The `CLOUDFLARE_API_TOKEN` secret is expanded inline in the `run` command. Even though `env:` is also set (line 18), the `${{ secrets.CLOUDFLARE_API_TOKEN }}` expression in `run:` causes GitHub Actions to substitute the secret value directly into the shell command string. This value can appear in:
- Process listing (`ps aux`)
- Shell debug traces
- Error messages or crash reports

**Remediation:** Remove the inline expansion and rely solely on the `env:` block:
```yaml
env:
  CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
run: npx nx deploy website
```

---

## Finding 4 — HIGH: CI Release Action Pinned to Mutable `master` Branch

**File:** `.github/actions/release/action.yml`, line 34

```yaml
uses: ad-m/github-push-action@master
```

This third-party GitHub Action is pinned to `master`, not a commit SHA. If the `ad-m/github-push-action` repository is compromised, a malicious version could:
- Exfiltrate `GITHUB_TOKEN` and `NPM_TOKEN` secrets
- Push arbitrary code to the repository
- Publish malicious packages to npm

**Remediation:** Pin to a specific commit SHA:
```yaml
uses: ad-m/github-push-action@<full-commit-sha>
```

---

## Finding 5 — MEDIUM: No Security Headers on Production Website

**File:** `apps/website/public/_headers`

The `_headers` file only sets cache headers for `/build/*`:
```
/build/*
  Cache-Control: public, max-age=31536000, s-maxage=31536000, immutable
```

The production Cloudflare Pages deployment is **missing all critical security headers** for all routes:

| Header | Status | Risk |
|---|---|---|
| `Content-Security-Policy` | Missing | XSS attacks, unauthorized script execution |
| `X-Frame-Options` | Missing | Clickjacking attacks |
| `X-Content-Type-Options` | Missing | MIME-type sniffing attacks |
| `Strict-Transport-Security` | Missing | SSL stripping / downgrade attacks |
| `Referrer-Policy` | Missing | Referrer information leakage |
| `Permissions-Policy` | Missing | Unauthorized browser feature access |

**Remediation:** Add security headers for all routes in `apps/website/public/_headers`:
```
/*
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';
```

---

## Finding 6 — MEDIUM: dangerouslySetInnerHTML With localStorage Data (DOM-Based XSS Vector)

**File:** `apps/website/src/routes/_components/router-head/css-theme-script.tsx`, lines 4–10

```typescript
const themeScript = `
  document.documentElement
    .setAttribute('class',
      localStorage.getItem('${THEME_STORAGE_KEY}') ??
      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    )`;
return <script dangerouslySetInnerHTML={themeScript} />;
```

The `THEME_STORAGE_KEY` is a compile-time constant interpolated into the script template, so the immediate XSS risk is limited. However, the script reads from `localStorage` at runtime and injects the value into `setAttribute('class', ...)`. If another vulnerability allows an attacker to control the localStorage value for `THEME_STORAGE_KEY`, the `setAttribute` call for `class` is relatively safe — but this pattern sets a precedent where `dangerouslySetInnerHTML` is used for inline scripts without sanitization.

**Remediation:** Consider using a safer pattern that validates the localStorage value against an allowlist of known themes before applying it.

---

## Finding 7 — MEDIUM: Overly Broad Vite Dev Server Filesystem Access

**Files:**
- `apps/website/vite.config.ts`, lines 22–25
- `packages/kit-headless/vite.config.ts`, lines 21–24
- `packages/kit-tailwind/vite.config.ts`, lines 19–22
- `packages/kit-material/vite.config.ts`, lines 19–22
- `packages/kit-fluffy/vite.config.ts`, lines 29–32

```typescript
server: {
  fs: {
    allow: ['../../'],
  },
},
```

All Vite configs allow the dev server to serve files from two directories above each package — which resolves to the monorepo root. In a development context this is expected, but if the dev server is accidentally exposed on a network (e.g., bound to `0.0.0.0`), it could serve any file from the workspace, including `.env` files, `nx.json` (with the access token), or `pnpm-lock.yaml`.

**Remediation:** Restrict `server.fs.allow` to only the specific directories needed, or ensure `server.host` is not set to `0.0.0.0` or `true`.

---

## Finding 8 — MEDIUM: Source Maps Enabled Globally in tsconfig.base.json

**File:** `tsconfig.base.json`, line 5

```json
"sourceMap": true,
```

Source maps are enabled globally. If production builds include source maps and they are deployed to Cloudflare Pages, they would expose the original TypeScript source code, making it easier for attackers to identify vulnerabilities.

**Remediation:** Ensure production builds do not include source maps, or verify that Vite's production build configuration strips them. Consider setting `"sourceMap": false` in production-specific tsconfig or verifying Vite's `build.sourcemap` is `false` (the default).

---

## Finding 9 — MEDIUM: Version-Publish Targets Skip Git Hook Verification

**Files:**
- `packages/kit-headless/project.json`, line 50
- `packages/kit-tailwind/project.json`, line 49
- `packages/kit-fluffy/project.json`, line 49

```json
"version-publish": {
  "executor": "@jscutlery/semver:version",
  "options": {
    "noVerify": true,
    ...
  }
}
```

The `noVerify: true` option bypasses git commit hooks (equivalent to `git commit --no-verify`). This means the commitlint and format checks configured in `.husky/` are skipped during releases. If a malicious or malformed commit is created during the release process, it will not be caught.

**Remediation:** Remove `"noVerify": true` or document why it is necessary for automated releases.

---

## Finding 10 — MEDIUM: Loose Peer Dependency Range Allows Any Future Major Version

**Files:**
- `packages/kit-headless/package.json`, line 26
- `packages/kit-tailwind/package.json`, line 39
- `packages/kit-fluffy/package.json`, line 38

```json
"peerDependencies": {
  "@builder.io/qwik": ">1.1.0"
}
```

The `>1.1.0` range accepts any future major version (2.x, 3.x, etc.) of `@builder.io/qwik`. This could cause unexpected breakage and, in a supply-chain attack scenario, could pull in a compromised future major version without warning.

**Remediation:** Use a caret or tilde range: `"@builder.io/qwik": "^1.2.0"` to constrain to compatible versions.

---

## Finding 11 — MEDIUM: CI Uses End-of-Life Node.js 16

**Files:**
- `package.json`, line 6: `"node": ">=16.0.0"`
- `.github/actions/setup/action.yml`, line 9: `default: '16'`
- `.github/workflows/test.yml`, line 14: `node_version: [16]`
- `.github/workflows/release.yml`, line 14: `node_version: [16]`

Node.js 16 reached End-of-Life on **2023-09-11** and no longer receives security patches. Running CI and building packages on Node 16 means known vulnerabilities in the runtime are unpatched.

**Remediation:** Upgrade to Node.js 18 (LTS) or Node.js 20 (current LTS) across `engines`, CI matrix, and setup action defaults.

---

## Finding 12 — MEDIUM: Outdated CI Action Versions With Known Vulnerabilities

**Files:**
- `.github/workflows/test.yml`, line 17: `styfle/cancel-workflow-action@0.11.0`
- `.github/actions/setup/action.yml`, line 26: `pnpm/action-setup@v2.2.4`
- `.github/workflows/test.yml`, line 21: `actions/checkout@v3`
- `.github/actions/setup/action.yml`, line 15: `actions/checkout@v3`
- `.github/actions/setup/action.yml`, line 31: `actions/setup-node@v3`

These actions are pinned to old tags (not commit SHAs). Supply-chain attacks via tag mutation (deleting and re-creating a tag) are a known attack vector for GitHub Actions.

**Remediation:** Pin all third-party actions to full commit SHAs and use Dependabot or Renovate to keep them updated.

---

## Summary

| # | Severity | Finding | File(s) |
|---|----------|---------|---------|
| 1 | HIGH | Nx Cloud read-write token in repo | `nx.json:14` |
| 2 | HIGH | Root package.json not private | `package.json:8` |
| 3 | HIGH | Cloudflare token exposed in CLI args | `.github/workflows/website.yml:20` |
| 4 | HIGH | CI action pinned to mutable `master` | `.github/actions/release/action.yml:34` |
| 5 | MEDIUM | No security headers on production site | `apps/website/public/_headers` |
| 6 | MEDIUM | dangerouslySetInnerHTML with localStorage | `css-theme-script.tsx:4-10` |
| 7 | MEDIUM | Overly broad Vite fs.allow | Multiple `vite.config.ts` |
| 8 | MEDIUM | Source maps enabled globally | `tsconfig.base.json:5` |
| 9 | MEDIUM | noVerify skips git hooks in releases | Multiple `project.json` |
| 10 | MEDIUM | Unbounded peer dependency range | Multiple `package.json` |
| 11 | MEDIUM | CI uses EOL Node.js 16 | CI workflows + `package.json` |
| 12 | MEDIUM | CI actions pinned to tags, not SHAs | CI workflows |
