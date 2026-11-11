# Secret rotation and history purge

The brief requires the procedure **"revoke first, purge after"** on at least
one intentionally exposed secret. This is the exact sequence.

## 1. Revoke first

Rotate the secret at its source **before** touching git history. Anyone who
already has the old value must lose access immediately.

For the session signing key:

```bash
# Generate a new key (32+ random bytes)
openssl rand -base64 48

# Store it in the secret manager, never in git
kubectl -n helpdesk create secret generic helpdesk-app-secret \
  --from-literal=SECRET_KEY="$(openssl rand -base64 48)" \
  --dry-run=client -o yaml | kubectl apply -f -
```

Then update the Deployment to read `SECRET_KEY` from that Secret and redeploy.
All existing session cookies become invalid.

For a token (GitHub, registry, database), use the provider's "revoke" action
first, then create the replacement.

## 2. Then purge the history

Only after revocation:

```bash
# Option A: git filter-repo (recommended)
git filter-repo --path .env --invert-paths
# or remove the exact string from all commits with a replace file

# Option B: BFG
bfg --delete-files .env
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

Force-push and tell every collaborator to re-clone (old clones still contain
the secret):

```bash
git push --force --all
git push --force --tags
```

## 3. Verify

```bash
gitleaks detect --source . --log-opts="--all" --redact --exit-code 1
# Expected: no leaks found
```

Also verify the old secret no longer works (the forged cookie is rejected, the
revoked token returns 401).

## 4. Prevent recurrence

- Gitleaks pre-commit hook:
  `gitleaks protect --staged --redact`
- Gitleaks in CI on the full history (`fetch-depth: 0`).
- `.gitignore` for `.env`, `*.pem`, `*.key`.
- A project rule in `.gitleaks.toml` for the session key pattern (already
  included).
- Never log a secret: the app logs metadata only.

## Timeline to show in the report

| Time | Action | Evidence |
|---|---|---|
| T0 | Fake secret committed on a branch | commit hash |
| T1 | Pipeline fails at Gitleaks | screenshot |
| T2 | Secret revoked/rotated at the source | provider log / new key fingerprint |
| T3 | History purged and force-pushed | `git log` / filter-repo output |
| T4 | Full-history scan clean | Gitleaks output |
| T5 | Old cookie/token rejected | HTTP 401/redirect |
