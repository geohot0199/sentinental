# CI configuration

`github-actions-ci.yml` is the CI pipeline for this project. It runs, in order:

1. **Secret scan** — first, so a leaked credential fails the build before any
   later step could echo it into a log.
2. **Typecheck**
3. **Unit tests**
4. **Dependency audit** at `--audit-level=high`

## Activating it

The automation account used to open this pull request does not hold GitHub's
`workflows` permission, so it cannot commit under `.github/workflows/`. Enable
it yourself with:

```bash
mkdir -p .github/workflows
cp ci/github-actions-ci.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "ci: enable the verification pipeline"
```

Every check it runs is also runnable locally:

```bash
npm run scan:secrets
npm run typecheck
npm test
npm audit --audit-level=high
```
