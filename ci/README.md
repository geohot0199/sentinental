# CI configuration

`github-actions-ci.yml` is the CI pipeline for this project. It runs, in order:

1. **Secret scan** — first, so a leaked credential fails the build before any
   later step could echo it into a log.
2. **Typecheck**
3. **Lint** at `--max-warnings=0` — `@typescript-eslint` recommended plus the
   shape gates in `eslint.config.js`, `max-lines` 500 among them. Warnings fail
   too, so an unused disable directive cannot accumulate.
4. **Unit tests**
5. **Dependency audit** at `--audit-level=high`

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
npm run lint -- --max-warnings=0
npm test
npm audit --audit-level=high
```

To scan only what is staged, rather than every tracked file:

```bash
node --experimental-strip-types scripts/scan-secrets.ts --staged
```

## Landing page deployment

`pages.yml` publishes the static landing page in `site/` to GitHub Pages. It has
no build step — it uploads the folder as-is.

```bash
cp ci/pages.yml .github/workflows/pages.yml
git add .github/workflows/pages.yml
git commit -m "ci: publish the landing page to GitHub Pages"
```

Then set **Settings → Pages → Source** to **GitHub Actions**.

Until that is done, the page can be published from a branch instead:
**Settings → Pages → Source → Deploy from a branch**, pick the branch and the
`/site` folder. `site/.nojekyll` is included so GitHub serves the files exactly
as they are.

Preview it locally at any time with:

```bash
npm run site:dev        # http://localhost:4321
```
