# Releasing Nexus

Nexus releases use GitHub Releases as the only publishing trigger. The
`publish.yml` workflow validates that the release tag and `package.json`
version match, runs the complete test/audit/package checks, and publishes to npm
through short-lived OIDC credentials.

## One-time npm setup

Configure `@hawon/nexus` with this trusted GitHub Actions publisher on npmjs.com:

- Organization or user: `hawonb711-tech`
- Repository: `nexus`
- Workflow filename: `publish.yml`
- Allowed action: `npm publish`

No `NPM_TOKEN` is used. The workflow requires npm CLI 11.5.1+ and a GitHub-hosted
Node 24 runner; trusted publishing automatically attaches provenance.

## Release checklist

1. Update `package.json` with `npm version <patch|minor|major> --no-git-tag-version`.
2. Move the relevant `CHANGELOG.md` entries from `Unreleased` to the dated version.
3. Run `npm run check`, `npm run audit:core`, and `npm pack --dry-run`.
4. Merge through a green pull request.
5. Create and push an annotated `v<version>` tag at the merged commit.
6. Publish the matching GitHub Release. Do not run `npm publish` locally.
7. Confirm the Actions run succeeded and npm shows provenance for the new version.

The workflow treats an already-published npm version as a successful no-op. This
allows an older tag to receive a missing GitHub Release without attempting to
overwrite the immutable npm artifact.
