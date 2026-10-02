#!/usr/bin/env bash
# Promotes the tested tip of dev to main and releases it. Run by .github/workflows/promote.yml; the
# same file is used by every package repository.
#
#   VERSION          X.Y.Z to release; empty: the next patch number of the latest version tag
#   DRY_RUN          true: check everything and say what would happen, change nothing
#   ALLOW_UNCHECKED  true: release even if CI has not passed on the dev tip
#   REPO, GH_TOKEN   owner/name and a token (the workflow provides both)
#
# main gets the content of dev's tip as a merge commit that keeps main's history (a plain
# fast-forward when main is an ancestor of dev). The version tag and main are pushed together, so
# either both move or neither does. A push made with the workflow's own token starts no workflows,
# so the Release, CI and Docs workflows are started here.
set -euo pipefail

fail() { echo "::error::$*" >&2; exit 1; }

git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"
git fetch -q origin dev --no-tags
git fetch -q origin main --no-tags 2>/dev/null || true
git fetch -q origin --tags --force

dev=$(git rev-parse origin/dev)
have_main=false
if git rev-parse -q --verify origin/main > /dev/null; then have_main=true; fi

# 1. Something to release?
if $have_main && git merge-base --is-ancestor "$dev" origin/main; then
  fail "main already has everything on dev (${dev:0:7}); there is nothing to release"
fi

# 2. CI passed on exactly that commit?
state=$(gh api "repos/${REPO}/actions/runs?head_sha=${dev}&event=push&per_page=50" \
  --jq '[.workflow_runs[] | select(.name == "CI")][0] | if . == null then "none" else "\(.status):\(.conclusion // "")" end')
echo "CI on dev ${dev:0:7}: ${state}"
if [ "${state}" != "completed:success" ] && [ "${ALLOW_UNCHECKED:-false}" != "true" ]; then
  fail "CI has not passed on dev ${dev:0:7} (${state}). Wait for it, or run this with allow_unchecked."
fi

# 3. The version.
if [ -n "${VERSION:-}" ]; then
  [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version must look like 1.2.3, not '${VERSION}'"
  next="v${VERSION}"
else
  latest=$(git tag --list 'v[0-9]*' | sort -V | tail -1)
  IFS=. read -r major minor patch <<< "${latest:-v0.0.0}"
  next="v${major#v}.${minor}.$((patch + 1))"
fi
if git rev-parse -q --verify "refs/tags/${next}" > /dev/null; then fail "${next} already exists"; fi

# 4. The commit main will point at.
if ! $have_main; then
  new=$dev
  how="main does not exist yet: it starts at dev"
elif git merge-base --is-ancestor origin/main "$dev"; then
  new=$dev
  how="fast-forward: main moves to dev"
else
  new=$(git commit-tree "${dev}^{tree}" -p origin/main -p "$dev" -m "Release ${next}: main takes the content of dev (${dev:0:7})" \
    -m "main keeps its history; its content is exactly dev's at the commit CI checked.")
  [ "$(git rev-parse "${new}^{tree}")" = "$(git rev-parse "${dev}^{tree}")" ] || fail "the merge commit differs from dev's content"
  how="merge commit ${new:0:7}: main's history stays, the content is dev's"
fi
echo "Release ${next}: ${how}"

if [ "${DRY_RUN:-false}" = "true" ]; then
  echo "Dry run: nothing was changed."
  exit 0
fi

# 5. Publish.
git tag "${next}" "${new}"
git push --atomic origin "${next}" "${new}:refs/heads/main"
gh workflow run release.yml --ref main -f "version=${next#v}"
git cat-file -e "${new}:.github/workflows/documentation.yml" 2> /dev/null && gh workflow run documentation.yml --ref main || true
gh workflow run ci.yml --ref main || true
echo "Released ${next}. The Release workflow is publishing it: https://github.com/${REPO}/actions"
